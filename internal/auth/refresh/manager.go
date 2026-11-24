// Package refresh issues and rotates the opaque refresh tokens that keep a session alive.
//
// The access token (package token) is a short-lived JWT. The refresh token is a random
// string whose hash lives in Redis, which is what allows instant revocation and theft
// detection. Every refresh swaps the presented token for a new one. If a token that was
// already swapped shows up again, the whole session is treated as stolen.
//
// This package only manages tokens. The caller (the auth service) owns everything else
// about the session: the database row, the "session is active" marker the middleware
// checks, auth events, and issuing the new access token.
package refresh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dositadi/handling-sessions-with-redis-and-golang/internal/shared/config"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

var (
	// ErrInvalidConfig means the refresh settings or the store are missing or unusable.
	ErrInvalidConfig = errors.New("invalid refresh token configuration")

	// ErrInvalidParams means the values given to Issue failed validation.
	ErrInvalidParams = errors.New("invalid refresh token parameters")

	// ErrTokenInvalid covers a malformed, unknown, expired or already revoked token.
	// Callers answer 401 and the client must sign in again, without being told which.
	ErrTokenInvalid = errors.New("refresh token is invalid")

	// ErrReuseDetected means a token that had already been exchanged was presented again.
	// Use errors.As with *ReuseDetectedError to get the session. The live token of that
	// session has been deleted; the caller must still revoke the session itself.
	ErrReuseDetected = errors.New("refresh token reuse detected")
)

// ReuseDetectedError carries the session whose token was reused.
type ReuseDetectedError struct {
	Session SessionRef
}

func (e *ReuseDetectedError) Error() string { return ErrReuseDetected.Error() }

// Is lets errors.Is(err, ErrReuseDetected) match this type.
func (e *ReuseDetectedError) Is(target error) bool { return target == ErrReuseDetected }

// SessionRef identifies the session a refresh token belongs to. All three ids come from
// the server's own records, never from a request.
type SessionRef struct {
	SessionID  uuid.UUID
	BusinessID uuid.UUID
	UserID     uuid.UUID
}

// IssueParams is the input for issuing the first refresh token of a session.
//
// AbsoluteExpiresAt is the session's hard limit, the same value stored in
// sessions.absolute_expires_at. No token of the session outlives it, however often the
// client refreshes.
type IssueParams struct {
	SessionID         uuid.UUID `validate:"required"`
	BusinessID        uuid.UUID `validate:"required"`
	UserID            uuid.UUID `validate:"required"`
	AbsoluteExpiresAt time.Time `validate:"required"`
}

// Issued is a newly issued refresh token.
type Issued struct {
	// Token is the value to send to the client. Never log it.
	Token string
	// ExpiresAt is when the token stops being valid if it is not used, in UTC. The
	// service stores it as sessions.expires_at.
	ExpiresAt time.Time
}

// Rotated is the result of a successful Rotate.
type Rotated struct {
	// Token is the replacement token to send to the client. Never log it.
	Token string
	// ExpiresAt is when the new token stops being valid if it is not used, in UTC.
	ExpiresAt time.Time
	// AbsoluteExpiresAt is the session's hard limit.
	AbsoluteExpiresAt time.Time
	// Session identifies whose session this is. The service must still check the session
	// and user are active before issuing an access token.
	Session SessionRef
	// Replayed is true when the presented token had already been exchanged a moment
	// earlier and this was accepted as a retry (see config.RefreshConfig.ReuseLeeway).
	Replayed bool
}

// Store is where refresh token records live. It is defined here, where it is consumed,
// and RedisStore is the production implementation. Rotate must be atomic: two
// concurrent calls with the same token must not both succeed.
type Store interface {
	// Create stores the first token of a session.
	Create(ctx context.Context, record NewRecord) error
	// Rotate swaps the presented token for a new one.
	Rotate(ctx context.Context, request RotateRequest) (RotateResult, error)
	// RevokeSession deletes the live token of a session. Revoking a session that has no
	// token is not an error.
	RevokeSession(ctx context.Context, sessionID uuid.UUID) error
}

// NewRecord is the first token of a session, as handed to the Store.
type NewRecord struct {
	TokenHash         string
	Session           SessionRef
	AbsoluteExpiresAt time.Time
	TTL               time.Duration
}

// RotateRequest asks the Store to swap one token for another.
type RotateRequest struct {
	SessionID uuid.UUID
	OldHash   string
	NewHash   string
	Now       time.Time
	// TTL is the lifetime wanted for the new token. The Store caps it so the token never
	// outlives the session's absolute expiry.
	TTL    time.Duration
	Leeway time.Duration
}

// RotateOutcome says what happened to a Rotate request.
type RotateOutcome int

const (
	RotateNotFound RotateOutcome = iota
	RotateExpired
	RotateReused
	RotateRotated
	RotateReplayed
)

// RotateResult is what the Store reports back.
type RotateResult struct {
	Outcome           RotateOutcome
	Session           SessionRef
	AbsoluteExpiresAt time.Time
	// TTL is the lifetime actually given to the new token, after the cap.
	TTL time.Duration
}

// Manager issues and rotates refresh tokens. Build it once at startup with NewManager and
// share it; it holds no mutable state and is safe for concurrent use.
type Manager struct {
	store    Store
	tokenTTL time.Duration
	leeway   time.Duration
	validate *validator.Validate
	now      func() time.Time
}

// NewManager validates the config and returns a ready Manager. log is optional and may
// be nil. The manager logs only reuse detection, and never logs tokens.
func NewManager(cfg config.RefreshConfig, store Store) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: store is required", ErrInvalidConfig)
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(cfg); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}

	return &Manager{
		store:    store,
		tokenTTL: cfg.TokenTTL,
		leeway:   cfg.ReuseLeeway,
		validate: validate,
		now:      time.Now,
	}, nil
}

// Issue creates the first refresh token of a new session, normally right after login.
func (m *Manager) Issue(ctx context.Context, params IssueParams) (Issued, error) {
	if err := ctx.Err(); err != nil {
		return Issued{}, fmt.Errorf("issuing refresh token: %w", err)
	}

	if err := m.validate.Struct(params); err != nil {
		return Issued{}, fmt.Errorf("%w: %v", ErrInvalidParams, err)
	}

	now := m.now().UTC()
	untilAbsoluteExpiry := params.AbsoluteExpiresAt.Sub(now)
	if untilAbsoluteExpiry <= 0 {
		return Issued{}, fmt.Errorf("%w: session has already reached its absolute expiry", ErrInvalidParams)
	}
	ttl := min(m.tokenTTL, untilAbsoluteExpiry)

	token, hash, err := generateToken(params.SessionID)
	if err != nil {
		return Issued{}, err
	}

	err = m.store.Create(ctx, NewRecord{
		TokenHash: hash,
		Session: SessionRef{
			SessionID:  params.SessionID,
			BusinessID: params.BusinessID,
			UserID:     params.UserID,
		},
		AbsoluteExpiresAt: params.AbsoluteExpiresAt.UTC(),
		TTL:               ttl,
	})
	if err != nil {
		return Issued{}, fmt.Errorf("issuing refresh token: %w", err)
	}

	return Issued{Token: token, ExpiresAt: now.Add(ttl)}, nil
}

// Rotate exchanges a presented refresh token for a new one.
//
// Errors:
//   - ErrTokenInvalid: malformed, unknown, expired or revoked. The client must sign in.
//   - ErrReuseDetected (as *ReuseDetectedError): a used token came back. The session's live
//     token is deleted here; the caller must revoke the session, write the
//     refresh_reuse_detected event, and answer 401.
//   - anything else is an infrastructure failure; answer 5xx, not 401, so the client
//     retries instead of signing the user out.
func (m *Manager) Rotate(ctx context.Context, presented string) (Rotated, error) {
	if err := ctx.Err(); err != nil {
		return Rotated{}, fmt.Errorf("rotating refresh token: %w", err)
	}

	parsed, err := parseToken(presented)
	if err != nil {
		return Rotated{}, err
	}

	newToken, newHash, err := generateToken(parsed.sessionID)
	if err != nil {
		return Rotated{}, err
	}

	now := m.now().UTC()
	result, err := m.store.Rotate(ctx, RotateRequest{
		SessionID: parsed.sessionID,
		OldHash:   parsed.hash,
		NewHash:   newHash,
		Now:       now,
		TTL:       m.tokenTTL,
		Leeway:    m.leeway,
	})
	if err != nil {
		return Rotated{}, fmt.Errorf("rotating refresh token: %w", err)
	}

	// The session id is already known from the token itself, so the Store need not echo it.
	result.Session.SessionID = parsed.sessionID

	switch result.Outcome {
	case RotateRotated, RotateReplayed:
		return Rotated{
			Token:             newToken,
			ExpiresAt:         now.Add(result.TTL),
			AbsoluteExpiresAt: result.AbsoluteExpiresAt,
			Session:           result.Session,
			Replayed:          result.Outcome == RotateReplayed,
		}, nil

	case RotateReused:
		return Rotated{}, m.handleReuse(ctx, result.Session)

	default: // RotateNotFound, RotateExpired
		return Rotated{}, ErrTokenInvalid
	}
}

// RevokeSession deletes the live refresh token of a session, for logout, logout-all,
// password change and the like. The caller revokes the session itself separately.
func (m *Manager) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("%w: session id is required", ErrInvalidParams)
	}

	if err := m.store.RevokeSession(ctx, sessionID); err != nil {
		return fmt.Errorf("revoking refresh tokens of session: %w", err)
	}
	return nil
}

// handleReuse deletes the session's live token and returns the reuse error. A failure to
// delete is joined to it, so the caller still sees ErrReuseDetected and the session is
// revoked by the service either way.
func (m *Manager) handleReuse(ctx context.Context, session SessionRef) error {
	reuseErr := &ReuseDetectedError{Session: session}

	if err := m.store.RevokeSession(ctx, session.SessionID); err != nil {
		return errors.Join(reuseErr, fmt.Errorf("revoking refresh tokens of session: %w", err))
	}
	return reuseErr
}
