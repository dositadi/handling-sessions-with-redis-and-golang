package refresh

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// The three Lua scripts below do each store operation atomically on the Redis server, so
// two requests carrying the same refresh token cannot both succeed. They are plain files
// so they can be read, reviewed and tested on their own.
var (
	//go:embed scripts/create.lua
	createScriptSource string

	//go:embed scripts/rotate.lua
	rotateScriptSource string

	//go:embed scripts/revoke_session.lua
	revokeSessionScriptSource string
)

// RedisStore is the Redis implementation of Store.
//
// Keys (the session id in braces is a hash tag, so all keys of one session live in the
// same Redis Cluster slot):
//
//	auth:refresh:{<session id>}:tok:<token hash>   hash: bid, uid, abs, used_at, child
//	auth:refresh:{<session id>}:current            hash of the session's live token
//
// Token records expire on their own through PEXPIRE. A used token's record is kept until
// then as a tombstone, which is what makes reuse detectable.
type RedisStore struct {
	client       redis.Scripter
	createScript *redis.Script
	rotateScript *redis.Script
	revokeScript *redis.Script
}

// NewRedisStore returns a store that runs its scripts on the given client. Any go-redis
// client that can run scripts works, including a cluster client.
func NewRedisStore(client redis.Scripter) *RedisStore {
	return &RedisStore{
		client:       client,
		createScript: redis.NewScript(createScriptSource),
		rotateScript: redis.NewScript(rotateScriptSource),
		revokeScript: redis.NewScript(revokeSessionScriptSource),
	}
}

// Create stores the first token of a session.
func (s *RedisStore) Create(ctx context.Context, record NewRecord) error {
	sessionID := record.Session.SessionID

	keys := []string{
		tokenKey(sessionID, record.TokenHash),
		currentKey(sessionID),
	}
	args := []interface{}{
		record.TokenHash,
		record.Session.BusinessID.String(),
		record.Session.UserID.String(),
		record.AbsoluteExpiresAt.UnixMilli(),
		record.TTL.Milliseconds(),
		tokenKeyPrefix(sessionID),
	}

	if err := s.createScript.Run(ctx, s.client, keys, args...).Err(); err != nil {
		return fmt.Errorf("storing refresh token: %w", err)
	}
	return nil
}

// Rotate swaps the presented token for a new one, atomically.
func (s *RedisStore) Rotate(ctx context.Context, request RotateRequest) (RotateResult, error) {
	keys := []string{
		tokenKey(request.SessionID, request.OldHash),
		tokenKey(request.SessionID, request.NewHash),
		currentKey(request.SessionID),
	}
	args := []interface{}{
		request.Now.UnixMilli(),
		request.NewHash,
		request.TTL.Milliseconds(),
		request.Leeway.Milliseconds(),
		tokenKeyPrefix(request.SessionID),
	}

	reply, err := s.rotateScript.Run(ctx, s.client, keys, args...).Slice()
	if err != nil {
		return RotateResult{}, fmt.Errorf("running rotate script: %w", err)
	}

	return parseRotateReply(reply)
}

// RevokeSession deletes the live token of a session.
func (s *RedisStore) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	keys := []string{currentKey(sessionID)}
	args := []interface{}{tokenKeyPrefix(sessionID)}

	if err := s.revokeScript.Run(ctx, s.client, keys, args...).Err(); err != nil {
		return fmt.Errorf("revoking session tokens: %w", err)
	}
	return nil
}

// parseRotateReply turns the script's reply array into a RotateResult.
func parseRotateReply(reply []interface{}) (RotateResult, error) {
	if len(reply) == 0 {
		return RotateResult{}, fmt.Errorf("rotate script returned an empty reply")
	}

	outcomeName, ok := reply[0].(string)
	if !ok {
		return RotateResult{}, fmt.Errorf("rotate script returned an unexpected outcome type %T", reply[0])
	}

	var outcome RotateOutcome
	switch outcomeName {
	case "not_found":
		return RotateResult{Outcome: RotateNotFound}, nil
	case "expired":
		outcome = RotateExpired
	case "reused":
		outcome = RotateReused
	case "rotated":
		outcome = RotateRotated
	case "replayed":
		outcome = RotateReplayed
	default:
		return RotateResult{}, fmt.Errorf("rotate script returned an unknown outcome %q", outcomeName)
	}

	// Every outcome other than not_found carries: business id, user id, absolute expiry,
	// and (rotated and replayed only) the new token's lifetime in milliseconds.
	wantFields := 4
	if outcome == RotateRotated || outcome == RotateReplayed {
		wantFields = 5
	}
	if len(reply) < wantFields {
		return RotateResult{}, fmt.Errorf("rotate script reply for %q has %d fields, want %d", outcomeName, len(reply), wantFields)
	}

	fields := make([]string, wantFields)
	for i := range fields {
		text, isString := reply[i].(string)
		if !isString {
			return RotateResult{}, fmt.Errorf("rotate script reply field %d has unexpected type %T", i, reply[i])
		}
		fields[i] = text
	}

	businessID, err := uuid.Parse(fields[1])
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate script returned a bad business id: %w", err)
	}
	userID, err := uuid.Parse(fields[2])
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate script returned a bad user id: %w", err)
	}
	absoluteMillis, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil {
		return RotateResult{}, fmt.Errorf("rotate script returned a bad absolute expiry: %w", err)
	}

	result := RotateResult{
		Outcome: outcome,
		Session: SessionRef{
			BusinessID: businessID,
			UserID:     userID,
		},
		AbsoluteExpiresAt: time.UnixMilli(absoluteMillis).UTC(),
	}

	if wantFields == 5 {
		ttlMillis, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil {
			return RotateResult{}, fmt.Errorf("rotate script returned a bad ttl: %w", err)
		}
		result.TTL = time.Duration(ttlMillis) * time.Millisecond
	}

	return result, nil
}

func tokenKeyPrefix(sessionID uuid.UUID) string {
	return "auth:refresh:{" + sessionID.String() + "}:tok:"
}

func tokenKey(sessionID uuid.UUID, tokenHash string) string {
	return tokenKeyPrefix(sessionID) + tokenHash
}

func currentKey(sessionID uuid.UUID) string {
	return "auth:refresh:{" + sessionID.String() + "}:current"
}
