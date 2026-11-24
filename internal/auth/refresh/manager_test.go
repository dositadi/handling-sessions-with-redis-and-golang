package refresh

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dositadi/handling-sessions-with-redis-and-golang/internal/shared/config"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var baseTime = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time          { return c.now }
func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// fakeStore mirrors the rules in scripts/*.lua in plain Go so the Manager logic can be
// tested without Redis. The Lua itself is tested against a real Redis separately.
type fakeStore struct {
	mu      sync.Mutex
	clock   func() time.Time
	records map[string]*fakeRecord
	current map[uuid.UUID]string

	createErr   error
	rotateErr   error
	revokeErr   error
	rotateCalls int
	revokeCalls []uuid.UUID
}

type fakeRecord struct {
	session   SessionRef
	absolute  time.Time
	usedAt    time.Time
	child     string
	expiresAt time.Time
}

func newFakeStore(clock func() time.Time) *fakeStore {
	return &fakeStore{
		clock:   clock,
		records: make(map[string]*fakeRecord),
		current: make(map[uuid.UUID]string),
	}
}

func recordKey(sessionID uuid.UUID, hash string) string { return sessionID.String() + "/" + hash }

// live returns a record unless it is missing or has expired. Callers hold s.mu.
func (s *fakeStore) live(sessionID uuid.UUID, hash string) *fakeRecord {
	key := recordKey(sessionID, hash)
	record, ok := s.records[key]
	if !ok {
		return nil
	}
	if !s.clock().Before(record.expiresAt) {
		delete(s.records, key)
		return nil
	}
	return record
}

func (s *fakeStore) Create(_ context.Context, record NewRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.createErr != nil {
		return s.createErr
	}

	sessionID := record.Session.SessionID
	if previous, ok := s.current[sessionID]; ok {
		delete(s.records, recordKey(sessionID, previous))
	}

	s.records[recordKey(sessionID, record.TokenHash)] = &fakeRecord{
		session:   record.Session,
		absolute:  record.AbsoluteExpiresAt,
		expiresAt: s.clock().Add(record.TTL),
	}
	s.current[sessionID] = record.TokenHash
	return nil
}

func (s *fakeStore) Rotate(_ context.Context, request RotateRequest) (RotateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.rotateCalls++
	if s.rotateErr != nil {
		return RotateResult{}, s.rotateErr
	}

	old := s.live(request.SessionID, request.OldHash)
	if old == nil {
		return RotateResult{Outcome: RotateNotFound}, nil
	}

	// Like the real store, report ids but not the session id itself.
	session := SessionRef{BusinessID: old.session.BusinessID, UserID: old.session.UserID}

	if !request.Now.Before(old.absolute) {
		delete(s.records, recordKey(request.SessionID, request.OldHash))
		return RotateResult{Outcome: RotateExpired, Session: session, AbsoluteExpiresAt: old.absolute}, nil
	}

	outcome := RotateRotated
	if !old.usedAt.IsZero() {
		if request.Now.Sub(old.usedAt) > request.Leeway {
			return RotateResult{Outcome: RotateReused, Session: session, AbsoluteExpiresAt: old.absolute}, nil
		}
		if old.child != "" {
			child := s.live(request.SessionID, old.child)
			if child != nil && !child.usedAt.IsZero() {
				return RotateResult{Outcome: RotateReused, Session: session, AbsoluteExpiresAt: old.absolute}, nil
			}
			delete(s.records, recordKey(request.SessionID, old.child))
		}
		outcome = RotateReplayed
	}

	ttl := min(request.TTL, old.absolute.Sub(request.Now))

	if old.usedAt.IsZero() {
		old.usedAt = request.Now
	}
	old.child = request.NewHash

	s.records[recordKey(request.SessionID, request.NewHash)] = &fakeRecord{
		session:   old.session,
		absolute:  old.absolute,
		expiresAt: request.Now.Add(ttl),
	}
	s.current[request.SessionID] = request.NewHash

	return RotateResult{Outcome: outcome, Session: session, AbsoluteExpiresAt: old.absolute, TTL: ttl}, nil
}

func (s *fakeStore) RevokeSession(_ context.Context, sessionID uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.revokeCalls = append(s.revokeCalls, sessionID)
	if s.revokeErr != nil {
		return s.revokeErr
	}

	if current, ok := s.current[sessionID]; ok {
		delete(s.records, recordKey(sessionID, current))
	}
	delete(s.current, sessionID)
	return nil
}

// liveUnusedTokens counts tokens of a session that could still be exchanged.
func (s *fakeStore) liveUnusedTokens(sessionID uuid.UUID) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for key, record := range s.records {
		if record.session.SessionID != sessionID {
			continue
		}
		_ = key
		if s.clock().Before(record.expiresAt) && record.usedAt.IsZero() {
			count++
		}
	}
	return count
}

func defaultConfig() config.RefreshConfig {
	return config.RefreshConfig{TokenTTL: 24 * time.Hour, ReuseLeeway: 10 * time.Second}
}

func newTestSetup(t *testing.T) (*Manager, *fakeStore, *testClock) {
	t.Helper()
	return newTestSetupWithConfig(t, defaultConfig())
}

func newTestSetupWithConfig(t *testing.T, cfg config.RefreshConfig) (*Manager, *fakeStore, *testClock) {
	t.Helper()

	clock := &testClock{now: baseTime}
	store := newFakeStore(clock.Now)

	manager, err := NewManager(cfg, store)
	require.NoError(t, err)
	manager.now = clock.Now

	return manager, store, clock
}

func newParams() IssueParams {
	return IssueParams{
		SessionID:         uuid.New(),
		BusinessID:        uuid.New(),
		UserID:            uuid.New(),
		AbsoluteExpiresAt: baseTime.Add(30 * 24 * time.Hour),
	}
}

func issueFor(t *testing.T, manager *Manager, params IssueParams) Issued {
	t.Helper()
	issued, err := manager.Issue(context.Background(), params)
	require.NoError(t, err)
	return issued
}

func TestIssue_ReturnsTokenAndExpiry(t *testing.T) {
	manager, _, _ := newTestSetup(t)
	params := newParams()

	issued, err := manager.Issue(context.Background(), params)
	require.NoError(t, err)

	parsed, err := parseToken(issued.Token)
	require.NoError(t, err)
	assert.Equal(t, params.SessionID, parsed.sessionID)
	assert.True(t, baseTime.Add(24*time.Hour).Equal(issued.ExpiresAt))
}

func TestIssue_CapsLifetimeAtAbsoluteExpiry(t *testing.T) {
	manager, _, _ := newTestSetup(t)
	params := newParams()
	params.AbsoluteExpiresAt = baseTime.Add(2 * time.Hour)

	issued := issueFor(t, manager, params)

	assert.True(t, params.AbsoluteExpiresAt.Equal(issued.ExpiresAt), "a 24h token cannot outlive a 2h session")
}

func TestIssue_RejectsInvalidParams(t *testing.T) {
	manager, store, _ := newTestSetup(t)

	tests := []struct {
		name   string
		mutate func(*IssueParams)
	}{
		{"missing session id", func(p *IssueParams) { p.SessionID = uuid.Nil }},
		{"missing business id", func(p *IssueParams) { p.BusinessID = uuid.Nil }},
		{"missing user id", func(p *IssueParams) { p.UserID = uuid.Nil }},
		{"missing absolute expiry", func(p *IssueParams) { p.AbsoluteExpiresAt = time.Time{} }},
		{"absolute expiry in the past", func(p *IssueParams) { p.AbsoluteExpiresAt = baseTime.Add(-time.Minute) }},
		{"absolute expiry is now", func(p *IssueParams) { p.AbsoluteExpiresAt = baseTime }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := newParams()
			test.mutate(&params)

			_, err := manager.Issue(context.Background(), params)
			assert.ErrorIs(t, err, ErrInvalidParams)
		})
	}

	assert.Len(t, store.records, 0, "nothing is stored for invalid input")
}

func TestIssue_StoreFailureIsReported(t *testing.T) {
	manager, store, _ := newTestSetup(t)
	store.createErr = errors.New("redis down")

	_, err := manager.Issue(context.Background(), newParams())

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrInvalidParams)
	assert.Contains(t, err.Error(), "redis down")
}

func TestIssueAndRotate_RespectCancelledContext(t *testing.T) {
	manager, _, _ := newTestSetup(t)
	issued := issueFor(t, manager, newParams())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := manager.Issue(ctx, newParams())
	assert.ErrorIs(t, err, context.Canceled)

	_, err = manager.Rotate(ctx, issued.Token)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestRotate_ChainsAcrossRefreshes(t *testing.T) {
	manager, _, clock := newTestSetup(t)
	params := newParams()
	issued := issueFor(t, manager, params)

	first, err := manager.Rotate(context.Background(), issued.Token)
	require.NoError(t, err)
	assert.NotEqual(t, issued.Token, first.Token)
	assert.False(t, first.Replayed)
	assert.Equal(t, SessionRef{SessionID: params.SessionID, BusinessID: params.BusinessID, UserID: params.UserID}, first.Session)
	assert.True(t, params.AbsoluteExpiresAt.Equal(first.AbsoluteExpiresAt))

	clock.Advance(15 * time.Minute)
	second, err := manager.Rotate(context.Background(), first.Token)
	require.NoError(t, err)
	assert.NotEqual(t, first.Token, second.Token)
	assert.True(t, clock.Now().Add(24*time.Hour).Equal(second.ExpiresAt), "each rotation gets a fresh lifetime")
}

func TestRotate_NeverOutlivesAbsoluteExpiry(t *testing.T) {
	manager, _, clock := newTestSetup(t)
	params := newParams()
	params.AbsoluteExpiresAt = baseTime.Add(time.Hour)
	issued := issueFor(t, manager, params)

	clock.Advance(50 * time.Minute)
	rotated, err := manager.Rotate(context.Background(), issued.Token)
	require.NoError(t, err)

	assert.True(t, params.AbsoluteExpiresAt.Equal(rotated.ExpiresAt), "capped at the session's hard limit, not now+24h")

	clock.Advance(11 * time.Minute)
	_, err = manager.Rotate(context.Background(), rotated.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid, "past the absolute expiry no token works")
}

func TestRotate_IdleTokenExpires(t *testing.T) {
	manager, _, clock := newTestSetup(t)
	issued := issueFor(t, manager, newParams())

	clock.Advance(24*time.Hour + time.Second)

	_, err := manager.Rotate(context.Background(), issued.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid)
	assert.NotErrorIs(t, err, ErrReuseDetected)
}

func TestRotate_ReuseAfterLeewayRevokesTheSession(t *testing.T) {
	manager, store, clock := newTestSetup(t)
	params := newParams()
	original := issueFor(t, manager, params)

	rotated, err := manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)

	clock.Advance(11 * time.Second) // past the 10s leeway

	_, err = manager.Rotate(context.Background(), original.Token)
	require.ErrorIs(t, err, ErrReuseDetected)

	var reuse *ReuseDetectedError
	require.True(t, errors.As(err, &reuse))
	assert.Equal(t, SessionRef{SessionID: params.SessionID, BusinessID: params.BusinessID, UserID: params.UserID}, reuse.Session,
		"the service needs the full session reference to revoke it")
	assert.Equal(t, []uuid.UUID{params.SessionID}, store.revokeCalls)

	_, err = manager.Rotate(context.Background(), rotated.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid, "the thief's and the owner's newest tokens both stop working")
}

func TestRotate_RetryInsideLeewayIsAcceptedAsReplay(t *testing.T) {
	manager, store, clock := newTestSetup(t)
	params := newParams()
	original := issueFor(t, manager, params)

	lost, err := manager.Rotate(context.Background(), original.Token) // response never reached the client
	require.NoError(t, err)

	clock.Advance(5 * time.Second)
	retried, err := manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)
	assert.True(t, retried.Replayed)
	assert.NotEqual(t, lost.Token, retried.Token)
	assert.Equal(t, 1, store.liveUnusedTokens(params.SessionID), "still exactly one live token")

	_, err = manager.Rotate(context.Background(), lost.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid, "the token from the lost response was dropped")
	assert.NotErrorIs(t, err, ErrReuseDetected)

	next, err := manager.Rotate(context.Background(), retried.Token)
	require.NoError(t, err)
	assert.False(t, next.Replayed)
}

func TestRotate_RetryAfterNewerTokenWasUsedIsReuse(t *testing.T) {
	manager, _, clock := newTestSetup(t)
	original := issueFor(t, manager, newParams())

	first, err := manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)
	second, err := manager.Rotate(context.Background(), first.Token)
	require.NoError(t, err)

	clock.Advance(time.Second) // still inside the leeway, but the chain has moved on
	_, err = manager.Rotate(context.Background(), original.Token)
	require.ErrorIs(t, err, ErrReuseDetected)

	_, err = manager.Rotate(context.Background(), second.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestRotate_ZeroLeewayTreatsEveryReuseAsTheft(t *testing.T) {
	manager, _, clock := newTestSetupWithConfig(t, config.RefreshConfig{TokenTTL: 24 * time.Hour, ReuseLeeway: 0})
	original := issueFor(t, manager, newParams())

	_, err := manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)

	clock.Advance(time.Millisecond)
	_, err = manager.Rotate(context.Background(), original.Token)
	assert.ErrorIs(t, err, ErrReuseDetected)
}

func TestRotate_ConcurrentUseOfOneTokenLeavesOneLiveToken(t *testing.T) {
	manager, store, _ := newTestSetup(t)
	params := newParams()
	original := issueFor(t, manager, params)

	const callers = 25
	results := make([]Rotated, callers)
	errs := make([]error, callers)

	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = manager.Rotate(context.Background(), original.Token)
		}(i)
	}
	wg.Wait()

	rotated, replayed := 0, 0
	for i := 0; i < callers; i++ {
		require.NoError(t, errs[i])
		if results[i].Replayed {
			replayed++
		} else {
			rotated++
		}
	}

	assert.Equal(t, 1, rotated, "exactly one caller performs the real rotation")
	assert.Equal(t, callers-1, replayed)
	assert.Equal(t, 1, store.liveUnusedTokens(params.SessionID), "however many raced, one live token remains")
}

func TestRotate_OutcomesFromStoreMapToErrors(t *testing.T) {
	session := SessionRef{BusinessID: uuid.New(), UserID: uuid.New()}
	token, _, err := generateToken(uuid.New())
	require.NoError(t, err)

	tests := []struct {
		name    string
		outcome RotateOutcome
		wantErr error
	}{
		{"not found", RotateNotFound, ErrTokenInvalid},
		{"expired", RotateExpired, ErrTokenInvalid},
		{"reused", RotateReused, ErrReuseDetected},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, store, _ := newTestSetup(t)
			stub := &outcomeStore{fakeStore: store, result: RotateResult{Outcome: test.outcome, Session: session}}
			manager.store = stub

			_, rotateErr := manager.Rotate(context.Background(), token)
			assert.ErrorIs(t, rotateErr, test.wantErr)
		})
	}
}

type outcomeStore struct {
	*fakeStore
	result RotateResult
}

func (o *outcomeStore) Rotate(context.Context, RotateRequest) (RotateResult, error) {
	return o.result, nil
}

func TestRotate_MalformedTokensNeverReachTheStore(t *testing.T) {
	manager, store, _ := newTestSetup(t)

	for _, token := range []string{"", "garbage", "rt_", "rt_" + string(make([]byte, 100))} {
		_, err := manager.Rotate(context.Background(), token)
		assert.ErrorIs(t, err, ErrTokenInvalid)
	}

	assert.Equal(t, 0, store.rotateCalls)
}

func TestRotate_WellFormedButUnknownTokenIsInvalidNotReuse(t *testing.T) {
	manager, store, _ := newTestSetup(t)
	unknown, _, err := generateToken(uuid.New())
	require.NoError(t, err)

	_, err = manager.Rotate(context.Background(), unknown)

	assert.ErrorIs(t, err, ErrTokenInvalid)
	assert.NotErrorIs(t, err, ErrReuseDetected)
	assert.Len(t, store.revokeCalls, 0, "a guess must not be able to revoke anyone's session")
}

func TestRotate_StoreFailureIsNotAnAuthFailure(t *testing.T) {
	manager, store, _ := newTestSetup(t)
	issued := issueFor(t, manager, newParams())
	store.rotateErr = errors.New("redis down")

	_, err := manager.Rotate(context.Background(), issued.Token)

	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrTokenInvalid, "an outage must not sign users out")
	assert.NotErrorIs(t, err, ErrReuseDetected)
	assert.NotContains(t, err.Error(), issued.Token, "errors never contain the token")
}

func TestRotate_ReuseIsStillReportedWhenRevokingFails(t *testing.T) {
	manager, store, clock := newTestSetup(t)
	original := issueFor(t, manager, newParams())

	_, err := manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)

	clock.Advance(time.Minute)
	store.revokeErr = errors.New("redis down")

	_, err = manager.Rotate(context.Background(), original.Token)

	assert.ErrorIs(t, err, ErrReuseDetected, "the service must still revoke the session")
	assert.Contains(t, err.Error(), "redis down")
}

func TestRotate_ReuseWithLoggerConfigured(t *testing.T) {
	clock := &testClock{now: baseTime}
	store := newFakeStore(clock.Now)

	manager, err := NewManager(defaultConfig(), store)
	require.NoError(t, err)
	manager.now = clock.Now

	original := issueFor(t, manager, newParams())
	_, err = manager.Rotate(context.Background(), original.Token)
	require.NoError(t, err)

	clock.Advance(time.Minute)
	_, err = manager.Rotate(context.Background(), original.Token)
	assert.ErrorIs(t, err, ErrReuseDetected)
}

func TestRevokeSession(t *testing.T) {
	manager, store, _ := newTestSetup(t)
	params := newParams()
	issued := issueFor(t, manager, params)

	require.NoError(t, manager.RevokeSession(context.Background(), params.SessionID))

	_, err := manager.Rotate(context.Background(), issued.Token)
	assert.ErrorIs(t, err, ErrTokenInvalid)

	assert.NoError(t, manager.RevokeSession(context.Background(), uuid.New()), "revoking an unknown session is not an error")
	assert.ErrorIs(t, manager.RevokeSession(context.Background(), uuid.Nil), ErrInvalidParams)

	store.revokeErr = errors.New("redis down")
	assert.Error(t, manager.RevokeSession(context.Background(), params.SessionID))
}

func TestNewManager_ValidatesConfigAndStore(t *testing.T) {
	store := newFakeStore(time.Now)

	tests := []struct {
		name    string
		cfg     config.RefreshConfig
		store   Store
		wantErr bool
	}{
		{"defaults", config.RefreshConfig{TokenTTL: 168 * time.Hour, ReuseLeeway: 10 * time.Second}, store, false},
		{"zero leeway is allowed", config.RefreshConfig{TokenTTL: time.Hour, ReuseLeeway: 0}, store, false},
		{"token ttl below one hour", config.RefreshConfig{TokenTTL: 30 * time.Minute, ReuseLeeway: time.Second}, store, true},
		{"token ttl above 720h", config.RefreshConfig{TokenTTL: 721 * time.Hour, ReuseLeeway: time.Second}, store, true},
		{"zero token ttl", config.RefreshConfig{TokenTTL: 0, ReuseLeeway: time.Second}, store, true},
		{"leeway above one minute", config.RefreshConfig{TokenTTL: time.Hour, ReuseLeeway: 2 * time.Minute}, store, true},
		{"negative leeway", config.RefreshConfig{TokenTTL: time.Hour, ReuseLeeway: -time.Second}, store, true},
		{"missing store", config.RefreshConfig{TokenTTL: time.Hour, ReuseLeeway: time.Second}, nil, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := NewManager(test.cfg, test.store)
			if test.wantErr {
				assert.ErrorIs(t, err, ErrInvalidConfig)
				assert.Nil(t, manager)
				return
			}
			assert.NoError(t, err)
		})
	}
}
