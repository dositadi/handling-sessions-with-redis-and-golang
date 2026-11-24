package refresh

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken_FormatAndRoundTrip(t *testing.T) {
	sessionID := uuid.New()

	token, hash, err := generateToken(sessionID)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(token, "rt_"))
	assert.Equal(t, tokenLength, len(token))
	assert.Equal(t, 79, tokenLength)
	assert.NotEqual(t, token, hash, "only the hash is ever stored")
	assert.Equal(t, 64, len(hash), "hex SHA-256")

	parsed, err := parseToken(token)
	require.NoError(t, err)
	assert.Equal(t, sessionID, parsed.sessionID)
	assert.Equal(t, hash, parsed.hash)
}

func TestGenerateToken_IsRandom(t *testing.T) {
	sessionID := uuid.New()
	seen := make(map[string]bool)

	for i := 0; i < 200; i++ {
		token, _, err := generateToken(sessionID)
		require.NoError(t, err)
		require.True(t, !seen[token], "duplicate token generated")
		seen[token] = true
	}
}

func TestHashToken_IsDeterministic(t *testing.T) {
	assert.Equal(t, hashToken("abc"), hashToken("abc"))
	assert.NotEqual(t, hashToken("abc"), hashToken("abd"))
}

func TestParseToken_RejectsMalformedInput(t *testing.T) {
	sessionID := uuid.New()
	valid, _, err := generateToken(sessionID)
	require.NoError(t, err)

	sessionPart := valid[3:35]
	secretPart := valid[36:]

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"too short", valid[:len(valid)-1]},
		{"too long", valid + "A"},
		{"wrong prefix", "xx_" + valid[3:]},
		{"no prefix", valid[3:]},
		{"wrong separator", "rt_" + sessionPart + "-" + secretPart},
		{"session part not hex", "rt_" + strings.Repeat("z", 32) + "_" + secretPart},
		{"session part uppercase hex", "rt_" + strings.ToUpper(sessionPart) + "_" + secretPart},
		{"secret part not base64url", "rt_" + sessionPart + "_" + strings.Repeat("!", 43)},
		{"secret part has non-canonical trailing bits", "rt_" + sessionPart + "_" + secretPart[:42] + "B"},
		{"nil session id", "rt_" + strings.Repeat("0", 32) + "_" + secretPart},
		{"whitespace around token", " " + valid},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, parseErr := parseToken(test.token)
			assert.ErrorIs(t, parseErr, ErrTokenInvalid)
		})
	}
}

func TestParseToken_RejectsEveryTruncationAndExtension(t *testing.T) {
	token, _, err := generateToken(uuid.New())
	require.NoError(t, err)

	for length := 0; length < len(token); length++ {
		_, parseErr := parseToken(token[:length])
		require.ErrorIs(t, parseErr, ErrTokenInvalid, "length %d", length)
	}
}

func TestKeys_ShareOneHashTagPerSession(t *testing.T) {
	sessionID := uuid.New()
	tag := "{" + sessionID.String() + "}"

	assert.Contains(t, tokenKey(sessionID, "abc"), tag)
	assert.Contains(t, currentKey(sessionID), tag)
	assert.True(t, strings.HasPrefix(tokenKey(sessionID, "abc"), tokenKeyPrefix(sessionID)))
	assert.Equal(t, tokenKeyPrefix(sessionID)+"abc", tokenKey(sessionID, "abc"))
}
