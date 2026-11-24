package refresh

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The replies below have exactly the shape scripts/rotate.lua returns (checked against a
// real Redis), so these tests pin the contract between the script and the Go parser.

func TestParseRotateReply_Success(t *testing.T) {
	businessID, userID := uuid.New(), uuid.New()

	tests := []struct {
		name    string
		reply   []interface{}
		outcome RotateOutcome
		ttl     time.Duration
	}{
		{
			"rotated",
			[]interface{}{"rotated", businessID.String(), userID.String(), "1802592000000", "604800000"},
			RotateRotated, 7 * 24 * time.Hour,
		},
		{
			"replayed",
			[]interface{}{"replayed", businessID.String(), userID.String(), "1802592000000", "4000"},
			RotateReplayed, 4 * time.Second,
		},
		{
			"reused carries no ttl",
			[]interface{}{"reused", businessID.String(), userID.String(), "1802592000000"},
			RotateReused, 0,
		},
		{
			"expired carries no ttl",
			[]interface{}{"expired", businessID.String(), userID.String(), "1802592000000"},
			RotateExpired, 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := parseRotateReply(test.reply)
			require.NoError(t, err)

			assert.Equal(t, test.outcome, result.Outcome)
			assert.Equal(t, businessID, result.Session.BusinessID)
			assert.Equal(t, userID, result.Session.UserID)
			assert.Equal(t, test.ttl, result.TTL)
			assert.Equal(t, time.UnixMilli(1802592000000).UTC(), result.AbsoluteExpiresAt)
		})
	}
}

func TestParseRotateReply_NotFound(t *testing.T) {
	result, err := parseRotateReply([]interface{}{"not_found"})

	require.NoError(t, err)
	assert.Equal(t, RotateNotFound, result.Outcome)
}

func TestParseRotateReply_RejectsMalformedReplies(t *testing.T) {
	businessID, userID := uuid.New().String(), uuid.New().String()

	tests := []struct {
		name  string
		reply []interface{}
	}{
		{"empty", []interface{}{}},
		{"outcome is not a string", []interface{}{int64(1)}},
		{"unknown outcome", []interface{}{"banana", businessID, userID, "1"}},
		{"rotated missing the ttl", []interface{}{"rotated", businessID, userID, "1802592000000"}},
		{"reused missing fields", []interface{}{"reused", businessID}},
		{"field is not a string", []interface{}{"rotated", businessID, userID, int64(5), "10"}},
		{"bad business id", []interface{}{"reused", "nope", userID, "1802592000000"}},
		{"bad user id", []interface{}{"reused", businessID, "nope", "1802592000000"}},
		{"bad absolute expiry", []interface{}{"reused", businessID, userID, "soon"}},
		{"bad ttl", []interface{}{"rotated", businessID, userID, "1802592000000", "forever"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseRotateReply(test.reply)
			assert.Error(t, err)
		})
	}
}
