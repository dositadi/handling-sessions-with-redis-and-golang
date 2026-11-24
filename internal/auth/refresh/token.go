package refresh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// A refresh token looks like:
//
//	rt_<32 hex characters: the session id>_<43 characters: 32 random bytes, base64url>
//
// It is an opaque random string, not a JWT. The server never stores the token itself,
// only its SHA-256 hash, so a leaked Redis dump cannot be replayed. A fast hash is right
// here: unlike a password, the secret part is 256 bits of randomness, so there is
// nothing to brute-force.
//
// The session id is embedded so the Redis keys of one session can share a hash tag, and
// so a presented token can be located without a lookup table. It is not secret (it is
// also in the access token) and it grants nothing without the random part.
const (
	tokenPrefix    = "rt_"
	sessionPartLen = 32
	secretByteLen  = 32
	secretPartLen  = 43 // base64url of 32 bytes, without padding
	tokenLength    = len(tokenPrefix) + sessionPartLen + 1 + secretPartLen
)

// parsedToken is a presented token that has passed the format checks. It says nothing
// about whether the token is valid, only that it is well formed.
type parsedToken struct {
	sessionID uuid.UUID
	hash      string
}

// generateToken creates a new random token for a session and returns it with its hash.
func generateToken(sessionID uuid.UUID) (token, hash string, err error) {
	secret := make([]byte, secretByteLen)
	if _, err := rand.Read(secret); err != nil {
		return "", "", fmt.Errorf("generating refresh token secret: %w", err)
	}

	token = tokenPrefix +
		hex.EncodeToString(sessionID[:]) +
		"_" +
		base64.RawURLEncoding.EncodeToString(secret)

	return token, hashToken(token), nil
}

// parseToken checks the shape of a presented token before any Redis call is made, so
// garbage input is rejected cheaply. Every failure is ErrTokenInvalid.
func parseToken(raw string) (parsedToken, error) {
	if len(raw) != tokenLength || !strings.HasPrefix(raw, tokenPrefix) {
		return parsedToken{}, ErrTokenInvalid
	}

	body := raw[len(tokenPrefix):]
	sessionPart := body[:sessionPartLen]
	secretPart := body[sessionPartLen+1:]

	if body[sessionPartLen] != '_' {
		return parsedToken{}, ErrTokenInvalid
	}

	sessionBytes, err := hex.DecodeString(sessionPart)
	if err != nil || hex.EncodeToString(sessionBytes) != sessionPart { // lowercase only
		return parsedToken{}, ErrTokenInvalid
	}

	secret, err := base64.RawURLEncoding.Strict().DecodeString(secretPart)
	if err != nil || len(secret) != secretByteLen {
		return parsedToken{}, ErrTokenInvalid
	}

	var sessionID uuid.UUID
	copy(sessionID[:], sessionBytes)
	if sessionID == uuid.Nil {
		return parsedToken{}, ErrTokenInvalid
	}

	return parsedToken{sessionID: sessionID, hash: hashToken(raw)}, nil
}

// hashToken returns the hex SHA-256 of a whole token string.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
