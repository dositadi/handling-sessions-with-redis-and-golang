package config

import (
	"os"
	"time"
)

// RefreshConfig holds the settings for opaque refresh tokens.
//
// The `validate` tags are checked by the auth refresh package (go-playground/validator)
// when its manager is constructed, so a bad value stops the server at startup.
type RefreshConfig struct {
	// TokenTTL is how long a refresh token stays valid without being used. Each
	// rotation issues a new token with a fresh TTL, so an active client keeps its
	// session alive until the session's absolute expiry, which is set per session by
	// the service and always wins over this value.
	// Env: REFRESH_TOKEN_TTL (default 168h, allowed 1h to 720h)
	TokenTTL time.Duration `validate:"gte=1h,lte=720h"`

	// ReuseLeeway is the window after a token is first used during which presenting it
	// again is treated as a retry (a refresh response lost on a bad network) and not as
	// theft. After the window, or once the newer token has itself been used, reuse
	// revokes the whole session. Set it to 0s to treat every reuse as theft.
	// Env: REFRESH_REUSE_LEEWAY (default 10s, allowed 0s to 1m)
	ReuseLeeway time.Duration `validate:"gte=0s,lte=1m"`
}

// loadRefreshConfig reads the refresh token settings from the environment. It does not
// validate them; the refresh manager does that in NewManager.
func loadRefreshConfig() RefreshConfig {
	return RefreshConfig{
		TokenTTL:    getEnvDurationOrDefault("REFRESH_TOKEN_TTL", 168*time.Hour),
		ReuseLeeway: getEnvDurationOrDefault("REFRESH_REUSE_LEEWAY", 10*time.Second),
	}
}

func getEnvDurationOrDefault(key string, duration time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return duration
}
