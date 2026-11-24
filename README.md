# handling-sessions-with-redis-and-golang
A production-grade refresh token implementation that uses Redis and Lua scripts to enforce a single, atomic invariant: a session has exactly one live refresh token at any moment.
