-- Deletes the live refresh token of a session, so it can no longer be exchanged.
-- Used tombstones are left to expire on their own.
--
-- KEYS[1]  pointer to the session's current token
-- ARGV[1]  key prefix of this session's token records

local current = redis.call('GET', KEYS[1])
if current then
  redis.call('DEL', ARGV[1] .. current)
end
redis.call('DEL', KEYS[1])

return 1
