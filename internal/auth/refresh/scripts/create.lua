-- Stores the first refresh token of a session.
--
-- KEYS[1]  record of the new token
-- KEYS[2]  pointer to the session's current token
-- ARGV[1]  new token hash
-- ARGV[2]  business id
-- ARGV[3]  user id
-- ARGV[4]  absolute expiry of the session, unix milliseconds
-- ARGV[5]  lifetime of the new token, milliseconds
-- ARGV[6]  key prefix of this session's token records

-- A session has exactly one live token. Drop any stale one before storing the new one.
local previous = redis.call('GET', KEYS[2])
if previous then
  redis.call('DEL', ARGV[6] .. previous)
end

redis.call('HSET', KEYS[1],
  'bid', ARGV[2],
  'uid', ARGV[3],
  'abs', ARGV[4],
  'used_at', '0',
  'child', '')
redis.call('PEXPIRE', KEYS[1], ARGV[5])
redis.call('SET', KEYS[2], ARGV[1], 'PX', ARGV[5])

return 1
