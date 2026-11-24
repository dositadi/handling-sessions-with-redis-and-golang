-- Exchanges a presented refresh token for a new one, atomically.
--
-- KEYS[1]  record of the presented (old) token
-- KEYS[2]  record of the new token
-- KEYS[3]  pointer to the session's current token
-- ARGV[1]  now, unix milliseconds
-- ARGV[2]  new token hash
-- ARGV[3]  lifetime of the new token, milliseconds (capped here by the session's absolute expiry)
-- ARGV[4]  reuse leeway, milliseconds
-- ARGV[5]  key prefix of this session's token records
--
-- Returns an array whose first element is the outcome:
--   {'not_found'}                              unknown or already expired token
--   {'expired',  bid, uid, abs}                session passed its absolute expiry
--   {'reused',   bid, uid, abs}                a used token came back: treat as theft
--   {'rotated',  bid, uid, abs, ttl_ms}        normal rotation
--   {'replayed', bid, uid, abs, ttl_ms}        retry of a recent rotation, inside the leeway

local fields = redis.call('HGETALL', KEYS[1])
if #fields == 0 then
  return {'not_found'}
end

local record = {}
for i = 1, #fields, 2 do
  record[fields[i]] = fields[i + 1]
end

local now = tonumber(ARGV[1])
local leeway = tonumber(ARGV[4])
local absoluteExpiry = tonumber(record['abs'])
local usedAt = tonumber(record['used_at'])

if now >= absoluteExpiry then
  redis.call('DEL', KEYS[1])
  return {'expired', record['bid'], record['uid'], record['abs']}
end

local outcome = 'rotated'

if usedAt > 0 then
  -- The token was already exchanged. Outside the leeway this is reuse.
  if now - usedAt > leeway then
    return {'reused', record['bid'], record['uid'], record['abs']}
  end

  -- Inside the leeway it is a retry. If the token issued last time has itself been
  -- used already, the retry came too late and is reuse after all.
  local previousChild = record['child']
  if previousChild and previousChild ~= '' then
    local childKey = ARGV[5] .. previousChild
    local childUsedAt = redis.call('HGET', childKey, 'used_at')
    if childUsedAt and childUsedAt ~= '0' then
      return {'reused', record['bid'], record['uid'], record['abs']}
    end
    -- Only one live token per session: drop the one the lost response carried.
    redis.call('DEL', childKey)
  end

  outcome = 'replayed'
end

local ttl = tonumber(ARGV[3])
local remaining = absoluteExpiry - now
if remaining < ttl then
  ttl = remaining
end

-- Keep the old record as a tombstone (it expires on its own) so reuse can be detected.
if usedAt == 0 then
  redis.call('HSET', KEYS[1], 'used_at', ARGV[1])
end
redis.call('HSET', KEYS[1], 'child', ARGV[2])

redis.call('HSET', KEYS[2],
  'bid', record['bid'],
  'uid', record['uid'],
  'abs', record['abs'],
  'used_at', '0',
  'child', '')
redis.call('PEXPIRE', KEYS[2], ttl)
redis.call('SET', KEYS[3], ARGV[2], 'PX', ttl)

return {outcome, record['bid'], record['uid'], record['abs'], tostring(ttl)}
