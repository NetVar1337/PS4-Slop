-- ps4_find_value.lua
-- Find the address of a 32-bit game value on a PS4 (ps4debug-NG):
--   1. connect to the console and attach to the game process
--   2. exact-scan for ARGS.value
--   3. optionally keep re-reading the hits for ARGS.wait_ms while you change
--      the value in-game, keeping only addresses that now hold ARGS.next_value
-- Returns the surviving addresses (hex) so they can be fed to the watchlist.
ARGS = ARGS or {}
local host       = ARGS.host or "192.168.1.50"   -- console IP
local process    = ARGS.process or "eboot.bin"   -- substring of the process name
local value      = ARGS.value or 100             -- current in-game value
local next_value = ARGS.next_value               -- value after you change it (optional)
local wait_ms    = ARGS.wait_ms or 30000         -- how long to wait for the change
local width      = ARGS.width or "i32"           -- i8..u64, f32, f64
local scan_begin = ARGS.scan_begin               -- optional address range
local scan_end   = ARGS.scan_end
local max_show   = ARGS.max_show or 32

local function fmt_bytes_for(width_name)
  local map = { i8 = "<i1", u8 = "<I1", i16 = "<i2", u16 = "<I2", i32 = "<i4", u32 = "<I4",
                i64 = "<i8", u64 = "<I8", f32 = "<f", f64 = "<d" }
  local f = map[width_name]
  if not f then error("unsupported width " .. tostring(width_name)) end
  return f, string.packsize(f)
end
local unpack_fmt, value_size = fmt_bytes_for(width)

-- 1. console + process
if (slop.target.status().backend or ""):upper() ~= "PS4" then
  print("connecting to " .. host)
  slop.ps4.connect(host)
end
local pid, name
for _, p in ipairs(slop.target.list()) do
  if p.name and p.name:find(process, 1, true) then pid, name = p.pid, p.name; break end
end
if not pid then error("no process matching '" .. process .. "' on the console") end
local ok, attached = slop.target.attach(pid)
if not ok then error("attach to pid " .. pid .. " failed") end
print(string.format("attached to %s (pid %d)", attached or name, pid))

-- 2. first scan
local cfg = { kind = "exact", width = width, value = value, alignment = math.min(value_size, 4) }
if scan_begin then cfg.begin = scan_begin end
if scan_end then cfg["end"] = scan_end end
local hits = slop.mem.scan(cfg)
print(string.format("scan %s == %s: %d hits%s", width, tostring(value), #hits,
                    #hits >= 10000 and " (capped, narrow the range)" or ""))

-- 3. narrow while the value changes in-game
local function read_value(addr)
  local okr, raw = pcall(slop.mem.read_bytes, addr, value_size)
  if not okr or not raw or #raw < value_size then return nil end
  return (string.unpack(unpack_fmt, raw))
end

if next_value ~= nil and #hits > 0 then
  print(string.format("change the value in-game to %s within %d s...", tostring(next_value), wait_ms // 1000))
  local deadline = os.clock() + wait_ms / 1000
  local survivors = hits
  repeat
    local still = {}
    for _, a in ipairs(survivors) do
      local v = read_value(a)
      if v == next_value then still[#still + 1] = a end
    end
    if #still > 0 then survivors = still; break end
  until os.clock() >= deadline
  if survivors == hits then
    print("value never changed to " .. tostring(next_value) .. "; keeping the first-scan hits")
  end
  hits = survivors
  print(string.format("%d address(es) now hold %s", #hits, tostring(next_value)))
end

local out = {}
for i = 1, math.min(#hits, max_show) do
  out[#out + 1] = string.format("0x%X", hits[i])
  print(string.format("  0x%X = %s", hits[i], tostring(read_value(hits[i]))))
end
if #hits > max_show then print(string.format("  ... %d more", #hits - max_show)) end
return table.concat(out, ",")
