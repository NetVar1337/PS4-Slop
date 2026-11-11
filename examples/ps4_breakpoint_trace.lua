-- ps4_breakpoint_trace.lua
-- Break once at an address in a PS4 game (ps4debug-NG), dump registers and the
-- call stack of the halted thread, then remove the breakpoint and resume.
-- Typical use: find who writes a value (ps4_find_value.lua), disassemble the
-- writer, then trace its callers with this script.
ARGS = ARGS or {}
local host     = ARGS.host or "192.168.1.50"
local process  = ARGS.process or "eboot.bin"   -- substring of the process name
local addr     = ARGS.addr                     -- breakpoint address (required)
local wait_ms  = ARGS.wait_ms or 30000          -- how long to wait for the hit
local depth    = ARGS.depth or 16              -- call stack frames
if not addr then error("set ARGS.addr to the instruction address to break on") end

local function show(v, indent)
  indent = indent or ""
  if type(v) ~= "table" then return tostring(v) end
  local keys = {}
  for k in pairs(v) do keys[#keys + 1] = k end
  table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local parts = {}
  for _, k in ipairs(keys) do
    local x = v[k]
    if type(x) == "number" and math.type(x) == "integer" and x > 0xFFFF then
      parts[#parts + 1] = string.format("%s%s=0x%X", indent, tostring(k), x)
    elseif type(x) == "table" then
      parts[#parts + 1] = string.format("%s%s={\n%s\n%s}", indent, tostring(k), show(x, indent .. "  "), indent)
    else
      parts[#parts + 1] = string.format("%s%s=%s", indent, tostring(k), tostring(x))
    end
  end
  return table.concat(parts, "\n")
end

-- console, process, debugger
if (slop.target.status().backend or ""):upper() ~= "PS4" then
  print("connecting to " .. host)
  slop.ps4.connect(host)
end
local pid
for _, p in ipairs(slop.target.list()) do
  if p.name and p.name:find(process, 1, true) then pid = p.pid; break end
end
if not pid then error("no process matching '" .. process .. "'") end
slop.debugger.attach(pid)
print(string.format("debugging pid %d, breakpoint at 0x%X", pid, addr))

local bp = slop.debugger.bp_set(addr)
local cleaned = false
local function cleanup()
  if cleaned then return end
  cleaned = true
  pcall(slop.debugger.bp_clear, addr)
  pcall(slop.debugger.continue)
end

local ok, err = pcall(function()
  print("bp: " .. show(bp))
  slop.debugger.continue()
  local stop = slop.debugger.wait(wait_ms)
  if not (stop and stop.halted) then
    print(string.format("no hit within %d ms", wait_ms))
    return
  end
  local lwpid = stop.lwpid or stop.tid
  print("== halted ==\n" .. show(stop))
  print("== registers ==\n" .. show(slop.debugger.regs(lwpid)))
  print("== call stack ==\n" .. show(slop.debugger.callstack(lwpid, depth)))
end)
cleanup()
if not ok then error(err) end
return "done"
