-- ps4_eboot_overview.lua
-- Static overview of a dumped PS4 module (decrypted eboot.bin / .sprx as ELF,
-- e.g. produced by target.ps4_dump_module): load it into the shared session,
-- wait for analysis, then list the largest functions and the code that
-- references strings matching ARGS.keywords. Renames/comments made afterwards
-- in the UI apply to the same session.
ARGS = ARGS or {}
local path     = ARGS.path                     -- dumped module on the PC (required)
local keywords = ARGS.keywords or { "health", "ammo", "player", "damage", "debug" }
local top_n    = ARGS.top_n or 15
local wait_ms  = ARGS.wait_ms or 120000
local per_key  = ARGS.per_keyword or 5
if not path then error("set ARGS.path to the dumped eboot/module file") end

if not slop.image.load(path) then error("could not load " .. path) end
local st = slop.image.status()
print(string.format("loaded %s base=0x%X entry=0x%X", st.name or path, st.base or 0, st.entry or 0))
if not slop.image.wait_ready(wait_ms) then
  print("analysis still running after " .. wait_ms .. " ms; results below may be partial")
end

-- largest functions: usually the game loop, renderers, big state machines
local fns = slop.disasm.functions(100000)
table.sort(fns, function(a, b) return (a.size or 0) > (b.size or 0) end)
print(string.format("\n== %d largest of %d functions ==", math.min(top_n, #fns), #fns))
for i = 1, math.min(top_n, #fns) do
  local f = fns[i]
  print(string.format("  0x%X  %-32s %6d bytes", f.va, f.name or "?", f.size or 0))
end

-- strings of interest and the functions that use them
local strings = slop.disasm.strings(5, 200000)
print(string.format("\n== %d strings scanned ==", #strings))
for _, key in ipairs(keywords) do
  local shown = 0
  local needle = key:lower()
  for _, s in ipairs(strings) do
    if shown >= per_key then break end
    if s.text and s.text:lower():find(needle, 1, true) then
      local users = {}
      for _, x in ipairs(slop.disasm.xrefs_to(s.va)) do
        local fn = slop.disasm.function_at(x.from)
        users[#users + 1] = fn and string.format("%s+0x%X", fn.name, x.from - fn.va)
                                or string.format("0x%X", x.from)
        if #users >= 4 then break end
      end
      print(string.format("  [%s] 0x%X %q <- %s", key, s.va, s.text:sub(1, 60),
                          #users > 0 and table.concat(users, ", ") or "no code xrefs"))
      shown = shown + 1
    end
  end
end
return #fns
