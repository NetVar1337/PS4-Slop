-- ============================================================================
-- ue5_dumper.lua
-- reverse-slop SDK dumper for Unreal Engine 5.x x64 builds (PS4 or PC: both
-- are x86-64, the object layout below is the same for a given engine version).
--
-- Walks FUObjectArray (GObjects) + FNamePool (GNames) of the attached process
-- and emits a Dumpspace-style ClassesInfo.json (classes/structs with their
-- properties and functions) plus FNames.txt.
--
-- Parameters (prepend `ARGS = {...}` or edit the defaults):
--   gobjects    FUObjectArray address (required; find via AOB/xrefs)
--   gnames      FNamePool address (required)
--   output_dir  write files there (needs the script_unsafe setting); when
--               unset or sandboxed the dump is printed instead
--   max_objects hard cap for the object walk (default 400000)
--   verbose     progress every 5000 objects
--   layout      table overriding any offset below, e.g. {UFN_FUNCTIONFLAGS_OFFSET=0xB8}
--
-- Tested layout: UE 5.3.x. Run via the Scripts panel or the `script` MCP tool
-- (action=run) with a large timeout_ms.
-- ============================================================================
ARGS = ARGS or {}
local GObjects_VA = ARGS.gobjects or 0
local GNames_VA   = ARGS.gnames or 0
local OUTPUT_DIR  = ARGS.output_dir
local MAX_OBJECTS = ARGS.max_objects or 400000
local VERBOSE     = ARGS.verbose or false

local L = {}
-- ==== UE 5.x LAYOUT CONSTANTS ==============================================
-- FUObjectArray (UE 5.3.x)
L.UOA_OBJOBJECTS_OFFSET   = 0x10   -- ObjObjects: FChunkedFixedUObjectArray
-- FChunkedFixedUObjectArray
L.CFA_OBJECTS_OFFSET      = 0x00   -- Objects: FUObjectItem**
L.CFA_MAXELEMENTS_OFFSET  = 0x14   -- MaxElements
L.CFA_NUMELEMENTS_OFFSET  = 0x18   -- NumElements
L.CFA_MAXCHUNKS_OFFSET    = 0x1C   -- MaxChunks
L.CFA_NUMCHUNKS_OFFSET    = 0x20   -- NumChunks
L.ELEMENTS_PER_CHUNK      = 64 * 1024 -- 65536
-- FUObjectItem (24 bytes on x64)
L.UOI_SIZE                = 24
L.UOI_OBJECT_OFFSET       = 0x00   -- UObject*
L.UOI_FLAGS_OFFSET        = 0x08
L.UOI_CLUSTER_OFFSET      = 0x0C
L.UOI_SERIAL_OFFSET       = 0x10

-- UObject layout (UE 5.x, no editor)
L.UO_VTABLE_OFFSET        = 0x00
L.UO_OBJECTFLAGS_OFFSET   = 0x08
L.UO_INTERNALINDEX_OFFSET = 0x0C
L.UO_CLASSPRIVATE_OFFSET  = 0x10
L.UO_NAMEPRIVATE_OFFSET   = 0x18   -- FName (8 bytes: ComparisonIndex + Number)
L.UO_OUTERPRIVATE_OFFSET  = 0x20

-- UStruct layout (extends UObject)
L.US_SUPERSTRUCT_OFFSET   = 0x40   -- UStruct*
L.US_CHILDREN_OFFSET      = 0x48   -- UField* (only functions in UE5.3)
L.US_CHILDPROPS_OFFSET    = 0x50   -- FField* (all FProperties)
L.US_PROPERTIES_SIZE_OFF  = 0x58   -- int32 PropertiesSize
L.US_MIN_ALIGN_OFFSET     = 0x5C   -- int32 MinAlignment

-- UFunction extra fields (extends UStruct)
L.UFN_FUNCTIONFLAGS_OFFSET = 0xB0  -- EFunctionFlags (varies by build)

-- FField (UE 5.x FProperty base)
L.FF_VTABLE_OFFSET        = 0x00
L.FF_CLASSPRIVATE_OFFSET  = 0x08   -- FFieldClass*
L.FF_NEXT_OFFSET          = 0x20   -- FField* (linked list of fields)
L.FF_NAMEPRIVATE_OFFSET   = 0x28   -- FName

-- FProperty (extends FField)
L.FP_ARRAYDIM_OFFSET      = 0x38
L.FP_ELEMENTSIZE_OFFSET   = 0x3C
L.FP_OFFSET_OFFSET        = 0x4C   -- int32 Offset_Internal
L.FP_PROPERTYFLAGS_OFFSET = 0x40   -- EPropertyFlags (uint64)

-- FName (UE 5.x): { uint32 ComparisonIndex; uint32 Number; } == 8 bytes
-- FNamePool block resolution:
--   PoolAlignment = 2 (bytes) -> block_index = idx >> 16, byte_offset = (idx & 0xFFFF) * 2
--   Blocks[block_index] + byte_offset -> FNameEntry
-- FNameEntry: uint16 header, then string bytes
--   header layout: bit 0 = bIsWide, next 5 = LowercaseProbeHash, next 10 = Len

-- FNamePool layout (UE 5.3.x default: 0x10 header + blocks array)
L.NP_HEADER_SIZE          = 0x10
L.NP_BLOCKS_OFFSET        = L.NP_HEADER_SIZE
L.NP_STRIDE_SHIFT         = 1     -- entries are 2-byte aligned within a block
L.NP_BLOCK_SIZE_BYTES     = 128 * 1024 -- 128KB per block (2^16 * 2)

for k, v in pairs(ARGS.layout or {}) do
  if L[k] == nil then error("unknown layout key " .. tostring(k)) end
  L[k] = v
end

-- ==== MEMORY HELPERS ========================================================
-- reads that fail (unmapped/freed pages) yield 0 / "" instead of aborting the walk
local function read_raw(addr, len)
  local ok, raw = pcall(slop.mem.read_bytes, addr, len)
  if ok and raw and #raw == len then return raw end
  return nil
end
local function read_u64(addr)
  local raw = read_raw(addr, 8); if not raw then return 0 end
  return (string.unpack("<I8", raw))
end
local function read_u32(addr)
  local raw = read_raw(addr, 4); if not raw then return 0 end
  return (string.unpack("<I4", raw))
end
local function read_u16(addr)
  local raw = read_raw(addr, 2); if not raw then return 0 end
  return (string.unpack("<I2", raw))
end
local function read_cstr(addr, maxlen)
  local raw = read_raw(addr, maxlen or 256); if not raw then return "" end
  return raw:match("^[^%z]*")
end
local function read_wstr(addr, chars)
  local raw = read_raw(addr, chars * 2); if not raw then return "" end
  local out = {}
  for i = 1, #raw - 1, 2 do
    local cp = string.unpack("<I2", raw, i)
    if cp == 0 then break end
    out[#out + 1] = utf8.char(cp)
  end
  return table.concat(out)
end

-- ==== FNAME RESOLUTION ======================================================
local fname_cache = {}
local function fname_string(comparison_index)
  if fname_cache[comparison_index] then return fname_cache[comparison_index] end
  if comparison_index == 0 then return "None" end

  local block_idx = comparison_index >> 16
  local byte_off  = (comparison_index & 0xFFFF) << L.NP_STRIDE_SHIFT
  local block_ptr_va = GNames_VA + L.NP_BLOCKS_OFFSET + block_idx * 8
  local block_base = read_u64(block_ptr_va)
  if block_base == 0 then
    local s = string.format("<bad_block_%d>", block_idx)
    fname_cache[comparison_index] = s
    return s
  end
  local entry_va = block_base + byte_off
  local header = read_u16(entry_va)
  local is_wide = header & 0x1
  local len = header >> 6
  if len == 0 or len > 1024 then
    local s = string.format("<bad_entry_len_%d>", len)
    fname_cache[comparison_index] = s
    return s
  end

  local s
  if is_wide == 0 then
    s = read_cstr(entry_va + 2, len)
  else
    s = read_wstr(entry_va + 2, len)
  end
  fname_cache[comparison_index] = s
  return s
end

local function fname_of(name_priv_va)
  local comp = read_u32(name_priv_va)
  local num  = read_u32(name_priv_va + 4)
  local s = fname_string(comp)
  if num > 0 then return s .. "_" .. tostring(num - 1) end
  return s
end

-- ==== FUOBJECTARRAY WALKER ==================================================
local function get_object_by_index(chunks_ptr, idx)
  local chunk_idx = idx // L.ELEMENTS_PER_CHUNK
  local within    = idx % L.ELEMENTS_PER_CHUNK
  local chunk_ptr = read_u64(chunks_ptr + chunk_idx * 8)
  if chunk_ptr == 0 then return 0 end
  local item_va = chunk_ptr + within * L.UOI_SIZE
  return read_u64(item_va + L.UOI_OBJECT_OFFSET), item_va
end

local function walk_objects()
  local obj_obj_va = GObjects_VA + L.UOA_OBJOBJECTS_OFFSET
  local chunks_ptr = read_u64(obj_obj_va + L.CFA_OBJECTS_OFFSET)
  local num_elems  = read_u32(obj_obj_va + L.CFA_NUMELEMENTS_OFFSET)
  local num_chunks = read_u32(obj_obj_va + L.CFA_NUMCHUNKS_OFFSET)
  print(string.format("[GObjects] Chunks=0x%X NumElems=%d NumChunks=%d",
                       chunks_ptr, num_elems, num_chunks))
  if num_elems > MAX_OBJECTS then num_elems = MAX_OBJECTS end

  local by_index = {}       -- idx -> {va, class_va, name, outer_idx}
  for i = 0, num_elems - 1 do
    local uobj_va = get_object_by_index(chunks_ptr, i)
    if uobj_va ~= 0 then
      local class_va = read_u64(uobj_va + L.UO_CLASSPRIVATE_OFFSET)
      local outer_va = read_u64(uobj_va + L.UO_OUTERPRIVATE_OFFSET)
      local name     = fname_of(uobj_va + L.UO_NAMEPRIVATE_OFFSET)
      by_index[i] = { va=uobj_va, class_va=class_va, outer_va=outer_va, name=name }
    end
    if VERBOSE and i % 5000 == 0 then print("  walked "..i) end
  end
  print("[GObjects] indexed " .. tostring((function()local c=0;for _ in pairs(by_index) do c=c+1 end;return c end)()) .. " live objects")
  return by_index
end

-- ==== FIELD/PROPERTY WALK ==================================================
local function walk_properties(struct_va)
  local props = {}
  local head = read_u64(struct_va + L.US_CHILDPROPS_OFFSET)
  local guard = 0
  while head ~= 0 and guard < 4096 do
    local pname   = fname_of(head + L.FF_NAMEPRIVATE_OFFSET)
    local pclass  = read_u64(head + L.FF_CLASSPRIVATE_OFFSET)  -- FFieldClass*
    local pclass_name_va = pclass ~= 0 and (pclass + 0x00) or 0  -- FFieldClass.Name is at 0
    local ptype = pclass_name_va ~= 0 and fname_of(pclass_name_va) or "<unknown>"
    local poff  = read_u32(head + L.FP_OFFSET_OFFSET)
    local psize = read_u32(head + L.FP_ELEMENTSIZE_OFFSET)
    local pdim  = read_u32(head + L.FP_ARRAYDIM_OFFSET)
    local pflag = read_u64(head + L.FP_PROPERTYFLAGS_OFFSET)
    props[#props+1] = { name=pname, type=ptype, offset=poff, size=psize, dim=pdim, flags=pflag }
    head = read_u64(head + L.FF_NEXT_OFFSET)
    guard = guard + 1
  end
  return props
end

local function walk_functions(struct_va)
  local fns = {}
  local head = read_u64(struct_va + L.US_CHILDREN_OFFSET)
  local guard = 0
  while head ~= 0 and guard < 4096 do
    local fname = fname_of(head + L.UO_NAMEPRIVATE_OFFSET)
    local flags = read_u32(head + L.UFN_FUNCTIONFLAGS_OFFSET)
    local params = walk_properties(head)
    fns[#fns+1] = { name=fname, flags=flags, params=params }
    head = read_u64(head + L.FF_NEXT_OFFSET)
    guard = guard + 1
  end
  return fns
end

-- ==== JSON EMIT =============================================================
local function json_escape(s)
  return (s or ""):gsub("\\", "\\\\"):gsub("\"", "\\\""):gsub("\n", "\\n"):gsub("\r", "\\r")
end
local function json_val(v)
  if type(v) == "string" then return string.format('"%s"', json_escape(v)) end
  if type(v) == "number" then
    if v == math.floor(v) then return string.format("%d", v) end
    return tostring(v)
  end
  if type(v) == "boolean" then return v and "true" or "false" end
  if v == nil then return "null" end
  return tostring(v)
end
local function emit_kv_pairs(t, keys)
  local parts = {}
  for _, k in ipairs(keys) do parts[#parts+1] = string.format('"%s":%s', k, json_val(t[k])) end
  return "{" .. table.concat(parts, ",") .. "}"
end

-- ==== OUTPUT ================================================================
local function classes_json(structs)
  local out = { "[" }
  for i, s in ipairs(structs) do
    local props, fns = {}, {}
    for _, p in ipairs(s.props or {}) do
      props[#props + 1] = "      " .. emit_kv_pairs(p, {"name", "type", "offset", "size", "dim", "flags"})
    end
    for _, fn in ipairs(s.fns or {}) do
      fns[#fns + 1] = "      " .. emit_kv_pairs({name = fn.name, flags = fn.flags}, {"name", "flags"})
    end
    out[#out + 1] = string.format('  {\n    "name": %s,\n    "va": %d,\n    "super": %d,\n' ..
      '    "properties": [\n%s\n    ],\n    "functions": [\n%s\n    ]\n  }%s',
      json_val(s.name), s.va, s.super or 0, table.concat(props, ",\n"), table.concat(fns, ",\n"),
      i < #structs and "," or "")
  end
  out[#out + 1] = "]"
  return table.concat(out, "\n")
end

local function fnames_txt()
  local keys = {}
  for k in pairs(fname_cache) do keys[#keys + 1] = k end
  table.sort(keys)
  local lines = {}
  for _, k in ipairs(keys) do lines[#lines + 1] = string.format("%d\t%s", k, fname_cache[k]) end
  return table.concat(lines, "\n") .. "\n"
end

local function write_file(name, text)
  local path = OUTPUT_DIR .. "\\" .. name
  local f, err = io.open(path, "w")
  if not f then error("cannot write " .. path .. ": " .. tostring(err)) end
  f:write(text)
  f:close()
  print("wrote " .. path)
end

-- ==== DRIVER ================================================================
local function main()
  if GObjects_VA == 0 or GNames_VA == 0 then
    error("set ARGS.gobjects and ARGS.gnames (FUObjectArray / FNamePool addresses)")
  end
  if OUTPUT_DIR and io == nil then
    print("output_dir ignored: file output needs the script_unsafe setting; printing the dump instead")
    OUTPUT_DIR = nil
  end

  local start = os.clock()
  local objects = walk_objects()
  print(string.format("walked in %.1fs", os.clock() - start))

  -- classify: which objects are UStructs (classes/structs), enums, functions
  local structs, enums, functions = {}, {}, {}
  for _, info in pairs(objects) do
    if info.class_va and info.class_va ~= 0 then
      local cls = objects[read_u32(info.class_va + L.UO_INTERNALINDEX_OFFSET)]
      local cname = cls and cls.name or "?"
      if cname == "Class" or cname == "ScriptStruct" then
        info.props = walk_properties(info.va)
        info.fns   = walk_functions(info.va)
        info.super = read_u64(info.va + L.US_SUPERSTRUCT_OFFSET)
        structs[#structs + 1] = info
      elseif cname == "Enum" then
        enums[#enums + 1] = info
      elseif cname == "Function" then
        functions[#functions + 1] = info
      end
    end
  end
  table.sort(structs, function(a, b) return a.name < b.name end)
  print(string.format("classified: %d struct-like, %d enums, %d functions",
                      #structs, #enums, #functions))

  local classes = classes_json(structs)
  if OUTPUT_DIR then
    write_file("ClassesInfo.json", classes)
    write_file("FNames.txt", fnames_txt())
  else
    print("== ClassesInfo.json ==")
    print(classes)
  end
  return string.format("%d classes/structs, %d enums, %d functions", #structs, #enums, #functions)
end

return main()
