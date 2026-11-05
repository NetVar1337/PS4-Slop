from .base import LiveAnalysis, clipped
from ..config import WorkbenchError


class IDAWorkbench(LiveAnalysis):
    target = "ida"

    def on_ui(self, action, write=False):
        import ida_kernwin
        result, errors = [], []

        def invoke():
            try:
                result.append(action())
            except Exception as error:
                errors.append(error)
            return 1
        status = ida_kernwin.execute_sync(invoke, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ)
        if errors:
            raise errors[0]
        if status == -1 or not result:
            raise WorkbenchError("IDA main-thread execution failed")
        return result[0]

    def input_hash(self):
        import ida_nalt

        def read():
            digest = ida_nalt.retrieve_input_file_sha256()
            if not digest:
                raise WorkbenchError("IDA input file SHA-256 is unavailable")
            return bytes(digest).hex()
        return self.on_ui(read)

    def sync_debugger_regions(self, pid, apply=False):
        mappings = self.client.call("process_maps", pid=pid)
        if not isinstance(mappings, list):
            raise WorkbenchError("Inspect the saved large map artifact before importing regions")
        from ..rsp import numeric
        regions = [{"start": numeric(entry["start"]), "end": numeric(entry["end"]),
                    "name": str(entry["name"])[:256], "protection": entry["protection"]}
                   for entry in mappings if numeric(entry["end"]) > numeric(entry["start"])]
        if not apply:
            return {"regions": regions, "applied": False}

        def install():
            import ida_dbg
            import ida_idd
            original = ida_dbg.get_manual_regions()
            entries = ida_idd.meminfo_vec_t()
            for region in regions:
                entry = ida_idd.memory_info_t()
                entry.start_ea, entry.end_ea = region["start"], region["end"]
                entry.name, entry.sclass = region["name"], "CODE" if region["protection"] & 4 else "DATA"
                entry.sbase, entry.bitness = 0, 2
                protection = region["protection"]
                entry.perm = ((protection & 1) << 2) | (protection & 2) | ((protection & 4) >> 2)
                entries.push_back(entry)
            ida_dbg.set_manual_regions(entries)
            ida_dbg.enable_manual_regions(True)
            return {"applied": True, "region_count": len(regions), "previous_regions": original, "console_changed": False}
        return self.on_ui(install, write=True)

    def analyze(self, operation, arguments):
        write = operation in ("rename", "comment")

        def execute():
            import itertools
            import ida_bytes
            import ida_funcs
            import ida_hexrays
            import ida_lines
            import ida_name
            import ida_nalt
            import idautils
            import idc
            from ..tools import parse_address
            expected = getattr(self, "expected_program_hash", None)
            digest = ida_nalt.retrieve_input_file_sha256()
            if expected and (not digest or bytes(digest).hex() != expected):
                raise WorkbenchError("IDA database changed; stop and restart its analysis agent")
            flt = (arguments.get("filter") or "").lower()
            if operation == "functions":
                offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
                items = (
                    {"address": hex(ea), "name": ida_funcs.get_func_name(ea)[:256]}
                    for ea in idautils.Functions()
                )
                if flt:
                    items = (item for item in items if flt in item["name"].lower())
                return list(itertools.islice(items, offset, offset + limit))
            if operation == "strings":
                offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
                min_len = arguments.get("min_length", 4)
                out = []
                skipped = 0
                for s in idautils.Strings():
                    val = str(s)
                    if len(val) < min_len or (flt and flt not in val.lower()):
                        continue
                    if skipped < offset:
                        skipped += 1
                        continue
                    out.append({"address": hex(int(s.ea)), "length": int(s.length), "value": val[:512]})
                    if len(out) >= limit:
                        break
                return out
            if operation == "imports":
                offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
                collected = []
                qty = ida_nalt.get_import_module_qty()
                for idx in range(qty):
                    mod_name = ida_nalt.get_import_module_name(idx) or ""

                    def _cb(ea, name, ordinal):
                        sym_name = name or f"ord_{ordinal}"
                        if not flt or flt in sym_name.lower() or flt in mod_name.lower():
                            collected.append({
                                "address": hex(int(ea)),
                                "name": str(sym_name)[:256],
                                "library": str(mod_name)[:128],
                                "ordinal": int(ordinal or 0),
                            })
                        return len(collected) < offset + limit

                    ida_nalt.enum_import_names(idx, _cb)
                    if len(collected) >= offset + limit:
                        break
                return collected[offset:offset + limit]
            address = parse_address(arguments["address"])
            if operation == "decompile":
                if not ida_hexrays.init_hexrays_plugin():
                    raise WorkbenchError("IDA Hex-Rays decompiler is unavailable for this input")
                function = ida_funcs.get_func(address)
                if function is None:
                    raise WorkbenchError("No function at static address")
                result = ida_hexrays.decompile(function.start_ea)
                if result is None:
                    raise WorkbenchError("Hex-Rays did not produce a decompilation")
                return {"address": hex(function.start_ea), **clipped(result)}
            if operation == "xrefs":
                limit = arguments.get("limit", 100)
                direction = arguments.get("direction", "to")
                refs = []
                if direction in ("to", "both"):
                    for ref in idautils.XrefsTo(address):
                        refs.append({"from": hex(ref.frm), "to": hex(ref.to), "type": ref.type, "direction": "to"})
                        if len(refs) >= limit:
                            break
                if direction in ("from", "both") and len(refs) < limit:
                    for ref in idautils.XrefsFrom(address):
                        refs.append({"from": hex(ref.frm), "to": hex(ref.to), "type": ref.type, "direction": "from"})
                        if len(refs) >= limit:
                            break
                return refs
            if operation == "disasm":
                count = arguments.get("count", 32)
                cur = address
                insns = []
                for _ in range(count):
                    sz = ida_bytes.get_item_size(cur)
                    if not sz or sz <= 0:
                        break
                    raw_line = idc.generate_disasm_line(cur, 0) or ""
                    clean = ida_lines.tag_remove(raw_line) if hasattr(ida_lines, "tag_remove") else raw_line
                    insns.append({"address": hex(cur), "size": int(sz), "text": clean[:256]})
                    cur += sz
                return {"address": hex(address), "instructions": insns}
            if operation == "rename":
                name = arguments["name"]
                ok = ida_name.set_name(address, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK)
                return {"address": hex(address), "name": name, "applied": bool(ok)}
            if operation == "comment":
                text = arguments["text"]
                ok = ida_bytes.set_cmt(address, text, False)
                return {"address": hex(address), "text": text, "applied": bool(ok)}
            raise WorkbenchError("Unsupported IDA analysis operation")
        return self.on_ui(execute, write=write)

    def refresh_shadow(self, pid, rva, runtime_base, length, module_sha256, apply=False):
        import ida_bytes
        import ida_nalt
        import ida_segment
        content = self.read_live(pid, rva, runtime_base, length, module_sha256)
        if not apply:
            return {"hex": content.hex(), "database_changed": False}

        def patch():
            address = ida_nalt.get_imagebase() + rva
            segment = ida_segment.getseg(address)
            if segment is None or address + length > segment.end_ea:
                raise WorkbenchError("Static address range is outside one IDA segment")
            ida_bytes.patch_bytes(address, content)
            return {"address": hex(address), "database_changed": True, "console_changed": False}
        return self.on_ui(patch, write=True)
