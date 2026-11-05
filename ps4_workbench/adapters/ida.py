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
        def execute():
            import ida_funcs
            import ida_hexrays
            import ida_nalt
            import idautils
            from ..tools import parse_address
            expected = getattr(self, "expected_program_hash", None)
            digest = ida_nalt.retrieve_input_file_sha256()
            if expected and (not digest or bytes(digest).hex() != expected):
                raise WorkbenchError("IDA database changed; stop and restart its analysis agent")
            if operation == "functions":
                import itertools
                offset, limit = arguments.get("offset", 0), arguments.get("limit", 100)
                return [{"address": hex(address), "name": ida_funcs.get_func_name(address)[:256]}
                        for address in itertools.islice(idautils.Functions(), offset, offset + limit)]
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
                import itertools
                return [{"from": hex(reference.frm), "to": hex(reference.to), "type": reference.type}
                        for reference in itertools.islice(idautils.XrefsTo(address), arguments.get("limit", 100))]
            raise WorkbenchError("Unsupported IDA analysis operation")
        return self.on_ui(execute)

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
