import json
import sys
from pathlib import Path

import ida_auto
import ida_dbg
import ida_idd
import ida_pro
import idc


result = {"passed": False}
try:
    ida_auto.auto_wait()
    if not ida_dbg.load_debugger("gdb", True):
        raise RuntimeError("IDA Remote GDB debugger could not load")
    ida_dbg.set_remote_debugger("127.0.0.1", "", int(idc.ARGV[1]))
    sys.path.insert(0, idc.ARGV[3])
    from ps4_mcp.adapters.ida import IDAWorkbench
    live = IDAWorkbench(idc.ARGV[4], idc.ARGV[5])
    regions = live.sync_debugger_regions(71, apply=True)
    attached = ida_dbg.attach_process(71, -1)
    if attached <= 0:
        raise RuntimeError("IDA attach_process failed: " + str(attached))
    event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
    if event <= 0:
        raise RuntimeError("IDA did not receive a stop: " + str(event))
    instruction = ida_dbg.get_reg_val("RIP")
    memory = ida_idd.dbg_read_memory(0x400100, 6)
    if instruction != 0x400100 or memory != b"\xb8\x2a\x00\x00\x00\xc3":
        raise RuntimeError("Native debugger register/memory mismatch")
    if not ida_dbg.add_bpt(0x400105, 1, ida_idd.BPT_SOFT):
        raise RuntimeError("Native software breakpoint insertion failed")
    if not ida_dbg.step_into():
        raise RuntimeError("Native single-step request failed")
    event = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 10)
    if event <= 0 or ida_dbg.get_reg_val("RIP") != 0x400105:
        raise RuntimeError("Native single-step did not reach expected fixture PC")
    if not ida_dbg.del_bpt(0x400105):
        raise RuntimeError("Native software breakpoint removal failed")
    result = {"passed": True, "rip": hex(instruction), "memory_hex": memory.hex(),
              "single_step_verified": True, "software_breakpoint_round_trip": True,
              "manual_regions_installed": regions["region_count"],
              "backend": "loopback fixture, not PS4"}
    ida_dbg.detach_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 5)
except Exception as error:
    result["error"] = str(error)
Path(idc.ARGV[2]).write_text(json.dumps(result, indent=2), encoding="utf-8")
ida_pro.qexit(0 if result["passed"] else 1)
