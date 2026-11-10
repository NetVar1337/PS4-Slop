# SPDX-License-Identifier: GPL-3.0-only
"""Interactive CLI / REPL over the ps4debug-ng client library.

    python -m ps4debug_ng.cli [host]

Every mutating command asks for confirmation (or takes --yes). Commands map
1:1 to the MCP tool surface, so the audit-log replay works on CLI sessions
run through the MCP server.
"""

from __future__ import annotations

import cmd
import shlex
import sys

from . import actions, workflows
from .client import Ps4DebugClient, Ps4DebugError


class Ps4Shell(cmd.Cmd):
    intro = "ps4debug-ng CLI. 'help' for commands, Ctrl+C or 'exit' to quit."
    prompt = "ps4> "

    def __init__(self):
        super().__init__()
        self.c: Ps4DebugClient | None = None
        self.pid: int | None = None
        self.attached = False
        self._rpcstub: int | None = None
        self._freezes: dict[str, actions.Freeze] = {}

    # ---------------------------------------------------------------- helpers

    def _c(self) -> Ps4DebugClient:
        if not self.c:
            raise RuntimeError("not connected - use: connect [host]")
        return self.c

    def _p(self) -> int:
        if self.pid is None:
            raise RuntimeError("no pid selected - use: procs, then use <pid>")
        return self.pid

    def _yes(self, args, what: str) -> bool:
        return "--yes" in args or input(f"confirm {what}? [y/N] ").lower() == "y"

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except (RuntimeError, Ps4DebugError, OSError, ValueError) as e:
            print(f"error: {e}")
            return False

    def do_exit(self, args):
        return True

    do_quit = do_exit
    do_EOF = do_exit

    # ------------------------------------------------------------- connection

    def do_connect(self, args):
        """connect [host] - connect to the console (auto-discover if no host)"""
        parts = shlex.split(args)
        if self.c:
            self.c.close()
        host = parts[0] if parts else (Ps4DebugClient.discover() or "")
        self.c = Ps4DebugClient(host)
        self.c.connect()
        print(self.c.server_info())

    def do_info(self, args):
        """info - payload version, branding, firmware"""
        print(self._c().server_info())

    def do_procs(self, args):
        """procs - list processes"""
        for p in self._c().list_processes():
            print(f'{p["pid"]:>6}  {p["name"]}')

    def do_use(self, args):
        """use <pid> - select the working process"""
        self.pid = int(args.split()[0], 0)

    # -------------------------------------------------------- memory / scans

    def do_regions(self, args):
        """regions - memory map of the working process"""
        for r in self._c().list_regions(self._p()):
            print(f'{r["start"]:016x}-{r["end"]:016x} prot {r["prot"]:x} {r["name"]}')

    def do_modules(self, args):
        """modules - loaded modules of the working process"""
        c = self._c()
        for m in workflows.list_modules(c.list_regions(self._p())):
            print(f'{m["base"]:016x} {m["size"]:>10x} {m["regions"]:>3} {m["name"]}')

    def do_imports(self, args):
        """imports <module_base> - dynamic imports of a module (from memory)"""
        from . import elf as elf_mod
        c = self._c()
        info = elf_mod.parse_elf(c.read_memory, int(args.split()[0], 0))
        for s in info.imports:
            print(f'{s.name}  got={s.got or 0:x}')

    def do_exports(self, args):
        """exports <module_base> - dynamic exports of a module (from memory)"""
        from . import elf as elf_mod
        c = self._c()
        info = elf_mod.parse_elf(c.read_memory, int(args.split()[0], 0))
        for s in info.exports:
            print(f'{s.value:016x} {s.size:>6x} {s.name}')

    def do_read(self, args):
        """read <addr> [len] - hex dump of process memory"""
        p = shlex.split(args)
        data = self._c().read_memory(self._p(), int(p[0], 0), int(p[1]) if len(p) > 1 else 256)
        for off in range(0, len(data), 16):
            chunk = data[off:off + 16]
            hexp = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{int(p[0],0)+off:08x}  {hexp:<47} {asc}")

    def do_write(self, args):
        """write <addr> <hex> [--yes] - write bytes (payload-verified)"""
        p = shlex.split(args)
        if self._yes(p, f"write to {p[0]}"):
            self._c().write_memory(self._p(), int(p[0], 0), bytes.fromhex(p[1]))
            print("ok")

    def do_scan(self, args):
        """scan aob <hex> | scan value <n> [type] - memory scans (client-side)"""
        from . import scans
        c, pid = self._c(), self._p()
        regions = c.list_regions(pid)
        p = shlex.split(args)
        if p[0] == "aob":
            hits = c.scan_aob(pid, 0, 0x7FFF00000000, bytes.fromhex(p[1]),
                              regions=[r for r in regions if r["prot"] & 1])
        else:
            hits = scans.value_scan(c, pid, [r for r in regions if r["prot"] & 1],
                                    int(p[1], 0), p[2] if len(p) > 2 else "u32")
        print(f"{len(hits)} hits")
        for h in hits[:50]:
            print(f"  {h:x}")
        self._last_scan = hits

    def do_chains(self, args):
        """chains <target_hex> [depth] - CE-style pointer scan"""
        p = shlex.split(args)
        c, pid = self._c(), self._p()
        self._chains = workflows.find_pointer_chains(
            c, pid, int(p[0], 0), c.list_regions(pid),
            max_depth=int(p[1]) if len(p) > 1 else 5)
        for ch in self._chains[:30]:
            print(f'{ch["address"]:x} offsets {ch["offsets"]} stable={ch["stable"]}')

    def do_rescan(self, args):
        """rescan <target_hex> - revalidate chains after a restart"""
        c = self._c()
        target = int(args.split()[0], 0)
        for ch in getattr(self, "_chains", []):
            try:
                final = workflows.resolve_chain(c, self._p(), ch["address"], ch["offsets"])
                if final == target:
                    print(f'valid: {ch["address"]:x} {ch["offsets"]}')
            except (Ps4DebugError, OSError):
                pass

    # ------------------------------------------------------------------ debug

    def do_attach(self, args):
        """attach [pid] - attach debugger (defaults to working process)"""
        self._c().attach(self._p() if not args else int(args.split()[0], 0))
        self.attached = True

    def do_detach(self, args):
        """detach [--yes] - detach and resume the process"""
        if self._yes(shlex.split(args), "detach"):
            self._c().detach()
            self.attached = False

    def do_break(self, args):
        """break <index> <addr> [off] [--yes] - set/clear a breakpoint"""
        p = shlex.split(args)
        en = p[2] != "off" if len(p) > 2 else True
        if self._yes(p, f"breakpoint {p[0]} @ {p[1]}"):
            self._c().set_breakpoint(int(p[0]), int(p[1], 0), en)

    def do_watch(self, args):
        """watch <index> <addr> [len] [1=write|3=rw|0=exec] [off] [--yes]"""
        p = shlex.split(args)
        en = "off" not in p
        if self._yes(p, f"watchpoint {p[0]} @ {p[1]}"):
            self._c().set_watchpoint(int(p[0]), int(p[1], 0),
                                     int(p[2]) if len(p) > 2 and p[2].isdigit() else 8,
                                     int(p[3]) if len(p) > 3 and p[3].isdigit() else 1, en)

    def do_cont(self, args):
        """cont - continue execution"""
        self._c().continue_(0)

    def do_step(self, args):
        """step - single-step all threads"""
        self._c().step()

    def do_regs(self, args):
        """regs - GP registers of the current thread"""
        c = self._c()
        lw = c.thread_list()
        if not lw:
            print("no threads (attached?)")
            return
        r = c.get_registers(lw[0])
        for k in ("rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx",
                  "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
                  "r13", "r14", "r15", "rflags"):
            print(f"{k:>7} = {r[k]:016x}")

    def do_stack(self, args):
        """stack [depth] - RBP-chain call stack"""
        c = self._c()
        lw = c.thread_list()
        if not lw:
            print("no threads (attached?)")
            return
        r = c.get_registers(lw[0])
        for i, f in enumerate(c.read_stack(self._p(), r["rbp"], r["rsp"],
                                           int(args) if args.strip() else 16)):
            print(f"#{i:>2} rip {f['ret_addr']:x} rbp {f['rbp']:x}")

    def do_events(self, args):
        """events - drain pending debug events (breakpoint/watchpoint hits)"""
        for ev in self._c().wait_events(64):
            r = ev["registers"]
            print(f"pause rip={r['rip']:x} thread={ev['lwpid']} {ev.get('thread_name', '')}")

    def do_whatwrites(self, args):
        """whatwrites <addr> [len] - capture writers via hardware watchpoint"""
        p = shlex.split(args)
        if self._yes(p, f"watchpoint @ {p[0]}"):
            events = actions.find_what_writes(self._c(), int(p[0], 0),
                                              int(p[1]) if len(p) > 1 else 8)
            for ev in events:
                print(f"rip={ev['rip']:x} thread={ev['lwpid']}")
            print("(process is stopped - 'cont' to resume)")

    # ------------------------------------------------------------- execution

    def do_install(self, args):
        """install [--yes] - inject the RPC stub; prints stub address"""
        if self._yes(shlex.split(args), "inject RPC stub"):
            self._rpcstub = self._c().proc_install(self._p())
            print(f"rpcstub = {self._rpcstub:x}")

    def do_call(self, args):
        """call <addr> [args...] [--yes] - call a function in the target"""
        p = shlex.split(args)
        if not self._yes(p, f"call @ {p[0]}"):
            return
        c = self._c()
        if self._rpcstub is None:
            self._rpcstub = c.proc_install(self._p())
        rax = c.proc_call(self._p(), self._rpcstub, int(p[0], 0),
                          tuple(int(a, 0) for a in p[1:] if a != "--yes"))
        print(f"rax = {rax:#x}")

    def do_protect(self, args):
        """protect <addr> <len> <prot> [--yes] - mprotect (READ=1 WRITE=2 EXEC=4)"""
        p = shlex.split(args)
        if self._yes(p, f"protect @ {p[0]}"):
            self._c().proc_protect(self._p(), int(p[0], 0), int(p[1]), int(p[2]))

    def do_loadelf(self, args):
        """loadelf <path> [--yes] - load an ELF payload into the process"""
        p = shlex.split(args)
        if self._yes(p, "load ELF"):
            try:
                with open(p[0], "rb") as f:
                    elf = f.read()
            except OSError as e:
                print(f"error: cannot read {p[0]}: {e}")
                return
            self._c().proc_elf(self._p(), elf)
            print(f"loaded {len(elf)} bytes")

    # ------------------------------------------------------------------ misc

    def do_freeze(self, args):
        """freeze <addr> <hex> | freeze off <addr> - CE-style poke loop"""
        p = shlex.split(args)
        c = self._c()
        if p[0] == "off":
            fid = f"{self._p()}:{p[1]}"
            fz = self._freezes.pop(fid, None)
            if fz:
                fz.stop()
                print(f"stopped after {fz.writes} writes")
            return
        if self._yes(p, f"freeze @ {p[0]}"):
            fid = f"{self._p()}:{p[0]}"
            fz = actions.Freeze(c, self._p(), int(p[0], 0), bytes.fromhex(p[1]))
            fz.start()
            self._freezes[fid] = fz
            print(f"frozen: {fid}")

    def do_snapshot(self, args):
        """snapshot save <path> <addr> <len> | snapshot diff <a> <b>"""
        p = shlex.split(args)
        if p[0] == "save":
            workflows.snapshot_save(self._c(), self._p(), int(p[2], 0), int(p[3]), p[1])
            print("saved")
        else:
            diff = workflows.snapshot_diff(p[1], p[2])
            print(f"changed {len(diff['changed'])} / {diff['unchanged_count']} unchanged")
            print(" ".join(hex(o) for o in diff["changed"][:64]))

    def do_hash(self, args):
        """hash <addr> <len> - SHA-256 of a region"""
        import hashlib
        data = self._c().read_memory(self._p(), int(args.split()[0], 0), int(args.split()[1]))
        print(hashlib.sha256(data).hexdigest())

    def do_cheat(self, args):
        """cheat apply <file> [--yes] | cheat export <file> - ps4cheat files"""
        p = shlex.split(args)
        if p[0] == "apply":
            if self._yes(p, f"apply {p[1]}"):
                for line in actions.cheat_apply_pokes(self._c(), actions.cheat_import(p[1])["pokes"]):
                    print(line)
        else:
            raise RuntimeError("export is MCP-side (ps4_cheat_export); CLI is apply-only")

    def do_notify(self, args):
        """notify <text> [--yes] - console notification"""
        if self._yes(shlex.split(args), "notification"):
            self._c().notify(args.replace("--yes", "").strip())
            print("sent")

    def do_selftest(self, args):
        """selftest - run the hardware smoke test (exits the REPL)"""
        return True


def main() -> None:
    shell = Ps4Shell()
    if len(sys.argv) > 1:
        shell.do_connect(sys.argv[1])
    try:
        shell.cmdloop()
    finally:
        for fz in shell._freezes.values():
            fz.stop()
        if shell.c:
            shell.c.close()


if __name__ == "__main__":
    main()
