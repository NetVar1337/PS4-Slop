"""Host control-plane CLI for a running ``ps4-workbench`` broker.

Start the broker with a qualified local profile (see docs/QUALIFICATION.md):

    ps4-workbench --profile profiles/ps4-1400.local.json --toolset full \\
        broker --port 24600 --token-file profiles/broker-token.local

Then drive it:

    python -m ps4_workbench.ctl --url http://127.0.0.1:24600 \\
        --token-file profiles/broker-token.local status
    ... preflight --probe
    ... call memory_peek '{"pid": 71, "address": "0x400000", "length": 64}'
    ... stage --pid 71 --target target.json --payload payload.elf --sha256 <64hex>
    ... rpc --pid 71 --command 1 --argument 5      # features bitmask
    ... payload-status --pid 71
    ... export-offsets --module-sha256 <64hex> --namespace fortnite

The payload RPC command numbers follow the shared ABI in
``internals/include/internals/runtime.hpp``: 0 = status, 1 = features,
2 = shutdown. ``rpc`` accepts any command for payloads that extend it.

Mutations are never retried automatically; a failed call means inspect the
console state first (docs/QUALIFICATION.md section 6).
"""

import argparse
import json
import sys

from .client import BrokerClient
from .config import WorkbenchError, parse_address, require_hash, require_integer

RPC_STATUS = 0
RPC_FEATURES = 1
RPC_SHUTDOWN = 2
RPC_WRITE_CONFIG = 4
RPC_READ_CONFIG = 5
RPC_READ_TELEMETRY = 6


def _call(client, tool, **arguments):
    # request("call", ...) avoids BrokerClient.call's `name` keyword collision
    # for tools that themselves take a `name` argument (e.g. project_open).
    return client.request("call", name=tool, arguments=arguments)


def _add_common(parser):
    parser.add_argument("--url", required=True, help="http://127.0.0.1:PORT of the broker")
    parser.add_argument("--token-file", required=True, help="broker token file written by --token-file")
    parser.add_argument("--client", default=None, help="stable broker client identity")


def build_parser():
    parser = argparse.ArgumentParser(prog="ps4-workbench-ctl", description=__doc__.splitlines()[0])
    _add_common(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="console_status (offline unless --probe)").add_argument("--probe", action="store_true")
    sub.add_parser("tools", help="list tools exposed by the broker toolset")
    p = sub.add_parser("call", help="call any tool: call TOOL [JSON-ARGS]")
    p.add_argument("tool")
    p.add_argument("arguments", nargs="?", default="{}")
    p = sub.add_parser("preflight", help="14.00 preflight; add --probe for the identity handshake")
    p.add_argument("--probe", action="store_true")

    def payload_args(p):
        p.add_argument("--pid", type=int, required=True)
        p.add_argument("--target", help="ps4wb-internals-target-v1 artifact path (stage/recover)")
        p.add_argument("--payload", help="payload ELF artifact path (stage/recover)")
        p.add_argument("--sha256", help="expected payload SHA-256 (stage/recover)")

    p = sub.add_parser("stage", help="payload_stage: hash-qualified ELF upload via CMD_PROC_ELF_RPC")
    payload_args(p)
    p = sub.add_parser("recover", help="payload_recover: re-find a resident payload's RPC entry")
    payload_args(p)
    p = sub.add_parser("payload-status", help="payload_status for a staged/recovered PID")
    p.add_argument("--pid", type=int, required=True)
    p = sub.add_parser("shutdown", help="payload_shutdown (RPC command 2) for a PID")
    p.add_argument("--pid", type=int, required=True)
    p = sub.add_parser("rpc", help="payload_rpc with an explicit command number")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--command", type=int, required=True)
    p.add_argument("--argument", default="0x0")
    p.add_argument("--argument2", default="0x0")
    p = sub.add_parser("features", help="set the payload feature bitmask (RPC command 1)")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--bits", required=True, help="feature bitmask, decimal or 0x...")

    p = sub.add_parser("config", help="read/write a config word (RPC 5 read / 4 write)")
    p.add_argument("action", choices=["get", "set"])
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--value", default=None, help="value for set, decimal or 0x...")
    p = sub.add_parser("telemetry", help="read a telemetry word (RPC command 6)")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--index", type=int, required=True)
    p = sub.add_parser("watch", help="poll payload_status heartbeat and report staleness")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default 1.0)")
    p.add_argument("--count", type=int, default=0, help="stop after N polls (0 = until Ctrl+C)")

    p = sub.add_parser("export-offsets", help="project_export_offsets: annotations -> offsets.hpp + manifest")
    p.add_argument("--project", default=None)
    p.add_argument("--module-sha256", default=None)
    p.add_argument("--namespace", default=None)
    p.add_argument("--verify-bytes", type=int, default=None)
    return parser


def run(argv, client_factory=BrokerClient):
    args = build_parser().parse_args(argv)
    client = client_factory(args.url, args.token_file, args.client)

    if args.command == "status":
        result = _call(client, "console_status", probe=args.probe)
    elif args.command == "tools":
        result = client.request("tools")
    elif args.command == "call":
        arguments = json.loads(args.arguments)
        if not isinstance(arguments, dict):
            raise WorkbenchError("call arguments must be a JSON object")
        result = _call(client, args.tool, **arguments)
    elif args.command == "preflight":
        result = _call(client, "preflight", probe=args.probe)
    elif args.command == "stage":
        result = _call(client, "payload_stage", pid=require_integer(args.pid, "pid", 1, 2147483647),
                             target=args.target, payload=args.payload, sha256=require_hash(args.sha256))
    elif args.command == "recover":
        result = _call(client, "payload_recover", pid=require_integer(args.pid, "pid", 1, 2147483647),
                             target=args.target, payload=args.payload, sha256=require_hash(args.sha256))
    elif args.command == "payload-status":
        result = _call(client, "payload_status", pid=require_integer(args.pid, "pid", 1, 2147483647))
    elif args.command == "shutdown":
        result = _call(client, "payload_shutdown", pid=require_integer(args.pid, "pid", 1, 2147483647))
    elif args.command == "rpc":
        result = _call(client, "payload_rpc", pid=require_integer(args.pid, "pid", 1, 2147483647),
                             command=require_integer(args.command, "command", 0, 2**53 - 1),
                             argument=hex(parse_address(args.argument)),
                             argument2=hex(parse_address(args.argument2)))
    elif args.command == "features":
        result = _call(client, "payload_rpc", pid=require_integer(args.pid, "pid", 1, 2147483647),
                             command=RPC_FEATURES, argument=hex(parse_address(args.bits)), argument2="0x0")
    elif args.command == "config":
        pid = require_integer(args.pid, "pid", 1, 2147483647)
        index = require_integer(args.index, "index", 0, 31)
        if args.action == "get":
            result = _call(client, "payload_rpc", pid=pid, command=RPC_READ_CONFIG,
                           argument=hex(index), argument2="0x0")
        else:
            if args.value is None:
                raise WorkbenchError("config set requires --value")
            result = _call(client, "payload_rpc", pid=pid, command=RPC_WRITE_CONFIG,
                           argument=hex(index), argument2=hex(parse_address(args.value)))
    elif args.command == "telemetry":
        result = _call(client, "payload_rpc", pid=require_integer(args.pid, "pid", 1, 2147483647),
                       command=RPC_READ_TELEMETRY, argument=hex(require_integer(args.index, "index", 0, 15)),
                       argument2="0x0")
    elif args.command == "watch":
        result = _watch(client, args)
    elif args.command == "export-offsets":
        arguments = {}
        if args.project is not None:
            arguments["project"] = args.project
        if args.module_sha256 is not None:
            arguments["module_sha256"] = require_hash(args.module_sha256, "module_sha256")
        if args.namespace is not None:
            arguments["namespace"] = args.namespace
        if args.verify_bytes is not None:
            arguments["verify_bytes"] = require_integer(args.verify_bytes, "verify_bytes", 1, 32)
        result = _call(client, "project_export_offsets", **arguments)
    else:  # pragma: no cover - argparse enforces the choices
        raise WorkbenchError("unknown command")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _watch(client, args):
    import time

    pid = require_integer(args.pid, "pid", 1, 2147483647)
    interval = max(0.05, args.interval)
    previous = None
    stale = 0
    polls = 0
    while True:
        # WorkbenchError propagates: inspect the console, then payload_recover
        # or a manual re-stage; never an automatic retry.
        status = _call(client, "payload_status", pid=pid)
        heartbeat = status.get("heartbeat")
        if previous is not None and heartbeat == previous:
            stale += 1
        else:
            stale = 0
        previous = heartbeat
        polls += 1
        print(json.dumps(dict(status, poll=polls, stale_polls=stale), sort_keys=True), flush=True)
        if stale >= 3:
            print(json.dumps({
                "warning": "heartbeat unchanged for 3 polls; payload may be stalled. "
                           "Inspect the console, then payload_recover or a manual re-stage."
            }, sort_keys=True), flush=True)
            stale = 0
        if args.count and polls >= args.count:
            return {"polls": polls, "last": status}
        time.sleep(interval)


def main(argv=None):
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except WorkbenchError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except (ValueError, json.JSONDecodeError) as error:
        print(f"error: invalid arguments: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
