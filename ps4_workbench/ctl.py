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
    ... config get --pid 71 --index 0
    ... telemetry --pid 71 --index 0
    ... watch --pid 71
    ... update --game fortnite --pid 71          # or --game apex (full pipeline)
    ... update --game apex --pid 71 --old-artifact old.elf --annotations ann.json
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

    p = sub.add_parser("update", help="game-aware update pipeline: dump -> SDK -> offsets/target -> build -> next steps")
    p.add_argument("--game", choices=["fortnite", "apex"], required=True)
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--module", default=None)
    p.add_argument("--module-sha256", default=None)
    p.add_argument("--namespace", default=None)
    p.add_argument("--image-base", default=None)
    p.add_argument("--signature-sites", nargs="*", default=None)
    p.add_argument("--old-artifact", default=None, help="previous annotated build; with --annotations uses offset_refresh")
    p.add_argument("--annotations", default=None)
    p.add_argument("--payload-repo", default=None, help="payload repo for the build (default per game)")
    p.add_argument("--payload", default=None, help="payload ELF path relative to the repo")
    p.add_argument("--build-cmd", default="make", help="payload build command (default make)")
    p.add_argument("--build-argv", default=None, help="JSON argv array; executes without a shell")
    p.add_argument("--app-version", default=None, help="observed application version when opening a new project")
    p.add_argument("--session-id", default=None, help="resume an existing durable research session")
    p.add_argument("--no-build", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the plan without any console calls")
    p = sub.add_parser("session", help="create, advance, inspect, cancel or retry a durable recipe session")
    p.add_argument("action", choices=["create", "advance", "status", "cancel", "retry", "revise"])
    p.add_argument("--session", default=None)
    p.add_argument("--recipe", default=None)
    p.add_argument("--inputs", default="{}")
    p.add_argument("--step", type=int, default=None)
    p.add_argument("--recovery-evidence", default=None)
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
    elif args.command == "session":
        arguments = {"action": args.action}
        for key in ("session", "recipe", "step", "recovery_evidence"):
            value = getattr(args, key)
            if value is not None:
                arguments[key] = value
        if args.action in ("create", "revise"):
            arguments["inputs"] = json.loads(args.inputs)
        result = _call(client, "recipe_session", **arguments)
    elif args.command == "update":
        result = _update(client, args)
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


GAMES = {
    "fortnite": {"recipe": "unreal_pipeline", "repo": "../Fortnite-PS4", "payload": "payload.elf"},
    "apex": {"recipe": "source_pipeline", "repo": "../Apex-PS4", "payload": "build/apex_payload.elf", "status_magic": "0x41584553"},
}


def _artifact_bytes(client, path, expected_sha=None):
    import hashlib
    content = bytearray()
    while len(content) <= 16 * 1024 * 1024:
        part = _call(client, "artifact_read", artifact=path, offset=len(content), length=4096)
        block = bytes.fromhex(part["hex"])
        content.extend(block)
        if len(block) < 4096:
            if expected_sha and hashlib.sha256(content).hexdigest() != expected_sha:
                raise WorkbenchError(f"Artifact changed: {path}")
            return bytes(content)
    raise WorkbenchError("Artifact exceeds 16 MiB")


def _expanded(client, value):
    if "result_saved" in value:
        ref = value["result_saved"]
        return json.loads(_artifact_bytes(client, ref["path"], ref["sha256"]))
    return value


def _update(client, args):
    """Research, install generated inputs, build fresh ELF, preserve evidence."""
    import hashlib
    from pathlib import Path
    import shlex
    import subprocess
    import os
    from .build import build

    game = GAMES[args.game]
    repo = Path(args.payload_repo or game["repo"]).resolve()
    inputs = {"pid": args.pid, "namespace": args.namespace or "game",
              "status_magic": game.get("status_magic", "0x5053494e")}
    for key in ("module", "module_sha256", "image_base", "signature_sites"):
        value = getattr(args, key)
        if value is not None:
            inputs[key] = value
    if bool(args.old_artifact) != bool(args.annotations):
        raise WorkbenchError("Pass --old-artifact and --annotations together")
    recipe = game["recipe"]
    plan = {"game": args.game, "pipeline_recipe": recipe, "inputs": inputs,
            "payload_repo": str(repo), "build_cmd": None if args.no_build else args.build_cmd}
    if args.old_artifact:
        inputs.update(old_artifact=args.old_artifact, annotations=args.annotations)
        recipe = ("unreal" if args.game == "fortnite" else "source") + "_update"
        plan["update_recipe"] = "offset_refresh"
        plan["update_inputs"] = dict(inputs)
    if args.dry_run:
        return dict(plan, dry_run=True)

    # A new project needs the real application version; never invent one.
    active = _call(client, "project_open")
    if not active.get("active"):
        if not args.app_version:
            raise WorkbenchError("Open a project with the observed title/app version, or pass --app-version")
        info = _call(client, "process_info", pid=args.pid)
        _call(client, "project_open", title_id=info["title_id"], app_version=args.app_version, name=args.game)
    if args.session_id:
        update = _call(client, "recipe_session", action="status", session=args.session_id)
    else:
        update = _call(client, "recipe_session", action="create", recipe=recipe, inputs=inputs)
    session_id = update["id"]
    while update["state"] in ("pending", "running"):
        update = _expanded(client, _call(client, "recipe_session", action="advance", session=session_id))
        print(json.dumps({"session": session_id, "state": update["state"], "completed": update["completed"], "total": update["total"]}), file=sys.stderr, flush=True)
    if update["state"] != "completed":
        raise WorkbenchError(f"Research session {session_id} is {update['state']}; inspect it before explicitly retrying")
    outputs = update["outputs"]
    target_ref = outputs["project_export_target"]["target"]
    target = json.loads(_artifact_bytes(client, target_ref["path"], target_ref["sha256"]))
    prior = _call(client, "project_manifest").get("manifest") or {}
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
    if commit.returncode:
        raise WorkbenchError("Payload repository must have a pinned source commit")
    manifest = dict(prior, format="ps4wb-project-v1", title_id=target["title_id"],
                    app_version=target["application_version"], module_sha256=target["module_sha256"],
                    engine="unreal" if args.game == "fortnite" else "source", sdk="openorbis" if args.game == "fortnite" else "payload",
                    source_commit=commit.stdout.strip(), repository=str(repo), staging="immediate", rpc_version=1)
    _call(client, "project_manifest", manifest=manifest)
    installed = _call(client, "project_install", target=target_ref["path"],
                      offsets=outputs["project_export_offsets"]["header"]["path"],
                      engine=outputs["engine_sdk_export"]["artifact"]["path"])
    if args.no_build:
        return {"session": session_id, "update": update, "installed": installed, "build": None, "deployed": False}
    argv = json.loads(args.build_argv) if args.build_argv else shlex.split(args.build_cmd, posix=os.name != "nt")
    argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a for a in argv]
    evidence = build(repo, argv, args.payload or game["payload"])
    collected = _call(client, "project_collect_build")
    payload_file = Path(evidence["payload"]["path"])
    sha = evidence["payload"]["sha256"]
    return {"session": session_id, "update": update, "installed": installed, "build": evidence,
            "payload": {"path": str(payload_file), "sha256": sha}, "collected": collected, "deployed": False,
            "next": {"ingest": ["ps4-workbench", "ingest", str(payload_file)], "target": target_ref["path"],
                     "payload_sha256": sha, "action": "qualify the exact tested output before staging"}}


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
