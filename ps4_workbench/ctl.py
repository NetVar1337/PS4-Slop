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
    ... update --project-dir ../Fortnite-PS4 --pid 71   # reads workbench.json
    ... export-offsets --module-sha256 <64hex> --namespace fortnite [--archive]

The payload RPC command numbers follow the shared ABI in
``internals/include/internals/runtime.hpp``: 0 = status, 1 = features,
2 = shutdown. ``rpc`` accepts any command for payloads that extend it.

Mutations are never retried automatically; a failed call means inspect the
console state first (docs/QUALIFICATION.md section 6).
"""

import argparse
import json
import struct
import sys
from pathlib import Path

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
    parser = argparse.ArgumentParser(prog="ps4-workbench-ctl", description=__doc__ or "PS4 workbench control plane")
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
    p = sub.add_parser("features", help="set features by mask or generated names (RPC command 1)")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--bits", help="feature bitmask, decimal or 0x...")
    p.add_argument("--names", help="comma-separated generated feature names, or safe")
    p.add_argument("--project-dir", default=".", help="game repository for named features")

    p = sub.add_parser("config", help="read/write a config word by index or generated name")
    p.add_argument("action", choices=["get", "set"])
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--index", type=int)
    p.add_argument("--name")
    p.add_argument("--project-dir", default=".")
    p.add_argument("--value", default=None, help="typed value for set, decimal or 0x...")
    p = sub.add_parser("telemetry", help="read a telemetry word by index or generated name")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--index", type=int)
    p.add_argument("--name")
    p.add_argument("--project-dir", default=".")
    p = sub.add_parser("watch", help="poll payload_status heartbeat and report staleness")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--interval", type=float, default=1.0, help="seconds between polls (default 1.0)")
    p.add_argument("--count", type=int, default=0, help="stop after N polls (0 = until Ctrl+C)")
    p.add_argument("--safe-features", help="request this mask/name list once per stall episode")
    p.add_argument("--project-dir", default=".")
    p = sub.add_parser("profile", help="save/load a build-bound config profile with mirror confirmation")
    p.add_argument("action", choices=["save", "load"])
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--project-dir", default=".")
    p.add_argument("--features", help="save: mask/name override instead of reading active telemetry")

    p = sub.add_parser("export-offsets", help="project_export_offsets: annotations -> offsets.hpp + manifest")
    p.add_argument("--project", default=None)
    p.add_argument("--module-sha256", default=None)
    p.add_argument("--namespace", default=None)
    p.add_argument("--verify-bytes", type=int, default=None)
    p.add_argument("--archive", action="store_true", help="also write offsets/<sha>/ into the repo per-build store")

    p = sub.add_parser("update", help="game-aware update pipeline: dump -> SDK -> offsets/target -> build -> next steps")
    p.add_argument("--game", choices=["fortnite", "apex"], default=None,
                   help="named game; omitted = derive from workbench.json in --project-dir")
    p.add_argument("--project-dir", default=".",
                   help="game repository with workbench.json (default: cwd); supplies engine, repo, payload path")
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
        if (args.bits is None) == (args.names is None):
            raise WorkbenchError("Pass exactly one of --bits or --names")
        mask = parse_address(args.bits) if args.bits is not None else _feature_mask(load_rpc_descriptor(args.project_dir), args.names)
        require_integer(mask, "feature mask", 0, 2**32 - 1)
        result = _call(client, "payload_rpc", pid=require_integer(args.pid, "pid", 1, 2147483647),
                             command=RPC_FEATURES, argument=hex(mask), argument2="0x0")
        result["feature_mask"] = hex(mask)
    elif args.command == "config":
        pid = require_integer(args.pid, "pid", 1, 2147483647)
        field = _rpc_field(args, "config")
        index = field["index"]
        if args.action == "get":
            result = _call(client, "payload_rpc", pid=pid, command=RPC_READ_CONFIG,
                           argument=hex(index), argument2="0x0")
            result.update(name=field["name"], value=_decode_rpc(field, result["raw"]))
        else:
            if args.value is None:
                raise WorkbenchError("config set requires --value")
            encoded = _encode_rpc(field, args.value)
            result = _call(client, "payload_rpc", pid=pid, command=RPC_WRITE_CONFIG,
                           argument=hex(index), argument2=hex(encoded))
            result.update(name=field["name"], value=_decode_rpc(field, encoded))
    elif args.command == "telemetry":
        field = _rpc_field(args, "telemetry")
        result = _call(client, "payload_rpc", pid=require_integer(args.pid, "pid", 1, 2147483647),
                       command=RPC_READ_TELEMETRY, argument=hex(field["index"]), argument2="0x0")
        result.update(name=field["name"], value=_decode_rpc(field, result["raw"]))
    elif args.command == "profile":
        result = _profile_save(client, args) if args.action == "save" else _profile_load(client, args)
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
        if args.archive:
            arguments["archive"] = True
        result = _call(client, "project_export_offsets", **arguments)
    else:  # pragma: no cover - argparse enforces the choices
        raise WorkbenchError("unknown command")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


GAMES = {
    "fortnite": {"recipe": "unreal_pipeline", "repo": "../Fortnite-PS4", "payload": "payload.elf",
                 "engine": "unreal", "status_magic": "0x5053494e", "sdk": "openorbis"},
    "apex": {"recipe": "source_pipeline", "repo": "../Apex-PS4", "payload": "build/apex_payload.elf",
             "engine": "source", "status_magic": "0x41584553", "sdk": "payload"},
}

ENGINE_GAMES = {
    "unreal": {"recipe": "unreal_pipeline", "engine": "unreal", "status_magic": "0x5053494e", "sdk": "openorbis"},
    "source": {"recipe": "source_pipeline", "engine": "source", "status_magic": "0x41584553", "sdk": "payload"},
}


def load_descriptor(project_dir):
    """Read a game repo's workbench.json (ps4wb-scaffold-v1), or return None."""
    from pathlib import Path
    path = Path(project_dir) / "workbench.json"
    if not path.is_file():
        return None
    descriptor = json.loads(path.read_text())
    if not isinstance(descriptor, dict) or descriptor.get("format") != "ps4wb-scaffold-v1":
        raise WorkbenchError(f"{path}: unsupported descriptor format")
    return descriptor


def load_rpc_descriptor(project_dir):
    """Load generated RPC metadata without accepting paths outside the repo."""
    descriptor = load_descriptor(project_dir)
    if descriptor is None:
        raise WorkbenchError("Named RPC operations require a game workbench.json")
    root = Path(project_dir).resolve()
    path = (root / descriptor.get("generated_directory", "src/generated") / "rpc.json").resolve()
    if not path.is_relative_to(root):
        raise WorkbenchError("Generated RPC descriptor escapes the repository")
    try:
        result = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise WorkbenchError(f"Cannot read generated RPC descriptor: {error}") from error
    if result.get("format") != "ps4wb-rpc-v1":
        raise WorkbenchError("Unsupported generated RPC descriptor")
    return result


def _feature_mask(descriptor, value):
    """Parse a numeric mask or a comma-separated list of feature names."""
    try:
        return parse_address(value)
    except (ValueError, TypeError, WorkbenchError):
        pass
    features = {item.get("name"): require_integer(item.get("bit"), "feature bit", 0, 2**32 - 1)
                for item in descriptor.get("features", [])}
    mask = 0
    for name in str(value).split(","):
        name = name.strip()
        if not name or name == "safe":
            continue
        if name not in features:
            raise WorkbenchError(f"Unknown feature: {name}")
        mask |= features[name]
    return require_integer(mask, "feature mask", 0, 2**32 - 1)


def _rpc_field(args, group):
    name = getattr(args, "name", None)
    index = getattr(args, "index", None)
    if (name is None) == (index is None):
        raise WorkbenchError(f"Pass exactly one of --name or --index for {group}")
    if name is not None:
        descriptor = load_rpc_descriptor(args.project_dir)
        for field in descriptor.get(group, []):
            if field.get("name") == name:
                return field
        raise WorkbenchError(f"Unknown {group} field: {name}")
    return {"name": str(index), "index": require_integer(index, "index", 0, 31 if group == "config" else 15), "type": "u64"}


def _raw_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return parse_address(value)
    raise WorkbenchError("RPC result is not an integer")


def _decode_rpc(field, raw):
    raw = _raw_int(raw)
    kind = field.get("type", "u64")
    if kind == "bool":
        return bool(raw)
    if kind == "f32":
        return struct.unpack("<f", struct.pack("<I", raw & 0xffffffff))[0]
    if kind == "f64":
        return struct.unpack("<d", struct.pack("<Q", raw & 0xffffffffffffffff))[0]
    if kind == "i64":
        return raw - (1 << 64) if raw & (1 << 63) else raw
    return raw


def _encode_rpc(field, value):
    kind = field.get("type", "u64")
    if kind == "bool":
        if str(value).lower() in ("true", "1"):
            return 1
        if str(value).lower() in ("false", "0"):
            return 0
        raise WorkbenchError("Boolean RPC values must be true/false or 1/0")
    if kind == "f32":
        return struct.unpack("<I", struct.pack("<f", float(value)))[0]
    if kind == "f64":
        return struct.unpack("<Q", struct.pack("<d", float(value)))[0]
    parsed = int(str(value), 0)
    bits = 64
    minimum = -(1 << (bits - 1)) if kind == "i64" else 0
    maximum = (1 << (bits - 1)) - 1 if kind == "i64" else (1 << bits) - 1
    if not minimum <= parsed <= maximum:
        raise WorkbenchError(f"RPC value is outside {kind} range")
    return parsed & maximum


def _profile_hash(body):
    import hashlib
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _active_features(client, descriptor, pid):
    for field in descriptor.get("telemetry", []):
        if field.get("role") == "active_features":
            result = _call(client, "payload_rpc", pid=pid, command=RPC_READ_TELEMETRY,
                           argument=hex(field["index"]), argument2="0x0")
            return _raw_int(result["raw"])
    raise WorkbenchError("No active_features telemetry role; pass --features explicitly")


def _profile_save(client, args):
    from pathlib import Path
    descriptor = load_rpc_descriptor(args.project_dir)
    pid = require_integer(args.pid, "pid", 1, 2147483647)
    features = _feature_mask(descriptor, args.features) if args.features else _active_features(client, descriptor, pid)
    words = []
    for index in range(32):
        result = _call(client, "payload_rpc", pid=pid, command=RPC_READ_CONFIG,
                       argument=hex(index), argument2="0x0")
        words.append(hex(_raw_int(result["raw"])))
    body = {"format": "ps4wb-profile-v1", "module_sha256": descriptor.get("module_sha256"),
            "features": hex(features), "config": words}
    body["sha256"] = _profile_hash(body)
    path = Path(args.path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(body, indent=2, sort_keys=True))
    temporary.replace(path)
    return {"saved": str(path), "features": hex(features), "config_words": len(words),
            "module_sha256": body["module_sha256"], "sha256": body["sha256"]}


def _profile_load(client, args):
    import time
    from pathlib import Path
    descriptor = load_rpc_descriptor(args.project_dir)
    try:
        body = json.loads(Path(args.path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise WorkbenchError(f"Cannot read profile: {error}") from error
    if body.get("format") != "ps4wb-profile-v1" or not isinstance(body.get("config"), list) or len(body["config"]) > 32:
        raise WorkbenchError("Invalid profile format")
    if body.get("module_sha256") != descriptor.get("module_sha256"):
        raise WorkbenchError("Profile belongs to another module build")
    expected_hash = body.pop("sha256", None)
    if expected_hash != _profile_hash(body):
        raise WorkbenchError("Profile hash mismatch")
    pid = require_integer(args.pid, "pid", 1, 2147483647)
    features = _raw_int(body.get("features"))
    require_integer(features, "features", 0, 2**32 - 1)
    for index, word in enumerate(body["config"]):
        expected = _raw_int(word)
        require_integer(expected, "config word", 0, 2**64 - 1)
        _call(client, "payload_rpc", pid=pid, command=RPC_WRITE_CONFIG,
              argument=hex(index), argument2=hex(expected))
        deadline = time.monotonic() + 2.0
        while True:
            result = _call(client, "payload_rpc", pid=pid, command=RPC_READ_CONFIG,
                           argument=hex(index), argument2="0x0")
            if _raw_int(result["raw"]) == expected:
                break
            if time.monotonic() >= deadline:
                raise WorkbenchError(f"Config mirror timeout at index {index}; later writes were not sent")
            time.sleep(0.02)
    result = _call(client, "payload_rpc", pid=pid, command=RPC_FEATURES,
                   argument=hex(features), argument2="0x0")
    has_active_role = any(field.get("role") == "active_features" for field in descriptor.get("telemetry", []))
    # Legacy descriptors cannot confirm independently. A described readback that
    # fails is an error, never evidence that activation succeeded.
    active = _active_features(client, descriptor, pid) if has_active_role else features
    if active != features:
        raise WorkbenchError(f"Feature activation mismatch: requested {features:#x}, active {active:#x}")
    return {"loaded": args.path, "features": hex(features), "config_words": len(body["config"]),
            "mirror_confirmed": True, "result": result}


def _update(client, args):
    """Research, install generated inputs, build fresh ELF, preserve evidence."""
    from pathlib import Path
    import shlex
    import os
    from .build import build

    descriptor = load_descriptor(args.project_dir)
    if args.game:
        game = dict(GAMES[args.game])
        repo = Path(args.payload_repo or game["repo"]).resolve()
        default_payload = game["payload"]
        namespace_default = args.game
    elif descriptor and descriptor.get("engine") in ENGINE_GAMES:
        game = dict(ENGINE_GAMES[descriptor["engine"]])
        repo = Path(args.payload_repo or args.project_dir).resolve()
        default_payload = descriptor.get("payload", "payload.elf")
        namespace_default = "".join(c if c.isalnum() else "_" for c in repo.name.lower()).strip("_") or "game"
    else:
        raise WorkbenchError("Pass --game, or run with --project-dir pointing at a repo whose workbench.json declares engine unreal/source")
    engine = game["engine"]
    inputs = {"pid": args.pid, "namespace": args.namespace or namespace_default,
              "status_magic": game.get("status_magic", "0x5053494e")}
    for key in ("module", "module_sha256", "image_base", "signature_sites"):
        value = getattr(args, key)
        if value is not None:
            inputs[key] = value
    if bool(args.old_artifact) != bool(args.annotations):
        raise WorkbenchError("Pass --old-artifact and --annotations together")
    recipe = game["recipe"]
    plan = {"game": args.game or engine, "engine": engine, "pipeline_recipe": recipe, "inputs": inputs,
            "payload_repo": str(repo), "build_cmd": None if args.no_build else args.build_cmd}
    if args.old_artifact:
        inputs.update(old_artifact=args.old_artifact, annotations=args.annotations)
        recipe = engine + "_update"
        plan["update_recipe"] = "offset_refresh"
        plan["update_inputs"] = dict(inputs)
    if args.dry_run:
        return dict(plan, dry_run=True)

    # Rust owns research, project registration and installation. The CLI only
    # adds the local build/evidence steps, keeping both entry points identical.
    inputs.update(repository=str(repo), engine=engine, sdk=game.get("sdk", "payload"), staging="immediate")
    if args.app_version:
        inputs["app_version"] = args.app_version
    if args.session_id:
        inputs["session"] = args.session_id
    update = _call(client, "game_update", **inputs)
    session_id = update["session"]
    installed = update.get("installed")
    target_path = update["target"]
    if args.no_build:
        return {"session": session_id, "update": update, "installed": installed, "build": None, "deployed": False}
    try:
        argv = json.loads(args.build_argv) if args.build_argv else shlex.split(args.build_cmd, posix=os.name != "nt")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise WorkbenchError(f"Invalid build command: {error}") from error
    if not isinstance(argv, list) or not argv or not all(isinstance(part, str) for part in argv):
        raise WorkbenchError("build-argv must be a non-empty JSON string array")
    argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a for a in argv]
    evidence = build(repo, argv, args.payload or default_payload)
    collected = _call(client, "project_collect_build")
    payload_file = Path(evidence["payload"]["path"])
    sha = evidence["payload"]["sha256"]
    return {"session": session_id, "update": update, "installed": installed, "build": evidence,
            "payload": {"path": str(payload_file), "sha256": sha}, "collected": collected, "deployed": False,
            "next": {"ingest": ["ps4-workbench", "ingest", str(payload_file)], "target": target_path,
                     "payload_sha256": sha, "action": "qualify the exact tested output before staging"}}


def _watch(client, args):
    import time

    pid = require_integer(args.pid, "pid", 1, 2147483647)
    interval = max(0.05, args.interval)
    safe_mask = _feature_mask(load_rpc_descriptor(args.project_dir), args.safe_features) if args.safe_features is not None else None
    previous = None
    stale = 0
    polls = 0
    safe_sent = False
    while True:
        # WorkbenchError propagates: inspect the console, then payload_recover
        # or a manual re-stage; never an automatic retry.
        status = _call(client, "payload_status", pid=pid)
        heartbeat = status.get("heartbeat")
        if previous is not None and heartbeat == previous:
            stale += 1
        else:
            stale = 0
            safe_sent = False
        previous = heartbeat
        polls += 1
        print(json.dumps(dict(status, poll=polls, stale_polls=stale), sort_keys=True), flush=True)
        if stale >= 3:
            print(json.dumps({
                "warning": "heartbeat unchanged for 3 polls; payload may be stalled. "
                           "Inspect the console, then payload_recover or a manual re-stage."
            }, sort_keys=True), flush=True)
            if safe_mask is not None and not safe_sent:
                _call(client, "payload_rpc", pid=pid, command=RPC_FEATURES,
                      argument=hex(safe_mask), argument2="0x0")
                safe_sent = True
                print(json.dumps({"safe_features_requested": hex(safe_mask)}), flush=True)
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
