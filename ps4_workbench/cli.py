import argparse
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

from .artifacts import utc_now
from .config import Profile, WorkbenchError, require_hash
from .mcp import MCPServer
from .tools import ToolRegistry
from .workbench import Workbench


def write_qualification(profile, arguments):
    if arguments.attest != "I_TESTED_THIS_EXACT_CONFIGURATION":
        raise WorkbenchError("Qualification requires your explicit hardware-test attestation; it is not a guarantee")
    if not profile.data["jailbreak"].get("installed_commit") or not profile.data["jailbreak"].get("hen_build"):
        raise WorkbenchError("Record actual installed_commit and hen_build before qualification")
    if not arguments.approve or any(not profile.data["permissions"].get(name) for name in arguments.approve):
        raise WorkbenchError("Approve only named permissions already explicitly enabled in the local profile")
    if any(name in arguments.approve for name in ("process_write", "debug_control", "kernel_read", "kernel_write")):
        if not profile.data["debugger"].get("expected_brand") or not profile.data["debugger"].get("payload_sha256"):
            raise WorkbenchError("Pin the actual debugger brand and binary hash before qualification")
    for digest in arguments.payload_sha256 + arguments.build_recipe_sha256:
        require_hash(digest)
    if "payload_execute" in arguments.approve and not arguments.payload_sha256:
        raise WorkbenchError("Payload execution needs at least one tested artifact hash")
    if "build" in arguments.approve and not arguments.build_recipe_sha256:
        raise WorkbenchError("Build permission needs at least one reviewed recipe hash")
    target = profile.qualification_path
    if target.exists() and not arguments.replace:
        raise WorkbenchError("Qualification exists; use --replace only after requalification")
    evidence = Path(arguments.evidence).resolve()
    with evidence.open("rb") as stream:
        content = stream.read(profile.limit("transfer_bytes") + 1)
    if not content or len(content) > profile.limit("transfer_bytes"):
        raise WorkbenchError("Evidence file is empty or exceeds transfer limit")
    workbench = Workbench(profile)
    saved = workbench.store.save("qualification-evidence", content, {"original_name": evidence.name})
    record = {"recorded_at": utc_now(), "profile_sha256": profile.fingerprint, "attestation": arguments.attest,
              "approved_permissions": sorted(set(arguments.approve)), "evidence": saved,
              "debugger_payload_sha256": profile.data["debugger"].get("payload_sha256"),
              "payload_sha256_allowlist": sorted(set(arguments.payload_sha256)),
              "build_recipe_sha256_allowlist": sorted(set(arguments.build_recipe_sha256)),
              "hardware_compatibility_guaranteed": False}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    workbench.store.audit("local_qualification_recorded", qualification=record)
    return {"qualification_file": str(target), "record": record, "warning": "User attestation, not automated hardware certification"}


def parser():
    result = argparse.ArgumentParser(description="Local PS4 14.00 / Afterglow research workbench. No compatibility guarantee.")
    result.add_argument("--profile", default="profiles/ps4-1400.json")
    commands = result.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Local stdio MCP, optionally connected to a shared broker")
    serve.add_argument("--broker", help="Shared broker URL, e.g. http://127.0.0.1:8765")
    serve.add_argument("--token-file")
    serve.add_argument("--client-id")
    broker = commands.add_parser("broker", help="Authenticated loopback shared session service; no console connection on startup")
    broker.add_argument("--port", type=int, default=8765)
    broker.add_argument("--token-file")
    remote = commands.add_parser("remote-call", help="Call a tool through the already-running shared broker")
    remote.add_argument("tool")
    remote.add_argument("--broker", default="http://127.0.0.1:8765")
    remote.add_argument("--token-file")
    remote.add_argument("--client-id", default="cli")
    remote_inputs = remote.add_mutually_exclusive_group()
    remote_inputs.add_argument("--arguments", default="{}")
    remote_inputs.add_argument("--arguments-file")
    gdb = commands.add_parser("gdb-server", help="Loopback x86-64 GDB Remote bridge for IDA/Ghidra; attaches on debugger request")
    gdb.add_argument("--broker", default="http://127.0.0.1:8765")
    gdb.add_argument("--token-file")
    gdb.add_argument("--port", type=int, default=1234)
    gdb.add_argument("--pid", type=int, required=True)
    gdb.add_argument("--listen-address", required=True, help="PC IPv4 reachable from console callback on 755")
    gdb.add_argument("--observer", action="store_true", help="Observe an already attached session; deny controls")
    gdb.add_argument("--allow-writes", action="store_true", help="Allow audited RSP memory/register writes (M/P/G)")
    commands.add_parser("tools", help="List tools allowed by the local profile; no network")
    commands.add_parser("validate", help="Validate local profile and show configured services; no network")
    call = commands.add_parser("call", help="Invoke a tool once; debug session auto-detaches at exit")
    call.add_argument("tool")
    inputs = call.add_mutually_exclusive_group()
    inputs.add_argument("--arguments", default="{}", help="JSON tool arguments")
    inputs.add_argument("--arguments-file", help="Local UTF-8 JSON file (easier on Windows)")
    ingest = commands.add_parser("ingest", help="Import an explicitly chosen local file into artifact storage; no network")
    ingest.add_argument("file")
    digest = commands.add_parser("hash", help="SHA-256 of an explicitly chosen local file")
    digest.add_argument("file")
    qualify = commands.add_parser("qualify", help="LOCAL ONLY: record your hardware-test evidence and approvals, never an MCP tool")
    qualify.add_argument("--evidence", required=True)
    qualify.add_argument("--attest", required=True)
    qualify.add_argument("--approve", action="append", default=[])
    qualify.add_argument("--payload-sha256", action="append", default=[])
    qualify.add_argument("--build-recipe-sha256", action="append", default=[])
    qualify.add_argument("--replace", action="store_true")
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    workbench = None
    try:
        profile = Profile.load(arguments.profile)
        if arguments.command in ("broker", "gdb-server", "remote-call") or (arguments.command == "serve" and arguments.broker):
            from .broker import BrokerServer, SessionHub, load_token, token_file
            from .client import BrokerClient, RemoteRegistry
            secret_path = Path(arguments.token_file).resolve() if arguments.token_file else token_file(profile)
            if secret_path.is_relative_to(profile.artifact_root):
                raise WorkbenchError("Broker token must stay outside MCP-readable artifact storage")
            if arguments.command == "broker":
                token = load_token(secret_path, create=True)
                workbench = Workbench(profile)
                hub = SessionHub(ToolRegistry(workbench))
                with BrokerServer(hub, token, arguments.port) as server:
                    print(f"Broker: http://127.0.0.1:{server.server_port}; token file: {secret_path}", file=sys.stderr)
                    hub.start()
                    try:
                        server.serve_forever(poll_interval=0.1)
                    finally:
                        hub.close()
                return 0
            if arguments.command == "gdb-server":
                from .rsp import RspServer
                BrokerClient(arguments.broker, secret_path, expected_profile=profile.fingerprint)
                with RspServer(arguments.broker, secret_path, arguments.pid, arguments.listen_address,
                               arguments.port, arguments.observer, profile.fingerprint,
                               allow_writes=arguments.allow_writes) as server:
                    print(f"GDB Remote: 127.0.0.1:{server.server_address[1]}; PID {arguments.pid}; observer={arguments.observer}; allow_writes={arguments.allow_writes}", file=sys.stderr)
                    server.serve_forever(poll_interval=0.1)
                return 0
            client = BrokerClient(arguments.broker, secret_path, arguments.client_id, expected_profile=profile.fingerprint)
            if arguments.command == "serve":
                MCPServer(RemoteRegistry(client)).serve()
                return 0
            content = Path(arguments.arguments_file).read_text(encoding="utf-8-sig") if arguments.arguments_file else arguments.arguments
            result = RemoteRegistry(client).call(arguments.tool, json.loads(content))
        elif arguments.command == "hash":
            with Path(arguments.file).open("rb") as stream:
                result = {"sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
        elif arguments.command == "qualify":
            result = write_qualification(profile, arguments)
        else:
            workbench = Workbench(profile)
            registry = ToolRegistry(workbench)
            if arguments.command == "serve":
                MCPServer(registry).serve()
                return 0
            if arguments.command == "tools":
                result = [tool.describe() for tool in registry.available()]
            elif arguments.command == "validate":
                result = workbench.console.status()
            elif arguments.command == "ingest":
                with Path(arguments.file).open("rb") as stream:
                    content = stream.read(profile.limit("transfer_bytes") + 1)
                if len(content) > profile.limit("transfer_bytes"):
                    raise WorkbenchError("Input file exceeds transfer limit")
                result = workbench.store.save("import", content, {"original_name": Path(arguments.file).name})
            else:
                content = Path(arguments.arguments_file).read_text(encoding="utf-8-sig") if arguments.arguments_file else arguments.arguments
                result = registry.call(arguments.tool, json.loads(content))
        print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
        return 0
    except KeyboardInterrupt:
        return 0
    except (WorkbenchError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if workbench is not None:
            workbench.close()
