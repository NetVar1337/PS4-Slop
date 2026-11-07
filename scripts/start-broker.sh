#!/bin/sh
# start-broker.sh — start the shared broker for the control plane
# (ps4_workbench/ctl.py, IDA/Ghidra adapters, LIVE_WORKFLOW.md).
# The debug/full toolsets expose mutating tools only when the local profile
# permissions and qualification record allow them.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="${PS4WB_PROFILE:-profiles/ps4-1400.local.json}"
TOOLSET="${PS4WB_TOOLSET:-full}"
PORT="${PS4WB_PORT:-24600}"
TOKEN="${PS4WB_TOKEN:-profiles/broker-token.local}"
BIN="target/release/ps4-workbench"
[ -x "$BIN" ] || BIN="target/debug/ps4-workbench"
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }
echo "[start-broker] profile=$PROFILE toolset=$TOOLSET port=$PORT token=$TOKEN"
exec "$BIN" --profile "$PROFILE" --toolset "$TOOLSET" broker --port "$PORT" --token-file "$TOKEN"
