#!/bin/sh
# qualify-local.sh — run the offline checks first, then hand over to the real
# `qualify` CLI with the remaining arguments (evidence, attestation, approvals).
# Example:
#   scripts/qualify-local.sh --profile profiles/ps4-1400.local.json \
#     --evidence C:/research/my-hardware-tests.md \
#     --attest I_TESTED_THIS_EXACT_CONFIGURATION --approve debug_control \
#     --afterglow-directory C:/research/afterglow-web
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROFILE="profiles/ps4-1400.local.json"
for last do :; done
ARGS=("$@")
if [ ! -f "$PROFILE" ]; then
    echo "[qualify-local] $PROFILE missing; run scripts/setup-profile.sh first" >&2
    exit 1
fi

echo "[qualify-local] 1/4 cargo test (offline fixture + unit tests)"
cargo test --locked -j 2
echo "[qualify-local] 2/4 python adapter/ctl tests against the real broker"
python -m unittest discover -q || python3 -m unittest discover -q
echo "[qualify-local] 3/4 ps4-mcp validate"
BIN="target/debug/ps4-mcp"
[ -x "$BIN" ] || BIN="target/release/ps4-mcp"
[ -x "$BIN" ] || { echo "build ps4-mcp first: cargo build --locked" >&2; exit 1; }
"$BIN" --profile "$PROFILE" validate

echo "[qualify-local] 4/4 qualify CLI (no console contact; records your attestation)"
exec "$BIN" --profile "$PROFILE" qualify "$@"
