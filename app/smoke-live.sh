#!/bin/sh
set -eu
cd "$(dirname "$0")"

if [ -x .build/out/Products/Debug/ClipVaultApp ]; then
    app_bin="$PWD/.build/out/Products/Debug/ClipVaultApp"
elif [ -x .build/debug/ClipVaultApp ]; then
    app_bin="$PWD/.build/debug/ClipVaultApp"
else
    echo "ClipVaultApp binary not found; run swift build first." >&2
    exit 1
fi
if [ -x .build/out/Products/Debug/clipctl ]; then
    cli_bin="$PWD/.build/out/Products/Debug/clipctl"
elif [ -x .build/debug/clipctl ]; then
    cli_bin="$PWD/.build/debug/clipctl"
else
    echo "clipctl binary not found; run swift build first." >&2
    exit 1
fi
command -v pbcopy >/dev/null && command -v pbpaste >/dev/null || {
    echo "This smoke test requires macOS pbcopy and pbpaste." >&2
    exit 1
}

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/clipvault-smoke.XXXXXX")
socket_path="$work_dir/clipvault.sock"
marker="clipvault-smoke-$(python3 -c 'import uuid; print(uuid.uuid4())')"
reference_file="$work_dir/reference"

cleanup() {
    if [ "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

CLIPVAULT_TEST_MODE=1 CLIPVAULT_TEST_REFERENCE_FILE="$reference_file" CLIPVAULT_SOCKET="$socket_path" "$app_bin" --serve >"$work_dir/server.log" 2>&1 &
server_pid=$!

reference=""
server_ready=0
i=0
while [ "$i" -lt 30 ]; do
    i=$((i + 1))
    if CLIPVAULT_SOCKET="$socket_path" "$cli_bin" list >"$work_dir/list.json" 2>/dev/null; then
        server_ready=1
        break
    fi
    sleep 1
done
if [ "$server_ready" -eq 0 ]; then
    echo "ClipVaultApp --serve did not create a reachable CLIPVAULT_SOCKET listener." >&2
    if [ -f "$work_dir/server.log" ]; then cat "$work_dir/server.log" >&2; fi
    exit 1
fi

# Wait until the monitor has taken its initial changeCount snapshot before seeding.
printf %s "$marker" | pbcopy
sleep 2

i=0
while [ "$i" -lt 30 ]; do
    i=$((i + 1))
    if CLIPVAULT_SOCKET="$socket_path" "$cli_bin" list >"$work_dir/list.json" 2>/dev/null; then
        if reference=$(python3 - "$work_dir/list.json" "$marker" "$reference_file" <<'PY'
import json, os, re, sys
items = json.load(open(sys.argv[1], encoding="utf-8"))
marker = sys.argv[2]
if any(marker in json.dumps(item) for item in items):
    print("clipctl list exposed clipboard content", file=sys.stderr)
    sys.exit(10)
matches = [item for item in items if item.get("size") == len(marker.encode()) and item.get("type") == "public.utf8-plain-text"]
if not matches or not os.path.isfile(sys.argv[3]):
    sys.exit(2)
expected_reference = open(sys.argv[3], encoding="utf-8").read().strip()
if not re.fullmatch(r"clip://[0-9a-fA-F-]{36}", expected_reference):
    sys.exit(3)
matched = [item for item in matches if item.get("reference") == expected_reference]
if not matched:
    print("list reference did not match the captured item", file=sys.stderr)
    sys.exit(10)
print(matched[-1]["reference"])
PY
        ); then
            break
        else
            status=$?
            if [ "$status" -eq 10 ]; then exit 1; fi
        fi
    fi
    sleep 1
done

if [ -z "$reference" ]; then
    if [ "$server_ready" -eq 0 ]; then
        echo "ClipVaultApp --serve did not create a reachable CLIPVAULT_SOCKET listener." >&2
    else
        echo "Socket server responded, but the synthetic pasteboard item was not captured into the local vault." >&2
    fi
    if [ -f "$work_dir/server.log" ]; then cat "$work_dir/server.log" >&2; fi
    exit 1
fi

CLIPVAULT_SOCKET="$socket_path" "$cli_bin" copy "$reference"
actual=$(pbpaste)
if [ "$actual" != "$marker" ]; then
    echo "pasteboard content did not match the synthetic item after copy." >&2
    exit 1
fi
printf 'Live smoke passed: list returned metadata only; copy %s restored the synthetic pasteboard value.\n' "$reference"
