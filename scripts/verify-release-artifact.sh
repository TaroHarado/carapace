#!/usr/bin/env bash
set -euo pipefail

REPO="${1:-TaroHarado/carapace}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${TMPDIR:-/tmp}/carapace-release-smoke"

rm -rf "$WORK"
mkdir -p "$WORK"

API="https://api.github.com/repos/$REPO/releases/latest"
ASSET_URL=$(curl -fsSL "$API" | python - <<'PY'
import json,sys
data=json.load(sys.stdin)
for a in data.get('assets', []):
    name=a.get('name','')
    if name.endswith('x86_64-unknown-linux-gnu.tar.gz'):
        print(a['browser_download_url'])
        raise SystemExit(0)
raise SystemExit('asset not found')
PY
)

ARCHIVE="$WORK/cape-linux.tar.gz"
curl -fsSL "$ASSET_URL" -o "$ARCHIVE"
tar xzf "$ARCHIVE" -C "$WORK"

BIN="$WORK/cape"
if [[ ! -x "$BIN" ]]; then
  echo "Extracted archive does not contain executable cape" >&2
  exit 1
fi

echo "downloaded $(basename "$ASSET_URL")"
"$ROOT/scripts/smoke-release.sh" "$BIN"
"$ROOT/scripts/smoke-local.sh" "$BIN" 8592 "$ROOT/captures"
