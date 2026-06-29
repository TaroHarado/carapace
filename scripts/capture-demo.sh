#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/release/cape}"
PORT="${2:-8484}"
OUTDIR="${3:-$ROOT/captures}"

mkdir -p "$OUTDIR"

BROWSER="${CHROME_BIN:-}"
if [[ -z "$BROWSER" ]]; then
  for candidate in \
    /usr/bin/google-chrome \
    /usr/bin/chromium \
    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome; do
    if [[ -x "$candidate" ]]; then
      BROWSER="$candidate"
      break
    fi
  done
fi

if [[ -z "$BROWSER" ]]; then
  echo "No headless Chrome/Chromium found. Set CHROME_BIN." >&2
  exit 1
fi

cleanup() {
  if [[ -n "${WEB_PID:-}" ]]; then
    kill "$WEB_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"$BIN" web --listen "127.0.0.1:${PORT}" --site "$ROOT/site" >/tmp/saferouter-capture.out.log 2>/tmp/saferouter-capture.err.log &
WEB_PID=$!

for _ in {1..50}; do
  if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null; then
    break
  fi
  sleep 0.2
done

"$BROWSER" --headless=new --disable-gpu --window-size=1440,1100 --screenshot="$OUTDIR/saferouter-1440.png" "http://127.0.0.1:${PORT}" >/dev/null
"$BROWSER" --headless=new --disable-gpu --window-size=390,1200 --screenshot="$OUTDIR/saferouter-390.png" "http://127.0.0.1:${PORT}" >/dev/null

echo "wrote $OUTDIR/saferouter-1440.png"
echo "wrote $OUTDIR/saferouter-390.png"
