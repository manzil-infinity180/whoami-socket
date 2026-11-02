#!/usr/bin/env bash
# Runs the three scenes of the video in order. Linux or macOS.
set -euo pipefail
cd "$(dirname "$0")/.."
go build -o whoami .
SOCK=/tmp/whoami.sock
cleanup() { pkill -f "whoami serve" 2>/dev/null || true; rm -rf "$SOCK" /tmp/whoami-fake; }
trap cleanup EXIT

pause() { echo; read -r -p "── press enter: $1 ──" _; echo; }

pause "scene 1: asking around"
mkdir -p /tmp/whoami-fake && cp /bin/ls /tmp/whoami-fake/claude
PATH=/tmp/whoami-fake:$PATH bash -c 'exec -a claude bash -c "./whoami guess; true"'

pause "scene 2: asking the kernel"
./whoami serve --unix "$SOCK" & sleep 1
./whoami dial --unix "$SOCK"
bash -c "exec -a claude ./whoami dial --unix $SOCK"
sleep 0.5; pkill -f "whoami serve --unix"

pause "scene 3: the TCP trap"
./whoami serve --tcp 127.0.0.1:9999 & sleep 1
./whoami dial --tcp 127.0.0.1:9999 || true
