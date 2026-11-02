#!/bin/bash
# Run on your laptop from this repo. Rebuilds proxy-a at the current HEAD.
# Requires that HEAD is already on origin (git push).
set -euo pipefail

HOST="${PROXY_A_SSH:-ubuntu@52.74.112.181}"
HERE=$(cd "$(dirname "$0")" && pwd)
SHA=$(git -C "$HERE/.." rev-parse HEAD)

echo "rebuild $SHA on $HOST"
scp -o BatchMode=yes "$HERE/install-proxy-a.sh" "$HOST:/tmp/ah-install.sh"
ssh -o BatchMode=yes "$HOST" "INSTALL_SHA=$SHA bash /tmp/ah-install.sh"
echo "healthz:"
curl -sfS https://artifacts.noomz.space/healthz
echo
