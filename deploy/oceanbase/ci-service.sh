#!/usr/bin/env bash
set -euo pipefail
# Only workflow-local, already verified digest services select this entrypoint.
# No embedded/test password and no production root-empty bypass.
python3 /opt/moltis-oceanbase/init-material.py --directory /run/ci-material --runtime-uid 0
mkdir -p /run/root-init /run/root-recovery /run/server-private /run/public-trust /run/platform
cp -a /run/ci-material/root-init/. /run/root-init/
cp -a /run/ci-material/root-recovery/. /run/root-recovery/
cp -a /run/ci-material/server-private/. /run/server-private/
cp -a /run/ci-material/public-trust/. /run/public-trust/
cp -a /run/ci-material/platform/. /run/platform/
exec python3 /opt/moltis-oceanbase/entry.py
