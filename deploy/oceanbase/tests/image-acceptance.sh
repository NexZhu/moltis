#!/usr/bin/env bash
set -euo pipefail
: "${OCEANBASE_IMAGE_DIGEST:?Validated image digest required}"
: "${EXPECTED_ARCH:?Native runner architecture required}"
case "$(uname -m):$EXPECTED_ARCH" in x86_64:amd64|aarch64:arm64|arm64:arm64) ;; *) echo 'Native acceptance runner architecture mismatch' >&2; exit 1;; esac
args=(--source-commit "$OCEANBASE_SOURCE_COMMIT" --build-workflow-run-id "$OCEANBASE_BUILD_WORKFLOW_RUN_ID" --build-artifact-id "$OCEANBASE_BUILD_ARTIFACT_ID" --manifest-sha256 "$OCEANBASE_MANIFEST_SHA256" --artifact-dir "$MOLTIS_U1_PROOF_DIR")
test "$(bash deploy/oceanbase/verify-image.sh "${args[@]}")" = "$OCEANBASE_IMAGE_DIGEST"
work=$(mktemp -d)
# The temporary parent must be trusted root-owned, not runner-writable, for no-follow trust traversal.
sudo chown root:root "$work"
sudo chmod 755 "$work"
name="moltis-u1-$EXPECTED_ARCH-${GITHUB_RUN_ID:-local}-$$"
cleanup() { if [ -f "$work/tls-output/cleanup.json" ]; then sudo python3 deploy/oceanbase/tests/tls-lifecycle.py --cleanup --output "$work/tls-output"; fi; docker rm -f "$name" >/dev/null 2>&1 || true; sudo rm -rf "$work"; }
trap cleanup EXIT
empty="$name-empty"
docker create --name "$empty" "$OCEANBASE_IMAGE_DIGEST" >/dev/null
docker start "$empty" >/dev/null
test "$(docker wait "$empty")" != 0
docker rm "$empty" >/dev/null
sudo python3 deploy/oceanbase/init-material.py --directory "$work/material" --runtime-uid 0
# True material-negative cases run before SQL: broad key, wrong owner, symlink CA, wrong fingerprint.
for mode in broad-key wrong-owner symlink-ca wrong-fingerprint wrong-san expired; do
  sudo cp -a "$work/material" "$work/$mode"
  case "$mode" in
    broad-key) sudo chmod 644 "$work/$mode/server-private/server-key.pem";;
    wrong-owner) sudo chown 0:0 "$work/$mode/server-private/server-key.pem";;
    symlink-ca) sudo mv "$work/$mode/public-trust/ca.pem" "$work/$mode/public-trust/other.pem"; sudo ln -s other.pem "$work/$mode/public-trust/ca.pem";;
    wrong-fingerprint) sudo sh -c 'printf "{\"approved_ca_sha256\":[\"invalid\"]}" > "$1"' sh "$work/$mode/public-trust/tls-manifest.json";;
    wrong-san|expired) sudo python3 deploy/oceanbase/test-certificate.py "$work/$mode" "$mode";;
  esac
  id=$(docker create --mount "type=bind,src=$work/$mode/root-init,dst=/run/root-init,readonly" --mount "type=bind,src=$work/$mode/server-private,dst=/run/server-private,readonly" --mount "type=bind,src=$work/$mode/public-trust,dst=/run/public-trust,readonly" "$OCEANBASE_IMAGE_DIGEST")
  docker start "$id" >/dev/null
  test "$(docker wait "$id")" != 0
  case "$mode" in
    broad-key|wrong-owner) expected='material must be regular, correctly owned and exact mode';;
    symlink-ca) expected='too many levels of symbolic links';;
    wrong-fingerprint) expected='ca differs from approved init/rotation manifest';;
    wrong-san) expected='hostname mismatch';;
    expired) expected='certificate has expired';;
  esac
  docker logs "$id" 2>&1 | tr '[:upper:]' '[:lower:]' | grep -Fq "$expected"
  docker rm "$id" >/dev/null
done
docker run -d --name "$name" --memory 6g --cpus 4 --mount "type=bind,src=$work/material/root-init,dst=/run/root-init" --mount "type=bind,src=$work/material/root-recovery,dst=/run/root-recovery,readonly" --mount "type=bind,src=$work/material/server-private,dst=/run/server-private,readonly" --mount "type=bind,src=$work/material/public-trust,dst=/run/public-trust,readonly" --mount "type=bind,src=$work/material/platform,dst=/run/platform" --tmpfs /run --publish 127.0.0.1:2881:2881 "$OCEANBASE_IMAGE_DIGEST" >/dev/null
for attempt in {1..180}; do
  state=$(docker inspect --format '{{.State.Health.Status}}' "$name")
  if [ "$state" = healthy ]; then break; fi
  test "$(docker inspect --format '{{.State.Running}}' "$name")" = true
  sleep 2
done
test "$state" = healthy
test "$(docker exec "$name" uname -m)" = "$(uname -m)"
# Parent-authored bounded native script supplies actual logging/grants/host/cap/rotation evidence.
test -f deploy/oceanbase/tests/runtime-boundaries.py
docker exec -e OB_APPROVED_SQL_HOST=127.0.0.1 "$name" python3 /opt/moltis-oceanbase/platform-init.py --prefix moltis --sql-host '%' --wildcard-isolated-network --root-sql-host '%' --host-max-bytes 128 --runtime-uid 0
docker exec "$name" mkdir -p /opt/moltis-oceanbase/tests
docker cp deploy/oceanbase/tests/runtime-boundaries.py "$name:/opt/moltis-oceanbase/tests/runtime-boundaries.py"
docker exec -e MOLTIS_U1_ISOLATED=1 -e OB_APPROVED_SQL_HOST=127.0.0.1 "$name" python3 /opt/moltis-oceanbase/tests/runtime-boundaries.py --tenant moltis --account-host '%' --host-max-bytes 128 --root-secret-file /run/root-recovery/root-recovery.secret --host 127.0.0.1 --image-digest "$OCEANBASE_IMAGE_DIGEST" --approved-sql-host 127.0.0.1
sudo mkdir "$work/client"
sudo chown "$(id -u):$(id -g)" "$work/client"
sudo mkdir -m 700 "$work/tls-material"
sudo python3 deploy/oceanbase/tests/tls-lifecycle.py --image "$OCEANBASE_IMAGE_DIGEST" --directory "$work/tls-material" --runtime-uid 10001 --output "$work/tls-output"
# The next setup command produces actual metadata and scoped lifecycle credentials.
python3 deploy/oceanbase/ci-setup.py --container "$name" --directory "$work/client" --proof-dir "$MOLTIS_U1_PROOF_DIR" --tls-handshake-manifest "$work/tls-output/tls-handshakes.json"
MOLTIS_U1_CONFIG="$work/client/u1-config.json" MOLTIS_U1_ISOLATED=1 cargo test -p moltis-storage --test validation -- --nocapture
