# OceanBase U1 image and deployment gate

This directory implements the pinned-image U1 deployment inputs. It does **not** record a passed U1, an approved behavioral manifest, or permission to start U2. Image publication and the complete two-native-architecture acceptance must actually succeed before release. Local diagnostics of a different/unsigned image are not substitutes.

## Immutable inputs

`image-inputs.json` locks CE `v5.0.1_CE`, release source `071f4d9c82841d3ecb2d0004ef9213766308b714`, standard (not nonlse) server/libs `5.0.1.0-100000042026072912.el8`, both architecture RPM SHA256s, base image, upstream Docker script blobs, CPython 3.12.11+20251007, BuildKit, SBOM scanner and build-time binfmt digests. RPMs come only from the [GitHub release](https://github.com/oceanbase/oceanbase/releases/tag/v5.0.1_CE); a mirror with the same filename but different bytes is rejected. The [pinned upstream Docker scripts](https://github.com/oceanbase/docker-images/tree/1752971608da31981d349f47d14fe82e27d95399/oceanbase-ce) are archived with checked Git blob hashes, **not executed**: their native SQL initialization is plaintext. The immutable upstream base supplies obclient/OpenSSL/runtime libraries, not the selected observer; both fixed RPMs replace it, and `observer -V` must contain the complete selected build/source before build completes and at startup.

`parser-inputs.json` freezes default (`space`) → `ngram` → `ik`, all builtin to those RPMs, with no external install/plugin/dictionary/host override. [Fixed registration source](https://github.com/oceanbase/oceanbase/blob/071f4d9c82841d3ecb2d0004ef9213766308b714/src/storage/fts/ob_fts_builtin_parser_register.cpp) explicitly registers them. IK's dictionary is the fixed package builtin input. Connector candidates use `native_boolean`; memory/code candidates use `sql_hybrid_bool_rrf60` (typed boolean must/must_not, explicit rank constant 60). Actual preflight and all positive/negative fixtures decide the first all-passing combination on both architectures. **No per-table tuple is selected yet.** No install/rebuild-after-selection is permitted.

## Publication prerequisites and approval

An authorized operator must first choose the actual GH repository, GHCR namespace, protected branch/ref and reviewed source commit. Nothing defaults to upstream, a fork, PR HEAD, latest, or a fabricated run. Configure these repository/environment variables:

- `OCEANBASE_TRUSTED_REPOSITORY`: exact permitted `owner/repo`.
- `OCEANBASE_TRUSTED_REF`: exact protected `refs/heads/...` branch.
- `OCEANBASE_IMAGE_REPOSITORY`: exact lower-case `ghcr.io/owner/name`.
- `OCEANBASE_APPROVED_VERIFIER_COMMIT`: full reviewed 40-hex commit containing the shared verifier (CI/E2E verify this checkout, not PR-provided code).

Create protected GitHub environments `oceanbase-image-release` and `oceanbase-image-consumer`, with trusted reviewer approval and appropriate branch restrictions. Enable Actions/GHCR write, OIDC keyless signing/Fulcio/Rekor access and the real `ubuntu-22.04`/`ubuntu-24.04-arm` runners. Install Docker/buildx, gh, cosign 2.4.1, OpenSSL and Python ≥3.9 on local verifier hosts. The image carries independently hash-pinned Python 3.12. No local fake signing keys or unsigned approval mode exist.

An authorized maintainer starts `.github/workflows/oceanbase-image.yml` on the protected reviewed ref. The same run executes `build-sign` → no-database `image-verify` → native matrix `image-acceptance`. Publication includes actual BuildKit provenance/SPDX SBOM for both architectures, source/run-bound cosign attestations, image signature and the existing `sign-artifacts` keyless manifest mechanism plus transparency bundle. Build publication intentionally precedes runtime acceptance; publication alone does not approve use or U1.

The operator approves all four immutable handoff fields: source_commit, build_workflow_run_id, build_artifact_id and manifest_sha256. CI/E2E resolve them in the protected consumer environment and forward that exact quartet plus trust identities through image-verify outputs; dependent jobs do not resolve a different environment/repository value. The verifier admits an in-progress publication only inside its exact originating Actions run/workflow/repository/ref/commit; external consumers require the completed successful run, including native acceptance. Registry verification/pulls authenticate to private GHCR, and service credentials are supplied before job steps. Dependent services still start only after image verification. Ordinary just/local workspace tests exclude this destructive acceptance crate; configured U1 runs explicitly and fails closed without isolated inputs. No U2 application cutover is implied.

Local verification (provide the actual approved values, never inferred identifiers):

```bash
export OCEANBASE_TRUSTED_REPOSITORY OCEANBASE_TRUSTED_REF OCEANBASE_IMAGE_REPOSITORY GH_TOKEN
export OCEANBASE_SOURCE_COMMIT OCEANBASE_BUILD_WORKFLOW_RUN_ID OCEANBASE_BUILD_ARTIFACT_ID OCEANBASE_MANIFEST_SHA256
export MOLTIS_U1_PROOF_DIR=/absolute/approved-artifact-directory
args=(--source-commit "$OCEANBASE_SOURCE_COMMIT" --build-workflow-run-id "$OCEANBASE_BUILD_WORKFLOW_RUN_ID" --build-artifact-id "$OCEANBASE_BUILD_ARTIFACT_ID" --manifest-sha256 "$OCEANBASE_MANIFEST_SHA256" --artifact-dir "$MOLTIS_U1_PROOF_DIR")
python3 deploy/oceanbase/fetch-image-artifact.py "${args[@]}"
export OCEANBASE_IMAGE_DIGEST="$(bash deploy/oceanbase/verify-image.sh "${args[@]}")"
python3 deploy/oceanbase/test-image-proof.py
```

The common verifier checks live exact run/artifact repository/event/protected ref/source, manifest bytes hash and actual cosign certificate issuer/workflow/ref/commit/trigger/transparency proof, registry image signature, both source-bound provenance and SBOM subjects and predicate hashes. Missing/mismatched inputs fail closed with no digest output. All three workflows and Rust validation call the same implementation. `test-image-proof.py` exercises a real signed positive artifact and missing/invalid signatures/bundle, altered manifest/hash/source/run/digest/repository/workflow and missing quartet negatives; it never mocks cosign.

## Offline production material and SQL lifecycle

Use a new absolute operator-root-owned directory under an operator-controlled path (not writable `/tmp` parents). Linux operator root, Docker Compose v2 and OpenSSL are prerequisites. Do not put secrets in `.env`, command arguments or rendered Compose:

```bash
sudo python3 deploy/oceanbase/init-material.py --directory /srv/moltis-oceanbase/material --runtime-uid "$MOLTIS_RUNTIME_UID"
export OCEANBASE_MATERIAL_DIR=/srv/moltis-oceanbase/material
export DATABASE_PREFIX=moltis PLATFORM_DB_USER=moltis_platform
export PLATFORM_DB_SQL_HOST='%'
export OB_ACCOUNT_HOST_MAX_BYTES=128
# Base: private DB network, no published ports.
docker compose -f deploy/oceanbase/docker-compose.yml up -d oceanbase
# An explicit wildcard deployment must prove private networking/firewall/TLS/secret conditions.
# Invoke offline initializer with --wildcard-isolated-network only after that operator policy is satisfied.
docker compose -f deploy/oceanbase/docker-compose.yml run --rm platform-init --prefix moltis --username moltis_platform --sql-host '%' --wildcard-isolated-network --root-sql-host '%' --host-max-bytes 128 --runtime-uid "$MOLTIS_RUNTIME_UID" --tenant moltis
```

Host-process/local development uses the same loopback-only `docker-compose.ports.yml` overlay. Base Compose has no published ports. Operator initialization shares the DB network namespace and connects to loopback; ordinary gateway/tools never receive root material. This is client placement, not a database root-account source restriction: the fixed release protects the built-in `root@'%'` account and does not let it be dropped, renamed or locked. Deployments must restrict SQL ingress using the private network/host firewall and give sandbox/browser containers no route to it. Any permitted-source client holding the root credential can authenticate; secret custody is part of the approved boundary.

`internal: true` alone is not SQL ingress isolation: an ordinary bridge container reached the internal DB on the local runtime. Base Compose therefore uses Docker's native `gateway_mode_ipv4=isolated`; the same running observer's isolated address accepted a private-network SQL handshake while an ordinary-bridge client timed out. No extra firewall service or application-level source fallback is added. The host/local loopback overlay explicitly restores NAT for publishing 127.0.0.1:2881 and requires a tested host/runtime firewall to deny sandbox ingress. The isolated server-base proof does not certify that NAT overlay or another runtime.

Materials are separated: operator-only `ca-private/ca-key.pem` (0600; never DB/app-mounted), DB-only `server-private/server-key.pem` (0600 UID 10001), `public-trust/ca.pem` and approved `tls-manifest.json` (0444), temporary `root-init/root.env` (0600), offline durable `root-recovery/root-recovery.secret` (0600) and runtime-UID-owned `platform/platform-db-password.secret` (0600). Application mounts only platform secret read-only and public-trust read-only. Never mount either root directory or private-key directory into the application. Never copy private materials into build artifacts/evidence.

Before first SQL-ready, entry validates nonempty root material, owner/modes/no-follow reads, approved CA, certificate/SAN/key match, stages the TLS wallet and starts observer with SSL enabled. Native management uses pinned obclient 2.2.14 with `--ssl-ca --ssl-verify-server-cert`; the base client's 2.2.13 IP-SAN check is not used. Built-in root and platform accounts REQUIRE SSL; encrypted status and plaintext rejection gate readiness. Root stays `root@'%'` with a random operator-only file credential, then rotates to offline recovery material; no application root or account-level loopback-only claim. Standard non-root account-host bounds remain measured 128 bytes, valid DNS/IPv4/explicit `%`, unsupported IPv6 rejected; client address and account source remain distinct.

The 6-GiB observer reserves 1 GiB system memory; bootstrap explicitly sets the measured minimum resource-pool floor to 1 GiB, shrinks the sys unit to 1 GiB memory/2 GiB log disk, waits for server allocation readback, then creates the 3-GiB user tenant with 2 GiB log disk. This fits the fixed 5-GiB allocatable memory/log capacities with reserved headroom; it is not a passed HNSW capacity profile. Full U1 still measures the actual cgroup peak and both logical indexes.

Offline init accepts only current `<prefix>_platform`/`<prefix>_admin<alnum suffix>`, prefix `[a-z][a-z0-9]{0,15}`. Existing accounts/control DB are never treated fresh or silently ALTERed. `platform-grants.sql` is the sole credential-free template: global CREATE USER only; exact DDL/DML grants on the single escaped tenant prefix, the finite supplemental double-escaped tenant target pattern required by observed CE grant-check semantics, and exact escaped control name. No global CREATE/SUPER/SELECT blanket. Platform cap is `2 * control_max + 4` (14 default), read back. Isolated CI initializes `ci_e2e_admin`/`e2e%` once with an explicit finite aggregate cap; no application production escape hatch.

Tenant and control DDL also require database-scoped `REFERENCES` in this release: the real sqlx FK fixture failed with 1142 without it. The platform gets this privilege with grant option only on its escaped tenant patterns, and without grant option on its control database; tenant fixtures get it only on their own database. The runtime gate exercises own-database FK creation and rejects cross-database references.

Advisory locks survive COMMIT/DDL and are reclaimed asynchronously after their owning session closes. The pinned [object-lock garbage collector](https://github.com/oceanbase/oceanbase/blob/071f4d9c82841d3ecb2d0004ef9213766308b714/src/storage/tablelock/ob_table_lock_service.cpp#L231-L255) runs every 10 seconds. A diagnostic saw the closed owner absent from PROCESSLIST while GET_LOCK still returned 0, then acquired after about 3.18 seconds; a 5-second assumption also failed. Gates use a 10-second server wait within the existing 15/20-second client budget, not immediate-release claims or extra RELEASE_LOCK-only semantics.

The pinned sqlx binary protocol reports LONGTEXT as BLOB: direct String decoding failed. Fixtures read bytes, validate UTF-8 when returning text, and compare exact content bytes during projection readback; opaque JSON-looking strings are never parsed/re-serialized. The default `ob_query_timeout` is 10,000,000 microseconds; 10-second advisory acquisition must set a bounded larger query deadline (15 seconds in the gate) or it races server timeout 4012.

Fixed 5.0.1 returned no rows for `SHOW STATUS LIKE 'Ssl_cipher'`; no server status value is invented. SQLx proves authenticated VerifyIdentity with the approved CA and rejects disabled TLS with 1045; the paired real obclient session exposes a negotiated TLS cipher. Native/SQLx wrong CA, wrong SAN and expired leaves must fail with certificate-specific causes before authentication.

Connector Boolean mode must require every literal term rather than bind raw user text as optional OR terms. The U1 candidate splits punctuation into quoted Unicode alphanumeric terms while preserving underscore and dot, requires each with `+`, and retains fixture exclusions with `-`; `std::vector` becomes `+"std" +"vector"`, but `user_id` and dotted paths stay whole to match the native analyzer. The unchanged native corpus proves all positives and negatives; complete joined-layout validation is still required. Stable score/item_id SQL pagination is unchanged. Both query-mode configurations are included in parser fingerprints.

Offline platform initialization durably prepares a root-owned `root-init/initjournal.json` before account SQL, binding prefix/tenant/username/account host, transport/trust/template, cap/UID and exact material digests. Partial initialization requires explicit `--resume` with the same arguments and files; it independently authenticates sys/tenant roots with original or prepublished recovery material, verifies exact platform secret/grants/SSL/cap and reconciles only journal-owned effects. Unknown accounts or mismatched bindings refuse mutation. Public `platform/init.env` and `platform/init.done` are fsynced before original root.env retirement. Native fault injection covers account creation, first grant, cap, each root rotation, both publication files and unlink-before-final-journal; completed resume makes no DDL. Restart uses only `OB_ROOT_PASSWORD_FILE=/run/root-recovery/root-recovery.secret` with operator recovery mount, never regenerated init material. Configuration consumers in U2 are not implemented here.

CA lifetime 3650 days, leaf lifetime 90 days, measured expiry dates in public TLS manifest. Renewal/restore is an **offline** operator operation: stop every client and disable restart, take the deployment's exclusive lock, stage/fsync/publish materials with the same UID/modes, approve a new public trust artifact, verify SAN/expiry/native+sqlx TLS and private-mount negatives before serving. Nonincident CA overlap must be explicitly listed in the approved manifest and old trust removed after all clients switch. Suspected key/CA compromise requires new CA-only trust and new root/platform/tenant credentials; old cert/key and old credentials must actually be rejected before restarting any client. No renewal daemon, plaintext/old-material fallback, or claim that these complete U10 workflows have passed exists.

## Acceptance commands and limits

With a genuinely verified published image and its approved quartet on a native Linux runner:

```bash
export EXPECTED_ARCH=amd64 # arm64 on the native arm runner
bash deploy/oceanbase/tests/image-acceptance.sh
```

The script rejects missing root, broad/wrong-owner key, symlink CA, wrong fingerprint, wrong SAN and expired leaf before initialization; starts the real 6-GiB/4-CPU DB, initializes/retire-root offline, invokes `tests/runtime-boundaries.py` for actual account/logging/session-cap boundaries, generates root-authenticated tenant/build readback and scoped lifecycle credentials, and runs `cargo test -p moltis-storage --test validation -- --nocapture`. The Rust helper re-verifies the image before mutation. Container memory is measured from the actual DB cgroup, not host memory or snapshots. Runtime SQL secrets are passed through private tmpfs native option files; config with isolated fixture credentials is a local 0600 file, never normal application environment.

Review hardening includes typed parser/connector inputs rejected before SQL, secrecy-wrapped driver credentials, full parent/child migration shape refusal and native root compromise handling with a durable candidate plus identity-checked enumeration/KILL. Missing completion markers are rejected before observer launch on persisted data; an incomplete bootstrap never restarts SQL while waiting to fail.

Native account-host limits are now measured inside the gate: valid DNS-shaped 128-byte host CREATE/readback succeeds exactly; 129-byte host is rejected without another account row. The report emits 128 only after this real boundary succeeds. Local SQLx/native wrong-SAN and expired-certificate SQL-wire handshakes were separately observed rejecting before authentication; those unsigned fixtures are not signed workflow acceptance.

Unsigned local arm64 diagnostics passed all frozen 256/512/1024-chunk profiles at 32/768/1536/4096 dimensions with real next-generation population concurrent with gateway/two-tool queries, including W10000. Every worker recorded population overlap and observed writes; measured peak including workspace reached 4,323,995,648 bytes, below the frozen 5-GiB budget. The fitting-baseline over-budget candidate used the same estimate-before-DDL path and left actual generations/metadata unchanged. This is one architecture's local observation, not the common signed selection or a published default.

The canonical image acceptance now runs `tests/tls-lifecycle.py` and feeds its real wrong-SAN/expired SQL endpoints into required typed Rust/native handshake gates. Private fixture materials use nonce-owned Linux volumes so actual UID10001/0600 is preserved on macOS Docker as well as Linux; only public CA/receipt/manifest are outputs. Unique CA issuer names and leaf AKI/SKI avoid ambiguous issuer selection during legitimate overlap. Unsigned local execution completed 30 renewal/restore/private-mount/overlap/new-only/credential-revocation observations, followed by passing SQLx/native certificate-specific handshakes. The U1 application-material gate is not a nonexistent U2 Moltis entry.

Final local hardening repeated the full lifecycle with complete CA-bundle approval: 31 observations passed, including stale new+old bundle paired with a new-only manifest being rejected before SQL. The trust reader checks every PEM CA and exact approved digest set, not only the first certificate. A real unavailable Docker socket also failed cleanup without marking ownership state cleaned; daemon uncertainty never means resources disappeared.

Remaining approval requires native amd64+arm64 full signed U1, independently genuine wrong identity/attestation cases, actual skipped-dependent-service observations and the final published deployment network proof. Local IPv4 isolated server-base routing succeeded; NAT loopback overlay firewall remains deployment-specific. Missing evidence never permits crypto/fixture skip, unsigned approval or a guessed common behavior manifest.
