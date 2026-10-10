#!/usr/bin/env python3
"""One fail-closed image proof gate, shared by all three workflows and U1."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile
import io

MANIFEST = "oceanbase-image-manifest.json"
PROVENANCE = "https://slsa.dev/provenance/v1"
SBOM = "https://moltis.org/oceanbase/sbom/v1"
WORKFLOW = ".github/workflows/oceanbase-image.yml"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(path, binary=False):
    result = subprocess.run(["gh", "api", path], check=True, stdout=subprocess.PIPE)
    return result.stdout if binary else json.loads(result.stdout)


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--build-workflow-run-id", required=True)
    parser.add_argument("--build-artifact-id", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_commit), "full source commit required")
    require(re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256), "manifest SHA256 required")
    for value in (args.build_workflow_run_id, args.build_artifact_id):
        require(re.fullmatch(r"[1-9][0-9]*", value), "exact numeric run/artifact ID required")
    return args


def source_gate(args):
    repo = os.environ["OCEANBASE_TRUSTED_REPOSITORY"]
    ref = os.environ["OCEANBASE_TRUSTED_REF"]
    image_repo = os.environ["OCEANBASE_IMAGE_REPOSITORY"]
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo), "invalid trusted repository")
    require(ref.startswith("refs/heads/") and re.fullmatch(r"refs/heads/[A-Za-z0-9_./-]+", ref), "protected branch ref required")
    require(re.fullmatch(r"ghcr.io/[a-z0-9_.-]+/[a-z0-9_./-]+", image_repo), "GHCR repository required")
    branch = api(f"repos/{repo}/branches/{ref.removeprefix('refs/heads/')}")
    require(branch.get("protected") is True, "build ref must be protected")
    run = api(f"repos/{repo}/actions/runs/{args.build_workflow_run_id}")
    require(run["repository"]["full_name"] == repo and run["head_repository"]["full_name"] == repo, "foreign build repository")
    require(run["event"] == "workflow_dispatch", "PR/push/workflow_run builds are not approved image sources")
    require(run["path"] == WORKFLOW and run["head_branch"] == ref.removeprefix("refs/heads/"), "wrong build workflow/ref")
    require(run["head_sha"] == args.source_commit and not run.get("pull_requests"), "build commit/PR identity mismatch")
    require(run.get("conclusion") not in ("failure", "cancelled", "timed_out", "action_required"), "failed build run")
    same_run = (os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("GITHUB_REPOSITORY") == repo
                and os.environ.get("GITHUB_REF") == ref
                and os.environ.get("GITHUB_SHA") == args.source_commit
                and os.environ.get("GITHUB_RUN_ID") == args.build_workflow_run_id
                and os.environ.get("GITHUB_WORKFLOW_REF") == f"{repo}/{WORKFLOW}@{ref}")
    require(same_run or (run.get("status") == "completed" and run.get("conclusion") == "success"), "external image consumption requires completed successful native acceptance run")
    artifact = api(f"repos/{repo}/actions/artifacts/{args.build_artifact_id}")
    require(not artifact["expired"] and artifact["name"] == f"oceanbase-image-manifest-{args.build_workflow_run_id}", "wrong/expired artifact")
    require(str(artifact["workflow_run"]["id"]) == args.build_workflow_run_id and artifact["workflow_run"]["head_sha"] == args.source_commit, "artifact build identity mismatch")
    return repo, ref, image_repo


def fetch(args):
    repo, _, _ = source_gate(args)
    data = api(f"repos/{repo}/actions/artifacts/{args.build_artifact_id}/zip", binary=True)
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        allowed = {MANIFEST, *(MANIFEST + suffix for suffix in (".sig", ".crt", ".bundle", ".sha256", ".sha512"))}
        for fixture in ('source', 'run', 'repository', 'workflow', 'ref', 'image', 'provenance', 'sbom'):
            name = 'oceanbase-negative-' + fixture + '.json'
            allowed.update([name, *(name + suffix for suffix in ('.sig', '.crt', '.bundle'))])
        require(set(archive.namelist()) <= allowed, "unexpected artifact member")
        for name in archive.namelist():
            (args.artifact_dir / name).write_bytes(archive.read(name))


def cosign(command, options):
    result = subprocess.run(["cosign", command, *options], check=True, stdout=subprocess.PIPE)
    return result.stdout


def statements(raw):
    values = []
    text = raw.decode()
    decoder = json.JSONDecoder()
    while text.strip():
        text = text.lstrip()
        item, end = decoder.raw_decode(text)
        for envelope in item if isinstance(item, list) else [item]:
            values.append(json.loads(base64.b64decode(envelope["payload"], validate=True)))
        text = text[end:]
    return values


def verify(args):
    repo, ref, image_repo = source_gate(args)
    path = args.artifact_dir / MANIFEST
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.manifest_sha256, "manifest hash mismatch")
    identity = f"https://github.com/{repo}/{WORKFLOW}@{ref}"
    identity_options = ["--certificate-identity", identity, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com", "--certificate-github-workflow-repository", repo, "--certificate-github-workflow-ref", ref, "--certificate-github-workflow-sha", args.source_commit, "--certificate-github-workflow-trigger", "workflow_dispatch"]
    for suffix in (".sig", ".crt", ".bundle"):
        require((args.artifact_dir / (MANIFEST + suffix)).is_file(), f"missing manifest {suffix}")
    cosign("verify-blob", [*identity_options, "--certificate", str(path) + ".crt", "--signature", str(path) + ".sig", "--bundle", str(path) + ".bundle", str(path)])
    manifest = json.loads(raw)
    require(manifest["source_commit"] == args.source_commit and str(manifest["build_workflow_run_id"]) == args.build_workflow_run_id, "manifest source/run mismatch")
    require(manifest["repository"] == repo and manifest["workflow"] == WORKFLOW and manifest["ref"] == ref, "manifest workflow identity mismatch")
    image = manifest["image_digest"]
    require(re.fullmatch(re.escape(image_repo) + r"@sha256:[0-9a-f]{64}", image), "unapproved image repository/digest")
    sha = image.split("@sha256:")[1]
    cosign("verify", [*identity_options, "--output", "json", image])
    for kind, predicate_type in (("provenance", PROVENANCE), ("sbom", SBOM)):
        decoded = statements(cosign("verify-attestation", [*identity_options, "--type", predicate_type, image]))
        matching = []
        for statement in decoded:
            if statement.get("predicateType") != predicate_type:
                continue
            subject = statement.get("subject", [])
            if not any(item.get("digest", {}).get("sha256") == sha and item.get("name") == image_repo for item in subject):
                continue
            predicate = statement["predicate"]
            context = predicate.get("moltis", {})
            if context == {"repository": repo, "source_commit": args.source_commit, "build_workflow_run_id": args.build_workflow_run_id, "workflow": WORKFLOW, "ref": ref}:
                matching.append(predicate)
        require(len(matching) == 1, f"missing/ambiguous {kind} source-bound attestation")
        predicate = matching[0]
        require(hashlib.sha256(json.dumps(predicate, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == manifest[kind + "_sha256"], f"{kind} hash mismatch")
        require(set(predicate["architectures"]) == {"linux/amd64", "linux/arm64"}, f"{kind} lacks both architectures")
        if kind == "sbom":
            for document in predicate["architectures"].values():
                require(document.get("SPDX", {}).get("spdxVersion") == "SPDX-2.3" and document["SPDX"].get("packages"), "actual BuildKit SPDX SBOM required")
        else:
            require(predicate["buildDefinition"]["externalParameters"]["source_commit"] == args.source_commit, "provenance source mismatch")
            require(predicate["buildDefinition"]["externalParameters"]["image_inputs"] == json.loads((Path(__file__).parent / "image-inputs.json").read_text()), "provenance image input mismatch")
            require(predicate["buildDefinition"]["externalParameters"]["parser_inputs"] == json.loads((Path(__file__).parent / "parser-inputs.json").read_text()), "provenance parser input mismatch")
    return image


if __name__ == "__main__":
    try:
        args = arguments()
        if args.fetch:
            fetch(args)
        else:
            print(verify(args))
    except (KeyError, ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"OceanBase image proof rejected: {error}", file=sys.stderr)
        sys.exit(1)
