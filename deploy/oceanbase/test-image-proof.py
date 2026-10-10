#!/usr/bin/env python3
"""Negative acceptance against a real signed approved artifact; no crypto mocks."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).parent
source = Path(os.environ['MOLTIS_U1_PROOF_DIR'])
base = ['--source-commit', os.environ['OCEANBASE_SOURCE_COMMIT'], '--build-workflow-run-id', os.environ['OCEANBASE_BUILD_WORKFLOW_RUN_ID'], '--build-artifact-id', os.environ['OCEANBASE_BUILD_ARTIFACT_ID'], '--manifest-sha256', os.environ['OCEANBASE_MANIFEST_SHA256']]
def call(directory, arguments=base, environment=None):
    return subprocess.run(['bash', str(root / 'verify-image.sh'), *arguments, '--artifact-dir', str(directory)], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
positive = call(source)
if positive.returncode or b'@sha256:' not in positive.stdout:
    raise SystemExit('positive real signature verification failed')
with tempfile.TemporaryDirectory() as temporary:
    # Each semantic fixture is genuinely signed by the same pinned OIDC publication run.
    for name, expected in [('source', b'manifest source/run mismatch'), ('run', b'manifest source/run mismatch'), ('repository', b'manifest workflow identity mismatch'), ('workflow', b'manifest workflow identity mismatch'), ('ref', b'manifest workflow identity mismatch'), ('image', b'unapproved image repository/digest'), ('provenance', b'provenance hash mismatch'), ('sbom', b'sbom hash mismatch')]:
        directory = Path(temporary) / ('signed-' + name)
        shutil.copytree(source, directory)
        fixture = source / ('oceanbase-negative-' + name + '.json')
        for suffix in ('', '.sig', '.crt', '.bundle'):
            shutil.copyfile(Path(str(fixture) + suffix), directory / ('oceanbase-image-manifest.json' + suffix))
        args = base.copy()
        args[7] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        result = call(directory, args)
        if result.returncode == 0 or result.stdout or expected and expected not in result.stderr:
            raise SystemExit('genuine signed ' + name + ' identity fixture did not reach its semantic rejection gate')
    for name in ['manifest_missing', 'signature_missing', 'signature_invalid', 'bundle_missing', 'hash_changed', 'tampered_commit', 'tampered_run', 'tampered_digest', 'tampered_workflow', 'tampered_repository']:
        directory = Path(temporary) / name
        shutil.copytree(source, directory)
        path = directory / 'oceanbase-image-manifest.json'
        args = base.copy()
        if name == 'manifest_missing':
            path.unlink()
        elif name == 'signature_missing':
            Path(str(path) + '.sig').unlink()
        elif name == 'bundle_missing':
            Path(str(path) + '.bundle').unlink()
        elif name == 'signature_invalid':
            Path(str(path) + '.sig').write_text('aW52YWxpZA==')
        elif name == 'hash_changed':
            args[7] = '0' * 64
        else:
            value = json.loads(path.read_text())
            field, changed = {'tampered_commit': ('source_commit', '0' * 40), 'tampered_run': ('build_workflow_run_id', '1'), 'tampered_digest': ('image_digest', positive.stdout.decode().strip().split('@')[0] + '@sha256:' + '0' * 64), 'tampered_workflow': ('workflow', '.github/workflows/ci.yml'), 'tampered_repository': ('repository', 'untrusted/foreign')}[name]
            value[field] = changed
            path.write_text(json.dumps(value))
            args[7] = hashlib.sha256(path.read_bytes()).hexdigest()
        result = call(directory, args)
        if result.returncode == 0 or result.stdout:
            raise SystemExit(name + ' incorrectly produced a validated image')
    # Keep the genuine signed bytes unchanged: these exercise live approval identity checks, not signature tamper rejection.
    for name, index, value, expected in [('source_identity', 1, '0' * 40, b'build commit/PR identity mismatch'), ('run_identity', 3, '1', None), ('artifact_identity', 5, '1', None)]:
        args = base.copy()
        args[index] = value
        result = call(source, args)
        if result.returncode == 0 or result.stdout or expected and expected not in result.stderr:
            raise SystemExit(name + ' did not reject the unchanged signed artifact at its approval identity gate')
    for variable, value in [('OCEANBASE_TRUSTED_REPOSITORY', 'untrusted/foreign'), ('OCEANBASE_TRUSTED_REF', 'refs/pull/1/merge'), ('OCEANBASE_IMAGE_REPOSITORY', 'ghcr.io/untrusted/foreign')]:
        environment = dict(os.environ, **{variable: value})
        result = call(source, environment=environment)
        if result.returncode == 0 or result.stdout:
            raise SystemExit(variable + ' identity mismatch accepted')
    for index in [1, 3, 5, 7]:
        args = base.copy()
        args[index] = ''
        if call(source, args).returncode == 0:
            raise SystemExit('missing approval field accepted')
print('Real approved image proof positive, genuine signed semantic negatives, byte-tamper and live approval mismatch checks completed. This is not the full runtime U1 gate.')
