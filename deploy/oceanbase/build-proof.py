#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).parent
repo = os.environ['GITHUB_REPOSITORY']
commit = os.environ['GITHUB_SHA']
run = os.environ['GITHUB_RUN_ID']
ref = os.environ['GITHUB_REF']
image = os.environ['IMAGE_DIGEST']
context = dict(repository=repo, source_commit=commit, build_workflow_run_id=run, workflow='.github/workflows/oceanbase-image.yml', ref=ref)
def inspect(kind):
    raw = subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', image, '--format', '{{json .' + kind + '}}'])
    data = json.loads(raw)
    if not set(data) >= {'linux/amd64', 'linux/arm64'}:
        raise SystemExit(kind + ' missing architecture')
    return {arch: data[arch] for arch in ['linux/amd64', 'linux/arm64']}
provenance = {'buildDefinition': {'buildType': 'https://moltis.org/oceanbase/buildkit/v1', 'externalParameters': {'source_commit': commit, 'image_inputs': json.loads((root / 'image-inputs.json').read_text()), 'parser_inputs': json.loads((root / 'parser-inputs.json').read_text())}, 'resolvedDependencies': [{'uri': 'git+https://github.com/' + repo, 'digest': {'gitCommit': commit}}]}, 'runDetails': {'builder': {'id': 'https://github.com/' + repo + '/.github/workflows/oceanbase-image.yml@' + ref}, 'metadata': {'invocationId': 'https://github.com/' + repo + '/actions/runs/' + run}}, 'architectures': inspect('Provenance'), 'moltis': context}
sbom = {'architectures': inspect('SBOM'), 'moltis': context}
manifest = {'schema_version': 1, 'image_digest': image, **context}
Path('image-proof').mkdir(exist_ok=True)
for name, value in [('provenance', provenance), ('sbom', sbom)]:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    Path('image-proof/' + name + '.json').write_bytes(raw)
    manifest[name + '_sha256'] = hashlib.sha256(raw).hexdigest()
Path('image-proof/oceanbase-image-manifest.json').write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
negative_fields = {
    'source': ('source_commit', '0' * 40),
    'run': ('build_workflow_run_id', '1'),
    'repository': ('repository', 'untrusted/foreign'),
    'workflow': ('workflow', '.github/workflows/ci.yml'),
    'ref': ('ref', 'refs/heads/untrusted'),
    'image': ('image_digest', 'ghcr.io/untrusted/foreign@' + image.split('@')[1]),
    'provenance': ('provenance_sha256', '0' * 64),
    'sbom': ('sbom_sha256', '0' * 64),
}
for name, (field, value) in negative_fields.items():
    negative = dict(manifest)
    negative[field] = value
    Path('image-proof/oceanbase-negative-' + name + '.json').write_text(json.dumps(negative, sort_keys=True, separators=(',', ':')) + '\n')
