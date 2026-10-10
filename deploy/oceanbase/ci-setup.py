#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--container', required=True)
parser.add_argument('--directory', type=Path, required=True)
parser.add_argument('--proof-dir', type=Path, required=True)
parser.add_argument('--tls-handshake-manifest', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parent
args.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
args.directory = args.directory.resolve()
def docker(*argv, **kwargs):
    return subprocess.run(['docker', *argv], check=True, **kwargs)
image = os.environ['OCEANBASE_IMAGE_DIGEST']
# The caller already uses workflow-local needs; reverify before any SQL mutation.
proof = ['--source-commit', os.environ['OCEANBASE_SOURCE_COMMIT'], '--build-workflow-run-id', os.environ['OCEANBASE_BUILD_WORKFLOW_RUN_ID'], '--build-artifact-id', os.environ['OCEANBASE_BUILD_ARTIFACT_ID'], '--manifest-sha256', os.environ['OCEANBASE_MANIFEST_SHA256'], '--artifact-dir', str(args.proof_dir)]
validated = subprocess.check_output(['bash', str(root / 'verify-image.sh'), *proof], text=True).strip()
if validated != image:
    raise SystemExit('CI service image differs from validated digest')
handshakes = json.loads(args.tls_handshake_manifest.read_text())
if not isinstance(handshakes, list) or not {'wrong_san', 'expired'} <= {item.get('expectation') for item in handshakes}:
    raise SystemExit('complete actual wrong-SAN/expired handshake endpoints required')
docker('exec', '-e', 'OCEANBASE_IMAGE_DIGEST=' + image, args.container, 'python3', '/opt/moltis-oceanbase/ci-init.py')
for source, target in [('/run/ci-client/.', str(args.directory)), ('/run/public-trust/ca.pem', str(args.directory / 'ca.pem'))]:
    docker('cp', args.container + ':' + source, target)
for path in args.directory.iterdir():
    os.chmod(path, 0o600)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Unapproved U1 negative CA', '-keyout', str(args.directory / 'wrong-ca-key.pem'), '-out', str(args.directory / 'wrong-ca.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
(args.directory / 'wrong-ca-key.pem').unlink()
secret = (args.directory / 'admin.secret').read_text().strip()
config = {'admin_url': 'mysql://ci_e2e_admin%40moltis:' + secret + '@127.0.0.1:2881/e2e_management', 'account_host': '%', 'ob_tenant': 'moltis', 'ca': str(args.directory / 'ca.pem'), 'wrong_ca': str(args.directory / 'wrong-ca.pem'), 'expected_build': (args.directory / 'build.txt').read_text().strip(), 'offline_tenant_readback': str(args.directory / 'tenant-readback.json'), 'native_tls_command': ['docker', 'exec', args.container, 'obclient', '--defaults-extra-file=/run/ci-client/native-client.cnf', '--host=127.0.0.1', '--port=2881', '--user=ci_e2e_admin@moltis', '--ssl-ca=/run/public-trust/ca.pem', '--ssl-verify-server-cert', '--execute=status'], 'memory_container': args.container, 'proof_dir': str(args.proof_dir.resolve()), 'parser_inputs': str(root / 'parser-inputs.json'), 'output': str(Path('target/oceanbase-u1-evidence').resolve() / (os.environ.get('EXPECTED_ARCH', 'native') + '.json'))}
config['tls_handshakes'] = [item for item in handshakes if item.get('expectation') != 'success'] + [{'name': 'canonical_success', 'host': '127.0.0.1', 'port': 2881, 'ca': config['ca'], 'expectation': 'success', 'native_command': config['native_tls_command']}]
Path(config['output']).parent.mkdir(parents=True, exist_ok=True)
path = args.directory / 'u1-config.json'
path.write_text(json.dumps(config, sort_keys=True) + '\n')
os.chmod(path, 0o600)
if 'GITHUB_ENV' in os.environ:
    with open(os.environ['GITHUB_ENV'], 'a') as stream:
        stream.write('MOLTIS_U1_CONFIG=' + str(path) + '\nMOLTIS_U1_ISOLATED=1\n')
print('Isolated CI config written as a private file; no credential environment/argv output.')
