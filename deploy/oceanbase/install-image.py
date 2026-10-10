#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

root = Path('/opt/moltis-oceanbase')
inputs = json.loads((root / 'image-inputs.json').read_text())
arch = inputs['architectures'][sys.argv[1]]
version = inputs['rpm_version']
for kind, package in [('libs', 'oceanbase-ce-libs'), ('server', 'oceanbase-ce')]:
    name = f"{package}-{version}.{arch['rpm_arch']}.rpm"
    path = Path('/tmp') / name
    with urllib.request.urlopen(f"https://github.com/oceanbase/oceanbase/releases/download/{inputs['oceanbase_release']}/{name}", timeout=60) as response, path.open('wb') as output:
        shutil.copyfileobj(response, output, length=1024 * 1024)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != arch[kind + '_sha256']:
        raise SystemExit(f'{kind} RPM digest mismatch')
    subprocess.run(['rpm', '-Uvh', '--nodeps', '--force', str(path)], check=True)
    path.unlink()
client_name = f"obclient-{inputs['obclient_version']}.{arch['rpm_arch']}.rpm"
client_path = Path('/tmp') / client_name
with urllib.request.urlopen(f"{inputs['obclient_source']}/{arch['rpm_arch']}/{client_name}", timeout=60) as response, client_path.open('wb') as output:
    shutil.copyfileobj(response, output, length=1024 * 1024)
with client_path.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
if digest != arch['obclient_sha256']:
    raise SystemExit('obclient RPM digest mismatch')
subprocess.run(['rpm', '-Uvh', '--nodeps', '--force', str(client_path)], check=True)
client_path.unlink()
files = subprocess.check_output(['rpm', '-ql', 'oceanbase-ce'], text=True).splitlines()
observer = next(Path(path) for path in files if path.endswith('/bin/observer'))
import os
libraries = observer.parent.parent / 'lib'
os.environ['LD_LIBRARY_PATH'] = str(libraries) + ':' + os.environ.get('LD_LIBRARY_PATH', '')
linkage = subprocess.check_output(['ldd', str(observer)], text=True)
if 'not found' in linkage:
    raise SystemExit('fixed observer runtime library input missing')
(root / 'observer-path').write_text(str(observer) + '\n')
version_output = subprocess.check_output([str(observer), '-V'], stderr=subprocess.STDOUT, text=True)
if inputs['oceanbase_source_commit'] not in version_output or '5.0.1.0' not in version_output or '100000042026072912' not in version_output:
    raise SystemExit('observer full build/source identity mismatch')
(root / 'observer-version.txt').write_text(version_output)
for command in ['obclient', 'openssl', 'python3']:
    subprocess.run(['bash', '-c', 'command -v "$1"', 'bash', command], check=True)
# The pinned upstream scripts are provenance inputs, not invoked: they bootstrap plaintext.
url = f"https://api.github.com/repos/oceanbase/docker-images/git/trees/{inputs['docker_images_tree']}"
with urllib.request.urlopen(url, timeout=60) as response:
    tree = json.load(response)
if tree['sha'] != inputs['docker_images_tree']:
    raise SystemExit('upstream docker-images tree mismatch')
(root / 'upstream-tree.json').write_text(json.dumps(tree, sort_keys=True))
import base64
upstream = root / 'upstream'
upstream.mkdir()
for name, blob in inputs['upstream_script_blobs'].items():
    with urllib.request.urlopen(f'https://api.github.com/repos/oceanbase/docker-images/git/blobs/{blob}', timeout=60) as response:
        record = json.load(response)
    data = base64.b64decode(record['content'])
    git_hash = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if git_hash != blob:
        raise SystemExit('upstream script blob checksum mismatch')
    (upstream / name).write_bytes(data)
