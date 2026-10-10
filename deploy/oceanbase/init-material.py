#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from material import publish

parser = argparse.ArgumentParser()
parser.add_argument('--directory', type=Path, required=True)
parser.add_argument('--runtime-uid', type=int, required=True)
args = parser.parse_args()
if os.geteuid() != 0:
    raise SystemExit('offline material initializer requires operator root')
root = args.directory
if not root.is_absolute() or root.exists():
    raise SystemExit('new absolute operator-owned directory required; do not overwrite restore materials')
root.mkdir(mode=0o700)
for part in ['root-init', 'root-recovery', 'ca-private', 'server-private', 'public-trust', 'platform']:
    (root / part).mkdir(mode=0o700 if part not in ['public-trust', 'platform'] else 0o755)
os.chown(root / 'server-private', 10001, 10001)
os.chown(root / 'platform', args.runtime_uid, args.runtime_uid)
with tempfile.TemporaryDirectory(dir=root / 'ca-private') as directory:
    stage = Path(directory)
    def openssl(*argv):
        subprocess.run(['openssl', *argv], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (stage / 'ca.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    openssl('req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '3650', '-subj', '/CN=Moltis OceanBase offline CA ' + secrets.token_hex(8), '-config', str(stage / 'ca.cnf'), '-keyout', str(stage / 'ca-key.pem'), '-out', str(stage / 'ca.pem'))
    openssl('req', '-new', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-subj', '/CN=oceanbase', '-keyout', str(stage / 'server-key.pem'), '-out', str(stage / 'server.csr'))
    (stage / 'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:oceanbase,DNS:localhost,IP:127.0.0.1\n')
    openssl('x509', '-req', '-in', str(stage / 'server.csr'), '-CA', str(stage / 'ca.pem'), '-CAkey', str(stage / 'ca-key.pem'), '-set_serial', str(secrets.randbits(128)), '-days', '90', '-sha256', '-extfile', str(stage / 'extensions'), '-out', str(stage / 'server-cert.pem'))
    publish(root / 'ca-private/ca-key.pem', (stage / 'ca-key.pem').read_bytes())
    publish(root / 'public-trust/ca.pem', (stage / 'ca.pem').read_bytes(), mode=0o444)
    publish(root / 'server-private/server-key.pem', (stage / 'server-key.pem').read_bytes(), uid=10001)
    publish(root / 'server-private/server-cert.pem', (stage / 'server-cert.pem').read_bytes(), uid=10001, mode=0o444)
    import hashlib
    der = subprocess.check_output(['openssl', 'x509', '-in', str(stage / 'ca.pem'), '-outform', 'DER'])
    dates = subprocess.check_output(['openssl', 'x509', '-in', str(stage / 'server-cert.pem'), '-noout', '-dates'], text=True)
    publish(root / 'public-trust/tls-manifest.json', (json.dumps({'schema_version': 1, 'approved_ca_sha256': [hashlib.sha256(der).hexdigest()], 'server_validity': dates, 'ca_days': 3650, 'server_days': 90}, sort_keys=True) + '\n').encode(), mode=0o444)
publish(root / 'root-init/root.env', ('ROOT_PASSWORD=' + ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(64)) + '\n').encode())
publish(root / 'platform/platform-db-password.secret', (''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(64)) + '\n').encode(), uid=args.runtime_uid)
publish(root / 'root-recovery/root-recovery.secret', (''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(64)) + '\n').encode())
print('Offline materials created. Approve and archive the public TLS manifest before starting SQL; no private material belongs in an application mount.')
