#!/usr/bin/env python3
"""Generate negative certificates only in an operator-owned temporary fixture."""
import argparse
from pathlib import Path
import subprocess
from material import publish

parser = argparse.ArgumentParser()
parser.add_argument('directory', type=Path)
parser.add_argument('mode', choices=['wrong-san', 'expired'])
args = parser.parse_args()
root = args.directory
stage = root / 'ca-private/negative'
stage.mkdir(mode=0o700)
(stage / 'index').touch()
(stage / 'serial').write_text('1000\n')
(stage / 'newcerts').mkdir()
(stage / 'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:' + ('wrong.invalid' if args.mode == 'wrong-san' else 'oceanbase,DNS:localhost,IP:127.0.0.1') + '\n')
config = '[ca]\ndefault_ca=signer\n[signer]\ndatabase=' + str(stage / 'index') + '\nserial=' + str(stage / 'serial') + '\nnew_certs_dir=' + str(stage / 'newcerts') + '\ncertificate=' + str(root / 'public-trust/ca.pem') + '\nprivate_key=' + str(root / 'ca-private/ca-key.pem') + '\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n'
(stage / 'openssl.cnf').write_text(config)
subprocess.run(['openssl', 'req', '-new', '-key', str(root / 'server-private/server-key.pem'), '-subj', '/CN=oceanbase', '-out', str(stage / 'server.csr')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
options = ['-startdate', '20200101000000Z', '-enddate', '20200102000000Z'] if args.mode == 'expired' else ['-days', '90']
subprocess.run(['openssl', 'ca', '-batch', '-config', str(stage / 'openssl.cnf'), '-in', str(stage / 'server.csr'), '-out', str(stage / 'signed.pem'), '-extfile', str(stage / 'extensions'), *options], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(['openssl', 'x509', '-in', str(stage / 'signed.pem'), '-out', str(stage / 'server-cert.pem')], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
publish(root / 'server-private/server-cert.pem', (stage / 'server-cert.pem').read_bytes(), uid=10001, mode=0o444)
