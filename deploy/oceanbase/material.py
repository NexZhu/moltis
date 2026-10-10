#!/usr/bin/env python3
"""Deployment-owned material: no-follow traversal and same-handle checks/reads."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


def read_checked(path, uid=0, mode=0o600):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute trusted path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, uid) or info.st_mode & 0o022:
                raise ValueError('untrusted/writable material parent')
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode:
                raise ValueError('material must be regular, correctly owned and exact mode')
            return stream.read()
    finally:
        os.close(fd)


def publish(path, data, uid=0, mode=0o600):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.staged-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, uid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def password(path):
    value = read_checked(path).decode().strip()
    if value.startswith('ROOT_PASSWORD='):
        value = value.removeprefix('ROOT_PASSWORD=')
    if not re.fullmatch(r'[A-Za-z0-9]{32,128}', value):
        raise ValueError('nonempty 32..128 ASCII alphanumeric password required')
    return value


def trust(path, manifest):
    import json
    data = read_checked(path, mode=0o444)
    approved = json.loads(read_checked(manifest, mode=0o444))
    certificates = re.findall(rb'-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----', data, re.DOTALL)
    if not certificates or re.sub(rb'-----BEGIN CERTIFICATE-----\s+.*?\s+-----END CERTIFICATE-----', b'', data, flags=re.DOTALL).strip():
        raise ValueError('trust bundle must contain only PEM CA certificates')
    digests = []
    for certificate in certificates:
        der = subprocess.check_output(['openssl', 'x509', '-outform', 'DER'], input=certificate)
        digests.append(hashlib.sha256(der).hexdigest())
        text = subprocess.check_output(['openssl', 'x509', '-noout', '-text'], input=certificate, text=False)
        if b'CA:TRUE' not in text:
            raise ValueError('trust file is not a CA')
    expected = approved['approved_ca_sha256']
    if not isinstance(expected, list) or not all(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) for value in expected) or len(set(digests)) != len(digests) or len(set(expected)) != len(expected) or set(digests) != set(expected):
        raise ValueError('CA differs from approved init/rotation manifest')
    return data


def native_sql(user, secret, sql, host=None, ca='/run/public-trust/ca.pem', manifest='/run/public-trust/tls-manifest.json', plaintext=False):
    host = host or os.environ.get('OB_APPROVED_SQL_HOST', 'oceanbase')
    trust(ca, manifest)
    # Secrets enter obclient through a private tmpfs option file, never env or argv.
    fd, name = tempfile.mkstemp(dir='/run', prefix='native-')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('[client]\npassword=' + secret + '\n')
        args = ['obclient', '--defaults-extra-file=' + name, '--protocol=tcp', '--host=' + host, '--port=2881', '--user=' + user, '--connect-timeout=3', '--batch', '--skip-column-names']
        args += ['--skip-ssl'] if plaintext else ['--ssl-ca=' + ca, '--ssl-verify-server-cert']
        result = subprocess.run(args, input=sql, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        if result.returncode:
            # Native errors can quote credential SQL: never emit stderr or input.
            raise RuntimeError('native SQL/TLS rejected (client exit ' + str(result.returncode) + ')')
        return result.stdout
    finally:
        os.unlink(name)
