#!/usr/bin/env python3
"""Isolated real-observer TLS lifecycle; caller verifies the image first.

--output is a public output directory. Successful runs retain ONLY unbootstrapped
negative SQL endpoints until --cleanup --output DIR. ci-setup adds the canonical
success endpoint to tls-handshakes.json; lifecycle positives live in receipt.json.
Private scaffolding stays in a nonce-owned root-only Linux volume; the empty host operator directory is only a sentinel. No private bytes enter output.
No provenance, Rust, production application activation, or full-U1 claim is made.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time

IMAGE_TOOLS = '/opt/moltis-oceanbase'
LABEL = 'org.moltis.u1-tls-lifecycle'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command, *, check=True, timeout=180, input=None):
    result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Never expose SQL, client option contents, or native credential errors.
        raise RuntimeError('command rejected: ' + command[0] + ' (exit ' + str(result.returncode) + ')')
    return result


def operator(action, values):
    """Runs inside the pinned image. Only this offline helper sees CA private keys."""
    sys.path.insert(0, IMAGE_TOOLS)
    from material import native_sql, password, publish, read_checked, trust
    root = Path('/operator')
    current = root / 'current'

    def copy_material(source, destination):
        destination.mkdir(mode=0o700)
        for part in ('ca-private', 'server-private', 'public-trust', 'root-init', 'root-recovery', 'platform'):
            original = source / part
            target = destination / part
            target.mkdir(mode=stat.S_IMODE(original.stat().st_mode))
            os.chown(target, original.stat().st_uid, original.stat().st_gid)
            for item in original.iterdir():
                if item.is_file() and not item.is_symlink():
                    info = item.stat()
                    publish(target / item.name, read_checked(item, uid=info.st_uid, mode=stat.S_IMODE(info.st_mode)), uid=info.st_uid, mode=stat.S_IMODE(info.st_mode))

    def activate(source, overlap=False):
        # All clients/observer are stopped by the controller before this durable cutover.
        for name in ('server-key.pem', 'server-cert.pem'):
            mode = 0o600 if name.endswith('key.pem') else 0o444
            publish(current / 'server-private' / name, read_checked(source / 'server-private' / name, uid=10001, mode=mode), uid=10001, mode=mode)
        ca = read_checked(source / 'public-trust/ca.pem', mode=0o444)
        manifest = json.loads(read_checked(source / 'public-trust/tls-manifest.json', mode=0o444))
        if overlap:
            old = read_checked(root / 'archive/public-trust/ca.pem', mode=0o444)
            old_manifest = json.loads(read_checked(root / 'archive/public-trust/tls-manifest.json', mode=0o444))
            ca += old
            manifest['approved_ca_sha256'] += old_manifest['approved_ca_sha256']
        publish(current / 'public-trust/ca.pem', ca, mode=0o444)
        publish(current / 'public-trust/tls-manifest.json', (json.dumps(manifest, sort_keys=True) + '\n').encode(), mode=0o444)
        # The private signing material is operator-only even during normal overlap.
        publish(current / 'ca-private/ca-key.pem', read_checked(source / 'ca-private/ca-key.pem'))

    if action == 'empty-volume':
        require(not any(root.iterdir()), 'new private fixture volume must be empty')
        require(root.stat().st_uid == 0, 'private fixture volume must be root-owned')
        os.chmod(root, 0o700)
        return
    if action == 'prepare':
        info = root.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'empty root-owned 0700 operator directory required')
        require(not any(root.iterdir()), 'operator directory must be empty')
        uid, nonce = values
        publish(root / 'owner.json', (json.dumps({'nonce': nonce}) + '\n').encode())
        for name in ('current', 'replacement'):
            run(['python3', IMAGE_TOOLS + '/init-material.py', '--directory', str(root / name), '--runtime-uid', uid])
        copy_material(current, root / 'archive')
        for mode in ('wrong-san', 'expired'):
            destination = root / mode
            copy_material(current, destination)
            run(['python3', IMAGE_TOOLS + '/test-certificate.py', str(destination), mode])
            # Every negative leaf uses exactly the original legitimate server key.
            require(read_checked(destination / 'server-private/server-key.pem', uid=10001) == read_checked(current / 'server-private/server-key.pem', uid=10001), 'negative leaf key changed')
            verified = run(['openssl', 'verify', '-no_check_time', '-CAfile', str(current / 'public-trust/ca.pem'), str(destination / 'server-private/server-cert.pem')])
            require(verified.returncode == 0, 'negative leaf is not genuinely CA-signed')
        for name in ('normal', 'wrong-san', 'expired', 'old-leaf'):
            (root / ('data-' + name)).mkdir(mode=0o700)
            os.chown(root / ('data-' + name), 10001, 10001)
        print('prepared')
    elif action == 'renew':
        # Normal renewal: retain CA/key, issue a fresh valid 90-day leaf.
        stage = current / 'ca-private' / ('renewal-' + secrets.token_hex(4))
        stage.mkdir(mode=0o700)
        (stage / 'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:oceanbase,DNS:localhost,IP:127.0.0.1\n')
        run(['openssl', 'req', '-new', '-key', str(current / 'server-private/server-key.pem'), '-subj', '/CN=oceanbase', '-out', str(stage / 'server.csr')])
        run(['openssl', 'x509', '-req', '-in', str(stage / 'server.csr'), '-CA', str(current / 'public-trust/ca.pem'), '-CAkey', str(current / 'ca-private/ca-key.pem'), '-set_serial', str(secrets.randbits(128)), '-days', '90', '-sha256', '-extfile', str(stage / 'extensions'), '-out', str(stage / 'server-cert.pem')])
        publish(current / 'server-private/server-cert.pem', (stage / 'server-cert.pem').read_bytes(), uid=10001, mode=0o444)
        manifest = json.loads(read_checked(current / 'public-trust/tls-manifest.json', mode=0o444))
        manifest['server_validity'] = run(['openssl', 'x509', '-in', str(stage / 'server-cert.pem'), '-noout', '-dates']).stdout
        publish(current / 'public-trust/tls-manifest.json', (json.dumps(manifest, sort_keys=True) + '\n').encode(), mode=0o444)
        print('renewed')
    elif action == 'restore':
        # Restore exact archived leaf/key with production publication ownership/modes.
        activate(root / 'archive')
        require(read_checked(current / 'server-private/server-key.pem', uid=10001) == read_checked(root / 'archive/server-private/server-key.pem', uid=10001), 'restore key differs')
        print('restored')
    elif action == 'stale-overlap-negative':
        approved = read_checked(current / 'public-trust/tls-manifest.json', mode=0o444)
        publish(current / 'public-trust/tls-manifest.json', read_checked(root / 'replacement/public-trust/tls-manifest.json', mode=0o444), mode=0o444)
        try:
            try:
                trust(current / 'public-trust/ca.pem', current / 'public-trust/tls-manifest.json')
            except ValueError as error:
                require(str(error) == 'CA differs from approved init/rotation manifest', 'stale overlap rejected for unrelated cause')
            else:
                raise RuntimeError('stale overlap bundle accepted new-only approval')
        finally:
            publish(current / 'public-trust/tls-manifest.json', approved, mode=0o444)
        print('stale overlap rejected before SQL')
    elif action in ('overlap', 'new-only'):
        activate(root / 'replacement', overlap=action == 'overlap')
        print(action)
    elif action == 'mutate':
        case = values[0]
        key = current / 'server-private/server-key.pem'
        cert = current / 'server-private/server-cert.pem'
        if case == 'key-owner':
            os.chown(key, 0, 0)
        elif case == 'key-mode':
            os.chmod(key, 0o644)
        elif case in ('wrong-san', 'expired'):
            publish(cert, read_checked(root / case / 'server-private/server-cert.pem', uid=10001, mode=0o444), uid=10001, mode=0o444)
        elif case == 'repair':
            os.chown(key, 10001, 10001)
            os.chmod(key, 0o600)
            publish(cert, read_checked(root / 'archive/server-private/server-cert.pem', uid=10001, mode=0o444), uid=10001, mode=0o444)
        else:
            raise RuntimeError('unknown mutation')
    elif action == 'export':
        name = values[0]
        print(read_checked(root / name / 'public-trust/ca.pem', mode=0o444).decode(), end='')
    elif action == 'cleanup':
        if not any(root.iterdir()):
            return
        owner = json.loads(read_checked(root / 'owner.json'))
        require(owner == {'nonce': values[0]}, 'operator cleanup owner differs')
        for item in root.iterdir():
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item)
            else:
                item.unlink()
    else:
        raise RuntimeError('unknown offline operator action')


def raw_observer():
    """Actual unbootstrapped SQL listener; bad leaves cannot pass normal entry."""
    sys.path.insert(0, IMAGE_TOOLS)
    from material import publish, read_checked
    home = Path('/var/lib/oceanbase')
    for part in ('wallet', 'store', 'store/clog', 'store/slog', 'store/sstable', 'etc', 'etc2', 'etc3', 'log', 'run'):
        directory = home / part
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, 10001, 10001)
    for name, source, mode in (
            ('ca.pem', '/run/public-trust/ca.pem', 0o444),
            ('server-cert.pem', '/run/server-private/server-cert.pem', 0o444),
            ('server-key.pem', '/run/server-private/server-key.pem', 0o600)):
        data = read_checked(source, uid=0 if name == 'ca.pem' else 10001, mode=mode)
        publish(home / 'wallet' / name, data, uid=10001, mode=mode)
    observer = Path(IMAGE_TOOLS + '/observer-path').read_text().strip()
    os.environ['LD_LIBRARY_PATH'] = str(Path(observer).parent.parent / 'lib') + ':' + os.environ.get('LD_LIBRARY_PATH', '')
    version_result = run([observer, '-V'])
    version = version_result.stdout + version_result.stderr
    inputs = json.loads(Path(IMAGE_TOOLS + '/image-inputs.json').read_text())
    require(all(value in version for value in ('5.0.1.0', '100000042026072912', inputs['oceanbase_source_commit'])), 'fixed raw observer build differs')
    ip = socket.gethostbyname(socket.gethostname())
    options = '__min_full_resource_pool_memory=1073741824,memory_limit=4G,system_memory=1G,datafile_size=2G,log_disk_size=2G,cpu_count=1,ssl_client_authentication=true,enable_sql_audit=false,enable_record_trace_log=false,syslog_level=ERROR,enable_syslog_wf=false,enable_syslog_recycle=true,max_syslog_file_count=2'
    os.chdir(home)
    os.setgroups([])
    os.setgid(10001)
    os.setuid(10001)
    os.execv(observer, [observer, '-N', '-p', '2881', '-P', '2882', '-z', 'zone1', '-n', 'moltis', '-c', '1', '-I', ip, '-r', ip + ':2882:2881', '-d', str(home / 'store'), '-o', options])


def app_material_gate(uid):
    # U1 configured application-material activation gate, not a U2 Moltis entry.
    # Reject private mounts before importing/invoking ANY database client.
    forbidden = ('ca-private', 'server-private', 'root-init', 'root-recovery')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    require(not any('/run/' + name in line for name in forbidden for line in mounts), 'private material mounted in configured application')
    for directory in (Path('/run/public-trust'), Path('/run/platform')):
        require(not any('key' in item.name.lower() or 'root' in item.name.lower() for item in directory.rglob('*')), 'private material in application public/platform mount')
    sys.path.insert(0, IMAGE_TOOLS)
    from material import read_checked, trust
    trust('/run/public-trust/ca.pem', '/run/public-trust/tls-manifest.json')
    secret = read_checked('/run/platform/platform-db-password.secret', uid=uid)
    require(re.fullmatch(rb'[A-Za-z0-9]{32,128}\n', secret), 'application secret rejected')
    print('configured application material accepted before SQL activation')


def rotate_credentials(uid):
    sys.path.insert(0, IMAGE_TOOLS)
    sys.path.insert(0, IMAGE_TOOLS + '/tests')
    from material import native_sql, password, publish, read_checked
    from importlib.machinery import SourceFileLoader
    runtime = SourceFileLoader('u1_runtime', IMAGE_TOOLS + '/tests/runtime-boundaries.py').load_module()
    original = password('/run/root-recovery/root-recovery.secret')
    previous_platform = read_checked('/run/platform/platform-db-password.secret', uid=uid).decode().strip()
    root_candidate = secrets.token_hex(24)
    platform_candidate = secrets.token_hex(24)
    publish('/run/root-recovery/previous-root.secret', (original + '\n').encode())
    publish('/run/root-recovery/candidate-root.secret', (root_candidate + '\n').encode())
    publish('/run/root-recovery/previous-platform.secret', (previous_platform + '\n').encode())
    publish('/run/root-recovery/candidate-platform.secret', (platform_candidate + '\n').encode())
    ca = '/run/public-trust/ca.pem'
    host = '127.0.0.1'
    for tenant in ('sys', 'moltis'):
        user = 'root@' + tenant
        held = runtime.Held(user, original, host, ca)
        try:
            native_sql(user, original, "ALTER USER 'root'@'%' IDENTIFIED BY '" + root_candidate + "';", host=host)
            runtime.rejected(lambda: native_sql(user, original, 'SELECT 1;', host=host))
            require(held.query('SELECT 1;') == '1', 'old root session did not remain for explicit termination')
            sessions = native_sql(user, root_candidate, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='root' AND ID<>CONNECTION_ID();", host=host).splitlines()
            require(held.session_id in sessions and all(value.isdigit() for value in sessions), 'old root session identity differs')
            for session in sessions:
                native_sql(user, root_candidate, 'KILL CONNECTION ' + session + ';', host=host)
            runtime.rejected(lambda: held.query('SELECT 1;'))
            require(native_sql(user, root_candidate, 'SELECT CURRENT_USER();', host=host).strip() == 'root@%', 'new root identity differs')
        finally:
            held.close()
    held = runtime.Held('moltis_platform@moltis', previous_platform, host, ca)
    try:
        native_sql('root@moltis', root_candidate, "ALTER USER 'moltis_platform'@'%' IDENTIFIED BY '" + platform_candidate + "';", host=host)
        runtime.rejected(lambda: native_sql('moltis_platform@moltis', previous_platform, 'SELECT 1;', host=host))
        require(held.query('SELECT 1;') == '1', 'old platform session did not remain for termination')
        sessions = native_sql('root@moltis', root_candidate, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='moltis_platform';", host=host).splitlines()
        require(held.session_id in sessions and all(value.isdigit() for value in sessions), 'platform session enumeration differs')
        for session in sessions:
            native_sql('root@moltis', root_candidate, 'KILL CONNECTION ' + session + ';', host=host)
        runtime.rejected(lambda: held.query('SELECT 1;'))
        require(native_sql('moltis_platform@moltis', platform_candidate, 'SELECT CURRENT_USER();', host=host).strip() == 'moltis_platform@%', 'new platform identity differs')
    finally:
        held.close()
    publish('/run/root-recovery/root-recovery.secret', (root_candidate + '\n').encode())
    publish('/run/platform/platform-db-password.secret', (platform_candidate + '\n').encode(), uid=uid)
    print('root and platform credentials rotated; old credentials rejected; old sessions identity-checked and terminated')


def native_options():
    sys.path.insert(0, IMAGE_TOOLS)
    from material import password, publish
    secret = password('/run/root-recovery/root-recovery.secret')
    publish('/run/root-recovery/client.cnf', ('[client]\npassword=' + secret + '\n').encode())


def credential_rejections():
    sys.path.insert(0, IMAGE_TOOLS)
    from material import native_sql, password
    for user, path in (('root@sys', '/run/root-recovery/previous-root.secret'),
                       ('root@moltis', '/run/root-recovery/previous-root.secret'),
                       ('moltis_platform@moltis', '/run/root-recovery/previous-platform.secret')):
        try:
            native_sql(user, password(path), 'SELECT 1;', host='127.0.0.1')
        except RuntimeError:
            continue
        raise RuntimeError('old credential accepted after emergency restart')
    print('old sys-root, tenant-root and platform credentials rejected after retained-data restart')


class Lifecycle:
    def __init__(self, args):
        self.args = args
        self.nonce = secrets.token_hex(12)
        self.prefix = 'moltis-u1-tls-' + self.nonce
        self.volume = self.prefix + '-private'
        run(['docker', 'volume', 'create', '--label', LABEL + '=' + self.nonce, self.volume])
        self.containers = []
        self.observations = []
        self.script = str(Path(__file__).resolve())
        self.output = args.output
        self.state = {'schema_version': 1, 'nonce': self.nonce, 'image': args.image,
                      'directory': str(args.directory), 'volume': self.volume, 'containers': self.containers}

    def mount(self, source, target, readonly=True):
        try:
            relative = Path(source).relative_to(self.args.directory)
        except ValueError:
            return ['--mount', 'type=bind,source=' + str(source) + ',target=' + target + (',readonly' if readonly else '')]
        suffix = ',volume-subpath=' + str(relative) if str(relative) != '.' else ''
        return ['--mount', 'type=volume,source=' + self.volume + ',target=' + target + suffix + (',readonly' if readonly else '')]

    def base(self, name, memory='256m', network=None):
        require(name not in self.containers, 'container name reused')
        self.containers.append(name)
        self.save_state()
        command = ['docker', 'run', '--name', name, '--label', LABEL + '=' + self.nonce,
                   '--memory', memory, '--cpus', '4' if memory == '6g' else '1',
                   '--tmpfs', '/run:rw,nosuid,nodev,mode=0755', '--network', network or 'none']
        command += self.mount(self.script, '/fixture.py')
        return command

    def save_state(self):
        path = self.output / 'cleanup.json'
        temporary = self.output / '.cleanup.json'
        temporary.write_text(json.dumps(self.state, sort_keys=True) + '\n')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def remove(self, name):
        result = run(['docker', 'inspect', '--format', '{{index .Config.Labels "' + LABEL + '"}}', name], check=False)
        if result.returncode == 0:
            require(result.stdout.strip() == self.nonce, 'refusing foreign container cleanup')
            run(['docker', 'stop', '--time', '70', name], timeout=90)
            run(['docker', 'rm', name], timeout=120)
        else:
            require(result.stderr.strip() == 'Error: No such object: ' + name, 'cannot establish owned container absence; retain cleanup state')
        self.containers.remove(name)
        self.save_state()

    def offline(self, action, *values):
        name = self.prefix + '-operator-' + secrets.token_hex(3)
        command = self.base(name)
        command += self.mount(self.args.directory, '/operator', False)
        command += ['--entrypoint', 'python3', self.args.image, '/fixture.py', '_operator', action, *map(str, values)]
        try:
            result = run(command, timeout=180).stdout
            if action == 'prepare':
                self.state['prepared'] = True
                self.save_state()
            return result
        finally:
            self.remove(name)

    def client(self, db, action, *values, writable=False, runtime_uid=None, private=None):
        name = self.prefix + '-client-' + secrets.token_hex(3)
        command = self.base(name, network='container:' + db if db else 'none')
        current = self.args.directory / 'current'
        for part in ('public-trust', 'platform'):
            command += self.mount(current / part, '/run/' + part, not writable)
        if runtime_uid is None:
            command += self.mount(current / 'root-recovery', '/run/root-recovery', not writable)
        else:
            command += ['--user', str(runtime_uid) + ':' + str(runtime_uid)]
        if private:
            command += self.mount(current / private, '/run/' + private)
        command += ['--entrypoint', 'python3', self.args.image, '/fixture.py', action, *map(str, values)]
        try:
            return run(command, check=False, timeout=240)
        finally:
            self.remove(name)

    def database(self, materials='current', raw=False, extra_ca=None):
        name = self.prefix + '-' + ('raw-' + materials + '-' + secrets.token_hex(3) if raw else 'normal-' + secrets.token_hex(3))
        command = self.base(name, memory='4g' if raw else '6g', network='bridge')
        command += ['--detach', '--hostname', 'oceanbase', '--publish', '127.0.0.1::2881']
        source = self.args.directory / materials
        command += self.mount(source / 'server-private', '/run/server-private')
        command += self.mount(source / 'public-trust', '/run/public-trust')
        data = 'data-' + (materials if raw and materials != 'archive' else 'old-leaf' if raw else 'normal')
        command += self.mount(self.args.directory / data, '/var/lib/oceanbase', False)
        if not raw:
            command += self.mount(source / 'root-init', '/run/root-init')
            command += self.mount(source / 'root-recovery', '/run/root-recovery')
            # root.env is retired by actual platform-init after the initial start.
            root_file = '/run/root-init/root.env' if not self.initialized else '/run/root-recovery/root-recovery.secret'
            command += ['--env', 'OB_ROOT_PASSWORD_FILE=' + root_file]
        if extra_ca:
            command += self.mount(self.args.directory / extra_ca / 'public-trust', '/run/probe-trust')
        if raw:
            command += ['--entrypoint', 'python3', self.args.image, '/fixture.py', '_raw']
        else:
            command += [self.args.image]
        run(command)
        return name

    def wait(self, db, raw=False):
        deadline = time.monotonic() + (120 if raw else 900)
        while time.monotonic() < deadline:
            alive = run(['docker', 'inspect', '--format', '{{.State.Running}}', db])
            if alive.stdout.strip() != 'true':
                state = run(['docker', 'inspect', '--format', '{{json .State}}', db]).stdout
                logs = run(['docker', 'logs', db], check=False)
                diagnostics = [line for line in (logs.stdout + logs.stderr).splitlines() if line.startswith(('RuntimeError:', 'ValueError:', 'FileNotFoundError:', 'PermissionError:'))]
                self.observe('observer_start_diagnostic', error=diagnostics[-1] if diagnostics else 'no safe exception cause')
                self.observe('observer_start_failure', container=db, state=json.loads(state), raw=raw)
                raise RuntimeError('actual observer exited before readiness: ' + db + ' state=' + state.strip())
            probe = ['docker', 'exec', db, 'python3', '-c',
                     "import socket; s=socket.create_connection(('127.0.0.1',2881),2); assert s.recv(4); s.close()"] if raw else ['docker', 'exec', db, 'test', '-f', '/run/oceanbase-ready']
            if run(probe, check=False, timeout=10).returncode == 0:
                return
            time.sleep(2)
        raise RuntimeError('actual observer readiness deadline: ' + db)

    def observe(self, name, **values):
        self.observations.append({'name': name, **values})

    def reject_entry(self, case, stage):
        self.offline('mutate', case)
        db = self.database()
        try:
            result = run(['docker', 'wait', db], timeout=45)
            require(result.stdout.strip().isdigit() and result.stdout.strip() != '0', 'unsafe entry accepted ' + case)
            # A rejected production entry must not have staged a wallet/served SQL.
            require(run(['docker', 'exec', db, 'test', '-f', '/run/oceanbase-ready'], check=False).returncode != 0, 'rejected entry reported ready')
            logs = run(['docker', 'logs', db]).stdout + run(['docker', 'logs', db]).stderr
            expected = {'key-owner': 'correctly owned', 'key-mode': 'exact mode',
                        'wrong-san': 'hostname mismatch', 'expired': 'certificate has expired'}[case]
            require(expected in logs.lower(), 'entry rejection not attributable to expected certificate/material gate: ' + case)
            self.observe(stage + '_' + case.replace('-', '_'), rejection='actual production entry before observer', diagnostic=expected)
        finally:
            self.remove(db)
            self.offline('mutate', 'repair')

    def app_gate(self, stage):
        accepted = self.client(None, '_app', self.args.runtime_uid, runtime_uid=self.args.runtime_uid)
        require(accepted.returncode == 0, 'configured application material gate refused public/platform: ' + (accepted.stderr.splitlines() or ['none'])[-1])
        for private in ('server-private', 'ca-private', 'root-recovery'):
            rejected = self.client(None, '_app', self.args.runtime_uid, runtime_uid=self.args.runtime_uid, private=private)
            require(rejected.returncode != 0 and 'private material mounted' in rejected.stderr, 'application private-mount gate did not reject ' + private)
        self.observe(stage + '_application_material_mounts', accepted=['public-trust', 'platform'], rejected=['server-private', 'ca-private', 'root-recovery'], scope='configured U1 material activation gate; no production Moltis application entry exists before U2')

    def options(self, db):
        result = self.client(db, '_options', writable=True)
        require(result.returncode == 0, 'native option publication failed')

    def native(self, db, *, ca='/run/public-trust/ca.pem', negative=False, execute='status'):
        command = ['docker', 'exec', db, 'obclient', '--no-defaults' if negative else '--defaults-extra-file=/run/root-recovery/client.cnf', '--protocol=tcp', '--host=127.0.0.1', '--port=2881', '--user=root@sys', '--ssl-ca=' + ca, '--ssl-verify-server-cert', '--connect-timeout=3', '--batch', '--skip-column-names', '--execute=' + execute]
        result = run(command, check=False, timeout=20)
        return command, result

    def identity(self, db, name):
        self.options(db)
        _, status = self.native(db)
        require(status.returncode == 0 and re.search(r'SSL:.*Cipher in use', status.stdout), 'native encrypted status failed')
        _, identity = self.native(db, execute='SELECT CURRENT_USER();')
        require(identity.returncode == 0 and identity.stdout.strip() == 'root@%', 'native root identity differs')
        self.observe(name, native_identity='root@%', encrypted=True, status=status.stdout.strip())

    def negative(self, db, expectation, name, ca='/run/public-trust/ca.pem'):
        command, result = self.native(db, ca=ca, negative=True, execute='SELECT CURRENT_USER();')
        diagnostic = result.stderr.strip()
        require(result.returncode != 0 and re.search(r'ERROR 2026\b', diagnostic), 'negative did not fail at native TLS handshake')
        lowered = diagnostic.lower()
        terms = {'wrong_san': ('validation', 'hostname', 'name mismatch'),
                 'expired': ('expired',), 'wrong_ca': ('certificate', 'issuer', 'verify')}[expectation]
        require(any(value in lowered for value in terms), 'native negative error category differs')
        self.observe(name, expectation=expectation, native_exit=result.returncode, native_diagnostic=diagnostic, before_authentication=True, endpoint='actual pinned observer SQL protocol')
        port = run(['docker', 'port', db, '2881/tcp']).stdout.strip()
        require(re.fullmatch(r'127\.0\.0\.1:[0-9]+', port), 'endpoint not loopback-published')
        return {'name': name, 'host': '127.0.0.1', 'port': int(port.split(':')[1]),
                'ca': str(self.output / ('new-ca.pem' if expectation == 'wrong_ca' else 'original-ca.pem')),
                'expectation': expectation, 'native_command': command}

    def execute(self):
        self.initialized = False
        self.offline('empty-volume')
        self.offline('prepare', self.args.runtime_uid, self.nonce)
        for case in ('key-owner', 'key-mode', 'wrong-san', 'expired'):
            self.reject_entry(case, 'initial')
        db = self.database()
        self.wait(db)
        # Production initializer and retired original root credential are exercised.
        name = self.prefix + '-init'
        command = self.base(name, network='container:' + db)
        for part in ('root-init', 'root-recovery', 'public-trust', 'platform'):
            command += self.mount(self.args.directory / 'current' / part, '/run/' + part, part in ('root-recovery', 'public-trust'))
        command += ['--env', 'OB_APPROVED_SQL_HOST=127.0.0.1', '--entrypoint', 'python3', self.args.image, IMAGE_TOOLS + '/platform-init.py', '--prefix', 'moltis', '--username', 'moltis_platform', '--sql-host', '%', '--root-sql-host', '%', '--host-max-bytes', '128', '--runtime-uid', str(self.args.runtime_uid), '--tenant', 'moltis', '--wildcard-isolated-network']
        try:
            run(command, timeout=300)
        finally:
            self.remove(name)
        self.initialized = True
        self.identity(db, 'initial_native_correct')
        self.app_gate('initial')
        self.remove(db)
        self.offline('renew')
        db = self.database()
        self.wait(db)
        self.identity(db, 'renewal_native_correct')
        self.remove(db)
        self.app_gate('renewal')
        for case in ('key-owner', 'key-mode', 'wrong-san', 'expired'):
            self.reject_entry(case, 'renewal')
        self.offline('restore')
        db = self.database()
        self.wait(db)
        self.identity(db, 'restore_native_correct')
        self.remove(db)
        self.app_gate('restore')
        for case in ('key-owner', 'key-mode', 'wrong-san', 'expired'):
            self.reject_entry(case, 'restore')
        self.offline('overlap')
        db = self.database()
        self.wait(db)
        self.identity(db, 'normal_ca_overlap_new_leaf')
        self.app_gate('normal_ca_overlap')
        self.remove(db)
        old_leaf = self.database('archive', raw=True, extra_ca='current')
        self.wait(old_leaf, raw=True)
        _, overlap = self.native(old_leaf, ca='/run/probe-trust/ca.pem', negative=True, execute='status')
        require(overlap.returncode == 0 and re.search(r'SSL:.*Cipher in use', overlap.stdout), 'approved CA overlap rejected still-valid old leaf: ' + overlap.stderr.strip())
        self.observe('normal_ca_overlap_old_leaf', encrypted=True, endpoint='actual pinned observer SQL protocol')
        self.remove(old_leaf)
        # Remove old trust after every client is stopped, then repeat handshake.
        self.offline('stale-overlap-negative')
        self.observe('stale_overlap_new_only_manifest_rejected', before_sql=True)
        self.offline('new-only')
        old_leaf = self.database('archive', raw=True, extra_ca='current')
        self.wait(old_leaf, raw=True)
        run(['docker', 'exec', old_leaf, 'openssl', 'x509', '-in', '/run/server-private/server-cert.pem', '-checkend', '0', '-noout'])
        self.negative(old_leaf, 'wrong_ca', 'old_still_valid_certificate_key_rejected', '/run/probe-trust/ca.pem')
        self.remove(old_leaf)
        # Offline new-only emergency trust on exactly the retained initialized data.
        self.app_gate('emergency')
        db = self.database(extra_ca='archive')
        self.wait(db)
        self.identity(db, 'emergency_new_only_retained_data')
        self.negative(db, 'wrong_ca', 'old_client_trust_rejected', '/run/probe-trust/ca.pem')
        rotated = self.client(db, '_rotate', self.args.runtime_uid, writable=True)
        require(rotated.returncode == 0, 'emergency credential/session rotation failed')
        self.observe('emergency_credential_rotation', root=['sys', 'moltis'], platform='moltis_platform', old_credentials_rejected=True, old_sessions_identity_checked_and_killed=True)
        self.remove(db)
        db = self.database()
        self.wait(db)
        self.identity(db, 'emergency_new_credential_restart')
        rejected = self.client(db, '_old_credentials')
        require(rejected.returncode == 0, 'old credentials accepted after restart')
        self.observe('emergency_old_credentials_restart', rejected=['sys-root', 'tenant-root', 'platform'])
        self.remove(db)
        # Normal lifecycle DB is stopped; only bounded raw TLS endpoints survive.
        (self.output / 'original-ca.pem').write_text(self.offline('export', 'archive'))
        (self.output / 'new-ca.pem').write_text(self.offline('export', 'replacement'))
        cases = []
        for materials, expectation, name in (('wrong-san', 'wrong_san', 'wrong_san'), ('expired', 'expired', 'expired')):
            raw = self.database(materials, raw=True)
            self.wait(raw, raw=True)
            cases.append(self.negative(raw, expectation, name))
        manifest = self.output / 'tls-handshakes.json'
        manifest.write_text(json.dumps(cases, indent=2) + '\n')
        receipt = {'schema_version': 1, 'image': self.args.image, 'image_verification': 'caller-owned; no crypto bypass provided', 'observations': self.observations,
                   'tls_handshake_manifest': str(manifest), 'retained_endpoints': self.containers,
                   'lifetime': 'negative endpoints retained until explicit --cleanup --output; ci-setup supplies canonical success',
                   'bounds': {'normal_observer_memory_bytes': 6442450944, 'raw_observer_memory_bytes_each': 4294967296, 'raw_observer_system_memory_bytes': 1073741824},
                   'scope': 'isolated TLS lifecycle only; not signed approval or full U1 acceptance'}
        (self.output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(manifest)


def cleanup(output):
    if not output.exists() or not any(output.iterdir()):
        return
    state = json.loads((output / 'cleanup.json').read_text())
    nonce = state['nonce']
    require(re.fullmatch(r'[0-9a-f]{24}', nonce), 'invalid cleanup nonce')
    require(re.fullmatch(r'(?:[^\s]+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})', state['image']), 'invalid cleanup image')
    require(Path(state['directory']).is_absolute(), 'invalid cleanup material directory')
    if state.get('cleaned'):
        return
    for name in state['containers']:
        require(name.startswith('moltis-u1-tls-' + nonce + '-'), 'foreign cleanup container name')
        found = run(['docker', 'inspect', '--format', '{{index .Config.Labels "' + LABEL + '"}}', name], check=False)
        if found.returncode == 0:
            require(found.stdout.strip() == nonce, 'foreign cleanup container label')
            run(['docker', 'stop', '--time', '70', name], timeout=90)
            run(['docker', 'rm', name], timeout=120)
        else:
            require(found.stderr.strip() == 'Error: No such object: ' + name, 'cannot establish owned container absence; retain cleanup state')
    volume = state['volume']
    require(volume == 'moltis-u1-tls-' + nonce + '-private', 'foreign cleanup volume name')
    label = run(['docker', 'volume', 'inspect', '--format', '{{index .Labels "' + LABEL + '"}}', volume], check=False)
    if label.returncode == 0:
        require(label.stdout.strip() == nonce, 'foreign cleanup volume label')
        run(['docker', 'run', '--rm', '--network', 'none', '--memory', '256m', '--cpus', '1', '--mount', 'type=volume,source=' + volume + ',target=/operator', '--mount', 'type=bind,source=' + str(Path(__file__).resolve()) + ',target=/fixture.py,readonly', '--entrypoint', 'python3', state['image'], '/fixture.py', '_operator', 'cleanup', nonce])
        run(['docker', 'volume', 'rm', volume])
    else:
        require(label.stderr.strip() in ('Error response from daemon: get ' + volume + ': no such volume', 'Error: No such volume: ' + volume), 'cannot establish private volume absence; retain cleanup state')
    state['containers'] = []
    state['cleaned'] = True
    (output / 'cleanup.json').write_text(json.dumps(state, sort_keys=True) + '\n')
    os.chmod(output / 'cleanup.json', 0o600)
    print('Owned containers and private material scaffold removed; public receipt/CA/manifest preserved.')


def main():
    if len(sys.argv) > 1 and sys.argv[1].startswith('_'):
        action, *values = sys.argv[1:]
        if action == '_operator':
            operator(values[0], values[1:])
        elif action == '_raw':
            raw_observer()
        elif action == '_app':
            app_material_gate(int(values[0]))
        elif action == '_rotate':
            rotate_credentials(int(values[0]))
        elif action == '_options':
            native_options()
        elif action == '_old_credentials':
            credential_rejections()
        else:
            raise RuntimeError('unknown fixture action')
        return
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--image', help='exact image digest already verified by caller')
    parser.add_argument('--directory', type=Path, help='existing empty operator-owned 0700 sentinel; private materials live only in a root-owned Linux volume')
    parser.add_argument('--runtime-uid', type=int)
    parser.add_argument('--output', required=True, type=Path, help='public output directory; keep until explicit cleanup')
    parser.add_argument('--cleanup', action='store_true', help='remove only nonce-owned endpoints/material scaffold, preserve public output')
    args = parser.parse_args()
    args.output = args.output.absolute()
    if args.cleanup:
        cleanup(args.output)
        return
    require(args.directory and args.directory.is_absolute() and args.directory.is_dir() and not args.directory.is_symlink(), 'existing absolute operator directory required')
    operator_info = args.directory.stat()
    require(operator_info.st_uid in (0, os.geteuid()) and stat.S_IMODE(operator_info.st_mode) == 0o700 and not any(args.directory.iterdir()), 'existing empty operator-owned 0700 sentinel directory required; private material uses a root-owned Linux volume')
    require(args.image and re.fullmatch(r'(?:[^\s]+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})', args.image), 'exact verified image digest required')
    require(args.runtime_uid is not None and args.runtime_uid > 0, 'non-root application runtime UID required')
    require(not args.output.exists(), 'new public output directory required')
    require(args.directory.resolve() not in (args.output, *args.output.parents), 'public output cannot be inside operator scaffold')
    args.output.mkdir(parents=True, mode=0o755)
    fixture = Lifecycle(args)
    try:
        fixture.execute()
    except BaseException as error:
        (args.output / 'receipt.json').write_text(json.dumps({'schema_version': 1, 'scope': 'failed isolated TLS lifecycle; not acceptance', 'error': str(error), 'observations': fixture.observations}, indent=2) + '\n')
        if (args.output / 'cleanup.json').exists():
            cleanup(args.output)
        raise


if __name__ == '__main__':
    main()
