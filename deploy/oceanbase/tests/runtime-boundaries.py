#!/usr/bin/env python3
"""Real U1 native-account/log boundaries on an explicitly isolated image.

Runs inside the acceptance DB network namespace. It never certifies Rust,
capacity, both architectures, or image provenance; the owning workflow does.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import subprocess
import sys
import tempfile
from string import Template

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from material import native_sql, password, read_checked, trust


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identifier(value):
    require(re.fullmatch(r'[a-z][a-z0-9_]{0,63}', value), 'invalid acceptance identifier')
    return '`' + value + '`'


def command(user, secret, host, ca):
    fd, path = tempfile.mkstemp(prefix='u1-client-', dir='/run')
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('[client]\npassword=' + secret + '\n')
    args = ['obclient', '--defaults-extra-file=' + path, '--protocol=tcp',
            '--host=' + host, '--port=2881', '--user=' + user,
            '--ssl-ca=' + ca, '--ssl-verify-server-cert', '--batch',
            '--skip-column-names', '--unbuffered', '--skip-reconnect',
            '--connect-timeout=3']
    return args, path


class Held:
    def __init__(self, user, secret, host, ca):
        args, self.path = command(user, secret, host, ca)
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, bufsize=1)
        try:
            self.session_id = self.query('SELECT CONNECTION_ID();')
            require(self.session_id.isdigit(), 'native session authentication failed')
        except BaseException:
            self.close()
            raise

    def query(self, statement):
        self.process.stdin.write(statement + '\n')
        self.process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            require(selector.select(timeout=5), 'native session reply deadline')
        value = self.process.stdout.readline().strip()
        require(value != '', 'native session closed without reply')
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()
        Path(self.path).unlink(missing_ok=True)


def rejected(call):
    try:
        call()
    except RuntimeError:
        return
    raise RuntimeError('forbidden native operation unexpectedly succeeded')


def root_incident(args):
    original = password(args.root_secret_file)
    candidate = secrets.token_hex(24)
    from material import publish
    candidate_path = '/run/u1-root-incident-candidate.secret'
    publish(candidate_path, (candidate + '\n').encode())
    candidate = password(candidate_path)
    try:
        for user in ['root@' + args.tenant, 'root@sys']:
            old = Held(user, original, args.host, args.ca)
            changed = False
            try:
                native_sql(user, original, "ALTER USER 'root'@'%' IDENTIFIED BY '" + candidate + "';", args.host, args.ca, args.trust_manifest)
                changed = True
                rejected(lambda: native_sql(user, original, 'SELECT 1;', args.host, args.ca, args.trust_manifest))
                require(old.query('SELECT 1;') == '1', 'ALTER alone unexpectedly revoked old root session')
                sessions = native_sql(user, candidate, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER='root' AND ID<>CONNECTION_ID();", args.host, args.ca, args.trust_manifest).splitlines()
                require(old.session_id in sessions and all(value.isdigit() for value in sessions), 'old root identity/session enumeration mismatch')
                for session in sessions:
                    native_sql(user, candidate, 'KILL CONNECTION ' + session + ';', args.host, args.ca, args.trust_manifest)
                rejected(lambda: old.query('SELECT 1;'))
                require(native_sql(user, candidate, 'SELECT CURRENT_USER();', args.host, args.ca, args.trust_manifest).strip() == 'root@%', 'new root credential failed')
            finally:
                old.close()
                if changed:
                    native_sql(user, candidate, "ALTER USER 'root'@'%' IDENTIFIED BY '" + original + "';", args.host, args.ca, args.trust_manifest)
    finally:
        Path(candidate_path).unlink(missing_ok=True)


def native_host_boundaries(args, root, prefix):
    user = prefix + '_hostbound'
    secret = secrets.token_hex(24)
    # Three valid DNS labels isolate the native byte bound from client resolution.
    allowed = 'a' * 63 + '.' + 'b' * 62 + '.c'
    rejected_host = 'a' * 63 + '.' + 'b' * 63 + '.c'
    require(len(allowed.encode()) == 128 and len(rejected_host.encode()) == 129,
            'invalid native host boundary fixture')
    require(root("SELECT count(*) FROM mysql.user WHERE user='" + user + "';").strip() == '0',
            'native host boundary account is not fixture-owned')
    try:
        root("CREATE USER '" + user + "'@'" + allowed + "' IDENTIFIED BY '" + secret + "' REQUIRE SSL;")
        require(root("SELECT host,OCTET_LENGTH(host) FROM mysql.user WHERE user='" + user + "';").strip() == allowed + '\t128',
                'native 128-byte account host was not stored exactly')
        rejected(lambda: root("CREATE USER '" + user + "'@'" + rejected_host + "' IDENTIFIED BY '" + secret + "' REQUIRE SSL;"))
        require(root("SELECT host,OCTET_LENGTH(host) FROM mysql.user WHERE user='" + user + "';").strip() == allowed + '\t128',
                'rejected 129-byte host created or changed an account')
    finally:
        root("DROP USER IF EXISTS '" + user + "'@'" + allowed + "';")


def initialization_interruptions(args):
    require(os.geteuid() == 0, 'offline initializer drill requires operator root')
    from material import publish
    original = password(args.root_secret_file)
    initializer = Path(__file__).resolve().parents[1] / 'platform-init.py'
    # The child runs the production main/DDL/material helpers, then dies at a real
    # side-effect boundary. Only its root-owned scratch materials are redirected.
    child = r'''
import json, os, pathlib, runpy, sys
entry, directory, flags, fault = sys.argv[1:]
sys.path.insert(0, str(pathlib.Path(entry).parent))
main = runpy.run_path(entry)['main']
scope = main.__globals__
actual_sql = scope['native_sql']
actual_publish = scope['publish']
actual_unlink = pathlib.Path.unlink
tenant = json.loads(flags)[json.loads(flags).index('--tenant') + 1]
def sql(*values, **kwargs):
    statement = values[2].lstrip()
    if fault == 'readonly' and statement.startswith(('CREATE ', 'GRANT ', 'ALTER ', 'DROP ', 'REVOKE ')):
        os._exit(95)
    result = actual_sql(*values, **kwargs)
    if ((fault == 'create' and statement.startswith('CREATE USER '))
            or (fault == 'grant' and statement.startswith('GRANT '))
            or (fault == 'cap' and 'MAX_USER_CONNECTIONS' in statement)
            or (fault == 'tenant_root' and values[0] == 'root@' + tenant and statement.startswith("ALTER USER 'root'") and 'IDENTIFIED BY' in statement)
            or (fault == 'sys_root' and values[0] == 'root@sys' and statement.startswith("ALTER USER 'root'") and 'IDENTIFIED BY' in statement)):
        os._exit(91)
    return result
def publish(path, *values, **kwargs):
    actual_publish(path, *values, **kwargs)
    if (fault == 'public' and pathlib.Path(path).name == 'init.env') or (fault == 'done' and pathlib.Path(path).name == 'init.done'):
        os._exit(91)
def unlink(path, *values, **kwargs):
    actual_unlink(path, *values, **kwargs)
    if fault == 'retire' and path == pathlib.Path(directory) / 'root-init/root.env':
        os._exit(91)
scope['native_sql'] = sql
scope['publish'] = publish
pathlib.Path.unlink = unlink
main(json.loads(flags), pathlib.Path(directory))
'''
    cases = ('fresh', 'create', 'grant', 'cap', 'tenant_root', 'sys_root', 'public', 'done', 'retire')
    for fault in cases:
        prefix = 'u1' + secrets.token_hex(4)
        user = prefix + ('_adminA' if fault == 'create' else '_platform')
        recovery = secrets.token_hex(24)
        platform_secret = secrets.token_hex(24)
        with tempfile.TemporaryDirectory(prefix='u1-init-', dir='/run') as directory:
            material = Path(directory)
            for part in ('root-init', 'root-recovery', 'platform', 'public-trust'):
                (material / part).mkdir(mode=0o700)
            publish(material / 'root-init/root.env', ('ROOT_PASSWORD=' + original + '\n').encode())
            publish(material / 'root-recovery/root-recovery.secret', (recovery + '\n').encode())
            publish(material / 'platform/platform-db-password.secret', (platform_secret + '\n').encode())
            publish(material / 'public-trust/ca.pem', read_checked(args.ca, mode=0o444), mode=0o444)
            publish(material / 'public-trust/tls-manifest.json', read_checked(args.trust_manifest, mode=0o444), mode=0o444)
            flags = ['--prefix', prefix, '--username', user, '--sql-host', args.account_host,
                     '--root-sql-host', '%', '--host-max-bytes', '128', '--runtime-uid', '0',
                     '--tenant', args.tenant, '--wildcard-isolated-network']

            def invoke(options, crash='readonly'):
                environment = os.environ.copy()
                environment['OB_APPROVED_SQL_HOST'] = args.host
                return subprocess.run([sys.executable, '-c', child, str(initializer), directory,
                                       json.dumps(options), crash], env=environment,
                                      capture_output=True, timeout=180)

            def root_sql(tenant, secret, statement):
                return native_sql('root@' + tenant, secret, statement, args.host, args.ca, args.trust_manifest)

            def root_material(tenant):
                for candidate in (recovery, original):
                    try:
                        identity = root_sql(tenant, candidate, 'SELECT CURRENT_USER();').strip()
                    except RuntimeError:
                        continue
                    require(identity == 'root@%', 'initializer drill authenticated a different root')
                    return candidate
                raise RuntimeError('initializer drill lost both prepared root materials')

            root = lambda statement: root_sql(args.tenant, root_material(args.tenant), statement)
            try:
                for tenant in (args.tenant, 'sys'):
                    require(root_sql(tenant, original, 'SELECT CURRENT_USER();').strip() == 'root@%',
                            'initializer drill requires matching original roots')
                require(root("SELECT count(*) FROM mysql.user WHERE user='" + user + "';").strip() == '0',
                        'initializer drill account is not fixture-owned')
                if fault == 'fresh':
                    root("CREATE USER '" + user + "'@'" + args.account_host + "' IDENTIFIED BY '" + platform_secret + "' REQUIRE SSL;")
                    try:
                        require(invoke(flags).returncode not in (0, 95)
                                and not (material / 'root-init/initjournal.json').exists(),
                                'fresh initializer adopted an existing file-matching account')
                        require(invoke(flags + ['--resume']).returncode not in (0, 95),
                                'resume adopted an account without prepared initialization binding')
                        require(root("SELECT host,ssl_type,max_user_connections FROM mysql.user WHERE user='" + user + "';").strip()
                                == args.account_host + '\tANY\t0',
                                'unbound account refusal changed native state')
                    finally:
                        root("DROP USER '" + user + "'@'" + args.account_host + "';")
                result = invoke(flags, fault)
                require(result.returncode == (0 if fault == 'fresh' else 91),
                        'actual initializer did not reach requested native fault boundary: ' + fault + ' (exit ' + str(result.returncode) + ')')
                journal_path = material / 'root-init/initjournal.json'
                journal_before = read_checked(journal_path)
                accounts_before = root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;')
                require(invoke(flags).returncode not in (0, 95), 'fresh mode adopted interrupted or completed initialization')
                if fault == 'create':
                    for field, wrong in (('--prefix', prefix + 'x'), ('--username', prefix + '_adminWrong'),
                                         ('--sql-host', 'wrong.invalid'), ('--tenant', 'wrongtenant'),
                                         ('--runtime-uid', '10001')):
                        options = flags.copy()
                        options[options.index(field) + 1] = wrong
                        require(invoke(options + ['--resume']).returncode not in (0, 95),
                                'wrong initialization binding was not refused before mutation: ' + field)
                    require(invoke(flags + ['--control-max', '6', '--resume']).returncode not in (0, 95),
                            'wrong initialization cap binding was not refused')
                    require(read_checked(journal_path) == journal_before
                            and root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;') == accounts_before,
                            'wrong initialization binding mutated journal or native accounts')
                    for path in (material / 'root-init/root.env', material / 'root-recovery/root-recovery.secret',
                                 material / 'platform/platform-db-password.secret'):
                        retained = read_checked(path)
                        publish(path, (secrets.token_hex(24) + '\n').encode())
                        state = root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;')
                        try:
                            require(invoke(flags + ['--resume']).returncode not in (0, 95),
                                    'changed prepared material was accepted for resume')
                            require(read_checked(journal_path) == journal_before
                                    and root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;') == state,
                                    'changed prepared material mutated initialization state')
                        finally:
                            publish(path, retained)
                    for mutation, restore in (("GRANT SELECT ON *.* TO '" + user + "'@'" + args.account_host + "';",
                                               "REVOKE SELECT ON *.* FROM '" + user + "'@'" + args.account_host + "';"),
                                              ("ALTER USER '" + user + "'@'" + args.account_host + "' WITH MAX_USER_CONNECTIONS 1;",
                                               "ALTER USER '" + user + "'@'" + args.account_host + "' WITH MAX_USER_CONNECTIONS 0;"),
                                              ("ALTER USER '" + user + "'@'" + args.account_host + "' IDENTIFIED BY '" + secrets.token_hex(24) + "';",
                                               "ALTER USER '" + user + "'@'" + args.account_host + "' IDENTIFIED BY '" + platform_secret + "';"),
                                              ("ALTER USER '" + user + "'@'" + args.account_host + "' REQUIRE NONE;",
                                               "ALTER USER '" + user + "'@'" + args.account_host + "' REQUIRE SSL;")):
                        root(mutation)
                        state = root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;')
                        grant_state = root("SHOW GRANTS FOR '" + user + "'@'" + args.account_host + "';")
                        try:
                            require(invoke(flags + ['--resume']).returncode not in (0, 95),
                                    'unbound preexisting platform privileges/cap/secret were reused')
                            require(read_checked(journal_path) == journal_before
                                    and root('SELECT user,host,ssl_type,max_user_connections FROM mysql.user ORDER BY user,host;') == state
                                    and root("SHOW GRANTS FOR '" + user + "'@'" + args.account_host + "';") == grant_state,
                                    'unbound account state was changed during resume rejection')
                        finally:
                            root(restore)
                    alternate = 'other.invalid'
                    root("CREATE USER '" + user + "'@'" + alternate + "' IDENTIFIED BY '" + platform_secret + "' REQUIRE SSL;")
                    try:
                        require(invoke(flags + ['--resume']).returncode not in (0, 95),
                                'resume adopted a same-name different-host account')
                    finally:
                        root("DROP USER '" + user + "'@'" + alternate + "';")
                if fault != 'fresh':
                    require(invoke(flags + ['--resume'], 'none').returncode == 0,
                            'actual initializer could not resume native interruption: ' + fault)
                require(not (material / 'root-init/root.env').exists(), 'startup root secret was not retired')
                require(json.loads(read_checked(journal_path))['retirement'] == 'done',
                        'root retirement was not durably completed')
                require(json.loads(read_checked(material / 'platform/init.done'))['username'] == user,
                        'public init done binding mismatch')
                require(read_checked(material / 'platform/init.env') ==
                        (f'PLATFORM_DB_USER={user}\nPLATFORM_DB_PASSWORD_FILE={material / "platform/platform-db-password.secret"}\nPLATFORM_DB_SQL_HOST={args.account_host}\n').encode(),
                        'public init environment was not durably published before retirement')
                require(native_sql(user + '@' + args.tenant, platform_secret, 'SELECT CURRENT_USER();',
                                   args.host, args.ca, args.trust_manifest).strip() == user + '@' + args.account_host,
                        'resumed platform secret selected the wrong canonical account')
                for tenant in (args.tenant, 'sys'):
                    require(root_sql(tenant, password(material / 'root-recovery/root-recovery.secret'), 'SELECT CURRENT_USER();').strip() == 'root@%',
                            'post-retirement recovery material did not authenticate root')
                    rejected(lambda tenant=tenant: root_sql(tenant, original, 'SELECT 1;'))
                require(invoke(flags + ['--resume']).returncode == 0,
                        'completed resume attempted account/grant/root mutation')
            finally:
                # This drill owns no business DB; only its synthetic user and the
                # isolated fixture's two root credentials are changed/restored.
                for tenant in (args.tenant, 'sys'):
                    current = root_material(tenant)
                    root_sql(tenant, current, "ALTER USER 'root'@'%' IDENTIFIED BY '" + original + "';")
                    root_sql(tenant, original, "ALTER USER 'root'@'%' REQUIRE SSL;")
                root_sql(args.tenant, original, "DROP USER IF EXISTS '" + user + "'@'" + args.account_host + "';")
    return list(cases)


def log_paths(home):
    directory = Path(home) / 'log'
    require(directory.is_dir(), 'actual observer log directory required')
    paths = [path for path in directory.rglob('*') if path.is_file()]
    require(paths, 'actual observer logs unavailable')
    return paths


def run(args):
    require(os.environ.get('MOLTIS_U1_ISOLATED') == '1', 'isolated acceptance consent required')
    require(args.tenant and re.fullmatch(r'[a-z][a-z0-9]{0,15}', args.tenant), 'invalid OB tenant')
    require(args.host_max_bytes == 128, 'account-host bound must match measured fixed release')
    secret = password(args.root_secret_file)
    trust(args.ca, args.trust_manifest)
    root_user = 'root@' + args.tenant
    root = lambda sql: native_sql(root_user, secret, sql, args.host, args.ca, args.trust_manifest)
    version = root('SELECT VERSION();').strip()
    require(version == '5.7.25-OceanBase_CE-v5.0.1.0', 'wrong release')
    status = root('status\n')
    require('100000042026072912-071f4d9c82841d3ecb2d0004ef9213766308b714' in status, 'wrong build/source')
    require(re.search(r'SSL:.*Cipher in use', status), 'native TLS was not active')
    rejected(lambda: native_sql(root_user, secret, 'SELECT 1;', args.host,
                               args.ca, args.trust_manifest, plaintext=True))
    if args.tenant_readback:
        require(args.image_digest and re.fullmatch(r'[^\s]+@sha256:[0-9a-f]{64}', args.image_digest),
                'cryptographically verified image digest required for offline readback')
        actual_tenant = root('SELECT tenant_name FROM oceanbase.DBA_OB_TENANTS;').strip()
        require(actual_tenant == args.tenant, 'actual OceanBase tenant differs from approved tenant')
        readback = {'image_digest': args.image_digest,
                    'build': root('SELECT @@version_comment;').strip(),
                    'sql_host': args.approved_sql_host or args.host,
                    'ca_sha256': hashlib.sha256(read_checked(args.ca, mode=0o444)).hexdigest(),
                    'root_current_user': root('SELECT CURRENT_USER();').strip(),
                    'tenant_name': actual_tenant}
        from material import publish
        publish(args.tenant_readback, json.dumps(readback, sort_keys=True).encode(), mode=0o444)
    prefix = 'u1' + secrets.token_hex(4)
    platform_name = prefix + '_platform'
    tenant_name = prefix + '_u_a_b'
    own = prefix + '_t_a_b'
    collision = prefix + '_t_a1b'
    outside = prefix + '_foreign'
    control = prefix + '_control'
    platform_secret = secrets.token_hex(24)
    tenant_secret = secrets.token_hex(24)
    new_tenant_secret = secrets.token_hex(24)
    created_users, created_dbs = [], []
    held = ExitStack()
    report = {'version': version, 'account_host_max_bytes': 128, 'gates': {}}
    try:
        values = dict(USERNAME=platform_name, SQL_HOST=args.account_host,
                      PASSWORD=platform_secret, TENANT_PATTERN=prefix + r'\_t\_%',
                      ESCAPED_TARGET_PATTERN=prefix + r'\\_t\\_%',
                      CONTROL_PATTERN=prefix + r'\_control', CONNECTION_CAP=14)
        template = Path(__file__).resolve().parents[1] / 'platform-grants.sql'
        root(Template(template.read_text()).substitute(values))
        created_users.append(platform_name)
        platform_user = platform_name + '@' + args.tenant
        platform = lambda sql: native_sql(platform_user, platform_secret, sql,
                                          args.host, args.ca, args.trust_manifest)
        require(platform('SELECT CURRENT_USER();').strip() == platform_name + '@' + args.account_host,
                'platform authenticated with wrong account-host identity')
        for db in (own, collision, control):
            platform('CREATE DATABASE ' + identifier(db) + ';')
            created_dbs.append(db)
        root('CREATE DATABASE ' + identifier(outside) + ';')
        created_dbs.append(outside)
        platform("CREATE USER '" + tenant_name + "'@'" + args.account_host +
                 "' IDENTIFIED BY '" + tenant_secret + "' REQUIRE SSL;")
        created_users.append(tenant_name)
        escaped_own = own.replace('_', r'\_')
        platform('GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,DROP,INDEX,REFERENCES ON `' +
                 escaped_own + "`.* TO '" + tenant_name + "'@'" + args.account_host + "';")
        platform("ALTER USER '" + tenant_name + "'@'" + args.account_host +
                 "' WITH MAX_USER_CONNECTIONS 12;")
        tenant_user = tenant_name + '@' + args.tenant
        tenant = lambda sql: native_sql(tenant_user, tenant_secret, sql,
                                        args.host, args.ca, args.trust_manifest)
        for db in (own, collision, outside):
            root('CREATE TABLE ' + identifier(db) + '.boundary(id INT PRIMARY KEY); INSERT INTO ' +
                 identifier(db) + '.boundary VALUES(1);')
        require(tenant('SELECT id FROM ' + identifier(own) + '.boundary;').strip() == '1',
                'tenant own database inaccessible')
        tenant('CREATE TABLE ' + identifier(own) + '.fk_own(id INT PRIMARY KEY,parent_id INT,FOREIGN KEY(parent_id) REFERENCES ' + identifier(own) + '.boundary(id));')
        rejected(lambda: tenant('CREATE TABLE ' + identifier(own) + '.fk_foreign(id INT PRIMARY KEY,parent_id INT,FOREIGN KEY(parent_id) REFERENCES ' + identifier(collision) + '.boundary(id));'))
        rejected(lambda: tenant('SELECT id FROM ' + identifier(collision) + '.boundary;'))
        rejected(lambda: tenant('SELECT id FROM ' + identifier(outside) + '.boundary;'))
        rejected(lambda: platform('SELECT id FROM ' + identifier(outside) + '.boundary;'))
        rejected(lambda: platform('GRANT SELECT ON ' + identifier(outside) + ".* TO '" +
                                 tenant_name + "'@'" + args.account_host + "';"))
        report['gates']['platform_minimum_grants_and_tenant_collision'] = 'passed'
        # Fourteen real simultaneous native sessions cover both gateway budgets,
        # two tool sessions and their two dedicated management slots.
        for _ in range(14):
            client = Held(platform_user, platform_secret, args.host, args.ca)
            held.callback(client.close)
        rejected(lambda: platform('SELECT 1;'))
        held.close()
        require(platform('SELECT 1;').strip() == '1', 'platform cap did not recover after release')
        report['gates']['platform_connection_cap_14'] = 'passed'
        old = Held(tenant_user, tenant_secret, args.host, args.ca)
        held.callback(old.close)
        platform("ALTER USER '" + tenant_name + "'@'" + args.account_host +
                 "' IDENTIFIED BY '" + new_tenant_secret + "';")
        rejected(lambda: tenant('SELECT 1;'))
        require(old.query('SELECT 1;') == '1', 'ALTER unexpectedly changed held-session contract')
        identity = root('SELECT USER FROM information_schema.PROCESSLIST WHERE ID=' + old.session_id + ';').strip()
        require(identity == tenant_name, 'native session ID no longer belongs to expected account')
        root('KILL CONNECTION ' + old.session_id + ';')
        rejected(lambda: old.query('SELECT 1;'))
        require(native_sql(tenant_user, new_tenant_secret, 'SELECT 1;', args.host,
                           args.ca, args.trust_manifest).strip() == '1', 'new tenant secret failed')
        report['gates']['rotation_and_native_old_session_termination'] = 'passed'
        for name, expected in [('enable_sql_audit', 'False'), ('audit_log_query_sql', 'NONE'),
                               ('audit_log_enable', 'False')]:
            text = root("SHOW PARAMETERS LIKE '" + name + "';")
            rows = [row.split('\t') for row in text.splitlines()]
            require(rows and all(row[6].lower() == expected.lower() for row in rows),
                    'managed log control readback mismatch: ' + name)
        marker = 'U1LogCanary' + secrets.token_hex(24)
        root("CREATE USER '" + prefix + "_audit'@'" + args.account_host +
             "' IDENTIFIED BY '" + marker + "' REQUIRE SSL;")
        created_users.append(prefix + '_audit')
        root("ALTER USER '" + prefix + "_audit'@'" + args.account_host +
             "' IDENTIFIED BY '" + marker + "';")
        root("SELECT '" + marker + "'; SELECT SLEEP(1.1);")
        root('CREATE TABLE ' + identifier(own) + '.log_probe(id INT PRIMARY KEY,content TEXT,vec VECTOR(3),FULLTEXT INDEX ft(content),VECTOR INDEX vi(vec) WITH(distance=cosine,type=hnsw,lib=vsag)) ORGANIZATION HEAP;')
        root('INSERT INTO ' + identifier(own) + ".log_probe VALUES(1,'" + marker + "','[1,0,0]');")
        canary_dsl = json.dumps({'query': {'match': {'content': marker}}, 'size': 1}, separators=(',', ':'))
        canary_hex = canary_dsl.encode().hex()
        root('SELECT id,__score FROM HYBRID_SEARCH(TABLE ' + identifier(own) +
             ".log_probe,_utf8mb4 X'" + canary_hex + "');")
        rejected(lambda: root('SELECT * FROM ' + identifier(own) +
                              ".missing WHERE id='" + marker + "';"))
        verifier = '*' + hashlib.sha1(hashlib.sha1(marker.encode()).digest()).hexdigest().upper()
        needles = [value.lower() for value in [marker.encode(), verifier.encode(), marker.encode().hex().encode(), canary_hex.encode()]]
        paths = log_paths(args.observer_home)
        for path in paths:
            require(not path.is_symlink(), 'unexpected log symlink')
            data = path.read_bytes().lower()
            require(not any(needle in data for needle in needles),
                    'synthetic business value or reusable credential appeared in observer log')
        audit = root("SELECT QUERY_SQL FROM oceanbase.GV$OB_SQL_AUDIT WHERE QUERY_SQL LIKE '%" +
                     marker + "%' AND QUERY_SQL NOT LIKE '%GV$OB_SQL_AUDIT%';")
        require(not audit.strip(), 'synthetic value captured in disabled SQL audit')
        report['gates']['managed_query_values_and_credentials_absent_from_logs'] = 'passed'
        report['log_files_checked'] = len(paths)
        # The actual initializer must reject invalid namespaces before reading
        # credentials or changing accounts; testing it avoids duplicated policy.
        initializer = Path(__file__).resolve().parents[1] / 'platform-init.py'
        common = ['--sql-host', args.account_host, '--root-sql-host', '%',
                  '--host-max-bytes', str(args.host_max_bytes), '--runtime-uid', '10001',
                  '--tenant', args.tenant]
        before = root("SELECT count(*) FROM mysql.user;")
        for prefix_value, user in [('a_t_b', 'a_t_b_platform'), (prefix, 'root'),
                                   (prefix, prefix + '_u_a_b'), (prefix, 'other_platform')]:
            result = subprocess.run([sys.executable, str(initializer), '--prefix', prefix_value,
                                     '--username', user, *common], capture_output=True, timeout=10)
            require(result.returncode != 0, 'initializer accepted forbidden account namespace')
        require(root('SELECT count(*) FROM mysql.user;') == before,
                'rejected namespace changed database accounts')
        report['gates']['initializer_namespace_rejection'] = 'passed'
        native_host_boundaries(args, root, prefix)
        report['gates']['actual_native_account_host_128_129'] = 'passed'
        report['initializer_fault_boundaries'] = initialization_interruptions(args)
        report['gates']['initializer_fresh_and_bound_explicit_resume'] = 'passed'
        root_incident(args)
        report['gates']['root_recovery_compromise_native'] = 'passed'
        print(json.dumps(report, sort_keys=True))
    finally:
        held.close()
        for db in reversed(created_dbs):
            root('SET SESSION recyclebin=OFF; DROP DATABASE IF EXISTS ' + identifier(db) + ';')
        for user in reversed(created_users):
            root("DROP USER IF EXISTS '" + user + "'@'" + args.account_host + "';")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--root-secret-file', default='/run/root-recovery/root-recovery.secret')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--account-host', required=True)
    parser.add_argument('--host-max-bytes', type=int, required=True)
    parser.add_argument('--ca', default='/run/public-trust/ca.pem')
    parser.add_argument('--trust-manifest', default='/run/public-trust/tls-manifest.json')
    parser.add_argument('--observer-home', default='/var/lib/oceanbase')
    parser.add_argument('--tenant-readback')
    parser.add_argument('--image-digest')
    parser.add_argument('--approved-sql-host')
    run(parser.parse_args())
