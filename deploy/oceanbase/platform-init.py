#!/usr/bin/env python3
"""Offline fresh init; interrupted mutations require an explicit bound --resume."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
from string import Template
from material import native_sql, password, publish, read_checked


def main(argv=None, directory=Path('/run')):
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--username')
    parser.add_argument('--sql-host', required=True)
    parser.add_argument('--root-sql-host', required=True)
    parser.add_argument('--host-max-bytes', required=True, type=int, help='actual U1-proven fixed-version account-host bound')
    parser.add_argument('--tenant', default='moltis')
    parser.add_argument('--runtime-uid', required=True, type=int)
    parser.add_argument('--control-max', default=5, type=int)
    parser.add_argument('--isolated-ci', action='store_true')
    parser.add_argument('--ci-cap', type=int)
    parser.add_argument('--wildcard-isolated-network', action='store_true')
    parser.add_argument('--resume', action='store_true', help='explicit offline recovery of this journal-bound initialization')
    args = parser.parse_args(argv)
    if not re.fullmatch('[a-z][a-z0-9]{0,15}', args.prefix):
        raise SystemExit('invalid namespace prefix')
    username = args.username or args.prefix + '_platform'
    production = username == args.prefix + '_platform' or re.fullmatch(re.escape(args.prefix) + '_admin[A-Za-z0-9]+', username)
    if len(username) > 64 or not (production or args.isolated_ci and username == 'ci_e2e_admin' and args.prefix == 'e2e'):
        raise SystemExit('platform username belongs to a different/tenant namespace')
    if not re.fullmatch('[a-z][a-z0-9]{0,15}', args.tenant):
        raise SystemExit('invalid OceanBase tenant')

    def host(value):
        if ':' in value:
            raise ValueError('CE 5.0.1 U1 rejects IPv6 SQL account hosts')
        if value == '%':
            if not (args.isolated_ci or args.wildcard_isolated_network):
                raise ValueError('wildcard requires explicit isolated network/TLS/source firewall policy')
            return value
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9.-]+', value) or any(len(label) > 63 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label) for label in value.split('.')):
                raise ValueError('unsupported SQL account host')
            canonical = value.lower()
        if not 0 < len(canonical.encode()) <= args.host_max_bytes:
            raise ValueError('SQL host exceeds U1-proven bound')
        return canonical

    if args.host_max_bytes != 128:
        raise SystemExit('CE 5.0.1 proven account-host limit is exactly 128 bytes')
    sql_host = host(args.sql_host)
    if args.root_sql_host != '%':
        raise SystemExit('CE 5.0.1 protected root account host is %, not an enforceable source allowlist')
    if not 1 <= args.control_max <= 1000:
        raise SystemExit('finite control pool limit required')
    cap = args.ci_cap if args.isolated_ci else 2 * args.control_max + 4
    if cap is None or not 1 <= cap <= 10000:
        raise SystemExit('explicit finite CI aggregate connection cap required')

    root_path = directory / 'root-init/root.env'
    journal_path = directory / 'root-init/initjournal.json'
    platform_path = directory / 'platform/platform-db-password.secret'
    public_path = directory / 'platform/init.env'
    done_path = directory / 'platform/init.done'
    # ponytail: one offline initializer, serialized on the existing operator directory.
    lock = os.open(root_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(lock)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit('untrusted initialization directory')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recovery = password(directory / 'root-recovery/root-recovery.secret')
        try:
            original = password(root_path)
        except FileNotFoundError:
            original = None
        platform_secret = read_checked(platform_path, uid=args.runtime_uid).decode().strip()
        if not re.fullmatch('[A-Za-z0-9]{32,128}', platform_secret):
            raise SystemExit('platform secret grammar rejected')
        if original == recovery:
            raise SystemExit('startup and recovery root materials must differ')
        template = Path(__file__).with_name('platform-grants.sql').read_text()
        pattern = args.prefix + (r'\_t\_%' if not args.isolated_ci else '%')
        second = args.prefix + (r'\\_t\\_%' if not args.isolated_ci else '%')
        values = dict(USERNAME=username, SQL_HOST=sql_host, PASSWORD=platform_secret,
                      TENANT_PATTERN=pattern, ESCAPED_TARGET_PATTERN=second,
                      CONTROL_PATTERN=args.prefix + r'\_control', CONNECTION_CAP=cap)
        statements = [part.strip() + ';' for part in Template(template).substitute(values).split(';') if part.strip()]
        statements[0] = '\n'.join(line for line in statements[0].splitlines() if not line.startswith('--'))
        mutations = statements[:-2]
        digest = lambda value: hashlib.sha256(value).hexdigest()
        binding = dict(tenant=args.tenant, prefix=args.prefix, username=username, sql_host=sql_host,
                       root_host='%', runtime_uid=args.runtime_uid, connection_cap=cap,
                       isolated_ci=args.isolated_ci, platform_secret_file=str(platform_path),
                       sql_endpoint=os.environ.get('OB_APPROVED_SQL_HOST', 'oceanbase'),
                       ca_sha256=digest(read_checked(directory / 'public-trust/ca.pem', mode=0o444)),
                       trust_sha256=digest(read_checked(directory / 'public-trust/tls-manifest.json', mode=0o444)),
                       grants_sha256=digest(template.encode()), platform_sha256=digest(platform_secret.encode()),
                       recovery_sha256=digest(recovery.encode()))
        try:
            journal = json.loads(read_checked(journal_path))
        except FileNotFoundError:
            journal = None
        if args.resume:
            if journal is None or journal.get('schema_version') != 1 or journal.get('binding') != binding:
                raise SystemExit('resume requires the exact durable initialization binding')
            if (type(journal.get('platform_step')) is not int or not 0 <= journal['platform_step'] <= len(mutations)
                    or type(journal.get('platform_pending')) is not bool
                    or set(journal.get('roots', {})) != {args.tenant, 'sys'}
                    or any(value not in ('original', 'rotating', 'recovery') for value in journal['roots'].values())
                    or journal.get('publication') not in ('pending', 'done')
                    or journal.get('retirement') not in ('not_started', 'pending', 'done')
                    or not re.fullmatch('[0-9a-f]{64}', journal.get('original_sha256', ''))):
                raise SystemExit('invalid initialization journal phase')
            platform_done = journal['platform_step'] == len(mutations) and not journal['platform_pending']
            roots_done = all(value == 'recovery' for value in journal['roots'].values())
            if (any(value != 'original' for value in journal['roots'].values()) and not platform_done
                    or journal['publication'] == 'done' and not roots_done
                    or journal['retirement'] != 'not_started' and journal['publication'] != 'done'):
                raise SystemExit('inconsistent initialization journal phases')
            if journal['retirement'] == 'done' and original is not None:
                raise SystemExit('retired startup root material must not be restored')
            if original is None:
                if journal['publication'] != 'done' or journal['retirement'] not in ('pending', 'done') or any(value != 'recovery' for value in journal['roots'].values()):
                    raise SystemExit('startup root material missing before durable retirement')
            elif digest(original.encode()) != journal.get('original_sha256'):
                raise SystemExit('startup root material differs from prepared initialization')
        else:
            if journal is not None:
                raise SystemExit('initialization journal exists; explicit offline --resume required')
            if original is None:
                raise SystemExit('fresh initialization requires original root material')
            journal = dict(schema_version=1, binding=binding, original_sha256=digest(original.encode()),
                           platform_step=0, platform_pending=False,
                           roots={args.tenant: 'original', 'sys': 'original'},
                           publication='pending', retirement='not_started')

        public = f'PLATFORM_DB_USER={username}\nPLATFORM_DB_PASSWORD_FILE={platform_path}\nPLATFORM_DB_SQL_HOST={sql_host}\n'.encode()
        done = (json.dumps({key: binding[key] for key in ('tenant', 'prefix', 'username', 'sql_host', 'runtime_uid', 'connection_cap', 'platform_secret_file')}, sort_keys=True) + '\n').encode()
        for path, expected in ((public_path, public), (done_path, done)):
            try:
                actual = read_checked(path, uid=args.runtime_uid)
            except FileNotFoundError:
                if journal['publication'] == 'done':
                    raise SystemExit('durably published initialization material is missing')
            else:
                if not args.resume or actual != expected:
                    raise SystemExit('initialization publication differs from prepared binding')

        def save():
            publish(journal_path, (json.dumps(journal, sort_keys=True) + '\n').encode())

        def authenticated(tenant, secret):
            user = 'root@' + tenant
            if native_sql(user, secret, 'SELECT CURRENT_USER();').strip() != 'root@%':
                raise SystemExit('root authenticated with a different account host')
            if not re.search(r'SSL:.*Cipher in use', native_sql(user, secret, 'status\n')):
                raise SystemExit('native init TLS status did not prove encrypted session')
            query = 'SELECT tenant_name FROM oceanbase.DBA_OB_TENANTS;' if tenant != 'sys' else 'SELECT tenant_name FROM oceanbase.DBA_OB_TENANTS WHERE tenant_id=1;'
            if native_sql(user, secret, query).strip() != tenant:
                raise SystemExit('root authenticated with a different OceanBase tenant')

        roots = {}
        for tenant, phase in journal['roots'].items():
            candidates = [recovery, original] if args.resume else [original]
            for candidate in candidates:
                if candidate is None:
                    continue
                try:
                    authenticated(tenant, candidate)
                except RuntimeError:
                    continue
                roots[tenant] = candidate
                break
            else:
                raise SystemExit('neither prepared root material authenticates this tenant')
            if phase == 'original' and roots[tenant] != original or phase == 'recovery' and roots[tenant] != recovery:
                raise SystemExit('root credential differs from recorded rotation phase')

        def sql(statement):
            return native_sql('root@' + args.tenant, roots[args.tenant], statement)

        def grants(text, batch=False):
            result = {}
            for line in text.splitlines():
                if batch:
                    line = line.replace('\\\\', '\\')
                match = re.fullmatch(r"GRANT (.+) ON (.+) TO '([^']+)'(?:@'([^']+)')?( WITH GRANT OPTION)?", line.rstrip(';'))
                if not match or match[3] != username or (match[4] or '%') != sql_host:
                    raise SystemExit('unexpected platform grant or account identity')
                privileges = frozenset(value.strip() for value in match[1].split(','))
                target, delegated = match[2], bool(match[5])
                if privileges == {'USAGE'} and target == '*.*' and not delegated:
                    continue
                if target in result:
                    raise SystemExit('duplicate platform grant target')
                result[target] = (privileges, delegated)
            return result

        def expected_grants(step):
            result = {}
            for statement in mutations[1:min(step, len(mutations) - 1)]:
                result.update(grants(statement))
            return result

        count = sql(f"SELECT count(*) FROM mysql.user WHERE user='{username}';").strip()
        if not args.resume and count != '0':
            raise SystemExit('existing platform account cannot be classified fresh; offline binding/rotation required')
        if sql(f"SELECT count(*) FROM information_schema.schemata WHERE schema_name='{args.prefix}_control';").strip() != '0':
            raise SystemExit('existing control database is not fresh; refusing mutation')
        step = journal['platform_step']
        if count == '0':
            if step != 0:
                raise SystemExit('prepared platform account is missing')
        else:
            if count != '1' or step == 0 and not journal['platform_pending']:
                raise SystemExit('unexpected existing platform account; refusing adoption')
            identity = native_sql(username + '@' + args.tenant, platform_secret, 'SELECT CURRENT_USER();').strip()
            if identity != username + '@' + sql_host:
                raise SystemExit('canonical platform account mismatch')
            row = sql(f"SELECT host,ssl_type,max_user_connections FROM mysql.user WHERE user='{username}';").strip().split('\t')
            actual_grants = grants(sql(f"SHOW GRANTS FOR '{username}'@'{sql_host}';"), batch=True)
            matched = None
            for possible in (step, step + 1) if journal['platform_pending'] else (step,):
                if possible < 1 or possible > len(mutations):
                    continue
                if row == [sql_host, 'ANY', str(cap if possible == len(mutations) else 0)] and actual_grants == expected_grants(possible):
                    matched = possible
                    break
            if matched is None:
                raise SystemExit('preexisting platform secret/grants/SSL/cap differ from prepared phase')
            journal['platform_step'] = matched
        # All materials, identities and existing SQL state are checked before any mutation.
        if not args.resume or journal['platform_pending']:
            journal['platform_pending'] = False
            save()
        while journal['platform_step'] < len(mutations):
            index = journal['platform_step']
            journal['platform_pending'] = True
            save()
            sql(mutations[index])
            journal['platform_step'] += 1
            journal['platform_pending'] = False
            save()
        identity = native_sql(username + '@' + args.tenant, platform_secret, 'SELECT CURRENT_USER();').strip()
        row = sql(f"SELECT host,ssl_type,max_user_connections FROM mysql.user WHERE user='{username}';").strip().split('\t')
        if identity != username + '@' + sql_host or row != [sql_host, 'ANY', str(cap)] or grants(sql(f"SHOW GRANTS FOR '{username}'@'{sql_host}';"), batch=True) != expected_grants(len(mutations)):
            raise SystemExit('final platform identity/grants/SSL/cap mismatch')

        for tenant in journal['roots']:
            if journal['roots'][tenant] != 'recovery':
                journal['roots'][tenant] = 'rotating'
                save()
                if roots[tenant] != recovery:
                    native_sql('root@' + tenant, roots[tenant], f"ALTER USER 'root'@'%' IDENTIFIED BY '{recovery}';")
                roots[tenant] = recovery
                native_sql('root@' + tenant, recovery, "ALTER USER 'root'@'%' REQUIRE SSL;")
                authenticated(tenant, recovery)
                journal['roots'][tenant] = 'recovery'
                save()
            if native_sql('root@' + tenant, recovery, "SELECT ssl_type FROM mysql.user WHERE user='root' AND host='%';").strip() != 'ANY':
                raise SystemExit('protected root TLS requirement mismatch')
        if journal['publication'] != 'done':
            publish(public_path, public, uid=args.runtime_uid)
            publish(done_path, done, uid=args.runtime_uid)
            journal['publication'] = 'done'
            save()
        if journal['retirement'] != 'done':
            journal['retirement'] = 'pending'
            save()
            root_path.unlink(missing_ok=True)
            os.fsync(lock)
            journal['retirement'] = 'done'
            save()
        print('Offline initialization completed; startup root credential retired. Application receives only public trust and its selected platform secret.')
    finally:
        os.close(lock)


if __name__ == '__main__':
    main()
