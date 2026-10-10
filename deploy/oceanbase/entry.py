#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
from material import native_sql, password, publish, read_checked, trust

HOME = Path('/var/lib/oceanbase')
UID = 10001
inputs = json.loads(Path('/opt/moltis-oceanbase/image-inputs.json').read_text())
root_path = os.environ.get('OB_ROOT_PASSWORD_FILE', '/run/root-init/root.env')
try:
    root_secret = password(root_path)
except (OSError, ValueError):
    raise SystemExit('trusted nonempty operator root credential file required before observer startup') from None
tenant = os.environ.get('OB_TENANT', 'moltis')
if not re.fullmatch('[a-z][a-z0-9]{0,15}', tenant):
    raise SystemExit('invalid OceanBase tenant')
ca = trust('/run/public-trust/ca.pem', '/run/public-trust/tls-manifest.json')
key = read_checked('/run/server-private/server-key.pem', uid=UID)
cert = read_checked('/run/server-private/server-cert.pem', uid=UID, mode=0o444)
subprocess.run(['openssl', 'verify', '-CAfile', '/run/public-trust/ca.pem', '-verify_hostname', 'oceanbase', '/run/server-private/server-cert.pem'], check=True, stdout=subprocess.DEVNULL)
subprocess.run(['openssl', 'x509', '-in', '/run/server-private/server-cert.pem', '-checkend', '0', '-noout'], check=True, stdout=subprocess.DEVNULL)
cert_public = subprocess.check_output(['openssl', 'x509', '-pubkey', '-noout'], input=cert)
key_public = subprocess.check_output(['openssl', 'pkey', '-pubout'], input=key)
if cert_public != key_public:
    raise SystemExit('server certificate/key mismatch')
for part in ['wallet', 'store', 'store/clog', 'store/slog', 'store/sstable', 'etc', 'etc2', 'etc3', 'log', 'run']:
    path = HOME / part
    path.mkdir(exist_ok=True, mode=0o700)
    os.chown(path, UID, UID)
publish(HOME / 'wallet/ca.pem', ca, uid=UID, mode=0o444)
publish(HOME / 'wallet/server-cert.pem', cert, uid=UID, mode=0o444)
publish(HOME / 'wallet/server-key.pem', key, uid=UID)
observer = Path('/opt/moltis-oceanbase/observer-path').read_text().strip()
os.environ['LD_LIBRARY_PATH'] = str(Path(observer).parent.parent / 'lib') + ':' + os.environ.get('LD_LIBRARY_PATH', '')
version = subprocess.check_output([observer, '-V'], stderr=subprocess.STDOUT, text=True)
if any(value not in version for value in ['5.0.1.0', '100000042026072912', inputs['oceanbase_source_commit']]):
    raise SystemExit('fixed observer build/source mismatch')
ip = socket.gethostbyname(socket.gethostname())
options = 'memory_limit=6G,system_memory=1G,datafile_size=5G,log_disk_size=5G,cpu_count=4,ssl_client_authentication=true,enable_sql_audit=false,enable_record_trace_log=false,syslog_level=ERROR,enable_syslog_wf=false,enable_syslog_recycle=true,max_syslog_file_count=4'
args = [observer, '-N', '-p', '2881', '-P', '2882', '-z', 'zone1', '-n', 'moltis', '-c', '1', '-I', ip, '-r', ip + ':2882:2881', '-d', str(HOME / 'store'), '-o', options]
def drop_identity():
    os.setgroups([])
    os.setgid(UID)
    os.setuid(UID)
fresh = not (HOME / 'etc/observer.config.bin').exists()
if not fresh and read_checked(HOME / '.initialized', uid=UID).decode().strip() != tenant:
    raise RuntimeError('existing data has no matching completed initialization; refusing repair/reset before observer startup')
process = subprocess.Popen(args, cwd=HOME, preexec_fn=drop_identity)
def stop(*_):
    process.send_signal(signal.SIGTERM)
    process.wait(timeout=60)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    # First accepted SQL is already VerifyIdentity TLS. Never invoke upstream obd plaintext bootstrap.
    for attempt in range(180):
        if process.poll() is not None:
            raise RuntimeError('observer exited before TLS SQL readiness')
        try:
            native_sql('root@sys', '' if fresh else root_secret, 'SELECT 1;', host='127.0.0.1')
            break
        except RuntimeError:
            time.sleep(2)
    else:
        raise RuntimeError('TLS SQL readiness deadline expired')
    if fresh:
        native_sql('root@sys', '', f"ALTER SYSTEM BOOTSTRAP ZONE 'zone1' SERVER '{ip}:2882';", host='127.0.0.1')
        for attempt in range(90):
            try:
                native_sql('root@sys', '', 'SELECT count(*) FROM mysql.user;', host='127.0.0.1')
                break
            except RuntimeError:
                if process.poll() is not None:
                    raise RuntimeError('observer exited while waiting for system schema')
                time.sleep(2)
        else:
            raise RuntimeError('bootstrap system schema readiness deadline expired')
        native_sql('root@sys', '', "ALTER SYSTEM SET audit_log_query_sql='NONE' TENANT=all; ALTER SYSTEM SET audit_log_enable=false TENANT=all;", host='127.0.0.1')
        native_sql('root@sys', '', f"ALTER USER 'root'@'%' IDENTIFIED BY '{root_secret}'; ALTER USER 'root'@'%' REQUIRE SSL;", host='127.0.0.1')
        native_sql('root@sys', root_secret, "ALTER SYSTEM SET __min_full_resource_pool_memory=1073741824; ALTER RESOURCE UNIT sys_unit_config MEMORY_SIZE='1G', LOG_DISK_SIZE='2G'; CREATE RESOURCE UNIT moltis_unit MAX_CPU=2, MIN_CPU=2, MEMORY_SIZE='3G', LOG_DISK_SIZE='2G';", host='127.0.0.1')
        for attempt in range(90):
            allocation = native_sql('root@sys', root_secret, 'SELECT MEM_ASSIGNED,LOG_DISK_ASSIGNED FROM oceanbase.GV$OB_SERVERS;', host='127.0.0.1').strip().split()
            if len(allocation) == 2 and int(allocation[0]) <= 1073741824 and int(allocation[1]) <= 2147483648:
                break
            if process.poll() is not None:
                raise RuntimeError('observer exited while waiting for system unit shrink')
            time.sleep(2)
        else:
            raise RuntimeError('system unit shrink readiness deadline expired')
        native_sql('root@sys', root_secret, "CREATE RESOURCE POOL moltis_pool UNIT='moltis_unit', UNIT_NUM=1, ZONE_LIST=('zone1');" + f"CREATE TENANT {tenant} RESOURCE_POOL_LIST=('moltis_pool') SET ob_compatibility_mode='mysql', ob_tcp_invited_nodes='%';", host='127.0.0.1')
        for attempt in range(90):
            try:
                native_sql('root@' + tenant, '', 'SELECT count(*) FROM mysql.user;', host='127.0.0.1')
                break
            except RuntimeError:
                if process.poll() is not None:
                    raise RuntimeError('observer exited while waiting for user tenant')
                time.sleep(2)
        else:
            raise RuntimeError('user tenant readiness deadline expired')
        native_sql('root@sys', root_secret, f"ALTER SYSTEM SET audit_log_query_sql='NONE' TENANT={tenant}; ALTER SYSTEM SET audit_log_enable=false TENANT={tenant};", host='127.0.0.1')
        native_sql('root@' + tenant, '', f"ALTER USER 'root'@'%' IDENTIFIED BY '{root_secret}'; ALTER USER 'root'@'%' REQUIRE SSL;", host='127.0.0.1')
        publish(HOME / '.initialized', (tenant + '\n').encode(), uid=UID)
    for user in ['root@sys', 'root@' + tenant]:
        for attempt in range(90):
            try:
                status = native_sql(user, root_secret, 'status\n', host='127.0.0.1')
                break
            except RuntimeError:
                if process.poll() is not None:
                    raise RuntimeError('observer exited while waiting for encrypted tenant readiness')
                time.sleep(2)
        else:
            raise RuntimeError('encrypted tenant readiness deadline expired')
        if not re.search(r'SSL:.*Cipher in use', status):
            raise RuntimeError('native client did not prove encrypted session')
        try:
            native_sql(user, root_secret, 'SELECT 1;', host='127.0.0.1', plaintext=True)
        except RuntimeError:
            pass
        else:
            raise RuntimeError('production root accepts plaintext')
    publish('/run/oceanbase-ready', b'TLS identity and plaintext rejection checked\n', mode=0o444)
    raise SystemExit(process.wait())
finally:
    Path('/run/oceanbase-ready').unlink(missing_ok=True)
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=60)
