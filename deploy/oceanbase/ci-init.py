#!/usr/bin/env python3
"""One explicit initializer per isolated CI service; never invoked by the app."""
import hashlib
import json
import os
from pathlib import Path
import re
from string import Template
from material import native_sql, password, publish, trust

host = '127.0.0.1'
root_path = '/run/root-init/root.env' if Path('/run/root-init/root.env').exists() else '/run/root-recovery/root-recovery.secret'
root = password(root_path)
root_user = 'root@moltis'
def sql(statement):
    return native_sql(root_user, root, statement, host=host)
trust_bytes = trust('/run/public-trust/ca.pem', '/run/public-trust/tls-manifest.json')
status = sql('status\n')
if not re.search(r'SSL:.*Cipher in use', status):
    raise SystemExit('isolated initializer requires verified native TLS')
actual_tenant = sql('SELECT tenant_name FROM oceanbase.DBA_OB_TENANTS;').strip()
if actual_tenant != 'moltis':
    raise SystemExit('actual OceanBase tenant differs from approved isolated target')
secret = password('/run/platform/platform-db-password.secret')
if sql("SELECT count(*) FROM mysql.user WHERE user='ci_e2e_admin';").strip() != '0':
    raise SystemExit('isolated CI admin already exists: do not reinitialize/ALTER shared account')
values = dict(USERNAME='ci_e2e_admin', SQL_HOST='%', PASSWORD=secret, TENANT_PATTERN='e2e%', ESCAPED_TARGET_PATTERN='e2e%', CONTROL_PATTERN=r'e2e\_control', CONNECTION_CAP=128)
result = sql(Template(Path(__file__).with_name('platform-grants.sql').read_text()).substitute(values))
if result.rstrip().splitlines()[-1] != '128':
    raise SystemExit('CI finite aggregate cap readback mismatch')
sql('CREATE DATABASE e2e_management CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;')
native_sql('root@sys', root, "ALTER SYSTEM SET enable_sql_audit=false; ALTER SYSTEM SET audit_log_query_sql='NONE' TENANT=all; ALTER SYSTEM SET audit_log_enable=false TENANT=all;", host=host)
sql('SET GLOBAL recyclebin=OFF;')
admin_user = 'ci_e2e_admin@moltis'
actual_build = native_sql(admin_user, secret, 'SELECT @@version_comment;', host=host).strip()
if not all(value in actual_build for value in ['5.0.1.0', '100000042026072912', '071f4d9c82841d3ecb2d0004ef9213766308b714']):
    raise SystemExit('actual build/source mismatch')
Path('/run/ci-client').mkdir(mode=0o700, exist_ok=True)
readback = {'image_digest': os.environ['OCEANBASE_IMAGE_DIGEST'], 'tenant_name': actual_tenant, 'sql_host': '127.0.0.1', 'root_current_user': sql('SELECT CURRENT_USER();').strip(), 'build': actual_build, 'ca_sha256': hashlib.sha256(trust_bytes).hexdigest()}
publish('/run/ci-client/tenant-readback.json', (json.dumps(readback, sort_keys=True) + '\n').encode(), mode=0o444)
publish('/run/ci-client/admin.secret', (secret + '\n').encode())
publish('/run/ci-client/build.txt', (actual_build + '\n').encode(), mode=0o444)
publish('/run/ci-client/native-client.cnf', ('[client]\npassword=' + secret + '\n').encode())
print('Isolated lifecycle account and authenticated native metadata initialized once.')
