#!/usr/bin/env python3
"""Run only the actual native/Kotlin model composition in a fresh socket-only PG18."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[2]
pg = Path(os.environ.get('REMOTE_TEST_PG_BIN', '/usr/lib/postgresql/18/bin'))
go = os.environ.get('REMOTE_TEST_GO') or shutil.which('go') or '/opt/go1.26.10/bin/go'
if not os.environ.get('REMOTE_TEST_KOTLIN_CLASSPATH'):
    raise SystemExit('Parent-provided REMOTE_TEST_KOTLIN_CLASSPATH is required; this launcher never runs Gradle.')
with tempfile.TemporaryDirectory(prefix='dsh-native-models-') as root:
    data = str(Path(root) / 'pgdata')
    subprocess.run([str(pg / 'initdb'), '-D', data, '--auth=trust', '--username=dsh_e2e', '--no-locale', '--encoding=UTF8'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([str(pg / 'pg_ctl'), '-D', data, '-l', str(Path(root) / 'postgres.log'), '-o', "-h '' -k " + root + ' -p 55439', '-w', 'start'], check=True, stdout=subprocess.DEVNULL)
    try:
        dsn = 'host=' + root + ' port=55439 user=dsh_e2e dbname=postgres sslmode=disable'
        for migration in sorted((repo / 'deploy/sql').glob('*.up.sql')):
            subprocess.run([str(pg / 'psql'), '-X', '--dbname', dsn, '-v', 'ON_ERROR_STOP=1', '-q', '-f', str(migration)], check=True, stdout=subprocess.DEVNULL)
        env = dict(os.environ, REMOTE_TEST_CLUSTER_ROOT=root, REMOTE_TEST_DATABASE_URL=dsn, REMOTE_TEST_PSQL=str(pg / 'psql'), REMOTE_TEST_PG_DUMP=str(pg / 'pg_dump'))
        result = subprocess.run([go, 'test', '-count=1', '-v', '-timeout=3m', '-run', '^TestKotlinNativeModelSelectionOverTLS$', './internal/httpapi'], cwd=repo / 'services/remote', env=env)
    finally:
        subprocess.run([str(pg / 'pg_ctl'), '-D', data, '-m', 'immediate', '-w', 'stop'], check=True, stdout=subprocess.DEVNULL)
raise SystemExit(result.returncode)
