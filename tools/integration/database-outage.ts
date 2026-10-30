import { execFileSync } from 'node:child_process'
import { realpath } from 'node:fs/promises'
import { basename, isAbsolute, join } from 'node:path'

const invalid = () => new Error('Database outage requires the exact owned disposable PostgreSQL cluster')

/** Test-only fault. Never accepts a general database URL or an external cluster. */
export async function withIsolatedDatabaseOutage(options: { cluster: string; database: string; psql: string }, during: () => Promise<void>): Promise<void> {
  const { cluster, database, psql } = options
  if (!isAbsolute(cluster) || !/^dsh-go-e2e-[A-Za-z0-9_-]+$/.test(basename(cluster)) || !isAbsolute(psql) ||
      database !== `host=${cluster} port=55439 user=dsh_e2e dbname=postgres sslmode=disable`) throw invalid()
  try { if (await realpath(cluster) !== cluster || await realpath(join(cluster, 'pgdata')) !== join(cluster, 'pgdata')) throw invalid() }
  catch { throw invalid() }
  const execute = (dsn: string, sql: string) => execFileSync(psql, ['-X', '--dbname', dsn, '-v', 'ON_ERROR_STOP=1', '-At'], {
    input: sql, encoding: 'utf8', timeout: 5000, maxBuffer: 64 * 1024,
  }).trim()
  const identity = JSON.parse(execute(database, `select json_build_object('database',current_database(),'user',current_user,'directory',current_setting('data_directory'))`))
  if (identity.database !== 'postgres' || identity.user !== 'dsh_e2e' || identity.directory !== join(cluster, 'pgdata')) throw invalid()
  const admin = `host=${cluster} port=55439 user=dsh_e2e dbname=template1 sslmode=disable`
  try {
    execute(admin, 'alter database postgres allow_connections false')
    execute(admin, "select pg_terminate_backend(pid) from pg_stat_activity where datname='postgres' and backend_type='client backend' and pid<>pg_backend_pid()")
    await during()
  } finally {
    // Also reconcile an uncertain ALTER outcome. The maintenance database stays
    // connected and the outer runner still owns removal of the whole cluster.
    execute(admin, 'alter database postgres allow_connections true')
  }
}
