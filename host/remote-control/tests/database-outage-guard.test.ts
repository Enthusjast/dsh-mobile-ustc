import test from 'node:test'
import assert from 'node:assert/strict'
import { withIsolatedDatabaseOutage } from '../../../tools/integration/database-outage.js'

test('database fault helper refuses general DSNs and non-owned cluster paths before invoking psql', async () => {
  const cluster = '/tmp/dsh-go-e2e-guard-fixture'
  const database = `host=${cluster} port=55439 user=dsh_e2e dbname=postgres sslmode=disable`
  for (const change of [
    { database: 'postgres://production.example/app' },
    { database: database.replace('dbname=postgres', 'dbname=template1') },
    { database: database + ' password=PRIVATE_TEST_VALUE' },
    { cluster: '/var/lib/postgresql/18/main' },
    { cluster: 'relative/dsh-go-e2e-fixture' },
    { psql: 'psql' },
  ]) {
    let invoked = false
    await assert.rejects(withIsolatedDatabaseOutage({ cluster, database, psql: '/never-invoke-psql', ...change }, async () => { invoked = true }),
      /exact owned disposable PostgreSQL cluster/)
    assert.equal(invoked, false)
  }
})
