import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { TestContext } from 'node:test'

/** Verify before loading any artifact code; never fall back after a failed check. */
export async function hostPackageEntry(t: Pick<TestContext, 'after' | 'diagnostic'>): Promise<string> {
  const directory = process.env.REMOTE_TEST_HOST_BUNDLE_DIRECTORY
  const expected = process.env.REMOTE_TEST_HOST_BUNDLE_MANIFEST_SHA256
  if (directory === undefined && expected === undefined) return resolve('host/remote-control/lib/index.js')
  assert.ok(directory && isAbsolute(directory) && expected && /^[0-9a-f]{64}$/.test(expected),
    'bundle tests require an absolute directory and independently pinned manifest SHA-256')
  await mkdir(resolve('.local'), { recursive: true, mode: 0o700 })
  const extraction = await mkdtemp(join(resolve('.local'), 'hbp-'))
  t.after(() => rm(extraction, { recursive: true, force: true }))
  const destination = join(extraction, 'unpacked')
  const tool = fileURLToPath(new URL('../release/host_bundle.py', import.meta.url))
  const checked = JSON.parse(execFileSync('python3', [tool, 'verify', '--directory', directory,
    '--expected-manifest-sha256', expected, '--unpack', destination], { encoding: 'utf8', timeout: 10_000 })) as { manifest_sha256: string; file_count: number }
  assert.equal(checked.manifest_sha256, expected)
  assert.ok(checked.file_count > 0)
  t.diagnostic('Loaded the offline-verified npm Host artifact from a fresh private extraction; the working-tree lib entry is not used in this run.')
  return join(destination, 'package/lib/index.js')
}
