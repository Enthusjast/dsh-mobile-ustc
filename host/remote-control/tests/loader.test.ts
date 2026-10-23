import test from 'node:test'
import assert from 'node:assert/strict'
import { request } from 'node:http'
import { lstat, stat } from 'node:fs/promises'
import { host } from './harness.js'

export function http(socketPath: string, path: string, body?: unknown): Promise<{ status: number; frames: any[] }> {
  return new Promise((accept, reject) => {
    const req = request({ socketPath, path, method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json' } }, res => {
      const buffers: Buffer[] = []
      res.on('data', chunk => buffers.push(chunk))
      res.on('end', () => {
        try { accept({ status: res.statusCode!, frames: Buffer.concat(buffers).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line)) }) }
        catch (error) { reject(error) }
      })
      res.on('error', reject)
    })
    req.on('error', reject)
    req.end(body === undefined ? undefined : JSON.stringify(body))
  })
}

test('built ESM plugin loads through the real Cordis Loader and removes its private socket on unload', async () => {
  const h = await host()
  try {
    assert.equal((await stat(h.socketPath)).mode & 0o777, 0o600)
    const probe = await http(h.socketPath, '/m0/probe')
    assert.equal(probe.status, 200)
    assert.equal(probe.frames[0].payload.runtime_id, h.runtimeId)
    assert.match(probe.frames[0].runtime_epoch, /^[a-f0-9-]{36}$/)
    assert.equal(h.errors.length, 0)
    const fiber = h.ctx.loader.resolve('remote').fiber!
    h.ctx.loader.remove('remote')
    await fiber.dispose()
    await fiber.await()
    await h.ctx.loader.await()
    const leftover = await lstat(h.socketPath).catch(error => {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined
      throw error
    })
    assert.equal(leftover, undefined, `plugin unload left an endpoint behind: ${leftover?.isSocket() ? 'socket' : 'file'} dev=${leftover?.dev} ino=${leftover?.ino}`)
  } finally { await h.close() }
})
