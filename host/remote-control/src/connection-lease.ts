import { ProbeError } from './protocol.js'

export interface HostConnectionClock { wall(): number; monotonic(): number }
const systemClock: HostConnectionClock = { wall: () => Date.now(), monotonic: () => performance.now() }

/** A pong cannot renew the original credential. Wall-clock changes cannot
 * extend the monotonic lifetime accepted from the current hello. */
export class HostConnectionLease {
  private readonly wallStarted: number
  private readonly monotonicStarted: number
  private readonly lifetime: number

  constructor(serverTime: string, expiresAt: string, private readonly clock: HostConnectionClock = systemClock) {
    this.wallStarted = clock.wall()
    this.monotonicStarted = clock.monotonic()
    const server = Date.parse(serverTime), expires = Date.parse(expiresAt)
    if (![this.wallStarted, this.monotonicStarted, server, expires].every(Number.isFinite)
      || this.wallStarted < 0 || this.monotonicStarted < 0 || Math.abs(server - this.wallStarted) > 30_000
      || expires <= server || expires - server > 300_000 || expires <= this.wallStarted) throw new ProbeError('protocol.unsupported')
    this.lifetime = Math.min(expires - this.wallStarted, expires - server)
  }

  remaining(): number {
    const wall = this.clock.wall(), monotonic = this.clock.monotonic()
    if (!Number.isFinite(wall) || !Number.isFinite(monotonic) || wall < this.wallStarted || monotonic < this.monotonicStarted) return 0
    return Math.max(0, Math.min(this.lifetime - (wall - this.wallStarted), this.lifetime - (monotonic - this.monotonicStarted)))
  }
}
