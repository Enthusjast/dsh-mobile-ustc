/** Reset only after a stable authenticated transport, so ordinary lease renewal
 * does not accumulate past failures while rapid connection flaps still back off. */
export class HostReconnectBackoff {
  private delay = 1000
  private acceptedAt: number | undefined

  constructor(private readonly now: () => number = () => performance.now(), private readonly random: () => number = Math.random) {}

  connected(): void { this.acceptedAt = this.now() }

  retryDelay(): number {
    if (this.acceptedAt !== undefined && this.now() - this.acceptedAt >= 30_000) this.delay = 1000
    this.acceptedAt = undefined
    const current = this.delay
    this.delay = Math.min(current * 2, 60_000)
    return current + Math.floor(this.random() * (current / 4))
  }
}
