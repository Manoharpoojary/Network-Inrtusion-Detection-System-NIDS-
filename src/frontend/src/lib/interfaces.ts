// Ordering of capturable interfaces for the live-capture form.

export interface CapturableInterface {
  name: string
  isUp: boolean
  isLoopback: boolean
  bytesRecv: number
}

/** Up, non-loopback interfaces first, busiest (most bytes received) first: the likely uplink. */
export function rankInterfaces(list: CapturableInterface[]): CapturableInterface[] {
  const tier = (i: CapturableInterface) => (i.isUp ? 0 : 2) + (i.isLoopback ? 1 : 0)
  return [...list].sort((a, b) => tier(a) - tier(b) || b.bytesRecv - a.bytesRecv)
}
