import { vi } from 'vitest'

type Handler = (url: URL, init?: RequestInit) => { status?: number; body: unknown } | undefined

/** Replace global fetch with a router over path -> JSON response. Unmatched paths return 404. */
export function mockFetch(routes: Record<string, unknown | Handler>) {
  const calls: { url: string; init?: RequestInit }[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://localhost')
    calls.push({ url: url.pathname + url.search, init })
    const route = routes[url.pathname]
    let status = 200
    let body: unknown = route
    if (typeof route === 'function') {
      const out = (route as Handler)(url, init)
      status = out?.status ?? 200
      body = out?.body
    } else if (route === undefined) {
      status = 404
      body = { error: { code: 'not_found', message: 'Not found', details: null } }
    }
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  })
  vi.stubGlobal('fetch', fn)
  return { fn, calls }
}
