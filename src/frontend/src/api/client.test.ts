import { afterEach, describe, expect, it, vi } from 'vitest'
import { mockFetch } from '../test/mockFetch'
import { ApiError, api, buildUrl } from './client'

afterEach(() => vi.unstubAllGlobals())

describe('api client', () => {
  it('builds query strings without empty values', () => {
    expect(buildUrl('/api/alerts', { severity: '', proto: 'TCP', offset: 0, q: undefined })).toBe(
      '/api/alerts?proto=TCP&offset=0',
    )
  })

  it('turns API error bodies into ApiError with details', async () => {
    mockFetch({
      '/api/predict': () => ({
        status: 422,
        body: {
          error: {
            code: 'request_validation',
            message: 'Request failed validation',
            details: [{ location: 'pkts', message: 'Input should be a valid number' }],
          },
        },
      }),
    })
    const err = await api.predict({ pkts: 'x' }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(422)
    expect((err as ApiError).code).toBe('request_validation')
    expect((err as ApiError).details[0].location).toBe('pkts')
  })

  it('reports an unreachable backend', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
    await expect(api.health()).rejects.toMatchObject({ code: 'network_error' })
    vi.stubGlobal('fetch', vi.fn(async () => new Response('Bad gateway', { status: 502 })))
    await expect(api.health()).rejects.toMatchObject({ code: 'backend_unreachable' })
  })

  it('sends the capture token only when provided', async () => {
    const { calls } = mockFetch({ '/api/network/live/stop': { state: 'stopped' } })
    await api.liveStop()
    await api.liveStop('secret')
    const headers = calls.map((c) => new Headers(c.init?.headers).get('X-Capture-Token'))
    expect(headers).toEqual([null, 'secret'])
  })
})
