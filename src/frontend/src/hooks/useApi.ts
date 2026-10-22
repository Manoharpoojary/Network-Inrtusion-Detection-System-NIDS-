import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../api/client'

export interface ApiState<T> {
  data: T | null
  error: ApiError | null
  loading: boolean
  reload: () => void
}

interface Result<T> {
  key: string | null
  data: T | null
  error: ApiError | null
}

function toApiError(err: unknown): ApiError {
  return err instanceof ApiError ? err : new ApiError(0, 'unknown', String(err))
}

/**
 * Load data from the API. Re-runs when the (JSON-serialisable) `deps` change; `reload()` re-runs
 * on demand. `loading` is true until the response for the current request arrives; responses for
 * superseded requests are ignored. Previous data stays visible while reloading.
 */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [tick, setTick] = useState(0)
  const [result, setResult] = useState<Result<T>>({ key: null, data: null, error: null })
  const fnRef = useRef(fn)
  const key = `${JSON.stringify(deps)}#${tick}`

  useEffect(() => {
    fnRef.current = fn
  })

  useEffect(() => {
    let cancelled = false
    fnRef.current()
      .then((data) => {
        if (!cancelled) setResult({ key, data, error: null })
      })
      .catch((err: unknown) => {
        if (!cancelled) setResult((prev) => ({ key, data: prev.data, error: toApiError(err) }))
      })
    return () => {
      cancelled = true
    }
  }, [key])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data: result.data, error: result.error, loading: result.key !== key, reload }
}

/** Call `reload` every `ms` milliseconds while `active` is true. */
export function usePolling(reload: () => void, ms: number, active: boolean) {
  useEffect(() => {
    if (!active) return
    const handle = window.setInterval(reload, ms)
    return () => window.clearInterval(handle)
  }, [reload, ms, active])
}
