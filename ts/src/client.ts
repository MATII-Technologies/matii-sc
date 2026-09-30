import sodium from 'libsodium-wrappers'
import {
  type KeyPair,
  type ParsedToken,
  decryptAsymmetric,
  kxSeedKeyPair,
  parseToken,
  ready,
  recoverTokenKey,
} from './crypto.ts'

export type Secret = { key: string; value: string; path: string; comment: string; tags: string[]; redacted: boolean }
export type DynamicLease = { id: string; expiresAt: Date; credentials: Record<string, string> }
export type Query = { appId?: string; appName?: string; env: string; path?: string }
export type TokenSource = () => Promise<string>

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(`matii: HTTP ${status}: ${message}`)
    this.status = status
  }
}

type EnvKey = {
  environment: { id: string; name: string; env_type?: string }
  wrapped_seed: string
  wrapped_salt: string
}
type AppKeys = { id: string; name: string; encryption: 'SSE' | 'E2E'; environment_keys: EnvKey[] }
type Bootstrap = { wrapped_key_share: string; apps: AppKeys[] }
type ApiSecret = { key: string; value: string | null; path: string; comment?: string; tags?: string[]; valueRedacted?: boolean }

const isLocal = (host: string) => ['localhost', '127.0.0.1', '[::1]'].includes(host)

/** Exchange a workload identity token (e.g. a Kubernetes projected token) for a service account token. */
export const oidcTokenSource = (opts: {
  apiBase: string
  serviceAccountId: string
  jwt: () => Promise<string>
  ttlSeconds?: number
  fetch?: typeof fetch
}): TokenSource => {
  let current: string | null = null
  let renewAt = 0
  const doFetch = opts.fetch ?? fetch
  return async () => {
    if (current && Date.now() < renewAt) return current
    const response = await doFetch(`${opts.apiBase.replace(/\/+$/, '')}/identities/external/v1/oidc/auth/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        account: { type: 'service', id: opts.serviceAccountId },
        oidc: { token: await opts.jwt() },
        ...(opts.ttlSeconds ? { tokenRequest: { ttl: opts.ttlSeconds } } : {}),
      }),
    })
    const body: any = await response.json().catch(() => ({}))
    if (!response.ok) throw new ApiError(response.status, body?.error ?? response.statusText)
    current = body.authentication.token as string
    renewAt = Date.now() + (body.authentication.TTL * 1000 * 4) / 5
    return current
  }
}

export class MatiiClient {
  private readonly base: string
  private readonly tokens: TokenSource
  private readonly doFetch: typeof fetch
  private bootstrap: { token: string; info: Bootstrap; tokenKey: KeyPair; env: Map<string, KeyPair> } | null = null

  constructor(opts: { host?: string; apiBase?: string; token?: string; tokens?: TokenSource; fetch?: typeof fetch }) {
    const base = (opts.apiBase ?? (opts.host ? `${opts.host.replace(/\/+$/, '')}/service` : '')).replace(/\/+$/, '')
    const url = new URL(base)
    if (url.protocol !== 'https:' && !isLocal(url.hostname)) throw new Error('matii: the API must use https')
    const token = opts.token
    if (!opts.tokens && !token) throw new Error('matii: token or tokens is required')
    this.tokens = opts.tokens ?? (async () => token!)
    this.base = base
    this.doFetch = opts.fetch ?? fetch
  }

  private async request<T>(
    path: string,
    init: { query?: Record<string, string>; headers?: Record<string, string>; method?: string; body?: unknown } = {}
  ): Promise<T> {
    const token: ParsedToken = parseToken(await this.tokens())
    const qs = init.query ? `?${new URLSearchParams(init.query)}` : ''
    const response = await this.doFetch(`${this.base}${path}${qs}`, {
      method: init.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${token.kind} ${token.value}`,
        Accept: 'application/json',
        ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    })
    const body: any = await response.json().catch(() => ({}))
    if (!response.ok) throw new ApiError(response.status, body?.error ?? body?.detail ?? response.statusText)
    return body as T
  }

  private async info() {
    await ready()
    const raw = await this.tokens()
    if (this.bootstrap?.token === raw) return this.bootstrap
    const info = await this.request<Bootstrap>('/secrets/tokens/')
    const tokenKey = recoverTokenKey(parseToken(raw), info.wrapped_key_share)
    this.bootstrap = { token: raw, info, tokenKey, env: new Map() }
    return this.bootstrap
  }

  /**
   * Short-lived credentials from the dynamic secret `name` (e.g. AWS STS credentials).
   * The values are secret: pass them to the process that needs them and do not log them.
   */
  async leaseDynamic(q: Query, name: string, ttlSeconds?: number): Promise<DynamicLease> {
    const boot = await this.info()
    const app = boot.info.apps.find((a) => (q.appId ? a.id === q.appId : a.name.toLowerCase() === q.appName?.toLowerCase()))
    const envKey = app?.environment_keys.find((k) => k.environment.name.toLowerCase() === q.env.toLowerCase())
    if (!app || !envKey) throw new Error('matii: this token has no access to that app/environment')
    const body = await this.request<{ leaseId: string; expiresAt: string; credentials: Record<string, string> }>(
      '/v1/dynamic-secrets/lease/',
      {
        method: 'POST',
        query: { app_id: app.id, env: envKey.environment.name },
        body: { name, path: q.path ?? '/', ...(ttlSeconds ? { ttlSeconds } : {}) },
      }
    )
    return { id: body.leaseId, expiresAt: new Date(body.expiresAt), credentials: body.credentials }
  }

  /** Secrets of one environment. E2EE values are decrypted locally; SSE values arrive decrypted. */
  async secrets(q: Query): Promise<Secret[]> {
    const boot = await this.info()
    const app = boot.info.apps.find((a) => (q.appId ? a.id === q.appId : a.name.toLowerCase() === q.appName?.toLowerCase()))
    const envKey = app?.environment_keys.find((k) => k.environment.name.toLowerCase() === q.env.toLowerCase())
    if (!app || !envKey) throw new Error('matii: this token has no access to that app/environment')
    if (app.encryption === 'SSE') {
      const items = await this.request<ApiSecret[]>('/v1/secrets/', {
        query: { app_id: app.id, env: envKey.environment.name, ...(q.path ? { path: q.path } : {}) },
      })
      return items.map((i) => ({
        key: i.key, value: i.value ?? '', path: i.path, comment: i.comment ?? '', tags: i.tags ?? [],
        redacted: i.value === null || !!i.valueRedacted,
      }))
    }
    let keys = boot.env.get(envKey.environment.id)
    if (!keys) {
      const seed = decryptAsymmetric(envKey.wrapped_seed, boot.tokenKey)
      keys = kxSeedKeyPair(sodium.from_hex(seed))
      boot.env.set(envKey.environment.id, keys)
    }
    const items = await this.request<ApiSecret[]>('/secrets/', {
      headers: { Environment: envKey.environment.id, ...(q.path ? { Path: q.path } : {}) },
    })
    return items.map((i) => ({
      key: decryptAsymmetric(i.key, keys!),
      value: i.value ? decryptAsymmetric(i.value, keys!) : '',
      path: i.path,
      comment: i.comment ? decryptAsymmetric(i.comment, keys!) : '',
      tags: i.tags ?? [],
      redacted: false,
    }))
  }
}

/** key -> value, skipping values the caller may not reveal. */
export const toMap = (secrets: Secret[]): Record<string, string> =>
  Object.fromEntries(secrets.filter((s) => !s.redacted).map((s) => [s.key, s.value]))
