import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import sodium from 'libsodium-wrappers'
import {
  decryptAsymmetric,
  encryptAsymmetric,
  keyDigest,
  kxSeedKeyPair,
  parseToken,
  ready,
  recoverTokenKey,
} from '../src/crypto.ts'
import { MatiiClient, toMap } from '../src/client.ts'

const v = JSON.parse(readFileSync(new URL('../../go/matii/testdata/vectors.json', import.meta.url), 'utf8'))

test('full E2EE chain matches the backend vectors', async () => {
  await ready()
  const tokenKey = recoverTokenKey(parseToken(v.token), v.wrapped_key_share)
  assert.equal(sodium.to_hex(tokenKey.privateKey), v.kx_private)
  const seed = decryptAsymmetric(v.wrapped_seed, tokenKey)
  const salt = decryptAsymmetric(v.wrapped_salt, tokenKey)
  assert.equal(seed, v.env_seed)
  const envKey = kxSeedKeyPair(sodium.from_hex(seed))
  assert.equal(sodium.to_hex(envKey.publicKey), v.env_public)
  for (const s of v.secrets) {
    assert.equal(decryptAsymmetric(s.key_ciphertext, envKey), s.key)
    assert.equal(decryptAsymmetric(s.value_ciphertext, envKey), s.value)
    assert.equal(keyDigest(s.key, salt), s.key_digest)
  }
})

test('round trip, tampering and wrong keys', async () => {
  await ready()
  const envKey = kxSeedKeyPair(sodium.from_hex(v.env_seed))
  const ct = encryptAsymmetric('round trip ✓', envKey.publicKey)
  assert.equal(decryptAsymmetric(ct, envKey), 'round trip ✓')
  assert.throws(() => decryptAsymmetric(ct.slice(0, -4) + 'AAAA', envKey))
  assert.throws(() => decryptAsymmetric(ct, kxSeedKeyPair(new Uint8Array(32))))
})

test('token parsing', () => {
  assert.equal(parseToken(v.token).kind, 'ServiceAccount')
  for (const bad of ['', 'pss_service:v1:a:b:c:d', 'x:v2:a:b:c:d']) assert.throws(() => parseToken(bad))
})

test('client: SSE values and redaction', async () => {
  const fake: typeof fetch = async (input) => {
    const url = new URL(String(input))
    const body =
      url.pathname === '/service/secrets/tokens/'
        ? { wrapped_key_share: v.wrapped_key_share, apps: [{ id: 'a1', name: 'Billing', encryption: 'SSE', environment_keys: [{ environment: { id: 'e1', name: 'production' } }] }] }
        : [{ key: 'K', value: 'v', path: '/' }, { key: 'H', value: null, path: '/', valueRedacted: true }]
    return new Response(JSON.stringify(body), { status: 200 })
  }
  const client = new MatiiClient({ host: 'http://localhost:8000', token: v.token, fetch: fake })
  assert.deepEqual(toMap(await client.secrets({ appName: 'billing', env: 'Production' })), { K: 'v' })
  assert.throws(() => new MatiiClient({ host: 'http://secrets.example.com', token: v.token }))
})

test('personal access tokens (pss_user:v1) parse', () => {
  const hex = 'a'.repeat(64)
  assert.equal(parseToken(`pss_user:v1:${hex}:${hex}:${hex}:${hex}`).kind, 'User')
  assert.throws(() => parseToken(`pss_service:v1:${hex}:${hex}:${hex}:${hex}`))
})

test('leaseDynamic posts name, path and ttl for the environment', async () => {
  await ready()
  const calls: { url: string; init: any }[] = []
  const fetchImpl = (async (url: string, init: any) => {
    calls.push({ url, init })
    if (url.endsWith('/secrets/tokens/'))
      return new Response(JSON.stringify({ wrapped_key_share: v.wrapped_key_share, apps: [{ id: 'a1', name: 'Billing', encryption: 'SSE', environment_keys: [{ environment: { id: 'e1', name: 'production' } }] }] }))
    return new Response(JSON.stringify({ leaseId: 'l1', expiresAt: '2030-01-01T00:00:00Z', credentials: { AWS_ACCESS_KEY_ID: 'ASIA' } }), { status: 201 })
  }) as unknown as typeof fetch
  const client = new MatiiClient({ host: 'http://localhost:8000', token: v.token, fetch: fetchImpl })
  const lease = await client.leaseDynamic({ appName: 'billing', env: 'production', path: '/ops' }, 'deploy', 1800)
  assert.equal(lease.credentials.AWS_ACCESS_KEY_ID, 'ASIA')
  const post = calls[1]
  assert.equal(post.url, 'http://localhost:8000/service/v1/dynamic-secrets/lease/?app_id=a1&env=production')
  assert.equal(post.init.method, 'POST')
  assert.deepEqual(JSON.parse(post.init.body), { name: 'deploy', path: '/ops', ttlSeconds: 1800 })
})
