// Conformance runner for the SETTLE vectors (test/spec/settle.json, format in FORMAT.md there).
// It implements the operations and placeholders that file uses; anything else fails the case loudly.

import { afterEach, describe, it, vi } from 'vitest'

import { verifyGID } from '../../src/gid.js'
import {
	BoostxAPIError,
	BoostxClient,
	BoostxError,
	MemoryKeyStore,
	createSettlementToken,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	type BoostxErrorCode,
} from '../../src/index.js'
import settleFile from '../spec/settle.json' with { type: 'json' }
import testkeysFile from '../spec/testkeys.json' with { type: 'json' }

type Case = { name: string; op: string; input: any; want: any }
type Rec = {
	keyStoreCalled: boolean
	constructing: boolean
	requests: { url: string; init: RequestInit }[]
	redirectNotManual: boolean
	networkError?: TypeError
	abort?: AbortController
}

const cases = (settleFile as unknown as { cases: Case[] }).cases
const testkeys = testkeysFile as unknown as { keys: Record<string, { pkcs8: string; spki: string }> }

const SIGN = { name: 'ECDSA', hash: 'SHA-256' }
const CODES: BoostxErrorCode[] = [
	'invalid_private_key',
	'invalid_public_key',
	'invalid_booster',
	'invalid_checkbet',
	'invalid_verify_keys',
	'invalid_gid',
	'invalid_signature',
	'missing_claim',
	'invalid_claim',
	'unknown_partner',
	'api_error',
]
// Statuses a Response must be built without a body.
const NULL_BODY = new Set([101, 204, 205, 304])
const enc = new TextEncoder()
const utf8 = (b: Uint8Array) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b)

function fail(msg: string): never {
	throw new Error(msg)
}
const show = (v: unknown) =>
	v instanceof Error ? `${v.name}: ${v.message}` : typeof v === 'number' ? String(v) : JSON.stringify(v)

// --- bytes ----------------------------------------------------------------------------------------------------------

const b64u = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')

// Strict: base64url alphabet only, no padding, no stray trailing bits.
function unb64u(s: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/.test(s)) fail(`segment is not base64url: ${s}`)
	const bytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
	if (b64u(bytes) !== s) fail(`segment is not canonical base64url: ${s}`)
	return bytes
}

const hexBytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))
const der = (pem: string) => Uint8Array.from(atob(pem.replace(/-----[A-Z ]+-----|\s/g, '')), (c) => c.charCodeAt(0))

function concat(parts: Uint8Array[]): Uint8Array {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
	let at = 0
	for (const p of parts) out.set(p, (at += p.length) - p.length)
	return out
}

// --- keys -----------------------------------------------------------------------------------------------------------

const KEYS: Record<string, { priv: any; pub: any }> = {}
async function loadKeys() {
	if (KEYS['@unusable']) return
	for (const [name, k] of Object.entries(testkeys.keys)) {
		if (name !== 'p384')
			KEYS[name] = { priv: await loadPrivateKeyFromPEM(k.pkcs8), pub: await loadPublicKeyFromPEM(k.spki) }
	}
	const p384 = testkeys.keys.p384!
	const alg = { name: 'ECDSA', namedCurve: 'P-384' }
	KEYS['@unusable'] = {
		priv: await crypto.subtle.importKey('pkcs8', der(p384.pkcs8), alg, false, ['sign']),
		pub: await crypto.subtle.importKey('spki', der(p384.spki), alg, false, ['verify']),
	}
}

function key(ref: unknown, role: 'priv' | 'pub'): any {
	if (ref === null) return null
	if (Array.isArray(ref)) return ref.map((r) => key(r, role))
	return (KEYS[ref as string] ?? fail(`unknown key reference ${show(ref)}`))[role]
}

// --- placeholders and special values ---------------------------------------------------------------------------------

// A time expression in `want`: matches any integer from t to t + slack.
class Time {
	constructor(
		readonly t: number,
		readonly slack: number,
	) {}
}

function placeholder(expr: string, now: number, inText: boolean): Time | Uint8Array | string {
	let m = /^now(Ms)?(?:([+-])(\d+))?$/.exec(expr)
	if (m) return new Time((m[1] ? now * 1000 : now) + (m[2] ? Number(m[2] + m[3]) : 0), m[1] ? 5000 : 5)
	if (inText && (m = /^hex:((?:[0-9a-f]{2})*)$/.exec(expr))) return hexBytes(m[1]!)
	if (expr === '$') return '$'
	return fail(`placeholder \${${expr}} is not supported by the settle runner`)
}

function expandText(text: string, now: number): Uint8Array {
	const parts: Uint8Array[] = []
	let last = 0
	for (const m of text.matchAll(/\$\{([^}]*)\}/g)) {
		parts.push(enc.encode(text.slice(last, m.index)))
		const v = placeholder(m[1]!, now, true)
		parts.push(v instanceof Uint8Array ? v : enc.encode(v instanceof Time ? String(v.t) : v))
		last = m.index + m[0].length
	}
	parts.push(enc.encode(text.slice(last)))
	return concat(parts)
}

const NUMBERS: Record<string, number> = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity, '-0': -0 }

function expandValue(v: any, now: number, forWant: boolean): any {
	if (typeof v === 'string') {
		const m = /^\$\{([^}]*)\}$/.exec(v)
		if (!m) return v
		const r = placeholder(m[1]!, now, false)
		return r instanceof Time && !forWant ? r.t : r
	}
	if (Array.isArray(v)) return v.map((x) => expandValue(x, now, forWant))
	if (v !== null && typeof v === 'object') {
		if ('$number' in v) return v.$number in NUMBERS ? NUMBERS[v.$number] : fail(`bad $number ${v.$number}`)
		if ('$illFormed' in v) return v.$illFormed + '\uD800'
		return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandValue(x, now, forWant)]))
	}
	return v
}

// --- comparison -----------------------------------------------------------------------------------------------------

function match(got: any, want: any, path: string): void {
	if (want instanceof Time) {
		if (!(Number.isInteger(got) && got >= want.t && got <= want.t + want.slack))
			fail(`${path}: want ${want.t}..${want.t + want.slack}, got ${show(got)}`)
	} else if (Array.isArray(want)) {
		if (!Array.isArray(got) || got.length !== want.length) fail(`${path}: want ${show(want)}, got ${show(got)}`)
		want.forEach((w, i) => match(got[i], w, `${path}[${i}]`))
	} else if (want !== null && typeof want === 'object') {
		if (got === null || typeof got !== 'object' || Array.isArray(got)) fail(`${path}: want an object, got ${show(got)}`)
		for (const [k, w] of Object.entries(want)) match(got[k], w, `${path}.${k}`)
	} else if (typeof want === 'number' ? !(typeof got === 'number' && got == want) : got !== want) {
		fail(`${path}: want ${show(want)}, got ${show(got)}`)
	}
}

function checkAbsent(obj: any, paths: string[] | undefined) {
	for (const p of paths ?? []) {
		const parts = p.split('.')
		const parent = parts.slice(0, -1).reduce((o, k) => o?.[k], obj)
		if (parent !== null && typeof parent === 'object' && Object.hasOwn(parent, parts.at(-1)!))
			fail(`payload member ${p} must be absent, got ${show(parent[parts.at(-1)!])}`)
	}
}

// The text after the last "missing required claim: " / "invalid claim value: ", as a run of [A-Za-z0-9_.].
function errorField(err: unknown): string | undefined {
	const msg = err instanceof Error ? err.message : ''
	let best: string | undefined
	let bestAt = -1
	for (const phrase of ['missing required claim: ', 'invalid claim value: ']) {
		const at = msg.lastIndexOf(phrase)
		if (at > bestAt) [bestAt, best] = [at, /^[A-Za-z0-9_.]*/.exec(msg.slice(at + phrase.length))![0]]
	}
	return best
}

function apiErrorOf(err: unknown): BoostxAPIError | undefined {
	for (let e = err, d = 0; e instanceof Error && d < 16; e = e.cause, d++) if (e instanceof BoostxAPIError) return e
	return undefined
}

function checkError(err: unknown, w: any, rec: Rec) {
	if (w.failure !== undefined) {
		const ok =
			w.failure === 'cancelled'
				? rec.abort !== undefined && err === rec.abort.signal.reason
				: w.failure === 'timeout'
					? (err as Error)?.name === 'TimeoutError'
					: w.failure === 'network'
						? rec.networkError !== undefined && err === rec.networkError
						: fail(`unknown failure ${w.failure}`)
		if (!ok) fail(`want failure ${w.failure}, got ${show(err)} [${codesOf(err).join(', ')}]`)
		return
	}
	match(codesOf(err), [...w.error].sort(), `error (${show(err)})`)
	if (w.at === 'construct' && !rec.constructing)
		fail(`want the error at construction, got it from the call: ${show(err)}`)
	if (w.field !== undefined) match(errorField(err), w.field, `field (${show(err)})`)
	if (w.status !== undefined) match(apiErrorOf(err)?.status, w.status, 'status')
	if (w.apiError !== undefined) match(apiErrorOf(err)?.error, w.apiError, 'apiError')
	if (w.reason !== undefined) fail('reason is not expected in the settle group')
}

const codesOf = (err: unknown) => CODES.filter((c) => isBoostxError(err, c)).sort()

// Every accepted builder result: three canonical segments, header exactly alg/typ, a verifying JWS and payload gid.
async function checkBuilt(token: unknown, signer: string, want: any) {
	if (typeof token !== 'string') fail(`want a token string, got ${show(token)}`)
	const parts = token.split('.')
	if (parts.length !== 3) fail(`token has ${parts.length} segments: ${token}`)
	const [h, p, s] = parts.map(unb64u) as [Uint8Array, Uint8Array, Uint8Array]
	const header = JSON.parse(utf8(h))
	if (Object.keys(header).sort().join() !== 'alg,typ' || header.alg !== 'ES256' || header.typ !== 'JWT')
		fail(`header: ${utf8(h)}`)
	if (!(await crypto.subtle.verify(SIGN, key(signer, 'pub'), s, enc.encode(`${parts[0]}.${parts[1]}`))))
		fail('JWS signature does not verify')
	const payload = JSON.parse(utf8(p))
	for (const root of Object.values(payload) as any[]) if (root?.gid) await verifyGID(root.gid, key(signer, 'pub'))
	if (want?.payload !== undefined) match(payload, want.payload, 'payload')
	checkAbsent(payload, want?.absent)
}

// --- operations -----------------------------------------------------------------------------------------------------

const delay = (ms: number, signal?: AbortSignal | null) =>
	new Promise<void>((resolve, reject) => {
		if (signal?.aborted) return reject(signal.reason)
		const t = setTimeout(resolve, ms)
		signal?.addEventListener('abort', () => (clearTimeout(t), reject(signal.reason)), { once: true })
	})

function bodyBytes(spec: any, now: number): Uint8Array {
	let b = spec.bodyHex !== undefined ? hexBytes(spec.bodyHex) : expandText(spec.body ?? '', now)
	if (spec.padTo !== undefined && spec.padTo > b.length) {
		const at = spec.padAt === undefined ? b.length : spec.padAt < 0 ? b.length + spec.padAt : spec.padAt
		b = concat([b.subarray(0, at), new Uint8Array(spec.padTo - b.length).fill(0x20), b.subarray(at)])
	}
	return b
}

// A client key store role value (FORMAT 6.7).
async function privateRole(v: any) {
	if (v === null) throw new BoostxError('invalid_private_key', 'no partner private key')
	if (typeof v === 'object' && !Array.isArray(v)) {
		if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
		if (v.error === 'other') throw new Error('store failure')
		if (v.delayMs === undefined) fail(`bad role value ${show(v)}`)
		await delay(v.delayMs)
		return key(v.key, 'priv')
	}
	return key(v, 'priv')
}

const OPS: Record<string, (i: any, now: number, rec: Rec) => Promise<unknown>> = {
	async 'settlement.create'(i) {
		return createSettlementToken(key(i.key === undefined ? 'partner' : i.key, 'priv'), i.params)
	},

	async 'keystore.register'(i) {
		const store = new MemoryKeyStore()
		const keys: Record<string, unknown> = {}
		for (const [n, role] of [
			['partnerPublicKey', 'pub'],
			['partnerPrivateKey', 'priv'],
			['boostxPublicKey', 'pub'],
		] as const)
			if (n in i) keys[n] = key(i[n], role)
		store.register(i.partner, keys)
		return store
	},

	async 'client.submit'(i, now, rec) {
		const spec = i.keyStore === undefined ? { acme: 'partner' } : i.keyStore
		const keyStore = spec && {
			partnerPrivateKey: async (partner: string) => {
				rec.keyStoreCalled = true
				if (!Object.hasOwn(spec, partner)) throw new BoostxError('unknown_partner', 'unknown partner')
				return privateRole(spec[partner])
			},
		}
		const r = i.response ?? {}
		const fakeFetch = async (url: string | URL | Request, init: RequestInit = {}) => {
			rec.requests.push({ url: url instanceof Request ? url.url : String(url), init })
			if (init.redirect !== 'manual') rec.redirectNotManual = true
			if (r.networkError) throw (rec.networkError = new TypeError('fetch failed'))
			if (r.delayMs) await delay(r.delayMs, init.signal)
			const status = r.status ?? 200
			const bytes = bodyBytes(r, now)
			const body = NULL_BODY.has(status)
				? null
				: new ReadableStream<Uint8Array>({
						async pull(ctl) {
							if (r.bodyDelayMs) await delay(r.bodyDelayMs, init.signal)
							ctl.enqueue(bytes)
							ctl.close()
						},
					})
			return new Response(body, { status, headers: r.headers ?? { 'content-type': 'application/json' } })
		}
		rec.constructing = true
		const client = new BoostxClient(keyStore, {
			fetch: fakeFetch as typeof fetch,
			baseURL: 'https://boostx.test',
			...i.options,
		})
		rec.constructing = false
		if (!('cancel' in i)) return client.submitSettlement(i.params)
		if (i.cancel === null) return client.submitSettlement(i.params, { signal: null })
		rec.abort = new AbortController()
		if (i.cancel === 'before') rec.abort.abort()
		else setTimeout(() => rec.abort!.abort(), i.cancel.afterMs)
		return client.submitSettlement(i.params, { signal: rec.abort.signal })
	},
}

async function checkOK(c: Case, input: any, got: any, ok: any, rec: Rec) {
	if (c.op === 'settlement.create') return checkBuilt(got, input.key ?? 'partner', ok)
	if (c.op === 'client.submit') return // ok is {}: the call resolved, nothing else to compare
	// keystore.register: the registration succeeded; now each lookup against its own want.
	for (const [n, l] of (input.lookups ?? []).entries()) {
		const where = `lookup ${n} ${l.method}(${show(l.partner)})`
		let res: any
		try {
			res = await got[l.method](l.partner)
		} catch (err) {
			if (l.want.ok !== undefined) fail(`${where}: want ok, got ${show(err)}`)
			checkError(err, l.want, rec)
			continue
		}
		if (l.want.ok === undefined) fail(`${where}: want error ${show(l.want)}, got a key`)
		const role = l.method === 'partnerPrivateKey' ? 'priv' : 'pub'
		const want = l.want.ok.keys ?? [l.want.ok.key]
		const list = l.method === 'partnerPublicKeys' ? res : [res]
		if (!Array.isArray(list) || list.length !== want.length || list.some((k, j) => k !== key(want[j], role)))
			fail(`${where}: want keys ${show(want)}, got other keys`)
	}
}

async function checkRequest(rec: Rec, w: any, signer: string) {
	if (rec.requests.length !== 1) fail(`want one request, got ${rec.requests.length}`)
	const { url, init } = rec.requests[0]!
	if (w.url !== undefined) match(url, w.url, 'request.url')
	if (w.method !== undefined) match(init.method, w.method, 'request.method')
	if (w.contentType !== undefined)
		match(new Headers(init.headers).get('content-type'), w.contentType, 'request.contentType')
	const body = JSON.parse(typeof init.body === 'string' ? init.body : await new Response(init.body).text())
	match(Object.keys(body ?? {}), ['settlementJWT'], 'request body members')
	await checkBuilt(body.settlementJWT, signer, w)
}

// --- the cases ------------------------------------------------------------------------------------------------------

afterEach(() => {
	vi.restoreAllMocks()
})

describe('settle conformance vectors', () => {
	for (const c of cases) {
		it(c.name, async () => {
			await loadKeys()
			const now = Math.floor(Date.now() / 1000)
			vi.spyOn(Date, 'now').mockReturnValue(now * 1000 + 500)
			const { response, ...rest } = c.input
			const input = { ...expandValue(rest, now, false), ...(response === undefined ? {} : { response }) }
			const want = expandValue(c.want, now, true)
			const op = OPS[c.op] ?? fail(`operation ${c.op} is not supported by the settle runner`)
			const rec: Rec = { keyStoreCalled: false, constructing: false, requests: [], redirectNotManual: false }

			let got: unknown
			let err: unknown
			let threw = false
			try {
				got = await op(input, now, rec)
			} catch (e) {
				threw = true
				err = e
			}
			if (want.ok !== undefined) {
				if (threw) fail(`want ok, got ${show(err)} [${codesOf(err).join(', ')}]`)
				await checkOK(c, input, got, want.ok, rec)
			} else {
				if (!threw) fail(`want ${show(want.error ?? want.failure)}, got ok`)
				checkError(err, want, rec)
			}
			if (rec.redirectNotManual) fail("a request was sent without redirect: 'manual'")
			if (want.requests !== undefined) match(rec.requests.length, want.requests, 'requests')
			if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
			if (want.request !== undefined) {
				const store = input.keyStore === undefined ? { acme: 'partner' } : input.keyStore
				const ref = store?.[input.params?.partner]
				await checkRequest(rec, want.request, typeof ref === 'string' ? ref : 'partner')
			}
		})
	}
})
