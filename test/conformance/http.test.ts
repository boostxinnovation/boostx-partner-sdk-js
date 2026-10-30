// Conformance runner for the HTTP vectors (test/spec/http.json, format in FORMAT.md there).
// It implements the operations and placeholders that file uses; anything else fails the case loudly.

import { afterEach, describe, it, vi } from 'vitest'

import { verifyGID } from '../../src/gid.js'
import {
	BoostxAPIError,
	BoostxClient,
	BoostxError,
	MemoryKeyStore,
	RoundRejectedError,
	buildGID,
	createFetchHandler,
	createVerifyKeysResponseToken,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	parseBoosterToken,
	parseCheckBetToken,
	parseVerifyKeysRequestToken,
	parseVerifyKeysResponseToken,
	verifyKeysReason,
	type BetStore,
	type BoostxErrorCode,
} from '../../src/index.js'
import httpFile from '../spec/http.json' with { type: 'json' }
import testkeysFile from '../spec/testkeys.json' with { type: 'json' }

type Case = { name: string; op: string; input: any; sigs?: Record<string, any>; want: any }
type Sig = { partner?: string; user?: string; bet?: string; signature: string }
type Ctx = { now: number; sigs: Record<string, Sig>; token?: string }
type Rec = {
	keyStoreCalled: boolean
	betStoreCalled: boolean
	constructing: boolean
	setBoostArg?: unknown
	checkBetArg?: unknown
	requests: { url: string; init: RequestInit }[]
	redirectNotManual: boolean
	networkError?: TypeError
	abort?: AbortController
}
type Served = { status: number; allow: string | null; text: string }

const cases = (httpFile as unknown as { cases: Case[] }).cases
const testkeys = testkeysFile as unknown as {
	keys: Record<string, { pkcs8: string; spki: string }>
	gidSignatures: { key: string; partner: string; user: string; bet: string; signature: string }[]
}

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
const TOKEN_FIELD: Record<string, string> = {
	'set-boost': 'boosterJWT',
	'check-bet': 'checkbetJWT',
	'verify-keys': 'verifyKeysJWT',
}
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

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
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

async function prepare(c: Case): Promise<Ctx> {
	const ctx: Ctx = { now: Math.floor(Date.now() / 1000), sigs: {} }
	for (const s of testkeys.gidSignatures) ctx.sigs[s.key === 'partner' ? 'gid' : 'gid2'] = s
	for (const [name, s] of Object.entries(c.sigs ?? {})) {
		if (s.fixed !== undefined) ctx.sigs[name] = { signature: s.fixed }
		else if (s.text !== undefined) {
			const sig = await crypto.subtle.sign(SIGN, key(s.key, 'priv'), expandText(s.text, ctx))
			ctx.sigs[name] = { signature: b64u(new Uint8Array(sig)) }
		} else {
			const g = await buildGID(key(s.key, 'priv'), s.partner, s.user, s.bet)
			ctx.sigs[name] = { partner: s.partner, user: s.user, bet: s.bet, signature: g.signature }
		}
	}
	return ctx
}

function placeholder(expr: string, ctx: Ctx, inText: boolean): Time | Uint8Array | string {
	let m = /^now(Ms)?(?:([+-])(\d+))?$/.exec(expr)
	if (m) return new Time((m[1] ? ctx.now * 1000 : ctx.now) + (m[2] ? Number(m[2] + m[3]) : 0), m[1] ? 5000 : 5)
	if ((m = /^sig:(.+)$/.exec(expr))) return (ctx.sigs[m[1]!] ?? fail(`no signature ${m[1]}`)).signature
	if (expr === 'gid' || (m = /^gid:(.+)$/.exec(expr))) {
		const s = ctx.sigs[m?.[1] ?? 'gid'] ?? fail(`no signature for \${${expr}}`)
		if (s.partner === undefined) fail(`\${${expr}} needs a signature with ids`)
		return JSON.stringify({ partner: s.partner, user: s.user, bet: s.bet, signature: s.signature })
	}
	if (inText && (m = /^hex:((?:[0-9a-f]{2})*)$/.exec(expr))) return hexBytes(m[1]!)
	if (inText && expr === 'token') return JSON.stringify(ctx.token ?? fail('${token} without a token')).slice(1, -1)
	if (expr === '$') return '$'
	return fail(`placeholder \${${expr}} is not supported by the http runner`)
}

function expandText(text: string, ctx: Ctx): Uint8Array {
	const parts: Uint8Array[] = []
	let last = 0
	for (const m of text.matchAll(/\$\{([^}]*)\}/g)) {
		parts.push(enc.encode(text.slice(last, m.index)))
		const v = placeholder(m[1]!, ctx, true)
		parts.push(v instanceof Uint8Array ? v : enc.encode(v instanceof Time ? String(v.t) : v))
		last = m.index + m[0].length
	}
	parts.push(enc.encode(text.slice(last)))
	return concat(parts)
}

const NUMBERS: Record<string, number> = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity, '-0': -0 }

function expandValue(v: any, ctx: Ctx, forWant: boolean): any {
	if (typeof v === 'string') {
		const m = /^\$\{([^}]*)\}$/.exec(v)
		if (!m) return v
		const r = placeholder(m[1]!, ctx, false)
		return r instanceof Time && !forWant ? r.t : r
	}
	if (Array.isArray(v)) return v.map((x) => expandValue(x, ctx, forWant))
	if (v !== null && typeof v === 'object') {
		if ('$number' in v) return v.$number in NUMBERS ? NUMBERS[v.$number] : fail(`bad $number ${v.$number}`)
		if ('$illFormed' in v) return v.$illFormed + '\uD800'
		return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expandValue(x, ctx, forWant)]))
	}
	return v
}

// --- token specs ----------------------------------------------------------------------------------------------------

function transform(text: string, t: any): string {
	if (t === 'pad') return text + (text.length % 4 === 0 ? '====' : '='.repeat(4 - (text.length % 4)))
	if (t === 'std-alphabet') return text.replace(/-/g, '+').replace(/_/g, '/')
	if (t === 'trailing-bits') {
		if (text.length % 4 === 0) fail('trailing-bits on a segment whose length is a multiple of 4')
		return text.slice(0, -1) + B64U[B64U.indexOf(text.at(-1)!) + 1]
	}
	if (t === 'empty') return ''
	if (t === 'zero') return b64u(new Uint8Array(64))
	if (t === 'flip') {
		const b = unb64u(text)
		b[0] = b[0]! ^ 1
		return b64u(b)
	}
	if (t !== null && typeof t === 'object') {
		if ('insert' in t) {
			const at = t.at < 0 ? text.length + t.at : t.at
			return text.slice(0, at) + t.insert + text.slice(at)
		}
		if ('append' in t) return text + t.append
		if ('truncate' in t) return text.slice(0, text.length - t.truncate)
		if ('segments' in t) return text.split('.').slice(0, t.segments).join('.')
	}
	return fail(`transform ${show(t)} is not supported by the http runner`)
}

function apply(text: string, list: unknown[] | undefined, what: string): string {
	for (const t of list ?? []) {
		const out = transform(text, t)
		if (out === text) fail(`transform ${show(t)} left the ${what} unchanged`)
		text = out
	}
	return text
}

async function buildToken(spec: any, ctx: Ctx, defaultKey: string): Promise<string> {
	if (spec.raw !== undefined) return new TextDecoder().decode(expandText(spec.raw, ctx))
	const seg = (hex: string | undefined, text: string | undefined) =>
		b64u(hex !== undefined ? hexBytes(hex) : expandText(text ?? fail('token spec without a payload'), ctx))
	const h = apply(seg(spec.headerHex, spec.header ?? '{"alg":"ES256","typ":"JWT"}'), spec.headerSegment, 'header')
	const p = apply(seg(spec.payloadHex, spec.payload), spec.payloadSegment, 'payload')
	for (let i = 0; ; i++) {
		const sig = await crypto.subtle.sign(SIGN, key(spec.key ?? defaultKey, 'priv'), enc.encode(`${h}.${p}`))
		try {
			const s = apply(b64u(new Uint8Array(sig)), spec.signature, 'signature')
			return apply(`${h}.${p}.${s}`, spec.transform, 'token')
		} catch (e) {
			// ECDSA is randomised: re-sign until std-alphabet finds a '-' or '_' to change.
			if (i >= 63 || !spec.signature?.includes('std-alphabet')) throw e
		}
	}
}

// --- comparison -----------------------------------------------------------------------------------------------------

// `exact`: objects must have the same members (want.body); otherwise only the members listed are compared.
function match(got: any, want: any, path: string, exact = false): void {
	if (want instanceof Time) {
		if (!(Number.isInteger(got) && got >= want.t && got <= want.t + want.slack))
			fail(`${path}: want ${want.t}..${want.t + want.slack}, got ${show(got)}`)
	} else if (Array.isArray(want)) {
		if (!Array.isArray(got) || got.length !== want.length) fail(`${path}: want ${show(want)}, got ${show(got)}`)
		want.forEach((w, i) => match(got[i], w, `${path}[${i}]`, exact))
	} else if (want !== null && typeof want === 'object') {
		if (got === null || typeof got !== 'object' || Array.isArray(got)) fail(`${path}: want an object, got ${show(got)}`)
		if (exact && Object.keys(got).sort().join() !== Object.keys(want).sort().join())
			fail(`${path}: want members ${show(Object.keys(want))}, got ${show(got)}`)
		for (const [k, w] of Object.entries(want)) match(got[k], w, `${path}.${k}`, exact)
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

const codesOf = (err: unknown) => CODES.filter((c) => isBoostxError(err, c)).sort()

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
	if (w.reason !== undefined) match(verifyKeysReason(err), w.reason, `reason (${show(err)})`)
	if (w.status !== undefined) match(apiErrorOf(err)?.status, w.status, 'status')
	if (w.apiError !== undefined) match(apiErrorOf(err)?.error, w.apiError, 'apiError')
}

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

// --- fakes ----------------------------------------------------------------------------------------------------------

const delay = (ms: number, signal?: AbortSignal | null) =>
	new Promise<void>((resolve, reject) => {
		if (signal?.aborted) return reject(signal.reason)
		const t = setTimeout(resolve, ms)
		signal?.addEventListener('abort', () => (clearTimeout(t), reject(signal.reason)), { once: true })
	})

function bodyBytes(spec: any, ctx: Ctx): Uint8Array {
	let b = spec.bodyHex !== undefined ? hexBytes(spec.bodyHex) : expandText(spec.body ?? '', ctx)
	if (spec.padTo !== undefined && spec.padTo > b.length) {
		const at = spec.padAt === undefined ? b.length : spec.padAt < 0 ? b.length + spec.padAt : spec.padAt
		b = concat([b.subarray(0, at), new Uint8Array(spec.padTo - b.length).fill(0x20), b.subarray(at)])
	}
	return b
}

// A key store role value (FORMAT 6.7). The handlers' key store takes no cancellation, so a delay always runs out.
async function roleValue(v: any, half: 'priv' | 'pub') {
	if (v === null)
		throw new BoostxError(half === 'priv' ? 'invalid_private_key' : 'invalid_public_key', 'role not given')
	if (typeof v === 'object' && !Array.isArray(v)) {
		if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
		if (v.error === 'other') throw new Error('store failure')
		if (v.delayMs === undefined) fail(`bad role value ${show(v)}`)
		await delay(v.delayMs)
		return key(v.key, half)
	}
	return key(v, half)
}

function lookup(spec: Record<string, any>, role: string, half: 'priv' | 'pub', rec: Rec) {
	return async (partner: string) => {
		rec.keyStoreCalled = true
		if (!Object.hasOwn(spec, partner)) throw new BoostxError('unknown_partner', 'unknown partner')
		return roleValue(spec[partner][role], half)
	}
}

// --- operations -----------------------------------------------------------------------------------------------------

// Left out means the default; null is passed through.
const inboundKeys = (i: any): [any, any] => [
	key(i.boostxKey === undefined ? 'boostx' : i.boostxKey, 'pub'),
	key(i.partnerKeys === undefined ? ['partner'] : i.partnerKeys, 'pub'),
]

const OPS: Record<string, (i: any, ctx: Ctx, rec: Rec) => Promise<unknown>> = {
	async 'booster.parse'(i, ctx) {
		const token = await buildToken(i.token, ctx, 'boostx')
		return parseBoosterToken(token, ...inboundKeys(i))
	},

	async 'checkbet.parse'(i, ctx) {
		const token = await buildToken(i.token, ctx, 'boostx')
		return parseCheckBetToken(token, ...inboundKeys(i))
	},

	async 'verifykeys.parseRequest'(i, ctx) {
		const token = await buildToken(i.token, ctx, 'boostx')
		const pub = key(i.key === undefined ? 'boostx' : i.key, 'pub')
		const partnerID = i.partnerID ?? 'acme'
		if (i.windowSeconds === undefined) return parseVerifyKeysRequestToken(token, pub, partnerID)
		return parseVerifyKeysRequestToken(token, pub, partnerID, { maxSkewSeconds: i.windowSeconds })
	},

	async 'verifykeys.createResponse'(i) {
		return createVerifyKeysResponseToken(key(i.key === undefined ? 'partner' : i.key, 'priv'), i.partnerID, i.nonce)
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

	async 'client.submit'(i, ctx, rec) {
		const spec = i.keyStore === undefined ? { acme: 'partner' } : i.keyStore
		const keyStore = spec && {
			partnerPrivateKey: async (partner: string) => {
				rec.keyStoreCalled = true
				if (!Object.hasOwn(spec, partner)) throw new BoostxError('unknown_partner', 'unknown partner')
				return roleValue(spec[partner], 'priv')
			},
		}
		const r = i.response ?? {}
		const fakeFetch = async (url: string | URL | Request, init: RequestInit = {}) => {
			rec.requests.push({ url: url instanceof Request ? url.url : String(url), init })
			if (init.redirect !== 'manual') rec.redirectNotManual = true
			if (r.networkError) throw (rec.networkError = new TypeError('fetch failed'))
			if (r.delayMs) await delay(r.delayMs, init.signal)
			const status = r.status ?? 200
			const bytes = bodyBytes(r, ctx)
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

	async 'http.serve'(i, ctx, rec): Promise<Served> {
		if (i.token !== undefined) ctx.token = await buildToken(i.token, ctx, 'boostx')
		const ks =
			i.keyStore === undefined
				? { acme: { partnerPublicKeys: ['partner'], partnerPrivateKey: 'partner', boostxPublicKey: 'boostx' } }
				: i.keyStore
		const keyStore = ks && {
			partnerPublicKeys: lookup(ks, 'partnerPublicKeys', 'pub', rec),
			partnerPrivateKey: lookup(ks, 'partnerPrivateKey', 'priv', rec),
			boostxPublicKey: lookup(ks, 'boostxPublicKey', 'pub', rec),
		}
		const bs = { setBoost: 'ok', checkBet: true, ...i.betStore }
		const betStore: BetStore = {
			async setBoost(booster) {
				rec.betStoreCalled = true
				rec.setBoostArg = booster
				if (bs.setBoost === 'reject') throw new RoundRejectedError()
				if (bs.setBoost === 'reject-wrapped') throw new Error('x', { cause: new RoundRejectedError() })
				if (bs.setBoost === 'error') throw new Error('store failure')
				if (bs.setBoost !== 'ok') fail(`bad setBoost ${show(bs.setBoost)}`)
			},
		}
		if (bs.checkBet !== 'absent')
			betStore.checkBet = async (gid) => {
				rec.betStoreCalled = true
				rec.checkBetArg = gid
				if (bs.checkBet === 'error') throw new Error('store failure')
				return bs.checkBet
			}
		rec.constructing = true
		const handler = createFetchHandler({ betStore, keyStore: keyStore as any })
		rec.constructing = false

		const req = i.request ?? {}
		const method = req.method ?? 'POST'
		const path = req.path ?? `${(i.mount ?? '/boostx').replace(/\/$/, '')}/${i.endpoint}`
		const body =
			method === 'GET' || method === 'HEAD'
				? null
				: bodyBytes(
						{
							body: req.body ?? (i.token === undefined ? '' : `{"${TOKEN_FIELD[i.endpoint]}":"\${token}"}`),
							bodyHex: req.bodyHex,
							padTo: req.padTo,
							padAt: req.padAt,
						},
						ctx,
					)
		const res = await handler(new Request('https://partner.test' + path, { method, body }))
		return { status: res.status, allow: res.headers.get('allow'), text: await res.text() }
	},
}

// --- checks ---------------------------------------------------------------------------------------------------------

async function checkOK(c: Case, input: any, got: any, ok: any, rec: Rec) {
	switch (c.op) {
		case 'verifykeys.createResponse':
			return checkBuilt(got, input.key ?? 'partner', ok)
		case 'client.submit':
			return // ok is {}: the call resolved, nothing else to compare
		case 'booster.parse':
		case 'checkbet.parse':
		case 'verifykeys.parseRequest':
			return match(got, ok, 'ok')
	}
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

async function checkServed(got: Served, w: any, rec: Rec) {
	match(got.status, w.status, `status (body ${got.text})`)
	if (w.allow !== undefined) match(got.allow, w.allow, 'allow')
	// routerMayAnswer changes nothing here: createFetchHandler answers 404 and 405 itself, so its texts are compared.
	let body: any
	try {
		body = JSON.parse(got.text)
	} catch {
		fail(`response body is not JSON: ${got.text}`)
	}
	if (w.error !== undefined) match(body, { error: w.error }, 'body', true)
	if (w.errorPrefix !== undefined) {
		match(Object.keys(body ?? {}), ['error'], `body members (${got.text})`)
		if (typeof body.error !== 'string' || !body.error.startsWith(w.errorPrefix))
			fail(`body.error: want a string starting ${show(w.errorPrefix)}, got ${show(body.error)}`)
	}
	if (w.body !== undefined) match(body, w.body, 'body', true)
	if (w.responseJWT !== undefined) {
		const r = w.responseJWT
		const parsed = await parseVerifyKeysResponseToken(body?.result?.responseJWT, key(r.key, 'pub'), r.partnerID)
		match(parsed.nonce, r.nonce, 'responseJWT nonce')
	}
	if (w.setBoostArg !== undefined) match(rec.setBoostArg, w.setBoostArg, 'setBoostArg')
	if (w.checkBetArg !== undefined) match(rec.checkBetArg, w.checkBetArg, 'checkBetArg')
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

// Text fields expand as text (in buildToken and bodyBytes), never as JSON values.
const TEXT_INPUTS = ['token', 'request', 'response']

afterEach(() => {
	vi.restoreAllMocks()
})

describe('http conformance vectors', () => {
	for (const c of cases) {
		it(c.name, async () => {
			await loadKeys()
			const ctx = await prepare(c)
			vi.spyOn(Date, 'now').mockReturnValue(ctx.now * 1000 + 500)
			const input = expandValue(
				Object.fromEntries(Object.entries(c.input).filter(([k]) => !TEXT_INPUTS.includes(k))),
				ctx,
				false,
			)
			for (const k of TEXT_INPUTS) if (k in c.input) input[k] = c.input[k]
			const want = expandValue(c.want, ctx, true)
			const op = OPS[c.op] ?? fail(`operation ${c.op} is not supported by the http runner`)
			const rec: Rec = {
				keyStoreCalled: false,
				betStoreCalled: false,
				constructing: false,
				requests: [],
				redirectNotManual: false,
			}

			let got: unknown
			let err: unknown
			let threw = false
			try {
				got = await op(input, ctx, rec)
			} catch (e) {
				threw = true
				err = e
			}
			if (c.op === 'http.serve' && want.status !== undefined) {
				if (threw) fail(`want status ${want.status}, got ${show(err)} [${codesOf(err).join(', ')}]`)
				await checkServed(got as Served, want, rec)
			} else if (want.ok !== undefined) {
				if (threw) fail(`want ok, got ${show(err)} [${codesOf(err).join(', ')}]`)
				await checkOK(c, input, got, want.ok, rec)
			} else {
				if (!threw) fail(`want ${show(want.error ?? want.failure)}, got ok: ${show(got)}`)
				checkError(err, want, rec)
			}
			if (rec.redirectNotManual) fail("a request was sent without redirect: 'manual'")
			if (want.requests !== undefined) match(rec.requests.length, want.requests, 'requests')
			if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
			if (want.betStoreCalled !== undefined) match(rec.betStoreCalled, want.betStoreCalled, 'betStoreCalled')
			if (want.request !== undefined) {
				const store = input.keyStore === undefined ? { acme: 'partner' } : input.keyStore
				const ref = store?.[input.params?.partner]
				await checkRequest(rec, want.request, typeof ref === 'string' ? ref : 'partner')
			}
		})
	}
})
