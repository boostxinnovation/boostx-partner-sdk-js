// Runs the KEYS conformance vectors through the public API: key loaders, the in-memory key store, key checks of the
// builders, parsers, handlers and client, and the JWS segment and header rules. The vector format is
// test/spec/FORMAT.md; one test per case, named as the case.

import { beforeAll, describe, it } from 'vitest'

import { verifyGID } from '../../src/gid.js'
import {
	BoostxError,
	BoostxClient,
	MemoryKeyStore,
	RoundRejectedError,
	buildGID,
	createFetchHandler,
	createGamePassToken,
	createSettlementToken,
	createVerifyKeysRequestToken,
	createVerifyKeysResponseToken,
	extractBoosterPartner,
	extractCheckBetPartner,
	extractVerifyKeysRequestPartner,
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
	type ClientKeyStore,
	type CryptoKeyLike,
	type HandlersKeyStore,
} from '../../src/index.js'
import vectorFile from '../spec/keys.json' with { type: 'json' }
import testkeysFile from '../spec/testkeys.json' with { type: 'json' }

// Vector JSON is free-form: the runner reads it by the format, not by a static type.
type V = any
type Bytes = Uint8Array<ArrayBuffer>

const vectors = vectorFile as unknown as { group: string; cases: V[] }
const testkeys = testkeysFile as unknown as {
	keys: Record<string, Record<string, string>>
	gidSignatures: { key: string; partner: string; user: string; bet: string; signature: string }[]
}

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
const SIGN = { name: 'ECDSA', hash: 'SHA-256' }
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const enc = new TextEncoder()
const utf8 = (b: Uint8Array) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b)

// --- bytes ----------------------------------------------------------------------------------------------------------

function b64u(bytes: Uint8Array): string {
	let binary = ''
	for (const b of bytes) binary += String.fromCharCode(b)
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const unb64 = (s: string): Bytes =>
	Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const hex = (h: string): Bytes => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))
const der = (pem: string): Bytes => unb64(pem.replace(/-----[A-Z ]+-----|\s/g, ''))

function concat(parts: Uint8Array[]): Bytes {
	const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
	let at = 0
	for (const p of parts) {
		out.set(p, at)
		at += p.length
	}
	return out
}

type WebKey = Parameters<typeof crypto.subtle.sign>[1]

async function es256(priv: CryptoKeyLike, data: Bytes): Promise<string> {
	return b64u(new Uint8Array(await crypto.subtle.sign(SIGN, priv as WebKey, data)))
}

// --- keys -----------------------------------------------------------------------------------------------------------

const KEYS: Record<string, { priv: CryptoKeyLike; pub: CryptoKeyLike }> = {}

beforeAll(async () => {
	for (const [name, k] of Object.entries(testkeys.keys)) {
		if (name === 'p384') continue
		KEYS[name] = { priv: await loadPrivateKeyFromPEM(k.pkcs8!), pub: await loadPublicKeyFromPEM(k.spki!) }
	}
	const P384 = { name: 'ECDSA', namedCurve: 'P-384' }
	KEYS['@unusable'] = {
		priv: await crypto.subtle.importKey('pkcs8', der(testkeys.keys.p384!.pkcs8!), P384, false, ['sign']),
		pub: await crypto.subtle.importKey('spki', der(testkeys.keys.p384!.spki!), P384, false, ['verify']),
	}
})

function key(ref: V, role: 'priv' | 'pub'): V {
	if (ref === null) return null
	if (Array.isArray(ref)) return ref.map((r) => key(r, role))
	const pair = KEYS[ref]
	if (pair === undefined) throw new Error(`vector: unknown key reference ${JSON.stringify(ref)}`)
	return pair[role]
}

// A member left out takes the operation's default; null stays null.
const given = (i: V, name: string, dflt: V): V => (Object.hasOwn(i, name) ? i[name] : dflt)

// --- placeholders ---------------------------------------------------------------------------------------------------

/** A time expression in `want`: matches any integer from `value` to `value + slack`. */
class Time {
	constructor(
		readonly value: number,
		readonly slack: number,
	) {}
}

interface Sig {
	fixed: string
	partner?: string
	user?: string
	bet?: string
}

interface Ctx {
	now: number
	sigs: Record<string, Sig>
	token?: string
}

async function prepare(c: V): Promise<Ctx> {
	const ctx: Ctx = { now: Math.floor(Date.now() / 1000), sigs: {} }
	for (const s of testkeys.gidSignatures) {
		const name = ({ partner: 'gid', partner2: 'gid2' } as Record<string, string>)[s.key]
		if (name !== undefined) ctx.sigs[name] = { ...s, fixed: s.signature }
	}
	for (const [name, s] of Object.entries<V>(c.sigs ?? {})) {
		if (s.fixed !== undefined) ctx.sigs[name] = { fixed: s.fixed }
		else if (s.text !== undefined) ctx.sigs[name] = { fixed: await es256(key(s.key, 'priv'), expandText(s.text, ctx)) }
		else {
			const g = await buildGID(key(s.key, 'priv'), s.partner, s.user, s.bet)
			ctx.sigs[name] = { partner: s.partner, user: s.user, bet: s.bet, fixed: g.signature }
		}
	}
	return ctx
}

function sig(ctx: Ctx, name: string): Sig {
	const s = ctx.sigs[name]
	if (s === undefined) throw new Error(`vector: unknown signature ${name}`)
	return s
}

// `"`, `\` and C0 controls escaped, nothing else.
const escapeJSON = (s: string) => s.replace(/["\\\u0000-\u001f]/g, (ch) => JSON.stringify(ch).slice(1, -1))

function resolve(expr: string, ctx: Ctx, inText: boolean): string | Bytes | Time {
	const t = /^now(Ms)?(?:([+-]\d+))?$/.exec(expr)
	if (t) return new Time((t[1] ? ctx.now * 1000 : ctx.now) + Number(t[2] ?? 0), t[1] ? 5000 : 5)
	const s = /^sig:(.+)$/.exec(expr)
	if (s) return sig(ctx, s[1]!).fixed
	const g = expr === 'gid' ? 'gid' : /^gid:(.+)$/.exec(expr)?.[1]
	if (g !== undefined) {
		const { partner, user, bet, fixed } = sig(ctx, g)
		if (partner === undefined) throw new Error(`vector: \${gid:${g}} needs the ids form`)
		return JSON.stringify({ partner, user, bet, signature: fixed })
	}
	const h = /^hex:((?:[0-9a-f]{2})*)$/.exec(expr)
	if (h && inText) return hex(h[1]!)
	if (expr === 'token' && ctx.token !== undefined) return escapeJSON(ctx.token)
	if (expr === '$') return '$'
	throw new Error(`vector: bad placeholder \${${expr}}`)
}

function expandText(text: string, ctx: Ctx): Bytes {
	const parts: Uint8Array[] = []
	let last = 0
	for (const m of text.matchAll(/\$\{([^}]*)\}/g)) {
		parts.push(enc.encode(text.slice(last, m.index)))
		const v = resolve(m[1]!, ctx, true)
		parts.push(v instanceof Uint8Array ? v : enc.encode(v instanceof Time ? String(v.value) : v))
		last = m.index + m[0].length
	}
	parts.push(enc.encode(text.slice(last)))
	return concat(parts)
}

// JSON values: a string that is exactly one placeholder, and the special objects of FORMAT.md section 4.
function expand(v: V, ctx: Ctx, forWant = false): V {
	if (typeof v === 'string') {
		const m = /^\$\{([^}]*)\}$/.exec(v)
		if (!m) return v
		const r = resolve(m[1]!, ctx, false)
		return r instanceof Time && !forWant ? r.value : r
	}
	if (Array.isArray(v)) return v.map((x) => expand(x, ctx, forWant))
	if (v !== null && typeof v === 'object') {
		if ('$number' in v) return { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity, '-0': -0 }[v.$number as string]
		if ('$illFormed' in v) return v.$illFormed + '\uD800'
		return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, expand(x, ctx, forWant)]))
	}
	return v
}

// --- tokens ---------------------------------------------------------------------------------------------------------

function transform(text: string, t: V): string {
	if (t === 'pad') return text + (text.length % 4 === 0 ? '====' : '='.repeat(4 - (text.length % 4)))
	if (t === 'std-alphabet') return text.replace(/-/g, '+').replace(/_/g, '/')
	if (t === 'trailing-bits') {
		const next = ALPHABET[ALPHABET.indexOf(text.at(-1) ?? '') + 1]
		if (text.length % 4 === 0 || next === undefined) throw new Error('vector: trailing-bits does not apply')
		return text.slice(0, -1) + next
	}
	if (t === 'empty') return ''
	if (t === 'zero') return b64u(new Uint8Array(64))
	if (t === 'flip') {
		const b = unb64(text)
		b[0] = (b[0] ?? 0) ^ 1
		return b64u(b)
	}
	if (t?.insert !== undefined) {
		const at = t.at < 0 ? text.length + t.at : t.at
		return text.slice(0, at) + t.insert + text.slice(at)
	}
	if (t?.append !== undefined) return text + t.append
	if (t?.truncate !== undefined) return text.slice(0, -t.truncate)
	if (t?.segments !== undefined) return text.split('.').slice(0, t.segments).join('.')
	throw new Error(`vector: unknown transform ${JSON.stringify(t)}`)
}

function apply(text: string, list: V[] | undefined, what: string): string {
	for (const t of list ?? []) {
		const out = transform(text, t)
		if (out === text) throw new Error(`vector: transform ${JSON.stringify(t)} left the ${what} unchanged`)
		text = out
	}
	return text
}

const TOKEN_MEMBERS = [
	'raw',
	'header',
	'headerHex',
	'payload',
	'payloadHex',
	'headerSegment',
	'payloadSegment',
	'key',
	'signature',
	'transform',
]

async function buildToken(spec: V, ctx: Ctx, defaultKey: string): Promise<string> {
	only(spec, TOKEN_MEMBERS, 'token')
	if (spec.raw !== undefined) return new TextDecoder().decode(expandText(spec.raw, ctx))
	const seg = (h: string | undefined, text: string) => (h !== undefined ? hex(h) : expandText(text, ctx))
	const header = apply(
		b64u(seg(spec.headerHex, spec.header ?? '{"alg":"ES256","typ":"JWT"}')),
		spec.headerSegment,
		'header',
	)
	const payload = apply(b64u(seg(spec.payloadHex, spec.payload)), spec.payloadSegment, 'payload')
	const signer = key(spec.key ?? defaultKey, 'priv')
	for (let i = 0; ; i++) {
		const signature = await es256(signer, enc.encode(`${header}.${payload}`))
		try {
			return apply(`${header}.${payload}.${apply(signature, spec.signature, 'signature')}`, spec.transform, 'token')
		} catch (e) {
			// ECDSA is randomised: re-sign until std-alphabet has a '-' or '_' to change.
			if (i >= 63 || !spec.signature?.includes('std-alphabet')) throw e
		}
	}
}

// --- comparison -----------------------------------------------------------------------------------------------------

const show = (v: unknown): string =>
	v instanceof Time
		? `\${${v.value}..+${v.slack}}`
		: (JSON.stringify(v, (_k, x) => (x instanceof Time ? show(x) : x)) ?? String(v))

function match(got: unknown, want: V, path: string, exact = false): void {
	const mismatch = () => new Error(`${path}: got ${show(got)}, want ${show(want)}`)
	if (want instanceof Time) {
		if (typeof got !== 'number' || !Number.isInteger(got) || got < want.value || got > want.value + want.slack) {
			throw mismatch()
		}
	} else if (Array.isArray(want)) {
		if (!Array.isArray(got) || got.length !== want.length) throw mismatch()
		want.forEach((w, i) => match(got[i], w, `${path}[${i}]`, exact))
	} else if (want !== null && typeof want === 'object') {
		if (got === null || typeof got !== 'object' || Array.isArray(got)) throw mismatch()
		const g = got as Record<string, unknown>
		if (exact && Object.keys(g).sort().join() !== Object.keys(want).sort().join()) throw mismatch()
		for (const [k, w] of Object.entries(want)) match(g[k], w, `${path}.${k}`, exact)
	} else if (got !== want) {
		throw mismatch()
	}
}

function checkAbsent(obj: V, paths: string[] | undefined): void {
	for (const p of paths ?? []) {
		const parts = p.split('.')
		let o = obj
		for (const part of parts.slice(0, -1)) o = o?.[part]
		if (o !== null && typeof o === 'object' && Object.hasOwn(o, parts.at(-1)!)) throw new Error(`${p} is present`)
	}
}

function describeError(err: unknown): string {
	const parts: string[] = []
	for (let e = err, depth = 0; depth < 16 && e !== undefined; e = (e as Error)?.cause, depth++) {
		parts.push(e instanceof Error ? `${e.name}${e instanceof BoostxError ? `(${e.code})` : ''}: ${e.message}` : show(e))
		if (!(e instanceof Error)) break
	}
	return parts.join(' <- ')
}

// The text after the last claim phrase, as FORMAT.md 5.1 reads `field`.
function fieldOf(err: unknown): string | undefined {
	const msg = err instanceof Error ? err.message : ''
	const at = Math.max(msg.lastIndexOf('missing required claim: '), msg.lastIndexOf('invalid claim value: '))
	if (at < 0) return undefined
	return /^[A-Za-z0-9_.]*/.exec(msg.slice(at).replace(/^(missing required claim|invalid claim value): /, ''))![0]
}

function checkError(err: unknown, want: V): void {
	if (want.failure !== undefined) {
		const name = { cancelled: 'AbortError', timeout: 'TimeoutError', network: 'TypeError' }[want.failure as string]
		if ((err as Error)?.name !== name) throw new Error(`want failure ${want.failure}, got ${describeError(err)}`)
		return
	}
	const got = CODES.filter((c) => isBoostxError(err, c))
	if (got.slice().sort().join() !== [...want.error].sort().join()) {
		throw new Error(`error: got ${show(got)} from ${describeError(err)}, want ${show(want.error)}`)
	}
	if (want.field !== undefined) match(fieldOf(err), want.field, `field (${describeError(err)})`)
	if (want.reason !== undefined) match(verifyKeysReason(err), want.reason, `reason (${describeError(err)})`)
	if (want.status !== undefined) match((err as { status?: unknown }).status, want.status, 'status')
	if (want.apiError !== undefined) match((err as { error?: unknown }).error, want.apiError, 'apiError')
}

function only(obj: V, allowed: string[], what: string): void {
	for (const k of Object.keys(obj ?? {})) {
		if (!allowed.includes(k)) throw new Error(`runner: unsupported ${what} member ${JSON.stringify(k)}`)
	}
}

// Every accepted builder result: three canonical segments, header exactly alg/typ, a verifying JWS and payload gid.
async function checkBuilt(token: unknown, signer: string, want: V): Promise<void> {
	if (typeof token !== 'string') throw new Error(`want a token string, got ${show(token)}`)
	const parts = token.split('.')
	if (parts.length !== 3) throw new Error(`token has ${parts.length} segments: ${token}`)
	for (const s of parts) if (!/^[A-Za-z0-9_-]*$/.test(s) || b64u(unb64(s)) !== s) throw new Error(`segment ${s}`)
	const header = JSON.parse(utf8(unb64(parts[0]!)))
	match(header, { alg: 'ES256', typ: 'JWT' }, 'header', true)
	const verified = await crypto.subtle.verify(
		SIGN,
		key(signer, 'pub') as WebKey,
		unb64(parts[2]!),
		enc.encode(`${parts[0]}.${parts[1]}`),
	)
	if (!verified) throw new Error('JWS signature does not verify')
	const payload = JSON.parse(utf8(unb64(parts[1]!)))
	for (const root of Object.values<V>(payload)) if (root?.gid) await verifyGID(root.gid, key(signer, 'pub'))
	if (want?.payload !== undefined) match(payload, want.payload, 'payload')
	checkAbsent(payload, want?.absent)
}

// --- operations -----------------------------------------------------------------------------------------------------

interface Rec {
	keyStoreCalled: boolean
	betStoreCalled: boolean
	constructing: boolean
	requests: { url: string; init: RequestInit }[]
	redirectNotManual: boolean
}

const delay = (ms: number, signal?: AbortSignal | null) =>
	new Promise<void>((done, fail) => {
		if (signal?.aborted) return fail(signal.reason)
		const t = setTimeout(done, ms)
		signal?.addEventListener('abort', () => (clearTimeout(t), fail(signal.reason)), { once: true })
	})

function pemInput(i: V): string | Bytes {
	only(i, ['pem', 'pemRef', 'pemHex', 'replace'], 'input')
	if (i.pemHex !== undefined) return hex(i.pemHex)
	let text = i.pem
	if (i.pemRef !== undefined) {
		const [name, form] = i.pemRef.split('.')
		text = testkeys.keys[name]?.[form]
		if (text === undefined) throw new Error(`vector: unknown pemRef ${i.pemRef}`)
	}
	for (const [from, to] of i.replace ?? []) text = text.split(from).join(to)
	return text
}

function bodyBytes(spec: V, defaultBody: string, ctx: Ctx): Bytes {
	let b = spec.bodyHex !== undefined ? hex(spec.bodyHex) : expandText(spec.body ?? defaultBody, ctx)
	if (spec.padTo !== undefined && spec.padTo > b.length) {
		const at = spec.padAt === undefined ? b.length : spec.padAt < 0 ? b.length + spec.padAt : spec.padAt
		b = concat([b.slice(0, at), new Uint8Array(spec.padTo - b.length).fill(0x20), b.slice(at)])
	}
	return b
}

// A key store role value (FORMAT 6.7). `undefined`: the partner is not listed.
async function roleValue(v: V, role: 'priv' | 'pub', list: boolean, signal?: AbortSignal): Promise<V> {
	if (v === undefined) throw new BoostxError('unknown_partner', 'unknown partner')
	if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
		if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
		if (v.error === 'other') throw new Error('key store failure')
		if (v.delayMs === undefined) throw new Error(`vector: bad role value ${show(v)}`)
		await delay(v.delayMs, signal)
		v = v.key
	}
	if (v === null)
		throw new BoostxError(role === 'priv' ? 'invalid_private_key' : 'invalid_public_key', 'role not given')
	return key(list && !Array.isArray(v) ? [v] : v, role)
}

type Op = (i: V, ctx: Ctx, rec: Rec) => Promise<unknown>

const parseKeys = (i: V) =>
	[key(given(i, 'boostxKey', 'boostx'), 'pub'), key(given(i, 'partnerKeys', ['partner']), 'pub')] as const

function windowOptions(i: V) {
	return Object.hasOwn(i, 'windowSeconds') ? { maxSkewSeconds: i.windowSeconds } : undefined
}

const OPS: Record<string, Op> = {
	'key.loadPrivate': async (i) => loadPrivateKeyFromPEM(pemInput(i)),
	'key.loadPublic': async (i) => loadPublicKeyFromPEM(pemInput(i)),

	async 'keystore.register'(i) {
		only(i, ['partner', 'partnerPublicKey', 'partnerPrivateKey', 'boostxPublicKey', 'lookups'], 'input')
		const store = new MemoryKeyStore()
		const keys: Record<string, unknown> = {}
		for (const [n, role] of [
			['partnerPublicKey', 'pub'],
			['partnerPrivateKey', 'priv'],
			['boostxPublicKey', 'pub'],
		] as const)
			if (Object.hasOwn(i, n)) keys[n] = key(i[n], role)
		store.register(i.partner, keys)
		return store
	},

	'gid.build': async (i) => buildGID(key(given(i, 'key', 'partner'), 'priv'), i.partner, i.user, i.bet),
	'gamepass.create': async (i) => createGamePassToken(key(given(i, 'key', 'partner'), 'priv'), i.params),
	'settlement.create': async (i) => createSettlementToken(key(given(i, 'key', 'partner'), 'priv'), i.params),
	'verifykeys.createRequest': async (i) =>
		createVerifyKeysRequestToken(key(given(i, 'key', 'boostx'), 'priv'), i.partnerID, i.nonce),
	'verifykeys.createResponse': async (i) =>
		createVerifyKeysResponseToken(key(given(i, 'key', 'partner'), 'priv'), i.partnerID, i.nonce),

	'booster.extract': async (i, ctx) => ({ partner: extractBoosterPartner(await buildToken(i.token, ctx, 'boostx')) }),
	'checkbet.extract': async (i, ctx) => ({
		partner: extractCheckBetPartner(await buildToken(i.token, ctx, 'boostx')),
	}),
	'verifykeys.extractRequest': async (i, ctx) => ({
		partner: extractVerifyKeysRequestPartner(await buildToken(i.token, ctx, 'boostx')),
	}),
	'booster.parse': async (i, ctx) => parseBoosterToken(await buildToken(i.token, ctx, 'boostx'), ...parseKeys(i)),
	'checkbet.parse': async (i, ctx) => parseCheckBetToken(await buildToken(i.token, ctx, 'boostx'), ...parseKeys(i)),
	'verifykeys.parseRequest': async (i, ctx) =>
		parseVerifyKeysRequestToken(
			await buildToken(i.token, ctx, 'boostx'),
			key(given(i, 'key', 'boostx'), 'pub'),
			given(i, 'partnerID', 'acme'),
			windowOptions(i),
		),
	'verifykeys.parseResponse': async (i, ctx) =>
		parseVerifyKeysResponseToken(
			await buildToken(i.token, ctx, 'partner'),
			key(given(i, 'key', 'partner'), 'pub'),
			given(i, 'partnerID', 'acme'),
			windowOptions(i),
		),

	async 'client.submit'(i, ctx, rec) {
		only(i, ['keyStore', 'options', 'params', 'cancel', 'response'], 'input')
		const spec = given(i, 'keyStore', { acme: 'partner' })
		const keyStore: ClientKeyStore | null = spec && {
			async partnerPrivateKey(partner: string) {
				rec.keyStoreCalled = true
				return roleValue(Object.hasOwn(spec, partner) ? spec[partner] : undefined, 'priv', false)
			},
		}
		const r = i.response ?? {}
		const fakeFetch = async (url: string | URL | Request, init: RequestInit = {}) => {
			rec.requests.push({ url: url instanceof Request ? url.url : String(url), init })
			if (init.redirect !== 'manual') rec.redirectNotManual = true
			if (r.networkError) throw new TypeError('fetch failed')
			if (r.delayMs) await delay(r.delayMs, init.signal)
			const status = r.status ?? 200
			const bytes = bodyBytes(r, '', ctx)
			const body = [101, 204, 205, 304].includes(status)
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
		const opts = i.options ?? {}
		rec.constructing = true
		const client = new BoostxClient(keyStore as ClientKeyStore, {
			fetch: fakeFetch as typeof fetch,
			...opts,
			baseURL: Object.hasOwn(opts, 'baseURL') ? (opts.baseURL ?? undefined) : 'https://boostx.test',
		})
		rec.constructing = false
		if (!Object.hasOwn(i, 'cancel')) return client.submitSettlement(i.params)
		const abort = new AbortController()
		if (i.cancel === 'before') abort.abort()
		else setTimeout(() => abort.abort(), i.cancel.afterMs)
		return client.submitSettlement(i.params, { signal: abort.signal })
	},
}

const WANT_COMMON = ['ok', 'error', 'failure', 'field', 'reason', 'status', 'apiError', 'at']

async function checkOK(c: V, i: V, got: V, ok: V): Promise<void> {
	switch (c.op) {
		case 'key.loadPrivate':
		case 'key.loadPublic': {
			const pair = KEYS[ok.matches]
			if (pair === undefined) throw new Error(`vector: unknown key ${ok.matches}`)
			const priv = c.op === 'key.loadPrivate' ? got : pair.priv
			const pub = c.op === 'key.loadPublic' ? got : pair.pub
			const data = enc.encode('conformance probe')
			const signature = await crypto.subtle.sign(SIGN, priv as WebKey, data)
			if (!(await crypto.subtle.verify(SIGN, pub as WebKey, signature, data))) {
				throw new Error(`the loaded key is not ${ok.matches}'s`)
			}
			return
		}
		case 'keystore.register':
			for (const [n, l] of (i.lookups ?? []).entries()) {
				const where = `lookup ${n} ${l.method}(${show(l.partner)})`
				let res: V
				try {
					res = await got[l.method](l.partner)
				} catch (err) {
					if (l.want.ok !== undefined) throw new Error(`${where}: want ok, got ${describeError(err)}`)
					checkError(err, l.want)
					continue
				}
				if (l.want.ok === undefined) throw new Error(`${where}: want error ${show(l.want)}, got a key`)
				const role = l.method === 'partnerPrivateKey' ? 'priv' : 'pub'
				const want: string[] = l.want.ok.keys ?? [l.want.ok.key]
				const list = l.method === 'partnerPublicKeys' ? res : [res]
				if (!Array.isArray(list) || list.length !== want.length || list.some((k, j) => k !== key(want[j], role)))
					throw new Error(`${where}: want keys ${show(want)}, got other keys`)
			}
			return
		case 'gid.build': {
			match(got, ok.gid ?? {}, 'gid')
			if (ok.canonical !== undefined) {
				const verified = await crypto.subtle.verify(
					SIGN,
					key(given(i, 'key', 'partner'), 'pub') as WebKey,
					unb64(got.signature),
					enc.encode(ok.canonical),
				)
				if (!verified) throw new Error('the signature does not cover the canonical bytes')
			}
			return
		}
		case 'gamepass.create':
		case 'settlement.create':
		case 'verifykeys.createResponse':
			return checkBuilt(got, given(i, 'key', 'partner'), ok)
		case 'verifykeys.createRequest':
			return checkBuilt(got, given(i, 'key', 'boostx'), ok)
		case 'client.submit':
			return // ok is {}: the call resolved
		default:
			match(got, ok, 'ok')
	}
}

async function runOp(c: V, input: V, ctx: Ctx, want: V): Promise<void> {
	only(want, [...WANT_COMMON, 'requests', 'request', 'keyStoreCalled'], 'want')
	const op = OPS[c.op]
	if (op === undefined) throw new Error(`runner: unsupported op ${c.op}`)
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
	if (want.ok !== undefined) {
		if (threw) throw new Error(`want ok ${show(want.ok)}, got ${describeError(err)}`)
		await checkOK(c, input, got, want.ok)
	} else {
		if (!threw) throw new Error(`want ${show(want.error ?? want.failure)}, got ok ${show(got)}`)
		if (want.at === 'construct' && !rec.constructing) throw new Error('want the error at construction')
		if (want.at !== 'construct' && rec.constructing) throw new Error(`construction failed: ${describeError(err)}`)
		checkError(err, want)
	}
	if (rec.redirectNotManual) throw new Error("a request was sent without redirect: 'manual'")
	if (want.requests !== undefined) match(rec.requests.length, want.requests, 'requests')
	if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
	if (want.request !== undefined) {
		if (rec.requests.length !== 1) throw new Error(`want one request, got ${rec.requests.length}`)
		const { url, init } = rec.requests[0]!
		const w = want.request
		if (w.url !== undefined) match(url, w.url, 'request.url')
		if (w.method !== undefined) match(init.method, w.method, 'request.method')
		if (w.contentType !== undefined)
			match(new Headers(init.headers).get('content-type'), w.contentType, 'request.contentType')
		const body = JSON.parse(String(init.body))
		match(Object.keys(body ?? {}), ['settlementJWT'], 'request body members')
		const store = given(input, 'keyStore', { acme: 'partner' })
		const ref = store?.[input.params?.partner]
		await checkBuilt(body.settlementJWT, typeof ref === 'string' ? ref : 'partner', w)
	}
}

// --- handlers -------------------------------------------------------------------------------------------------------

const ROOT_FIELD: Record<string, string> = {
	'set-boost': 'boosterJWT',
	'check-bet': 'checkbetJWT',
	'verify-keys': 'verifyKeysJWT',
}

const SERVE_WANT = [
	'status',
	'error',
	'errorPrefix',
	'body',
	'allow',
	'routerMayAnswer',
	'setBoostArg',
	'checkBetArg',
	'responseJWT',
	'keyStoreCalled',
	'betStoreCalled',
	'at',
]

const DEFAULT_KEY_STORE = {
	acme: { partnerPublicKeys: ['partner'], partnerPrivateKey: 'partner', boostxPublicKey: 'boostx' },
}

async function runServe(input: V, ctx: Ctx, want: V): Promise<void> {
	only(input, ['mount', 'endpoint', 'token', 'request', 'keyStore', 'betStore'], 'input')
	only(input.request, ['method', 'path', 'body', 'bodyHex', 'padTo', 'padAt'], 'request')
	only(input.betStore, ['setBoost', 'checkBet'], 'betStore')
	only(want, SERVE_WANT, 'want')
	if (input.token !== undefined) ctx.token = await buildToken(input.token, ctx, 'boostx')

	const rec = {
		keyStoreCalled: false,
		betStoreCalled: false,
		setBoostArg: undefined as unknown,
		checkBetArg: undefined as unknown,
	}
	const ks = given(input, 'keyStore', DEFAULT_KEY_STORE)
	const role =
		(method: 'partnerPublicKeys' | 'partnerPrivateKey' | 'boostxPublicKey') =>
		async (partner: string): Promise<V> => {
			rec.keyStoreCalled = true
			const entry = Object.hasOwn(ks, partner) ? (ks[partner][method] ?? null) : undefined
			const priv = method === 'partnerPrivateKey'
			return roleValue(entry, priv ? 'priv' : 'pub', method === 'partnerPublicKeys')
		}
	const keyStore: HandlersKeyStore | null = ks && {
		partnerPublicKeys: role('partnerPublicKeys'),
		partnerPrivateKey: role('partnerPrivateKey'),
		boostxPublicKey: role('boostxPublicKey'),
	}

	const bs = { setBoost: 'ok', checkBet: true, ...input.betStore }
	const betStore: BetStore = {
		async setBoost(booster) {
			rec.betStoreCalled = true
			rec.setBoostArg = booster
			if (bs.setBoost === 'reject') throw new RoundRejectedError()
			if (bs.setBoost === 'reject-wrapped') throw new Error('x', { cause: new RoundRejectedError() })
			if (bs.setBoost === 'error') throw new Error('bet store failure')
		},
	}
	if (bs.checkBet !== 'absent') {
		betStore.checkBet = async (gid) => {
			rec.betStoreCalled = true
			rec.checkBetArg = gid
			if (bs.checkBet === 'error') throw new Error('bet store failure')
			return bs.checkBet
		}
	}

	let handler: (request: Request) => Promise<Response>
	try {
		handler = createFetchHandler({ betStore, keyStore: keyStore as HandlersKeyStore })
	} catch (err) {
		if (want.at !== 'construct') throw new Error(`construction failed: ${describeError(err)}`)
		return checkError(err, want)
	}
	if (want.at === 'construct') throw new Error('want a construction error, got a handler')

	const req = input.request ?? {}
	const method = req.method ?? 'POST'
	const path = req.path ?? `${(input.mount ?? '/boostx').replace(/\/$/, '')}/${input.endpoint}`
	const defaultBody = input.token !== undefined ? `{"${ROOT_FIELD[input.endpoint]}":"\${token}"}` : ''
	const body = method === 'GET' || method === 'HEAD' ? undefined : bodyBytes(req, defaultBody, ctx)
	const res = await handler(new Request('https://partner.test' + path, { method, body }))
	const text = await res.text()

	match(res.status, want.status, `status (body ${text})`)
	if (want.allow !== undefined) match(res.headers.get('allow'), want.allow, 'allow')
	// routerMayAnswer changes nothing here: createFetchHandler answers 404 and 405 itself, so its texts are compared.
	const parsed = JSON.parse(text)
	if (want.error !== undefined) match(parsed, { error: want.error }, 'body', true)
	if (want.errorPrefix !== undefined) {
		match(Object.keys(parsed), ['error'], 'body members')
		if (typeof parsed.error !== 'string' || !parsed.error.startsWith(want.errorPrefix)) {
			throw new Error(`body.error: got ${show(parsed.error)}, want prefix ${show(want.errorPrefix)}`)
		}
	}
	if (want.body !== undefined) match(parsed, want.body, 'body', true)
	if (want.responseJWT !== undefined) {
		const { key: k, partnerID, nonce } = want.responseJWT
		const r = await parseVerifyKeysResponseToken(parsed?.result?.responseJWT, key(k, 'pub'), partnerID)
		match(r.nonce, nonce, 'responseJWT.nonce')
	}
	if (want.setBoostArg !== undefined) match(rec.setBoostArg, want.setBoostArg, 'setBoostArg')
	if (want.checkBetArg !== undefined) match(rec.checkBetArg, want.checkBetArg, 'checkBetArg')
	if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
	if (want.betStoreCalled !== undefined) match(rec.betStoreCalled, want.betStoreCalled, 'betStoreCalled')
}

// --- the cases ------------------------------------------------------------------------------------------------------

// Members holding text fields (token specs, request and response bodies) are expanded where they are used.
const TEXT_MEMBERS = new Set(['token', 'request', 'response'])

async function runCase(c: V): Promise<void> {
	only(c, ['name', 'rules', 'op', 'input', 'sigs', 'want', 'wantZeroValue', 'needs', 'note'], 'case')
	const ctx = await prepare(c)
	const input = Object.fromEntries(
		Object.entries<V>(c.input).map(([k, v]) => [k, TEXT_MEMBERS.has(k) ? v : expand(v, ctx)]),
	)
	const want = expand(c.want, ctx, true)
	if (c.op === 'http.serve') return runServe(input, ctx, want)
	return runOp(c, input, ctx, want)
}

describe(`conformance: ${vectors.group}`, () => {
	for (const c of vectors.cases) it(c.name, () => runCase(c))
})
