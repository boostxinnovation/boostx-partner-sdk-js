// Runs the INBOUND conformance vectors through the public API: Booster and CheckBet extraction and parsing, and the
// endpoint handlers. The vector format is test/spec/FORMAT.md; one test per case, named as the case.

import { beforeAll, describe, it } from 'vitest'

import {
	BoostxError,
	RoundRejectedError,
	buildGID,
	createFetchHandler,
	extractBoosterPartner,
	extractCheckBetPartner,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	parseBoosterToken,
	parseCheckBetToken,
	parseVerifyKeysResponseToken,
	verifyKeysReason,
	type BetStore,
	type BoostxErrorCode,
	type CryptoKeyLike,
	type HandlersKeyStore,
} from '../../src/index.js'
import vectorFile from '../spec/inbound.json' with { type: 'json' }
import testkeys from '../spec/testkeys.json' with { type: 'json' }

// Vector JSON is free-form: the runner reads it by the format, not by a static type.
type V = any
type Bytes = Uint8Array<ArrayBuffer>

const vectors = vectorFile as unknown as { group: string; cases: V[] }

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

async function es256(priv: CryptoKeyLike, data: Bytes): Promise<string> {
	return b64u(new Uint8Array(await crypto.subtle.sign(SIGN, priv as Parameters<typeof crypto.subtle.sign>[1], data)))
}

// --- keys -----------------------------------------------------------------------------------------------------------

const KEYS: Record<string, { priv: CryptoKeyLike; pub: CryptoKeyLike }> = {}

beforeAll(async () => {
	for (const [name, k] of Object.entries(testkeys.keys)) {
		if (name === 'p384') continue
		KEYS[name] = { priv: await loadPrivateKeyFromPEM(k.pkcs8), pub: await loadPublicKeyFromPEM(k.spki) }
	}
	const P384 = { name: 'ECDSA', namedCurve: 'P-384' }
	KEYS['@unusable'] = {
		priv: await crypto.subtle.importKey('pkcs8', der(testkeys.keys.p384.pkcs8), P384, false, ['sign']),
		pub: await crypto.subtle.importKey('spki', der(testkeys.keys.p384.spki), P384, false, ['verify']),
	}
})

function key(ref: V, role: 'priv' | 'pub'): V {
	if (ref === null) return null
	if (Array.isArray(ref)) return ref.map((r) => key(r, role))
	const pair = KEYS[ref]
	if (pair === undefined) throw new Error(`vector: unknown key reference ${JSON.stringify(ref)}`)
	return pair[role]
}

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
		const name = { partner: 'gid', partner2: 'gid2' }[s.key]
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
	if (want.reason !== undefined) match(verifyKeysReason(err), want.reason, 'reason')
	if (want.status !== undefined) match((err as { status?: unknown }).status, want.status, 'status')
	if (want.apiError !== undefined) match((err as { error?: unknown }).error, want.apiError, 'apiError')
}

function only(obj: V, allowed: string[], what: string): void {
	for (const k of Object.keys(obj ?? {})) {
		if (!allowed.includes(k)) throw new Error(`runner: unsupported ${what} member ${JSON.stringify(k)}`)
	}
}

// --- operations -----------------------------------------------------------------------------------------------------

type Op = (token: string, input: V) => unknown

const OPS: Record<string, Op> = {
	'booster.extract': (token) => ({ partner: extractBoosterPartner(token) }),
	'checkbet.extract': (token) => ({ partner: extractCheckBetPartner(token) }),
	'booster.parse': (token, i) => parseBoosterToken(token, ...verifyingKeys(i)),
	'checkbet.parse': (token, i) => parseCheckBetToken(token, ...verifyingKeys(i)),
}

function verifyingKeys(i: V): [CryptoKeyLike, CryptoKeyLike[]] {
	return [
		key('boostxKey' in i ? i.boostxKey : 'boostx', 'pub'),
		key('partnerKeys' in i ? i.partnerKeys : ['partner'], 'pub'),
	]
}

async function runInbound(c: V, input: V, ctx: Ctx, want: V): Promise<void> {
	only(input, c.op.endsWith('.parse') ? ['token', 'boostxKey', 'partnerKeys'] : ['token'], 'input')
	only(want, ['ok', 'error', 'field', 'reason', 'failure'], 'want')
	const token = await buildToken(input.token, ctx, 'boostx')
	let got: unknown
	try {
		got = await OPS[c.op]!(token, input)
	} catch (err) {
		if (want.ok !== undefined) throw new Error(`want ok ${show(want.ok)}, got ${describeError(err)}`)
		return checkError(err, want)
	}
	if (want.ok === undefined) throw new Error(`want error ${show(want.error ?? want.failure)}, got ok ${show(got)}`)
	match(got, want.ok, 'ok')
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

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

function bodyBytes(spec: V, defaultBody: string, ctx: Ctx): Bytes {
	let b = spec.bodyHex !== undefined ? hex(spec.bodyHex) : expandText(spec.body ?? defaultBody, ctx)
	if (spec.padTo !== undefined && spec.padTo > b.length) {
		const at = spec.padAt === undefined ? b.length : spec.padAt < 0 ? b.length + spec.padAt : spec.padAt
		b = concat([b.slice(0, at), new Uint8Array(spec.padTo - b.length).fill(0x20), b.slice(at)])
	}
	return b
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
	const ks = input.keyStore === undefined ? DEFAULT_KEY_STORE : input.keyStore
	const role =
		(method: 'partnerPublicKeys' | 'partnerPrivateKey' | 'boostxPublicKey') =>
		async (partner: string): Promise<V> => {
			rec.keyStoreCalled = true
			if (!Object.hasOwn(ks, partner))
				throw new BoostxError('unknown_partner', `unknown partner ${JSON.stringify(partner)}`)
			let v = ks[partner][method] ?? null
			if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
				if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
				if (v.error === 'other') throw new Error('key store failure')
				await delay(v.delayMs)
				v = v.key
			}
			const priv = method === 'partnerPrivateKey'
			if (v === null) throw new BoostxError(priv ? 'invalid_private_key' : 'invalid_public_key', 'role not given')
			if (method === 'partnerPublicKeys') return key(Array.isArray(v) ? v : [v], 'pub')
			return key(v, priv ? 'priv' : 'pub')
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

async function runCase(c: V): Promise<void> {
	const ctx = await prepare(c)
	// Token specs and request bodies are text fields, expanded where they are used.
	const input = Object.fromEntries(
		Object.entries<V>(c.input).map(([k, v]) => [k, k === 'token' || k === 'request' ? v : expand(v, ctx)]),
	)
	const want = expand(c.want, ctx, true)
	if (c.op === 'http.serve') return runServe(input, ctx, want)
	if (OPS[c.op] === undefined) throw new Error(`runner: unsupported op ${c.op}`)
	return runInbound(c, input, ctx, want)
}

describe(`conformance: ${vectors.group}`, () => {
	for (const c of vectors.cases) it(c.name, () => runCase(c))
})
