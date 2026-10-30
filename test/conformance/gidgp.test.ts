// Runs the GIDGP conformance vectors through the public API: buildGID, the gamepass builder, the X helpers and the
// GID checks of the CheckBet parser, the key store and the check-bet handler. The vector format is
// test/spec/FORMAT.md; one test per case, named as the case.

import { beforeAll, describe, it } from 'vitest'

import { verifyGID } from '../../src/gid.js'
import {
	BoostxError,
	MemoryKeyStore,
	RoundRejectedError,
	buildGID,
	createFetchHandler,
	createGamePassToken,
	extractCheckBetPartner,
	floorX,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	parseCheckBetToken,
	playerX,
	type BetStore,
	type BoostxErrorCode,
	type CryptoKeyLike,
	type HandlersKeyStore,
} from '../../src/index.js'
import vectorFile from '../spec/gidgp.json' with { type: 'json' }
import testkeysFile from '../spec/testkeys.json' with { type: 'json' }

// Vector JSON is free-form: the runner reads it by the format, not by a static type.
type V = any
type Bytes = Uint8Array<ArrayBuffer>
type WebKey = Parameters<typeof crypto.subtle.sign>[1]

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

// --- bytes and keys -------------------------------------------------------------------------------------------------

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

const es256 = async (priv: CryptoKeyLike, data: Bytes) =>
	b64u(new Uint8Array(await crypto.subtle.sign(SIGN, priv as WebKey, data)))

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

// --- token specs (FORMAT 6.8) ---------------------------------------------------------------------------------------

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

async function buildToken(spec: V, ctx: Ctx, defaultKey: string): Promise<string> {
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
		: typeof v === 'number' && !Number.isFinite(v)
			? String(v)
			: (JSON.stringify(v, (_k, x) => (x instanceof Time ? show(x) : x)) ?? String(v))

// Numbers compare with === (so -0 equals 0); `exact` also requires the same member names.
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
	if (want.failure !== undefined) throw new Error(`runner: no failure outcome in this group (${want.failure})`)
	const got = CODES.filter((c) => isBoostxError(err, c))
	if (got.slice().sort().join() !== [...want.error].sort().join()) {
		throw new Error(`error: got ${show(got)} from ${describeError(err)}, want ${show(want.error)}`)
	}
	if (want.field !== undefined) match(fieldOf(err), want.field, `field (${describeError(err)})`)
}

// Every accepted builder result: three canonical segments, header exactly alg/typ, a verifying JWS and payload gid.
async function checkBuilt(token: unknown, signer: string, want: V): Promise<void> {
	if (typeof token !== 'string') throw new Error(`want a token string, got ${show(token)}`)
	const parts = token.split('.')
	if (parts.length !== 3) throw new Error(`token has ${parts.length} segments: ${token}`)
	for (const s of parts) if (!/^[A-Za-z0-9_-]*$/.test(s) || b64u(unb64(s)) !== s) throw new Error(`segment ${s}`)
	match(JSON.parse(utf8(unb64(parts[0]!))), { alg: 'ES256', typ: 'JWT' }, 'header', true)
	const verified = await crypto.subtle.verify(
		SIGN,
		key(signer, 'pub') as WebKey,
		unb64(parts[2]!),
		enc.encode(`${parts[0]}.${parts[1]}`),
	)
	if (!verified) throw new Error('JWS signature does not verify')
	const payload = JSON.parse(utf8(unb64(parts[1]!)))
	for (const root of Object.values<V>(payload)) if (root?.gid) await verifyGID(root.gid, key(signer, 'pub'))
	if (want.payload !== undefined) match(payload, want.payload, 'payload')
	checkAbsent(payload, want.absent)
}

// --- operations -----------------------------------------------------------------------------------------------------

// x helpers: decimals left out or null is passed as absent.
const decimals = (i: V) => i.decimals ?? undefined

const parseKeys = (i: V) =>
	[key(given(i, 'boostxKey', 'boostx'), 'pub'), key(given(i, 'partnerKeys', ['partner']), 'pub')] as const

const OPS: Record<string, (i: V, ctx: Ctx) => Promise<unknown>> = {
	'gid.build': async (i) => buildGID(key(given(i, 'key', 'partner'), 'priv'), i.partner, i.user, i.bet),
	'gamepass.create': async (i) => createGamePassToken(key(given(i, 'key', 'partner'), 'priv'), i.params),
	'x.floor': async (i) => ({ value: floorX(i.x, decimals(i)) }),
	'x.player': async (i) => ({ value: playerX(i.xBase, i.boost, decimals(i)) }),
	'checkbet.extract': async (i, ctx) => ({
		partner: extractCheckBetPartner(await buildToken(i.token, ctx, 'boostx')),
	}),
	'checkbet.parse': async (i, ctx) => parseCheckBetToken(await buildToken(i.token, ctx, 'boostx'), ...parseKeys(i)),
	async 'keystore.register'(i) {
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
}

async function checkOK(c: V, i: V, got: V, ok: V): Promise<void> {
	switch (c.op) {
		case 'gid.build':
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
		case 'gamepass.create':
			return checkBuilt(got, given(i, 'key', 'partner'), ok)
		case 'keystore.register':
			for (const [n, l] of (i.lookups ?? []).entries()) {
				const where = `lookup ${n} ${l.method}(${show(l.partner)})`
				let res: V
				try {
					res = await got[l.method](l.partner)
				} catch (err) {
					if (l.want.ok === undefined) checkError(err, l.want)
					else throw new Error(`${where}: want ok, got ${describeError(err)}`)
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
		default:
			match(got, ok, 'ok')
	}
}

async function runOp(c: V, input: V, ctx: Ctx, want: V): Promise<void> {
	const op = OPS[c.op]
	if (op === undefined) throw new Error(`runner: unsupported op ${c.op}`)
	let got: unknown
	try {
		got = await op(input, ctx)
	} catch (err) {
		if (want.ok !== undefined) throw new Error(`want ok ${show(want.ok)}, got ${describeError(err)}`)
		return checkError(err, want)
	}
	if (want.ok === undefined) throw new Error(`want error ${show(want.error)}, got ok ${show(got)}`)
	await checkOK(c, input, got, want.ok)
}

// --- handlers (FORMAT 6.7) ------------------------------------------------------------------------------------------

const ROOT_FIELD: Record<string, string> = {
	'set-boost': 'boosterJWT',
	'check-bet': 'checkbetJWT',
	'verify-keys': 'verifyKeysJWT',
}

const DEFAULT_KEY_STORE = {
	acme: { partnerPublicKeys: ['partner'], partnerPrivateKey: 'partner', boostxPublicKey: 'boostx' },
}

const delay = (ms: number) => new Promise((done) => setTimeout(done, ms))

// A key store role value. `undefined`: the partner is not listed.
async function roleValue(v: V, role: 'priv' | 'pub', list: boolean): Promise<V> {
	if (v === undefined) throw new BoostxError('unknown_partner', 'unknown partner')
	if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
		if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
		if (v.error === 'other') throw new Error('key store failure')
		await delay(v.delayMs)
		v = v.key
	}
	if (v === null)
		throw new BoostxError(role === 'priv' ? 'invalid_private_key' : 'invalid_public_key', 'role not given')
	return key(list && !Array.isArray(v) ? [v] : v, role)
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
	if (input.token !== undefined) ctx.token = await buildToken(input.token, ctx, 'boostx')
	const rec = { keyStoreCalled: false, betStoreCalled: false, setBoostArg: undefined as V, checkBetArg: undefined as V }

	const ks = given(input, 'keyStore', DEFAULT_KEY_STORE)
	const role =
		(method: 'partnerPublicKeys' | 'partnerPrivateKey' | 'boostxPublicKey') =>
		async (partner: string): Promise<V> => {
			rec.keyStoreCalled = true
			const entry = Object.hasOwn(ks, partner) ? (ks[partner][method] ?? null) : undefined
			return roleValue(entry, method === 'partnerPrivateKey' ? 'priv' : 'pub', method === 'partnerPublicKeys')
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
	if (want.setBoostArg !== undefined) match(rec.setBoostArg, want.setBoostArg, 'setBoostArg')
	if (want.checkBetArg !== undefined) match(rec.checkBetArg, want.checkBetArg, 'checkBetArg')
	if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
	if (want.betStoreCalled !== undefined) match(rec.betStoreCalled, want.betStoreCalled, 'betStoreCalled')
}

// --- the cases ------------------------------------------------------------------------------------------------------

// Members holding text fields (token specs, request bodies) are expanded where they are used.
const TEXT_MEMBERS = new Set(['token', 'request'])

async function runCase(c: V): Promise<void> {
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
