// Conformance runner for the VERIFYKEYS vectors (test/spec/verifykeys.json, format in FORMAT.md there).
// It implements the operations, placeholders and transforms that file uses; anything else fails the case loudly.

import { afterEach, beforeAll, describe, it, vi } from 'vitest'

import { verifyGID } from '../../src/gid.js'
import {
	BoostxError,
	createFetchHandler,
	createVerifyKeysRequestToken,
	createVerifyKeysResponseToken,
	extractVerifyKeysRequestPartner,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	parseVerifyKeysRequestToken,
	parseVerifyKeysResponseToken,
	verifyKeysReason,
	type BoostxErrorCode,
} from '../../src/index.js'
import testkeysFile from '../spec/testkeys.json' with { type: 'json' }
import vectorsFile from '../spec/verifykeys.json' with { type: 'json' }

type Case = { name: string; op: string; input: any; sigs?: unknown; want: any }
type Ctx = { now: number; token?: string }
type Rec = { keyStoreCalled: boolean; betStoreCalled: boolean; constructing: boolean }

const cases = (vectorsFile as unknown as { cases: Case[] }).cases
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
const WANT_MEMBERS = new Set([
	'ok',
	'error',
	'field',
	'reason',
	'at',
	'status',
	'errorPrefix',
	'body',
	'allow',
	'routerMayAnswer',
	'responseJWT',
	'keyStoreCalled',
	'betStoreCalled',
])
const DEFAULT_HEADER = '{"alg":"ES256","typ":"JWT"}'
const BODY_MEMBER: Record<string, string> = {
	'set-boost': 'boosterJWT',
	'check-bet': 'checkbetJWT',
	'verify-keys': 'verifyKeysJWT',
}
const DEFAULT_HANDLER_KEYS = {
	acme: { partnerPublicKeys: ['partner'], partnerPrivateKey: 'partner', boostxPublicKey: 'boostx' },
}
const enc = new TextEncoder()
const utf8 = (b: Uint8Array) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(b)

function fail(msg: string): never {
	throw new Error(msg)
}
const show = (v: unknown) =>
	v instanceof Error ? `${v.name}: ${v.message}` : typeof v === 'number' ? String(v) : JSON.stringify(v)

// --- bytes ----------------------------------------------------------------------------------------------------------

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

function b64u(bytes: Uint8Array): string {
	let s = ''
	for (const b of bytes) s += String.fromCharCode(b)
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))

// Strict: base64url alphabet only, no padding, no stray trailing bits.
function strictUnb64u(s: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]*$/.test(s)) fail(`segment is not base64url: ${s}`)
	const bytes = unb64u(s)
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

beforeAll(async () => {
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
})

function key(ref: unknown, role: 'priv' | 'pub'): any {
	if (ref === null) return null
	if (Array.isArray(ref)) return ref.map((r) => key(r, role))
	return (KEYS[ref as string] ?? fail(`unknown key reference ${show(ref)}`))[role]
}

// The predefined GID signatures (FORMAT 3.3).
const FIXED_SIGS: Record<string, (typeof testkeys.gidSignatures)[number]> = {}
for (const s of testkeys.gidSignatures)
	FIXED_SIGS[s.key === 'partner' ? 'gid' : s.key === 'partner2' ? 'gid2' : s.key] = s

// --- placeholders and special values --------------------------------------------------------------------------------

// A time expression in `want`: matches any integer from t to t + slack.
class Time {
	constructor(
		readonly t: number,
		readonly slack: number,
	) {}
}

function placeholder(expr: string, ctx: Ctx, inText: boolean): Time | Uint8Array | string {
	let m = /^now(Ms)?(?:([+-])(\d+))?$/.exec(expr)
	if (m) return new Time((m[1] ? ctx.now * 1000 : ctx.now) + (m[2] ? Number(m[2] + m[3]) : 0), m[1] ? 5000 : 5)
	if ((m = /^sig:(.+)$/.exec(expr))) return (FIXED_SIGS[m[1]!] ?? fail(`unknown signature ${m[1]}`)).signature
	if (expr === 'gid' || (m = /^gid:(.+)$/.exec(expr))) {
		const s = FIXED_SIGS[m ? m[1]! : 'gid'] ?? fail(`unknown signature in \${${expr}}`)
		return JSON.stringify({ partner: s.partner, user: s.user, bet: s.bet, signature: s.signature })
	}
	if (inText && (m = /^hex:((?:[0-9a-f]{2})*)$/.exec(expr))) return hexBytes(m[1]!)
	if (inText && expr === 'token') {
		if (ctx.token === undefined) fail('${token} used without a token')
		return JSON.stringify(ctx.token).slice(1, -1)
	}
	if (expr === '$') return '$'
	return fail(`placeholder \${${expr}} is not supported by the verifykeys runner`)
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

// --- token specs (FORMAT 6.8) ---------------------------------------------------------------------------------------

function transform(text: string, t: any, what: string): string {
	if (t === 'pad') return text + (text.length % 4 === 0 ? '====' : '='.repeat(4 - (text.length % 4)))
	if (t === 'std-alphabet') return text.replace(/-/g, '+').replace(/_/g, '/')
	if (t === 'trailing-bits') {
		if (text.length % 4 === 0) fail(`trailing-bits on a ${what} whose length is a multiple of 4`)
		return text.slice(0, -1) + ALPHABET[ALPHABET.indexOf(text.at(-1)!) + 1]
	}
	if (t === 'empty' && what === 'signature') return ''
	if (t === 'zero' && what === 'signature') return b64u(new Uint8Array(64))
	if (t === 'flip' && what === 'signature') {
		const b = unb64u(text)
		b[0]! ^= 1
		return b64u(b)
	}
	if (t !== null && typeof t === 'object') {
		if (t.insert !== undefined) {
			const at = t.at < 0 ? text.length + t.at : t.at
			return text.slice(0, at) + t.insert + text.slice(at)
		}
		if (t.append !== undefined) return text + t.append
		if (t.truncate !== undefined) return text.slice(0, -t.truncate)
		if (t.segments !== undefined && what === 'token') return text.split('.').slice(0, t.segments).join('.')
	}
	return fail(`transform ${show(t)} does not apply to the ${what}`)
}

function applyAll(text: string, list: unknown[] | undefined, what: string): string {
	for (const t of list ?? []) {
		const out = transform(text, t, what)
		if (out === text) fail(`transform ${show(t)} left the ${what} unchanged`)
		text = out
	}
	return text
}

async function buildToken(spec: any, ctx: Ctx, defaultKey: string): Promise<string> {
	if (spec.raw !== undefined) return utf8(expandText(spec.raw, ctx))
	if (spec.payload === undefined && spec.payloadHex === undefined) fail('token spec has no payload')
	const segment = (hex: string | undefined, text: string | undefined) =>
		b64u(hex !== undefined ? hexBytes(hex) : expandText(text!, ctx))
	const h = applyAll(segment(spec.headerHex, spec.header ?? DEFAULT_HEADER), spec.headerSegment, 'header')
	const p = applyAll(segment(spec.payloadHex, spec.payload), spec.payloadSegment, 'payload')
	const signer = key(spec.key === undefined ? defaultKey : spec.key, 'priv')
	let s: string | undefined
	for (let i = 0; s === undefined; i++) {
		const sig = b64u(new Uint8Array(await crypto.subtle.sign(SIGN, signer, enc.encode(`${h}.${p}`))))
		try {
			s = applyAll(sig, spec.signature, 'signature')
		} catch (e) {
			// A signature with neither '-' nor '_' is unchanged by std-alphabet: sign again (ECDSA is randomised).
			if (i >= 63 || !spec.signature?.includes('std-alphabet')) throw e
		}
	}
	return applyAll(`${h}.${p}.${s}`, spec.transform, 'token')
}

// --- comparison -----------------------------------------------------------------------------------------------------

// `exact`: objects must have exactly the wanted members (http bodies); otherwise only the listed ones are compared.
function match(got: any, want: any, path: string, exact = false): void {
	if (want instanceof Time) {
		if (!(Number.isInteger(got) && got >= want.t && got <= want.t + want.slack))
			fail(`${path}: want ${want.t}..${want.t + want.slack}, got ${show(got)}`)
	} else if (Array.isArray(want)) {
		if (!Array.isArray(got) || got.length !== want.length) fail(`${path}: want ${show(want)}, got ${show(got)}`)
		want.forEach((w, i) => match(got[i], w, `${path}[${i}]`, exact))
	} else if (want !== null && typeof want === 'object') {
		if (got === null || typeof got !== 'object' || Array.isArray(got)) fail(`${path}: want an object, got ${show(got)}`)
		if (exact && Object.keys(got).length !== Object.keys(want).length)
			fail(`${path}: want exactly ${show(want)}, got ${show(got)}`)
		for (const [k, w] of Object.entries(want)) {
			if (!Object.hasOwn(got, k)) fail(`${path}.${k}: missing, got ${show(got)}`)
			match(got[k], w, `${path}.${k}`, exact)
		}
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

const codesOf = (err: unknown) => CODES.filter((c) => isBoostxError(err, c)).sort()

function checkError(err: unknown, w: any, rec: Rec) {
	if (!Array.isArray(w.error)) fail(`want ${show(w)}, got a thrown ${show(err)} [${codesOf(err).join(', ')}]`)
	match(codesOf(err), [...w.error].sort(), `error (${show(err)})`)
	if (w.at === 'construct' && !rec.constructing) fail(`want the error at construction, got it later: ${show(err)}`)
	if (w.field !== undefined) match(errorField(err), w.field, `field (${show(err)})`)
	if (w.reason !== undefined) match(verifyKeysReason(err), w.reason, `reason (${show(err)})`)
}

// Every accepted builder result: three canonical segments, header exactly alg/typ, a verifying JWS and payload gid.
async function checkBuilt(token: unknown, signer: string, want: any) {
	if (typeof token !== 'string') fail(`want a token string, got ${show(token)}`)
	const parts = token.split('.')
	if (parts.length !== 3) fail(`token has ${parts.length} segments: ${token}`)
	const [h, p, s] = parts.map(strictUnb64u) as [Uint8Array, Uint8Array, Uint8Array]
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

async function checkHTTP(got: { status: number; allow: string | null; text: string }, w: any) {
	if (Array.isArray(w.error)) fail(`want ${show(w)}, got HTTP ${got.status} ${got.text}`)
	match(got.status, w.status, 'status')
	if (w.allow !== undefined) match(got.allow, w.allow, 'allow')
	// routerMayAnswer changes nothing here: createFetchHandler answers 404 and 405 itself, so its texts are compared.
	if (w.error === undefined && w.errorPrefix === undefined && w.body === undefined && w.responseJWT === undefined)
		return
	let body: any
	try {
		body = JSON.parse(got.text)
	} catch {
		fail(`body is not JSON: ${got.text}`)
	}
	if (w.error !== undefined) match(body, { error: w.error }, 'body', true)
	if (w.errorPrefix !== undefined) {
		match(Object.keys(body ?? {}), ['error'], `body members (${got.text})`)
		if (typeof body.error !== 'string' || !body.error.startsWith(w.errorPrefix))
			fail(`body error: want prefix ${show(w.errorPrefix)}, got ${show(body.error)}`)
	}
	if (w.body !== undefined) match(body, w.body, 'body', true)
	if (w.responseJWT !== undefined) {
		const r = await parseVerifyKeysResponseToken(
			body?.result?.responseJWT,
			key(w.responseJWT.key, 'pub'),
			w.responseJWT.partnerID,
		)
		match(r.nonce, w.responseJWT.nonce, 'responseJWT.nonce')
	}
}

// --- operations -----------------------------------------------------------------------------------------------------

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

function bodyBytes(spec: any, ctx: Ctx): Uint8Array {
	let b = spec.bodyHex !== undefined ? hexBytes(spec.bodyHex) : expandText(spec.body ?? '', ctx)
	if (spec.padTo !== undefined && spec.padTo > b.length) {
		const at = spec.padAt === undefined ? b.length : spec.padAt < 0 ? b.length + spec.padAt : spec.padAt
		b = concat([b.subarray(0, at), new Uint8Array(spec.padTo - b.length).fill(0x20), b.subarray(at)])
	}
	return b
}

// A handler key store role value (FORMAT 6.7). A role a listed partner does not give fails like null.
async function roleValue(v: any, role: 'priv' | 'pub', missing: BoostxErrorCode) {
	if (v == null) throw new BoostxError(missing, 'role not given')
	if (typeof v === 'object' && !Array.isArray(v)) {
		if (v.error === 'unknown_partner') throw new BoostxError('unknown_partner', 'unknown partner')
		if (v.error === 'other') throw new Error('store failure')
		if (v.delayMs === undefined) fail(`bad role value ${show(v)}`)
		await delay(v.delayMs)
		return key(v.key, role)
	}
	return key(v, role)
}

const has = (o: object, k: string) => Object.hasOwn(o, k)

async function parse(fn: typeof parseVerifyKeysRequestToken, i: any, ctx: Ctx, defaultKey: string) {
	const token = await buildToken(i.token, ctx, defaultKey)
	const options = has(i, 'windowSeconds') ? { maxSkewSeconds: i.windowSeconds } : undefined
	return fn(token, key(has(i, 'key') ? i.key : defaultKey, 'pub'), has(i, 'partnerID') ? i.partnerID : 'acme', options)
}

const OPS: Record<string, (i: any, ctx: Ctx, rec: Rec) => Promise<unknown>> = {
	async 'verifykeys.createRequest'(i) {
		return createVerifyKeysRequestToken(key(has(i, 'key') ? i.key : 'boostx', 'priv'), i.partnerID, i.nonce)
	},

	async 'verifykeys.createResponse'(i) {
		return createVerifyKeysResponseToken(key(has(i, 'key') ? i.key : 'partner', 'priv'), i.partnerID, i.nonce)
	},

	async 'verifykeys.extractRequest'(i, ctx) {
		return { partner: extractVerifyKeysRequestPartner(await buildToken(i.token, ctx, 'boostx')) }
	},

	'verifykeys.parseRequest': (i, ctx) => parse(parseVerifyKeysRequestToken, i, ctx, 'boostx'),
	'verifykeys.parseResponse': (i, ctx) => parse(parseVerifyKeysResponseToken, i, ctx, 'partner'),

	async 'http.serve'(i, ctx, rec) {
		if (i.token !== undefined) ctx.token = await buildToken(i.token, ctx, 'boostx')
		const ks = has(i, 'keyStore') ? i.keyStore : DEFAULT_HANDLER_KEYS
		const role =
			(method: string, r: 'priv' | 'pub', missing: BoostxErrorCode) =>
			async (partner: string): Promise<any> => {
				rec.keyStoreCalled = true
				if (!has(ks, partner)) throw new BoostxError('unknown_partner', 'unknown partner')
				return roleValue(ks[partner][method], r, missing)
			}
		const keyStore = ks && {
			partnerPublicKeys: role('partnerPublicKeys', 'pub', 'invalid_public_key'),
			partnerPrivateKey: role('partnerPrivateKey', 'priv', 'invalid_private_key'),
			boostxPublicKey: role('boostxPublicKey', 'pub', 'invalid_public_key'),
		}
		const bs = { setBoost: 'ok', checkBet: true, ...i.betStore }
		const betStore: any = {
			async setBoost() {
				rec.betStoreCalled = true
				if (bs.setBoost !== 'ok') fail(`setBoost ${show(bs.setBoost)} is not supported by the verifykeys runner`)
			},
		}
		if (bs.checkBet !== 'absent')
			betStore.checkBet = async () => {
				rec.betStoreCalled = true
				if (bs.checkBet === 'error') throw new Error('store failure')
				return bs.checkBet
			}
		rec.constructing = true
		const handler = createFetchHandler({ betStore, keyStore })
		rec.constructing = false

		const req = i.request ?? {}
		const method = req.method ?? 'POST'
		const path = req.path ?? `${(i.mount ?? '/boostx').replace(/\/$/, '')}/${i.endpoint}`
		const member = BODY_MEMBER[i.endpoint] ?? fail(`unknown endpoint ${show(i.endpoint)}`)
		const body = bodyBytes({ body: ctx.token === undefined ? '' : `{"${member}":"\${token}"}`, ...req }, ctx)
		const noBody = method === 'GET' || method === 'HEAD'
		const res = await handler(new Request('https://partner.test' + path, { method, body: noBody ? undefined : body }))
		return { status: res.status, allow: res.headers.get('allow'), text: await res.text() }
	},
}

// --- the cases ------------------------------------------------------------------------------------------------------

afterEach(() => {
	vi.restoreAllMocks()
})

describe('verifykeys conformance vectors', () => {
	for (const c of cases) {
		it(c.name, async () => {
			if (c.sigs !== undefined) fail('sigs are not supported by the verifykeys runner')
			for (const k of Object.keys(c.want)) if (!WANT_MEMBERS.has(k)) fail(`want.${k} is not supported`)
			const now = Math.floor(Date.now() / 1000)
			vi.spyOn(Date, 'now').mockReturnValue(now * 1000 + 500)
			const ctx: Ctx = { now }
			// Token specs and request bodies expand their own text fields.
			const { token, request, ...rest } = c.input
			const input = {
				...expandValue(rest, ctx, false),
				...(token === undefined ? {} : { token }),
				...(request === undefined ? {} : { request }),
			}
			const want = expandValue(c.want, ctx, true)
			const op = OPS[c.op] ?? fail(`operation ${c.op} is not supported by the verifykeys runner`)
			const rec: Rec = { keyStoreCalled: false, betStoreCalled: false, constructing: false }

			let got: any
			let err: unknown
			let threw = false
			try {
				got = await op(input, ctx, rec)
			} catch (e) {
				threw = true
				err = e
			}
			if (threw) {
				if (want.ok !== undefined || want.status !== undefined)
					fail(`want ${show(want.ok ?? `HTTP ${want.status}`)}, got ${show(err)} [${codesOf(err).join(', ')}]`)
				checkError(err, want, rec)
			} else if (c.op === 'http.serve') {
				await checkHTTP(got, want)
			} else if (want.ok === undefined) {
				fail(`want ${show(want.error)}, got ok ${show(got)}`)
			} else if (c.op.startsWith('verifykeys.create')) {
				await checkBuilt(got, has(input, 'key') ? input.key : c.op.endsWith('Request') ? 'boostx' : 'partner', want.ok)
			} else {
				match(got, want.ok, 'ok')
			}
			if (want.keyStoreCalled !== undefined) match(rec.keyStoreCalled, want.keyStoreCalled, 'keyStoreCalled')
			if (want.betStoreCalled !== undefined) match(rec.betStoreCalled, want.betStoreCalled, 'betStoreCalled')
		})
	}
})
