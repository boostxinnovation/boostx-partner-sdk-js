import { describe, expect, it } from 'vitest'

import { encodeBase64url } from '../src/base64url.js'
import { decodeJWTPayload, signJWT, verifyJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM } from '../src/keys.js'
import { BoostxError, isBoostxError } from '../src/errors.js'
import { PARTNER, OTHER, signParts as signWith } from './fixtures.js'

const enc = new TextEncoder()
const BOM = [0xef, 0xbb, 0xbf]
// The JSON escape of one UTF-16 code unit, built from its hex digits at run time.
const BS = String.fromCharCode(92)
const esc = (hex: string) => BS + 'u' + hex

const signParts = async (header: string | number[], payload: string | number[]) =>
	signWith(header, payload, await loadPrivateKeyFromPEM(PARTNER.privatePKCS8))

async function verified(token: string): Promise<unknown> {
	return verifyJWT(token, await loadPublicKeyFromPEM(PARTNER.publicSPKI)).catch((e: unknown) => e)
}

describe('ES256 JWT', () => {
	it('round-trips claims and signs with a 64-byte signature', async () => {
		const priv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
		const pub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
		const token = await signJWT({ iat: 1, a: 'b' }, priv)
		expect(token.split('.')[0]).toBe('eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9')
		expect(atob(token.split('.')[2]!.replace(/-/g, '+').replace(/_/g, '/')).length).toBe(64)
		expect(await verifyJWT(token, pub)).toEqual({ iat: 1, a: 'b' })
		expect(decodeJWTPayload(token)).toEqual({ iat: 1, a: 'b' })
	})

	it('signs with a SEC1 key the same way', async () => {
		const priv = await loadPrivateKeyFromPEM(PARTNER.privateSEC1)
		const pub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
		expect(await verifyJWT(await signJWT({ x: 1 }, priv), pub)).toEqual({ x: 1 })
	})

	// The last character of an 86-character signature carries 2 bits; the next one decodes to the same 64 bytes.
	it('rejects a signature segment with non-zero unused trailing bits', async () => {
		const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
		const token = await signJWT({ x: 1 }, await loadPrivateKeyFromPEM(PARTNER.privatePKCS8))
		const stray = token.slice(0, -1) + A[A.indexOf(token.at(-1)!) + 1]
		const err = await verifyJWT(stray, await loadPublicKeyFromPEM(PARTNER.publicSPKI)).catch((e) => e)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects a signature from another key', async () => {
		const token = await signJWT({ x: 1 }, await loadPrivateKeyFromPEM(OTHER.privatePKCS8))
		const err = await verifyJWT(token, await loadPublicKeyFromPEM(PARTNER.publicSPKI)).catch((e) => e)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('refuses a crit header member of any value as a signature failure, after the alg check', async () => {
		for (const crit of ['["b64"]', '[]', 'null', '"x"', '{}']) {
			const err = await verified(await signParts(`{"alg":"ES256","b64":false,"crit":${crit}}`, '{"x":1}'))
			expect(isBoostxError(err, 'invalid_signature'), crit).toBe(true)
			expect((err as Error).message).toBe('invalid token signature: crit is not supported')
		}
		const err = await verified(await signParts('{"alg":"none","crit":["b64"]}', '{"x":1}'))
		expect((err as Error).message).toBe('invalid token signature: expected ES256, got none')
	})

	it('ignores every other header member, whatever its type', async () => {
		for (const header of [
			'{"alg":"ES256","b64":false}',
			'{"alg":"ES256","typ":1,"kid":null,"x5u":[]}',
			' {"alg":"ES256"}',
		]) {
			expect(await verified(await signParts(header, '{"x":1}')), header).toEqual({ x: 1 })
		}
	})

	it('reads alg and crit by their exact names, and needs the header to be an object', async () => {
		for (const header of ['{"Alg":"ES256"}', '{"ALG":"ES256","alg ":"ES256"}']) {
			expect(isBoostxError(await verified(await signParts(header, '{"x":1}')), 'invalid_signature'), header).toBe(true)
		}
		const variants = await signParts('{"alg":"ES256","Crit":["b64"],"CRIT":[]}', '{"x":1}')
		expect(await verified(variants)).toEqual({ x: 1 })
		for (const header of ['null', '[]', '"ES256"', '1']) {
			const err = await verified(await signParts(header, '{"x":1}'))
			expect(err, header).not.toBeInstanceOf(BoostxError)
			expect((err as Error).message).toBe('invalid token header: not a JSON object')
		}
	})

	it('needs each segment in canonical base64url: a malformed header or payload, a signature failure otherwise', async () => {
		const [h, p, sig] = (await signParts('{"alg":"ES256"}', '{"x":1}')).split('.') as [string, string, string]
		const key = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
		// Signed over the segment text as it stands, so only its format can fail.
		const signed = async (input: string) =>
			`${input}.${encodeBase64url(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key as never, enc.encode(input))))}`
		for (const input of [
			`${h}=.${p}`,
			` ${h}.${p}`,
			`${h}.${p}=`,
			`${h}.${p} `,
			`${h}.${p}\n`,
			`${h}.${p.slice(0, -1)}`,
		]) {
			const err = await verified(await signed(input))
			expect(err, input).not.toBeInstanceOf(BoostxError)
			expect((err as Error).message).toMatch(/^invalid token (header|payload): not base64url$/)
		}
		for (const token of [
			`${h}.${p}.${sig}=`,
			`${h}.${p}.${sig}AA`,
			`${h}.${p}.${sig.slice(0, -2)}`,
			`${h}.${p}.${sig}\r`,
		]) {
			expect(isBoostxError(await verified(token), 'invalid_signature'), token).toBe(true)
		}
		expect(await verified(`${h}.${p}.${sig}`)).toEqual({ x: 1 })
	})

	it('refuses an alg of any other value or type as a signature failure', async () => {
		for (const alg of ['"ES384"', '"es256"', 'null', '{"toString":1}', '["ES256"]']) {
			const err = await verified(await signParts(`{"alg":${alg}}`, '{"x":1}'))
			expect(isBoostxError(err, 'invalid_signature'), alg).toBe(true)
		}
		expect(isBoostxError(await verified(await signParts('{"typ":"JWT"}', '{"x":1}')), 'invalid_signature')).toBe(true)
	})

	it('refuses a byte order mark or invalid UTF-8 in the header or the payload as malformed', async () => {
		const header = [...enc.encode('{"alg":"ES256"}')]
		const payload = [...enc.encode('{"x":1}')]
		for (const [h, p, want] of [
			[[...BOM, ...header], payload, 'invalid token header: not JSON'],
			[header, [...BOM, ...payload], 'invalid token payload: not JSON'],
			[[...header.slice(0, -1), 0xff, 0x7d], payload, 'invalid token header: not JSON'],
			[header, [...payload.slice(0, -1), 0xc0, 0xaf, 0x7d], 'invalid token payload: not JSON'],
		] as const) {
			const token = await signParts([...h], [...p])
			const err = await verified(token)
			expect(err).toBeInstanceOf(Error)
			expect(err).not.toBeInstanceOf(BoostxError)
			expect((err as Error).message).toBe(want)
			if (want.includes('payload')) expect(() => decodeJWTPayload(token)).toThrow(want)
		}
	})

	it('refuses an unpaired surrogate escape anywhere in the header or the payload as malformed', async () => {
		const header = '{"alg":"ES256"}'
		for (const [h, p, want] of [
			[header, `{"gid":{"user":"u${esc('D800')}"}}`, 'payload'],
			[header, `{"a":["${esc('DC00')}"]}`, 'payload'],
			[header, `{"${esc('DBFF')}x":1}`, 'payload'],
			[header, `{"s":"${esc('DE00')}${esc('D83D')}"}`, 'payload'],
			[`{"alg":"ES256","kid":"${esc('D800')}"}`, '{"x":1}', 'header'],
			// In a member that a repeated name replaces, so the parsed value never holds it.
			[header, `{"x":"${esc('D800')}","x":1}`, 'payload'],
			[header, `{"gid":{"user":"u${esc('dfff')}","user":"u"}}`, 'payload'],
			[`{"alg":"ES256","kid":"${esc('DC00')}","kid":"k"}`, '{"x":1}', 'header'],
			// Halves split by other text, or by an escaped backslash, are not a pair.
			[header, `{"a":"${esc('D83D')}","a":"${esc('DE00')}"}`, 'payload'],
			[header, `{"s":"${esc('D83D')}${BS}${BS}${esc('DE00')}"}`, 'payload'],
		] as const) {
			const token = await signParts(h, p)
			const message = `invalid token ${want}: not well-formed Unicode`
			expect(((await verified(token)) as Error).message).toBe(message)
			if (want === 'payload') expect(() => decodeJWTPayload(token)).toThrow(message)
		}
		const pair = await signParts(header, `{"s":"${esc('D83D')}${esc('DE00')}","t":"${esc('d83d')}${esc('de00')}"}`)
		expect(await verified(pair)).toEqual({ s: String.fromCodePoint(0x1f600), t: String.fromCodePoint(0x1f600) })
		// An escaped backslash before the text uD800 escapes no surrogate.
		const text = await signParts(header, `{"s":"${BS}${BS}uD800","t":"${BS}${BS}${BS}${BS}uDE00"}`)
		expect(await verified(text)).toEqual({ s: `${BS}uD800`, t: `${BS}${BS}uDE00` })
	})
})
