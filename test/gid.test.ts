import { describe, expect, it } from 'vitest'

import { encodeBase64url } from '../src/base64url.js'
import { isBoostxError } from '../src/errors.js'
import { buildGID, canonicalGIDPayload, parseGIDClaim, verifyGID } from '../src/gid.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { OTHER, PARTNER, publicKeyWithoutUsages } from './fixtures.js'
import sig from './spec/golden/gid-signature.json' with { type: 'json' }

const LONE_SURROGATE = String.fromCharCode(0xd800)
const P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const

const partnerPriv = () => loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
const partnerPub = () => loadPublicKeyFromPEM(PARTNER.publicSPKI)
const otherPub = () => loadPublicKeyFromPEM(OTHER.publicSPKI)

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
// The last character of an 86-character signature carries 2 bits; the next one decodes to the same 64 bytes.
const strayBits = (sig: string) => sig.slice(0, -1) + B64URL[B64URL.indexOf(sig.at(-1)!) + 1]

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

describe('canonicalGIDPayload', () => {
	// JSON.stringify's rules beyond the gidgp.json cases: a lone surrogate (which no builder accepts) escaped in
	// lowercase, and '/' and U+007F written as themselves.
	it('escapes a lone surrogate and writes / and U+007F as themselves', () => {
		const BS = String.fromCharCode(92)
		expect(canonicalGIDPayload('p/q', 'u' + LONE_SURROGATE, 'b' + String.fromCharCode(0x7f))).toBe(
			`{"partner":"p/q","user":"u${BS}ud800","bet":"b${String.fromCharCode(0x7f)}"}`,
		)
	})
})

describe('the GID signature test vector (golden/gid-signature.json)', () => {
	const { gid } = sig

	it('builds the 72 canonical bytes it lists', () => {
		const bytes = new TextEncoder().encode(canonicalGIDPayload(gid.partner, gid.user, gid.bet))
		expect(bytes.length).toBe(72)
		expect(hex(bytes)).toBe(sig.canonicalHex)
	})

	it('verifies its signature with its public key', async () => {
		await expect(verifyGID(gid, await loadPublicKeyFromPEM(sig.publicKeySpki))).resolves.toBeUndefined()
	})

	it('signs the same triple so that its public key verifies it', async () => {
		const built = await buildGID(await loadPrivateKeyFromPEM(sig.privateKeyPkcs8), gid.partner, gid.user, gid.bet)
		expect(built.signature).toMatch(/^[A-Za-z0-9_-]{86}$/)
		await expect(verifyGID(built, await loadPublicKeyFromPEM(sig.publicKeySpki))).resolves.toBeUndefined()
	})
})

describe('buildGID and verifyGID', () => {
	it('round-trips with an 86-character raw r||s signature', async () => {
		const gid = await buildGID(await partnerPriv(), 'partner-123', 'user-456', 'bet-789')
		expect(gid).toEqual({ partner: 'partner-123', user: 'user-456', bet: 'bet-789', signature: expect.any(String) })
		expect(gid.signature).toMatch(/^[A-Za-z0-9_-]{86}$/)
		await expect(verifyGID(gid, await partnerPub())).resolves.toBeUndefined()
	})

	it('round-trips ids with the characters encoders disagree on', async () => {
		const priv = await partnerPriv()
		const pub = await partnerPub()
		for (const id of ['acme&co', 'u<1>', 'a' + String.fromCharCode(0x2028) + 'b', 'a/b', 'Søren']) {
			await expect(verifyGID(await buildGID(priv, 'partner', id, 'bet-' + id), pub)).resolves.toBeUndefined()
		}
	})

	it('accepts any listed key, so an old key still verifies games started before a rotation', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		await expect(verifyGID(gid, [await otherPub(), await partnerPub()])).resolves.toBeUndefined()
		await expect(verifyGID(gid, [await partnerPub()])).resolves.toBeUndefined()
	})

	it('rejects a GID no listed key signed with invalid_signature', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		for (const keys of [await otherPub(), [await otherPub()]]) {
			const err = await verifyGID(gid, keys).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		}
	})

	it('rejects a tampered field with invalid_signature', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		for (const tampered of [
			{ ...gid, partner: 'q' },
			{ ...gid, user: 'v' },
			{ ...gid, bet: 'c' },
		]) {
			const err = await verifyGID(tampered, await partnerPub()).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		}
	})

	it('rejects a malformed signature with invalid_signature and invalid_gid, before trying any key', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		// A look-alike passes the up-front key check but throws if tried, which would be reported as invalid_public_key.
		const untried: CryptoKeyLike = { type: 'public', extractable: false, algorithm: P256, usages: ['verify'] }
		const malformed = [
			'',
			'not base64url!',
			gid.signature + '=',
			'+' + gid.signature.slice(1),
			encodeBase64url(new Uint8Array(63)),
			encodeBase64url(new Uint8Array(65)),
			gid.signature.slice(0, 85),
			strayBits(gid.signature),
		]
		for (const signature of malformed) {
			const err = await verifyGID({ ...gid, signature }, [untried, await partnerPub()]).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_gid'), signature).toBe(true)
			expect(isBoostxError(err, 'invalid_signature'), signature).toBe(true)
			expect((err as Error).message).toBe('invalid GID signature: not canonical base64url')
		}
		expect(gid.signature).toMatch(/^[A-Za-z0-9_-]{85}[AQgw]$/)
	})

	it('checks the keys before the signature', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		for (const keys of [[], await partnerPriv(), [await partnerPriv()]]) {
			const err = await verifyGID({ ...gid, signature: 'abc' }, keys).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_public_key')).toBe(true)
		}
	})

	it('skips a listed key that cannot verify', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		await expect(verifyGID(gid, [await partnerPriv(), await partnerPub()])).resolves.toBeUndefined()
		const err = await verifyGID(gid, [await partnerPriv(), await otherPub()]).catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
	})

	it('rejects with invalid_public_key when no listed key can verify', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		const bare = await publicKeyWithoutUsages(PARTNER.publicSPKI)
		await expect(verifyGID(gid, [bare, await partnerPub()])).resolves.toBeUndefined()
		for (const keys of [await partnerPriv(), [await partnerPriv(), await partnerPriv()], bare, [bare]]) {
			const err = await verifyGID(gid, keys).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_public_key')).toBe(true)
		}
	})

	it('rejects an empty key list with invalid_public_key', async () => {
		const gid = await buildGID(await partnerPriv(), 'p', 'u', 'b')
		const err = await verifyGID(gid, []).catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_public_key')).toBe(true)
	})

	it('refuses a non-string id with invalid_claim', async () => {
		const err = await buildGID(await partnerPriv(), 'p', 42 as unknown as string, 'b').catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_claim')).toBe(true)
		expect((err as Error).message).toBe('invalid claim value: user must be a string')
	})

	it('refuses an empty or absent id with missing_claim', async () => {
		const priv = await partnerPriv()
		for (const [partner, user, bet, name] of [
			['', 'u', 'b', 'partner'],
			['p', '', 'b', 'user'],
			['p', 'u', '', 'bet'],
			['p', undefined, 'b', 'user'],
		] as const) {
			const err = await buildGID(priv, partner, user as string, bet).catch((e: unknown) => e)
			expect(isBoostxError(err, 'missing_claim')).toBe(true)
			expect((err as Error).message).toBe(`missing required claim: ${name}`)
		}
	})

	it('refuses a lone surrogate with invalid_claim', async () => {
		const priv = await partnerPriv()
		for (const [partner, user, bet] of [
			[LONE_SURROGATE, 'u', 'b'],
			['p', 'u' + LONE_SURROGATE, 'b'],
			['p', 'u', String.fromCharCode(0xdc00) + 'b'],
		] as const) {
			const err = await buildGID(priv, partner, user, bet).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_claim')).toBe(true)
		}
	})

	it('refuses a key that cannot sign with invalid_private_key', async () => {
		const err = await buildGID(await partnerPub(), 'p', 'u', 'b').catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
	})

	it('checks the key, then every id for presence and type, then every id for well-formedness', async () => {
		const priv = await partnerPriv()
		for (const [key, partner, user, code] of [
			[await partnerPub(), '', 'u', 'invalid_private_key'],
			[undefined, LONE_SURROGATE, 'u', 'invalid_private_key'],
			[priv, LONE_SURROGATE, '', 'missing_claim'],
			[priv, LONE_SURROGATE, 7, 'invalid_claim'],
		] as const) {
			const err = await buildGID(key as CryptoKeyLike, partner, user as string, 'b').catch((e: unknown) => e)
			expect(isBoostxError(err, code), code).toBe(true)
		}
		const err = await buildGID(priv, LONE_SURROGATE, 'u', 'b').catch((e: unknown) => e)
		expect((err as Error).message).toBe('invalid claim value: partner is not well-formed Unicode')
	})
})

describe('parseGIDClaim', () => {
	it('returns the four string fields and drops anything else', () => {
		expect(parseGIDClaim({ partner: 'p', user: 'u', bet: 'b', signature: 's', extra: 1 })).toEqual({
			partner: 'p',
			user: 'u',
			bet: 'b',
			signature: 's',
		})
	})

	it('accepts empty strings: it checks shape only', () => {
		expect(parseGIDClaim({ partner: '', user: '', bet: '', signature: '' })).toEqual({
			partner: '',
			user: '',
			bet: '',
			signature: '',
		})
	})

	it.each([
		['null', null],
		['undefined', undefined],
		['a string', 'p:u:b'],
		['an array', ['p', 'u', 'b', 's']],
		['no signature', { partner: 'p', user: 'u', bet: 'b' }],
		['a numeric user', { partner: 'p', user: 1, bet: 'b', signature: 's' }],
		['a null bet', { partner: 'p', user: 'u', bet: null, signature: 's' }],
		['an object partner', { partner: {}, user: 'u', bet: 'b', signature: 's' }],
	])('rejects %s with invalid_gid', (_, value) => {
		expect(() => parseGIDClaim(value)).toThrow(expect.objectContaining({ code: 'invalid_gid' }))
	})
})
