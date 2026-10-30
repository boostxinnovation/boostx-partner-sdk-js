import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { encodeBase64url } from '../src/base64url.js'
import { extractBoosterPartner, parseBoosterToken } from '../src/booster.js'
import { BoostxError, isBoostxError } from '../src/errors.js'
import { buildGID, type GID } from '../src/gid.js'
import { signJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { BOOSTX, OTHER, PARTNER, publicKeyWithoutUsages, signParts } from './fixtures.js'

const IAT = 1732032100

let boostxPriv: CryptoKeyLike
let boostxPub: CryptoKeyLike
let partnerPriv: CryptoKeyLike
let partnerPub: CryptoKeyLike
let otherPriv: CryptoKeyLike
let otherPub: CryptoKeyLike
let gid: GID

beforeAll(async () => {
	boostxPriv = await loadPrivateKeyFromPEM(BOOSTX.privatePKCS8)
	boostxPub = await loadPublicKeyFromPEM(BOOSTX.publicSPKI)
	partnerPriv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	otherPriv = await loadPrivateKeyFromPEM(OTHER.privatePKCS8)
	otherPub = await loadPublicKeyFromPEM(OTHER.publicSPKI)
	gid = await buildGID(partnerPriv, 'partner-xyz', 'user-12345', 'bet-abc789')
})

afterEach(() => {
	vi.restoreAllMocks()
})

// The example on the Rounds page of the partner docs. Built at run time: gid exists only after beforeAll.
function round3(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return { gid, round: 3, boost: 0.85, final: false, jackpot: false, ...overrides }
}

// Signed as BoostX signs a BoosterJWT.
function boosterToken(overrides: Record<string, unknown> = {}, key = boostxPriv): Promise<string> {
	return signJWT({ booster: round3(overrides), iat: IAT }, key)
}

// Signs a payload given as raw JSON text, for values JSON.stringify cannot produce.
async function signRaw(payload: string, key: CryptoKeyLike): Promise<string> {
	const enc = new TextEncoder()
	const input = `${encodeBase64url(enc.encode('{"alg":"ES256","typ":"JWT"}'))}.${encodeBase64url(enc.encode(payload))}`
	const sig = await crypto.subtle.sign(
		{ name: 'ECDSA', hash: 'SHA-256' },
		key as Parameters<typeof crypto.subtle.sign>[1],
		enc.encode(input),
	)
	return `${input}.${encodeBase64url(new Uint8Array(sig))}`
}

async function rejection(p: Promise<unknown>): Promise<BoostxError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	)
	expect(err).toBeInstanceOf(BoostxError)
	return err as BoostxError
}

describe('parseBoosterToken', () => {
	it('returns the verified booster', async () => {
		const booster = await parseBoosterToken(await boosterToken(), boostxPub, partnerPub)
		expect(booster).toStrictEqual({ gid, round: 3, boost: 0.85, final: false, jackpot: false, iat: IAT })
	})

	it('returns a jackpot round', async () => {
		const token = await boosterToken({ round: 4, boost: 12.5, final: true, jackpot: true })
		expect(await parseBoosterToken(token, boostxPub, [partnerPub])).toStrictEqual({
			gid,
			round: 4,
			boost: 12.5,
			final: true,
			jackpot: true,
			iat: IAT,
		})
	})

	it('rejects a token not signed with the BoostX key', async () => {
		const err = await rejection(parseBoosterToken(await boosterToken({}, otherPriv), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(err.message).toBe('invalid Booster token: invalid token signature')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		expect(isBoostxError(err, 'invalid_gid')).toBe(false)
	})

	it('rejects a GID signed with another key', async () => {
		const foreign = await buildGID(otherPriv, gid.partner, gid.user, gid.bet)
		const err = await rejection(parseBoosterToken(await boosterToken({ gid: foreign }), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(err.message).toBe('invalid Booster token: failed to verify GID: invalid GID signature')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
	})

	it('rejects a GID whose fields were changed after signing', async () => {
		const token = await boosterToken({ gid: { ...gid, bet: 'bet-other' } })
		const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('accepts a GID signed with a previous key passed in the key list', async () => {
		const previous = await buildGID(otherPriv, gid.partner, gid.user, gid.bet)
		const token = await boosterToken({ gid: previous })
		expect((await parseBoosterToken(token, boostxPub, [partnerPub, otherPub])).gid).toStrictEqual(previous)
	})

	it('rejects a malformed GID signature as a GID signature failure', async () => {
		const token = await boosterToken({ gid: { ...gid, signature: 'abc' } })
		const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects an alg other than ES256', async () => {
		const [, payload, sig] = (await boosterToken()).split('.')
		const header = encodeBase64url(new TextEncoder().encode('{"alg":"ES384","typ":"JWT"}'))
		const err = await rejection(parseBoosterToken(`${header}.${payload}.${sig}`, boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(err.message).toContain('expected ES256, got ES384')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects a malformed token', async () => {
		for (const token of ['', 'a.b', 'a.b.c']) {
			expect((await rejection(parseBoosterToken(token, boostxPub, partnerPub))).code).toBe('invalid_booster')
		}
	})

	it('passes key errors through unwrapped', async () => {
		const token = await boosterToken()
		expect((await rejection(parseBoosterToken(token, boostxPub, []))).code).toBe('invalid_public_key')
		expect((await rejection(parseBoosterToken(token, partnerPriv, partnerPub))).code).toBe('invalid_public_key')
	})

	it('checks the BoostX key, then the partner keys, before reading the token', async () => {
		const bad = [
			await boosterToken({ round: 0 }),
			await boosterToken({ gid: { ...gid, signature: 'abc' } }),
			await boosterToken({}, otherPriv),
			'a.b.c',
			'',
		]
		for (const token of bad) {
			const boostxFirst = await rejection(parseBoosterToken(token, partnerPriv, [partnerPriv]))
			expect(boostxFirst.message).toBe('invalid public key: not an ECDSA P-256 public key that can verify')
			const partner = await rejection(parseBoosterToken(token, boostxPub, [partnerPriv]))
			expect(partner.code).toBe('invalid_public_key')
			expect(partner.message).toBe('invalid public key: no partner public key is an ECDSA P-256 key that can verify')
			expect((await rejection(parseBoosterToken(token, boostxPub, [partnerPriv, partnerPub]))).code).toBe(
				'invalid_booster',
			)
		}
	})

	it('treats a public key without the verify usage as unusable, before reading the token', async () => {
		const boostxBare = await publicKeyWithoutUsages(BOOSTX.publicSPKI)
		const partnerBare = await publicKeyWithoutUsages(PARTNER.publicSPKI)
		const good = await boosterToken()
		for (const token of [good, await boosterToken({ round: 0 }), 'a.b.c']) {
			const boostx = await rejection(parseBoosterToken(token, boostxBare, partnerPub))
			expect(boostx.message).toBe('invalid public key: not an ECDSA P-256 public key that can verify')
			expect((await rejection(parseBoosterToken(token, boostxPub, [partnerBare]))).code).toBe('invalid_public_key')
		}
		expect((await parseBoosterToken(good, boostxPub, [partnerBare, partnerPub])).gid).toStrictEqual(gid)
	})

	it('enforces a present exp or nbf against the clock in whole seconds, with no leeway', async () => {
		const NOW = 1732032200
		vi.spyOn(Date, 'now').mockReturnValue(NOW * 1000 + 999)
		const token = (claims: Record<string, unknown>) => signJWT({ booster: round3(), iat: IAT, ...claims }, boostxPriv)
		for (const claims of [{ exp: NOW + 1 }, { nbf: NOW }, { exp: NOW + 1, nbf: NOW - 1 }, { exp: 1e300, nbf: -1 }]) {
			expect(await parseBoosterToken(await token(claims), boostxPub, partnerPub)).toStrictEqual({
				...round3(),
				iat: IAT,
			})
		}
		for (const [claims, detail] of [
			[{ exp: NOW }, 'exp is not after the current time'],
			[{ exp: NOW - 1, nbf: NOW + 1 }, 'exp is not after the current time'],
			[{ nbf: NOW + 1 }, 'nbf is after the current time'],
			[{ exp: null }, 'exp must be a number'],
			[{ exp: String(NOW + 60) }, 'exp must be a number'],
			[{ nbf: null }, 'nbf must be a number'],
			[{ nbf: [NOW] }, 'nbf must be a number'],
		] as const) {
			const t = await token(claims)
			const err = await rejection(parseBoosterToken(t, boostxPub, partnerPub))
			expect(err.message).toBe(`invalid Booster token: invalid claim value: ${detail}`)
			expect(isBoostxError(err, 'invalid_claim')).toBe(true)
			expect(() => extractBoosterPartner(t)).toThrow(err.message)
		}
	})

	it('checks exp after iat and the booster fields, and before the GID signature', async () => {
		const expired = Math.floor(Date.now() / 1000)
		for (const [claims, detail] of [
			[{ booster: round3({ round: 0 }), iat: IAT, exp: expired }, 'invalid claim value: round must be an integer >= 1'],
			[{ booster: round3(), exp: expired }, 'missing required claim: iat'],
			[{ booster: round3(), iat: 1.5, exp: expired }, 'invalid claim value: iat must be an integer'],
			[
				{ booster: round3({ gid: { ...gid, signature: 'abc' } }), iat: IAT, exp: expired },
				'invalid claim value: exp is not after the current time',
			],
		] as const) {
			const err = await rejection(parseBoosterToken(await signJWT(claims, boostxPriv), boostxPub, partnerPub))
			expect(err.message).toBe(`invalid Booster token: ${detail}`)
			expect(isBoostxError(err, 'invalid_gid')).toBe(false)
		}
	})

	it('verifies the signature before the payload format, and checks gid.partner, then the booster fields, then iat', async () => {
		const foreign = await rejection(parseBoosterToken(await signRaw('[1]', otherPriv), boostxPub, partnerPub))
		expect(foreign.message).toBe('invalid Booster token: invalid token signature')
		expect(isBoostxError(foreign, 'invalid_signature')).toBe(true)
		for (const [token, detail, code] of [
			[
				await boosterToken({ gid: { ...gid, partner: '' }, round: 0 }),
				'missing required claim: gid.partner',
				'missing_claim',
			],
			[
				await signJWT({ booster: round3({ round: 0 }) }, boostxPriv),
				'invalid claim value: round must be an integer >= 1',
				'invalid_claim',
			],
		] as const) {
			const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
			expect(err.message).toBe(`invalid Booster token: ${detail}`)
			expect(isBoostxError(err, code)).toBe(true)
		}
	})

	it('refuses an unpaired surrogate escape in an id as a malformed token, and reads a paired one', async () => {
		const BS = String.fromCharCode(92)
		const emoji = await buildGID(partnerPriv, gid.partner, String.fromCodePoint(0x1f600), gid.bet)
		const json = (user: string, g: GID = emoji) =>
			`{"booster":{"gid":{"partner":"${g.partner}","user":"${user}","bet":"${g.bet}","signature":"${g.signature}"},"round":3,"boost":0.85,"final":false,"jackpot":false},"iat":${IAT}}`
		const paired = await signRaw(json(`${BS}uD83D${BS}uDE00`), boostxPriv)
		expect((await parseBoosterToken(paired, boostxPub, partnerPub)).gid).toStrictEqual(emoji)
		for (const [user, g] of [
			[`${BS}uD83D`, emoji],
			[`${BS}uDE00${BS}uD83D`, emoji],
			[`u${BS}udfff`, emoji],
			// A repeated user whose last value is the signed one.
			[`u${BS}uD800","user":"${gid.user}`, gid],
		] as const) {
			const token = await signRaw(json(user, g), boostxPriv)
			const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
			expect(err.code).toBe('invalid_booster')
			expect(err.message).toBe('invalid Booster token: invalid token payload: not well-formed Unicode')
			expect(isBoostxError(err, 'invalid_signature')).toBe(false)
			expect(() => extractBoosterPartner(token)).toThrow(expect.objectContaining({ code: 'invalid_booster' }))
		}
	})

	it.each(['gid', 'round', 'boost', 'final', 'jackpot'])('rejects a missing %s', async (name) => {
		const err = await rejection(parseBoosterToken(await boosterToken({ [name]: undefined }), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(err.message).toBe(`invalid Booster token: missing required claim: ${name}`)
		expect(isBoostxError(err, 'missing_claim')).toBe(true)
	})

	it('rejects a missing booster root, gid.partner or iat', async () => {
		for (const [token, name] of [
			[await signJWT({ iat: IAT, checkbet: { gid } }, boostxPriv), 'booster'],
			[await boosterToken({ gid: { ...gid, partner: '' } }), 'gid.partner'],
			[await signJWT({ booster: round3() }, boostxPriv), 'iat'],
		] as const) {
			const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
			expect(err.message).toBe(`invalid Booster token: missing required claim: ${name}`)
			expect(isBoostxError(err, 'missing_claim')).toBe(true)
		}
	})

	const invalid: [string, Record<string, unknown>][] = [
		['round 0', { round: 0 }],
		['round -1', { round: -1 }],
		['round 1.5', { round: 1.5 }],
		['round "3"', { round: '3' }],
		['round null', { round: null }],
		['round true', { round: true }],
		['round 2^53', { round: 2 ** 53 }],
		['boost 0', { boost: 0 }],
		['boost -0.5', { boost: -0.5 }],
		['boost "0.85"', { boost: '0.85' }],
		['boost null', { boost: null }],
		['boost {}', { boost: {} }],
		['final "false"', { final: 'false' }],
		['final 0', { final: 0 }],
		['final null', { final: null }],
		['jackpot 1', { jackpot: 1 }],
		['jackpot "true"', { jackpot: 'true' }],
		['jackpot null', { jackpot: null }],
	]
	it.each(invalid)('rejects %s', async (_, overrides) => {
		const err = await rejection(parseBoosterToken(await boosterToken(overrides), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_booster')
		expect(isBoostxError(err, 'invalid_claim')).toBe(true)
	})

	it('rejects an iat that is not an integer', async () => {
		for (const iat of ['1732032100', 1.5, null]) {
			const token = await signJWT({ booster: round3(), iat }, boostxPriv)
			const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
			expect(err.message).toBe('invalid Booster token: invalid claim value: iat must be an integer')
			expect(isBoostxError(err, 'invalid_claim')).toBe(true)
		}
	})

	it('judges round and iat by value, so 3.0 and 3e0 are 3, up to 2^53-1', async () => {
		const g = JSON.stringify(gid)
		for (const [round, iat] of [
			['3.0', '1732032100.0'],
			['3e0', '1.7320321e9'],
			['0.3e1', '17320321e2'],
		]) {
			const payload = `{"booster":{"gid":${g},"round":${round},"boost":0.85,"final":false,"jackpot":false},"iat":${iat}}`
			const booster = await parseBoosterToken(await signRaw(payload, boostxPriv), boostxPub, partnerPub)
			expect(booster).toMatchObject({ round: 3, iat: IAT })
		}
		const max = await signJWT({ booster: round3({ round: 2 ** 53 - 1 }), iat: -(2 ** 53 - 1) }, boostxPriv)
		expect(await parseBoosterToken(max, boostxPub, partnerPub)).toMatchObject({
			round: 2 ** 53 - 1,
			iat: -(2 ** 53 - 1),
		})
		const over = await signJWT({ booster: round3(), iat: 2 ** 53 }, boostxPriv)
		expect(isBoostxError(await rejection(parseBoosterToken(over, boostxPub, partnerPub)), 'invalid_claim')).toBe(true)
	})

	it('rejects a boost that parses to Infinity', async () => {
		const payload = `{"booster":{"gid":${JSON.stringify(gid)},"round":3,"boost":1e400,"final":false,"jackpot":false},"iat":1}`
		const err = await rejection(parseBoosterToken(await signRaw(payload, boostxPriv), boostxPub, partnerPub))
		expect(err.message).toBe('invalid Booster token: invalid claim value: boost must be a finite number > 0')
	})

	it('rejects a booster root or gid of the wrong type', async () => {
		for (const [root, code] of [
			[[], 'invalid_claim'],
			['x', 'invalid_claim'],
			[null, 'invalid_claim'],
			[round3({ gid: 'x' }), 'invalid_gid'],
			[round3({ gid: null }), 'invalid_gid'],
			[round3({ gid: { ...gid, user: 1 } }), 'invalid_gid'],
			[round3({ gid: { ...gid, bet: null } }), 'invalid_gid'],
			[round3({ gid: { partner: gid.partner, user: gid.user, bet: gid.bet } }), 'invalid_gid'],
		] as const) {
			const token = await signJWT({ booster: root, iat: IAT }, boostxPriv)
			const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
			expect(err.code).toBe('invalid_booster')
			expect(isBoostxError(err, code)).toBe(true)
			expect(() => extractBoosterPartner(token)).toThrow(expect.objectContaining({ code: 'invalid_booster' }))
		}
	})

	it('refuses invalid UTF-8 in an id as a malformed token', async () => {
		const enc = new TextEncoder()
		const [before, after] = JSON.stringify({ booster: round3({ gid: { ...gid, user: '@' } }), iat: IAT }).split('@')
		const token = await signParts(
			'{"alg":"ES256","typ":"JWT"}',
			[...enc.encode(before), 0xc3, 0x28, ...enc.encode(after)],
			boostxPriv,
		)
		const err = await rejection(parseBoosterToken(token, boostxPub, partnerPub))
		expect(err.message).toBe('invalid Booster token: invalid token payload: not JSON')
		expect(isBoostxError(err, 'invalid_signature')).toBe(false)
		expect(() => extractBoosterPartner(token)).toThrow(expect.objectContaining({ code: 'invalid_booster' }))
	})

	it('matches member names exactly, so another spelling neither supplies nor overrides one', async () => {
		const variants = await boosterToken({ gid: { ...gid, Partner: 'other', USER: 'other' } })
		expect((await parseBoosterToken(variants, boostxPub, partnerPub)).gid).toStrictEqual(gid)
		expect(extractBoosterPartner(variants)).toBe(gid.partner)
		const { user, ...rest } = gid
		const err = await rejection(
			parseBoosterToken(await boosterToken({ gid: { ...rest, User: user } }), boostxPub, partnerPub),
		)
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
		const root = await signJWT({ booster: { ...round3({ gid: undefined }), GID: gid }, iat: IAT }, boostxPriv)
		expect((await rejection(parseBoosterToken(root, boostxPub, partnerPub))).message).toBe(
			'invalid Booster token: missing required claim: gid',
		)
	})
})

describe('extractBoosterPartner', () => {
	it('returns gid.partner without verifying', async () => {
		expect(extractBoosterPartner(await boosterToken({}, otherPriv))).toBe('partner-xyz')
	})

	it('rejects malformed tokens', () => {
		const b64 = (s: string) => encodeBase64url(new TextEncoder().encode(s))
		for (const token of ['', 'not-a-jwt', 'a.b', 'a.b.c.d', 'a.!!!.c', `a.${b64('not json')}.c`, `a.${b64('[1]')}.c`]) {
			expect(() => extractBoosterPartner(token)).toThrow(BoostxError)
			try {
				extractBoosterPartner(token)
			} catch (e) {
				expect(isBoostxError(e, 'invalid_booster')).toBe(true)
			}
		}
	})

	it('rejects a missing gid or empty partner', async () => {
		for (const [overrides, name] of [
			[{ gid: undefined }, 'gid'],
			[{ gid: { ...gid, partner: '' } }, 'gid.partner'],
		] as const) {
			const token = await boosterToken(overrides)
			expect(() => extractBoosterPartner(token)).toThrow(`invalid Booster token: missing required claim: ${name}`)
		}
	})
})
