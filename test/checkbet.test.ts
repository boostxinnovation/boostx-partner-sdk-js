import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { encodeBase64url } from '../src/base64url.js'
import { extractCheckBetPartner, parseCheckBetToken } from '../src/checkbet.js'
import { BoostxError, isBoostxError } from '../src/errors.js'
import { buildGID, type GID } from '../src/gid.js'
import { signJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { BOOSTX, OTHER, PARTNER, signParts } from './fixtures.js'

const IAT = 1732032050

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

// Signed as BoostX signs a CheckBetJWT.
function checkBetToken(g: unknown = gid, key = boostxPriv): Promise<string> {
	return signJWT({ checkbet: { gid: g }, iat: IAT }, key)
}

async function rejection(p: Promise<unknown>): Promise<BoostxError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	)
	expect(err).toBeInstanceOf(BoostxError)
	return err as BoostxError
}

describe('parseCheckBetToken', () => {
	it('returns the verified check-bet', async () => {
		expect(await parseCheckBetToken(await checkBetToken(), boostxPub, partnerPub)).toStrictEqual({ gid, iat: IAT })
	})

	it('judges iat by value, so 1732032050.0 is 1732032050', async () => {
		const g = JSON.stringify(gid)
		for (const iat of ['1732032050.0', '1.73203205e9']) {
			const token = await signParts('{"alg":"ES256"}', `{"checkbet":{"gid":${g}},"iat":${iat}}`, boostxPriv)
			expect(await parseCheckBetToken(token, boostxPub, partnerPub)).toStrictEqual({ gid, iat: IAT })
		}
		const token = await signParts('{"alg":"ES256"}', `{"checkbet":{"gid":${g}},"iat":1732032050.5}`, boostxPriv)
		expect(isBoostxError(await rejection(parseCheckBetToken(token, boostxPub, partnerPub)), 'invalid_claim')).toBe(true)
	})

	it('rejects a token not signed with the BoostX key', async () => {
		const err = await rejection(parseCheckBetToken(await checkBetToken(gid, otherPriv), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_checkbet')
		expect(err.message).toBe('invalid CheckBet token: invalid token signature')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects a GID signed with another key', async () => {
		const foreign = await buildGID(otherPriv, gid.partner, gid.user, gid.bet)
		const err = await rejection(parseCheckBetToken(await checkBetToken(foreign), boostxPub, partnerPub))
		expect(err.code).toBe('invalid_checkbet')
		expect(err.message).toBe('invalid CheckBet token: failed to verify GID: invalid GID signature')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
	})

	it('accepts a GID signed with a previous key passed in the key list', async () => {
		const previous = await buildGID(otherPriv, gid.partner, gid.user, gid.bet)
		const token = await checkBetToken(previous)
		expect(await parseCheckBetToken(token, boostxPub, [partnerPub, otherPub])).toStrictEqual({
			gid: previous,
			iat: IAT,
		})
	})

	it('rejects a malformed GID signature as a GID signature failure', async () => {
		const err = await rejection(
			parseCheckBetToken(await checkBetToken({ ...gid, signature: '' }), boostxPub, partnerPub),
		)
		expect(isBoostxError(err, 'invalid_gid')).toBe(true)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects an alg other than ES256', async () => {
		const [, payload, sig] = (await checkBetToken()).split('.')
		const header = encodeBase64url(new TextEncoder().encode('{"alg":"none"}'))
		const err = await rejection(parseCheckBetToken(`${header}.${payload}.${sig}`, boostxPub, partnerPub))
		expect(err.code).toBe('invalid_checkbet')
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects a BoosterJWT, whose root field differs', async () => {
		const token = await signJWT(
			{ booster: { gid, round: 1, boost: 1, final: false, jackpot: false }, iat: IAT },
			boostxPriv,
		)
		const err = await rejection(parseCheckBetToken(token, boostxPub, partnerPub))
		expect(err.message).toBe('invalid CheckBet token: missing required claim: checkbet')
		expect(isBoostxError(err, 'missing_claim')).toBe(true)
	})

	it('rejects a missing gid, gid.partner or iat', async () => {
		for (const [token, name] of [
			[await signJWT({ checkbet: {}, iat: IAT }, boostxPriv), 'gid'],
			[await checkBetToken({ ...gid, partner: '' }), 'gid.partner'],
			[await signJWT({ checkbet: { gid } }, boostxPriv), 'iat'],
		] as const) {
			const err = await rejection(parseCheckBetToken(token, boostxPub, partnerPub))
			expect(err.message).toBe(`invalid CheckBet token: missing required claim: ${name}`)
			expect(isBoostxError(err, 'missing_claim')).toBe(true)
		}
	})

	it('rejects claims of the wrong type', async () => {
		for (const [payload, code] of [
			[{ checkbet: [], iat: IAT }, 'invalid_claim'],
			[{ checkbet: 'x', iat: IAT }, 'invalid_claim'],
			[{ checkbet: { gid: 'x' }, iat: IAT }, 'invalid_gid'],
			[{ checkbet: { gid: { ...gid, bet: 7 } }, iat: IAT }, 'invalid_gid'],
			[{ checkbet: { gid }, iat: '1732032050' }, 'invalid_claim'],
			[{ checkbet: { gid }, iat: 1.5 }, 'invalid_claim'],
		] as const) {
			const err = await rejection(parseCheckBetToken(await signJWT(payload, boostxPriv), boostxPub, partnerPub))
			expect(err.code).toBe('invalid_checkbet')
			expect(isBoostxError(err, code)).toBe(true)
		}
	})

	it('enforces a present exp or nbf against the clock in whole seconds, after iat', async () => {
		const NOW = 1732032200
		vi.spyOn(Date, 'now').mockReturnValue(NOW * 1000)
		const token = (claims: Record<string, unknown>) => signJWT({ checkbet: { gid }, iat: IAT, ...claims }, boostxPriv)
		for (const claims of [{ exp: NOW + 1 }, { nbf: NOW }]) {
			expect(await parseCheckBetToken(await token(claims), boostxPub, partnerPub)).toStrictEqual({ gid, iat: IAT })
		}
		for (const [claims, detail] of [
			[{ exp: NOW }, 'invalid claim value: exp is not after the current time'],
			[{ nbf: NOW + 1 }, 'invalid claim value: nbf is after the current time'],
			[{ exp: null }, 'invalid claim value: exp must be a number'],
			[{ nbf: '0' }, 'invalid claim value: nbf must be a number'],
			[{ iat: undefined, exp: NOW }, 'missing required claim: iat'],
		] as const) {
			const t = await token(claims)
			const err = await rejection(parseCheckBetToken(t, boostxPub, partnerPub))
			expect(err.message).toBe(`invalid CheckBet token: ${detail}`)
			expect(() => extractCheckBetPartner(t)).toThrow(err.message)
		}
	})

	it('passes key errors through unwrapped', async () => {
		const token = await checkBetToken()
		expect((await rejection(parseCheckBetToken(token, boostxPub, []))).code).toBe('invalid_public_key')
		expect((await rejection(parseCheckBetToken(token, partnerPriv, partnerPub))).code).toBe('invalid_public_key')
	})
})

describe('extractCheckBetPartner', () => {
	it('returns gid.partner without verifying', async () => {
		expect(extractCheckBetPartner(await checkBetToken(gid, otherPriv))).toBe('partner-xyz')
	})

	it('rejects malformed tokens', () => {
		const b64 = (s: string) => encodeBase64url(new TextEncoder().encode(s))
		for (const token of ['', 'a.b', 'a.b.c.d', 'a.%%%.c', `a.${b64('null')}.c`, `a.${b64('{"checkbet":1}')}.c`]) {
			let err: unknown
			try {
				extractCheckBetPartner(token)
			} catch (e) {
				err = e
			}
			expect(isBoostxError(err, 'invalid_checkbet')).toBe(true)
		}
	})

	it('rejects an empty partner', async () => {
		const token = await checkBetToken({ ...gid, partner: '' })
		expect(() => extractCheckBetPartner(token)).toThrow('invalid CheckBet token: missing required claim: gid.partner')
	})
})
