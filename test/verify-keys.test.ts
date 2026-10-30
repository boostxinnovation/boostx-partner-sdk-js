import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { encodeBase64url } from '../src/base64url.js'
import { BoostxError, isBoostxError, verifyKeysReason, type VerifyKeysReason } from '../src/errors.js'
import { decodeJWTPayload, signJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import {
	BOOSTX_IDENTITY,
	DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS,
	createVerifyKeysRequestToken,
	createVerifyKeysResponseToken,
	extractVerifyKeysRequestPartner,
	parseVerifyKeysRequestToken,
	parseVerifyKeysResponseToken,
} from '../src/verify-keys.js'
import { BOOSTX, OTHER, PARTNER, signParts } from './fixtures.js'

const NOW = 1_800_000_000
const PARTNER_ID = 'partner-123'

let boostxPriv: CryptoKeyLike
let boostxPub: CryptoKeyLike
let partnerPriv: CryptoKeyLike
let partnerPub: CryptoKeyLike
let otherPriv: CryptoKeyLike

beforeAll(async () => {
	boostxPriv = await loadPrivateKeyFromPEM(BOOSTX.privatePKCS8)
	boostxPub = await loadPublicKeyFromPEM(BOOSTX.publicSPKI)
	partnerPriv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	otherPriv = await loadPrivateKeyFromPEM(OTHER.privatePKCS8)
})

// A fixed clock half-way through second NOW, so iat boundaries are exact.
beforeEach(() => {
	vi.spyOn(Date, 'now').mockReturnValue(NOW * 1000 + 500)
})

afterEach(() => {
	vi.restoreAllMocks()
})

// A BoostX → partner request as BoostX signs it, with any claim overridden (undefined drops it).
function request(overrides: Record<string, unknown> = {}, key = boostxPriv): Promise<string> {
	return signJWT({ verifyKeys: { nonce: 42 }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: NOW, ...overrides }, key)
}

async function rejection(p: Promise<unknown>): Promise<BoostxError> {
	const err = await p.then(
		() => undefined,
		(e: unknown) => e,
	)
	expect(err).toBeInstanceOf(BoostxError)
	return err as BoostxError
}

async function expectReason(p: Promise<unknown>, reason: VerifyKeysReason): Promise<BoostxError> {
	const err = await rejection(p)
	expect(err.code).toBe('invalid_verify_keys')
	expect(verifyKeysReason(err)).toBe(reason)
	expect(err.message.startsWith(`invalid verifyKeysJWT: ${reason}`)).toBe(true)
	return err
}

function thrown(fn: () => unknown): unknown {
	try {
		fn()
	} catch (e) {
		return e
	}
	return undefined
}

describe('verify-keys request', () => {
	it('round-trips and has the documented wire shape', async () => {
		const token = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 7)
		expect(token.split('.')[0]).toBe('eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9')
		expect(decodeJWTPayload(token)).toStrictEqual({
			verifyKeys: { nonce: 7 },
			iss: 'boostx',
			aud: PARTNER_ID,
			iat: NOW,
		})
		expect(await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID)).toStrictEqual({
			partnerID: PARTNER_ID,
			nonce: 7,
			iat: NOW,
		})
	})

	it('resolves to the iat as received, inside the window', async () => {
		const token = await request({ iat: NOW - 30 })
		expect(await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID)).toStrictEqual({
			partnerID: PARTNER_ID,
			nonce: 42,
			iat: NOW - 30,
		})
	})

	it('accepts the nonce bounds 1 and 2^31-1', async () => {
		for (const nonce of [1, 0x7fffffff]) {
			const token = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, nonce)
			expect((await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID)).nonce).toBe(nonce)
		}
	})

	it('checks the private key before the partner ID and the nonce', async () => {
		for (const create of [createVerifyKeysRequestToken, createVerifyKeysResponseToken]) {
			for (const key of [boostxPub, undefined]) {
				const err = await rejection(create(key as CryptoKeyLike, '', 0))
				expect(err.code).toBe('invalid_private_key')
			}
			expect((await rejection(create(boostxPriv, '', 0))).code).toBe('missing_claim')
		}
	})

	it('refuses to sign a nonce outside [1, 2^31-1]', async () => {
		for (const nonce of [0, -1, 2 ** 31, 1.5, Number.NaN, '5' as unknown as number]) {
			const err = await rejection(createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, nonce))
			expect(err.code).toBe('invalid_claim')
		}
	})

	it('checks the public key before the partner ID and the token', async () => {
		for (const key of [boostxPriv, undefined]) {
			const request = await rejection(parseVerifyKeysRequestToken('garbage', key as CryptoKeyLike, ''))
			expect(request.code).toBe('invalid_public_key')
			const response = await rejection(parseVerifyKeysResponseToken('garbage', key as CryptoKeyLike, ''))
			expect(response.code).toBe('invalid_public_key')
		}
		expect((await rejection(parseVerifyKeysRequestToken('garbage', boostxPub, ''))).code).toBe('missing_claim')
	})

	it('refuses an empty or "boostx" partnerID on both create and parse', async () => {
		const token = await request()
		for (const [partnerID, code] of [
			['', 'missing_claim'],
			['boostx', 'invalid_claim'],
		] as const) {
			expect((await rejection(createVerifyKeysRequestToken(boostxPriv, partnerID, 1))).code).toBe(code)
			const err = await rejection(parseVerifyKeysRequestToken(token, boostxPub, partnerID))
			expect(err.code).toBe(code)
			expect(verifyKeysReason(err)).toBe('shape')
		}
	})

	it('refuses to sign for a partnerID with a lone surrogate, after the nonce', async () => {
		for (const create of [createVerifyKeysRequestToken, createVerifyKeysResponseToken]) {
			for (const partnerID of ['p\uD800', '\uDC00p']) {
				const err = await rejection(create(boostxPriv, partnerID, 1))
				expect(err.code).toBe('invalid_claim')
				expect(err.message).toBe('invalid claim value: partnerID is not well-formed Unicode')
				expect((await rejection(create(boostxPriv, partnerID, 0))).message).toMatch(/: nonce /)
			}
			await create(boostxPriv, 'p😀', 1)
		}
	})

	it('rejects a token signed with another key as signature', async () => {
		const err = await expectReason(
			parseVerifyKeysRequestToken(await request({}, otherPriv), boostxPub, PARTNER_ID),
			'signature',
		)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('rejects an alg other than ES256 as signature', async () => {
		const [, payload, sig] = (await request()).split('.')
		const header = encodeBase64url(new TextEncoder().encode('{"alg":"HS256","typ":"JWT"}'))
		await expectReason(parseVerifyKeysRequestToken(`${header}.${payload}.${sig}`, boostxPub, PARTNER_ID), 'signature')
	})

	it('rejects iss/aud mismatches as iss-aud', async () => {
		for (const overrides of [
			{ aud: 'partner-other' },
			{ iss: 'partner-123', aud: 'boostx' },
			{ iss: 'boostx-x' },
			{ iss: undefined },
			{ aud: undefined },
			{ iss: null },
		]) {
			await expectReason(parseVerifyKeysRequestToken(await request(overrides), boostxPub, PARTNER_ID), 'iss-aud')
		}
	})

	it('accepts iat within the default 30 s skew, in both directions', async () => {
		expect(DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS).toBe(30)
		for (const iat of [NOW - 30, NOW + 30]) {
			expect((await parseVerifyKeysRequestToken(await request({ iat }), boostxPub, PARTNER_ID)).nonce).toBe(42)
		}
	})

	it('rejects iat beyond the skew, in both directions, as stale', async () => {
		for (const iat of [NOW - 31, NOW + 31]) {
			await expectReason(parseVerifyKeysRequestToken(await request({ iat }), boostxPub, PARTNER_ID), 'stale')
		}
	})

	it('reads a missing or null iat as 0, so stale', async () => {
		for (const iat of [undefined, null]) {
			await expectReason(parseVerifyKeysRequestToken(await request({ iat }), boostxPub, PARTNER_ID), 'stale')
		}
	})

	it('honours maxSkewSeconds', async () => {
		const token = await request({ iat: NOW - 10 })
		await expectReason(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID, { maxSkewSeconds: 5 }), 'stale')
		expect((await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID, { maxSkewSeconds: 10 })).nonce).toBe(42)
		const late = await request({ iat: NOW - 50 })
		expect((await parseVerifyKeysRequestToken(late, boostxPub, PARTNER_ID, { maxSkewSeconds: 60 })).nonce).toBe(42)
	})

	it('reads maxSkewSeconds absent, null or 0 as 30, and cuts a fraction to whole seconds', async () => {
		const at = async (age: number, maxSkewSeconds: unknown) =>
			parseVerifyKeysRequestToken(await request({ iat: NOW - age }), boostxPub, PARTNER_ID, {
				maxSkewSeconds,
			} as { maxSkewSeconds?: number })
		for (const window of [undefined, null, 0, -0]) {
			expect((await at(30, window)).nonce).toBe(42)
			await expectReason(at(31, window), 'stale')
		}
		expect((await parseVerifyKeysRequestToken(await request({ iat: NOW - 30 }), boostxPub, PARTNER_ID)).nonce).toBe(42)
		// Typed to take null as well, for the options object and for the window.
		const late = await request({ iat: NOW - 31 })
		await expectReason(parseVerifyKeysRequestToken(late, boostxPub, PARTNER_ID, null), 'stale')
		await expectReason(parseVerifyKeysRequestToken(late, boostxPub, PARTNER_ID, { maxSkewSeconds: null }), 'stale')
		const response = await createVerifyKeysResponseToken(partnerPriv, PARTNER_ID, 42)
		expect((await parseVerifyKeysResponseToken(response, partnerPub, PARTNER_ID, null)).nonce).toBe(42)
		expect((await at(0, 0.5)).nonce).toBe(42)
		await expectReason(at(1, 0.5), 'stale')
		expect((await at(10, 10.9)).nonce).toBe(42)
		expect((await expectReason(at(11, 10.9), 'stale')).message).toBe(
			'invalid verifyKeysJWT: stale (iat outside the 10 s skew window)',
		)
	})

	it('refuses a negative or non-finite maxSkewSeconds', async () => {
		const token = await request()
		for (const maxSkewSeconds of [-1, -0.5, Number.NaN, Number.POSITIVE_INFINITY, '30' as unknown as number]) {
			const err = await rejection(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID, { maxSkewSeconds }))
			expect(err.code).toBe('invalid_claim')
		}
	})

	it('rejects a nonce of 0, a negative one, or none at all as nonce-format', async () => {
		for (const overrides of [
			{ verifyKeys: { nonce: 0 } },
			{ verifyKeys: { nonce: -5 } },
			{ verifyKeys: { nonce: null } },
			{ verifyKeys: {} },
			{ verifyKeys: null },
			{ verifyKeys: undefined },
		]) {
			await expectReason(parseVerifyKeysRequestToken(await request(overrides), boostxPub, PARTNER_ID), 'nonce-format')
		}
	})

	it('rejects every other nonce that is not an integer in [1, 2^31-1] as nonce-format', async () => {
		for (const nonce of [2 ** 31, -(2 ** 31) - 1, 1e300, 3.5, 0.5, '42', '', true, false, [1], { n: 1 }]) {
			const token = await request({ verifyKeys: { nonce } })
			await expectReason(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID), 'nonce-format')
		}
	})

	it('judges the nonce by value, so 5.0 and 5e0 are 5', async () => {
		for (const nonce of ['5.0', '5e0', '0.5e1']) {
			const claims = `{"verifyKeys":{"nonce":${nonce}},"iss":"boostx","aud":"${PARTNER_ID}","iat":${NOW}}`
			const token = await signParts('{"alg":"ES256"}', claims, boostxPriv)
			expect((await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID)).nonce).toBe(5)
		}
	})

	it('rejects claims of the wrong type as shape', async () => {
		for (const overrides of [
			{ iat: String(NOW) },
			{ iat: NOW + 0.5 },
			{ iat: 2 ** 53 },
			{ iat: -(2 ** 53) },
			{ iat: true },
			{ iss: 1 },
			{ aud: [PARTNER_ID] },
			{ verifyKeys: [42] },
			{ verifyKeys: 42 },
			{ verifyKeys: '42' },
		]) {
			await expectReason(parseVerifyKeysRequestToken(await request(overrides), boostxPub, PARTNER_ID), 'shape')
		}
	})

	it('judges iat by value up to 2^53-1, so 1.8e9 is accepted and 2^53-1 is merely stale', async () => {
		const claims = (iat: string) => `{"verifyKeys":{"nonce":42},"iss":"boostx","aud":"${PARTNER_ID}","iat":${iat}}`
		for (const iat of [`${NOW}.0`, `${NOW / 1e8}e8`]) {
			const token = await signParts('{"alg":"ES256"}', claims(iat), boostxPriv)
			expect((await parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID)).iat).toBe(NOW)
		}
		await expectReason(parseVerifyKeysRequestToken(await request({ iat: 2 ** 53 - 1 }), boostxPub, PARTNER_ID), 'stale')
		const overflow = await signParts('{"alg":"ES256"}', claims('1e400'), boostxPriv)
		await expectReason(parseVerifyKeysRequestToken(overflow, boostxPub, PARTNER_ID), 'shape')
	})

	it('holds a present exp or nbf to the clock in whole seconds, as stale', async () => {
		for (const overrides of [{ exp: NOW }, { exp: NOW - 1 }, { nbf: NOW + 1 }, { exp: NOW + 60, nbf: NOW + 60 }]) {
			await expectReason(parseVerifyKeysRequestToken(await request(overrides), boostxPub, PARTNER_ID), 'stale')
		}
		for (const overrides of [{ exp: NOW + 1 }, { nbf: NOW }, { exp: NOW + 1, nbf: NOW - 1 }, { exp: 1e300 }]) {
			expect((await parseVerifyKeysRequestToken(await request(overrides), boostxPub, PARTNER_ID)).nonce).toBe(42)
		}
	})

	it('refuses an exp or nbf that is not a number, null included, as shape', async () => {
		for (const overrides of [{ exp: null }, { exp: String(NOW + 60) }, { nbf: null }, { nbf: [NOW] }, { nbf: {} }]) {
			const token = await request(overrides)
			await expectReason(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID), 'shape')
			expect(verifyKeysReason(thrown(() => extractVerifyKeysRequestPartner(token)))).toBe('shape')
		}
	})

	it('reports the first failure: signature, claim types, iss-aud, stale, then nonce-format', async () => {
		const parse = async (overrides: Record<string, unknown>, key = boostxPriv) =>
			parseVerifyKeysRequestToken(await request(overrides, key), boostxPub, PARTNER_ID)
		await expectReason(parse({ iss: 1, aud: 'x', iat: 0, verifyKeys: { nonce: 0 } }, otherPriv), 'signature')
		await expectReason(parse({ exp: null, aud: 'x', iat: 0, verifyKeys: { nonce: 0 } }), 'shape')
		await expectReason(parse({ aud: 'x', iat: 0, exp: 0, verifyKeys: { nonce: 0 } }), 'iss-aud')
		await expectReason(parse({ iat: 0, verifyKeys: { nonce: 0 } }), 'stale')
		await expectReason(parse({ exp: NOW, verifyKeys: { nonce: '1' } }), 'stale')
		await expectReason(parse({ nbf: NOW + 1, verifyKeys: { nonce: '1' } }), 'stale')
		await expectReason(parse({ verifyKeys: { nonce: '1' } }), 'nonce-format')
	})

	it('verifies the signature before the payload format, so a foreign token with a non-object payload is signature', async () => {
		const token = await signParts('{"alg":"ES256"}', '[1]', otherPriv)
		await expectReason(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID), 'signature')
		await expectReason(
			parseVerifyKeysRequestToken(await signParts('{"alg":"ES256"}', '[1]', boostxPriv), boostxPub, PARTNER_ID),
			'shape',
		)
	})

	it('rejects a malformed token as shape', async () => {
		const b64 = (s: string) => encodeBase64url(new TextEncoder().encode(s))
		for (const token of ['', 'a.b', `${b64('{"alg":"ES256"}')}.${b64('[]')}`, `${b64('nope')}.x.y`]) {
			await expectReason(parseVerifyKeysRequestToken(token, boostxPub, PARTNER_ID), 'shape')
		}
	})

	it('passes a key that cannot verify through unwrapped, which verifyKeysReason maps to signature', async () => {
		const err = await rejection(parseVerifyKeysRequestToken(await request(), boostxPriv, PARTNER_ID))
		expect(err.code).toBe('invalid_public_key')
		expect(verifyKeysReason(err)).toBe('signature')
		expect(verifyKeysReason(new BoostxError('invalid_public_key', 'x'))).toBe('signature')
		expect(verifyKeysReason(new BoostxError('invalid_private_key', 'x'))).toBe('shape')
	})

	it('rejects a crit header as signature, and a byte order mark or an unpaired surrogate escape as shape', async () => {
		const claims = `{"verifyKeys":{"nonce":42},"iss":"boostx","aud":"${PARTNER_ID}","iat":${NOW}}`
		const crit = await signParts('{"alg":"ES256","crit":["exp"]}', claims, boostxPriv)
		await expectReason(parseVerifyKeysRequestToken(crit, boostxPub, PARTNER_ID), 'signature')
		const bom = await signParts([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"alg":"ES256"}')], claims, boostxPriv)
		await expectReason(parseVerifyKeysRequestToken(bom, boostxPub, PARTNER_ID), 'shape')
		const escaped = `${PARTNER_ID}${String.fromCharCode(92)}ud800`
		// The second repeats aud, keeping the expected value last.
		for (const lone of [claims.replace(PARTNER_ID, escaped), claims.replace('"aud"', `"aud":"${escaped}","aud"`)]) {
			const surrogate = await signParts('{"alg":"ES256"}', lone, boostxPriv)
			await expectReason(parseVerifyKeysRequestToken(surrogate, boostxPub, PARTNER_ID), 'shape')
			expect(verifyKeysReason(thrown(() => extractVerifyKeysRequestPartner(surrogate)))).toBe('shape')
		}
		expect(
			(await parseVerifyKeysRequestToken(await signParts('{"alg":"ES256"}', claims, boostxPriv), boostxPub, PARTNER_ID))
				.nonce,
		).toBe(42)
	})
})

describe('verify-keys response', () => {
	it('round-trips and has the documented wire shape', async () => {
		const token = await createVerifyKeysResponseToken(partnerPriv, PARTNER_ID, 1642938715)
		expect(decodeJWTPayload(token)).toStrictEqual({
			verifyKeys: { nonce: 1642938715 },
			iss: PARTNER_ID,
			aud: 'boostx',
			iat: NOW,
		})
		expect(await parseVerifyKeysResponseToken(token, partnerPub, PARTNER_ID)).toStrictEqual({
			partnerID: PARTNER_ID,
			nonce: 1642938715,
			iat: NOW,
		})
	})

	it('refuses to sign nonce 0 or 2^31, or for partner "boostx"', async () => {
		expect((await rejection(createVerifyKeysResponseToken(partnerPriv, PARTNER_ID, 0))).code).toBe('invalid_claim')
		expect((await rejection(createVerifyKeysResponseToken(partnerPriv, PARTNER_ID, 2 ** 31))).code).toBe(
			'invalid_claim',
		)
		expect((await rejection(createVerifyKeysResponseToken(partnerPriv, 'boostx', 1))).code).toBe('invalid_claim')
	})

	it('rejects a request presented as a response, and another partner, as iss-aud', async () => {
		const asRequest = await createVerifyKeysRequestToken(partnerPriv, PARTNER_ID, 1)
		await expectReason(parseVerifyKeysResponseToken(asRequest, partnerPub, PARTNER_ID), 'iss-aud')
		const foreign = await createVerifyKeysResponseToken(partnerPriv, 'partner-other', 1)
		await expectReason(parseVerifyKeysResponseToken(foreign, partnerPub, PARTNER_ID), 'iss-aud')
	})

	it('classifies signature, shape, stale and nonce failures as the request does', async () => {
		const response = (overrides: Record<string, unknown>, key = partnerPriv) =>
			signJWT({ verifyKeys: { nonce: 9 }, iss: PARTNER_ID, aud: 'boostx', iat: NOW, ...overrides }, key)
		await expectReason(parseVerifyKeysResponseToken(await response({}, otherPriv), partnerPub, PARTNER_ID), 'signature')
		await expectReason(parseVerifyKeysResponseToken(await response({ iat: NOW + 31 }), partnerPub, PARTNER_ID), 'stale')
		const nonce0 = await response({ verifyKeys: { nonce: 0 } })
		await expectReason(parseVerifyKeysResponseToken(nonce0, partnerPub, PARTNER_ID), 'nonce-format')
		const nonceStr = await response({ verifyKeys: { nonce: '9' } })
		await expectReason(parseVerifyKeysResponseToken(nonceStr, partnerPub, PARTNER_ID), 'nonce-format')
		const expired = await response({ exp: NOW })
		await expectReason(parseVerifyKeysResponseToken(expired, partnerPub, PARTNER_ID), 'stale')
		const notYet = await response({ nbf: NOW + 1 })
		await expectReason(parseVerifyKeysResponseToken(notYet, partnerPub, PARTNER_ID), 'stale')
		const nullExp = await response({ exp: null })
		await expectReason(parseVerifyKeysResponseToken(nullExp, partnerPub, PARTNER_ID), 'shape')
		const crit = await signParts(
			'{"alg":"ES256","crit":[]}',
			`{"verifyKeys":{"nonce":9},"iss":"${PARTNER_ID}","aud":"boostx","iat":${NOW}}`,
			partnerPriv,
		)
		await expectReason(parseVerifyKeysResponseToken(crit, partnerPub, PARTNER_ID), 'signature')
	})
})

describe('extractVerifyKeysRequestPartner', () => {
	it('returns aud without verifying', async () => {
		expect(extractVerifyKeysRequestPartner(await request({}, otherPriv))).toBe(PARTNER_ID)
	})

	it('never judges the nonce, the iss, the time or exp and nbf beyond their type', async () => {
		for (const overrides of [
			{ verifyKeys: { nonce: '1' } },
			{ verifyKeys: { nonce: 0 } },
			{ verifyKeys: {} },
			{ iss: 'mallory', iat: 0, exp: 0, nbf: NOW + 60 },
		]) {
			expect(extractVerifyKeysRequestPartner(await request(overrides))).toBe(PARTNER_ID)
		}
	})

	it('rejects malformed tokens and an aud naming no partner as shape', async () => {
		const b64 = (s: string) => encodeBase64url(new TextEncoder().encode(s))
		const tokens = [
			'',
			'a.b',
			'a.b.c.d',
			'a.***.c',
			`a.${b64('not json')}.c`,
			`a.${b64('"str"')}.c`,
			await request({ aud: undefined }),
			await request({ aud: '' }),
			await request({ aud: 'boostx' }),
			await request({ aud: [PARTNER_ID] }),
			await request({ iat: 1.5 }),
			await request({ verifyKeys: 1 }),
			await request({ exp: null }),
			await request({ nbf: 'soon' }),
		]
		for (const token of tokens) {
			const err = thrown(() => extractVerifyKeysRequestPartner(token))
			expect(isBoostxError(err, 'invalid_verify_keys')).toBe(true)
			expect(verifyKeysReason(err)).toBe('shape')
		}
	})
})
