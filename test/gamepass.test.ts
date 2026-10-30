import { beforeAll, describe, expect, it } from 'vitest'

import { decodeBase64url } from '../src/base64url.js'
import { isBoostxError, type BoostxErrorCode } from '../src/errors.js'
import { createGamePassToken, type GamePassParams } from '../src/gamepass.js'
import { parseGIDClaim, verifyGID } from '../src/gid.js'
import { decodeJWTPayload, verifyJWT, type Claims } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { OTHER, PARTNER } from './fixtures.js'

let priv: CryptoKeyLike
let pub: CryptoKeyLike

beforeAll(async () => {
	priv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	pub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
})

const BASE: GamePassParams = {
	partner: 'partner-123',
	user: 'user-456',
	bet: 'bet-789',
	amount: 100,
	currency: 'USD',
	x: 2,
}

/** The payload segment exactly as it travels. */
const rawPayload = (token: string) => new TextDecoder().decode(decodeBase64url(token.split('.')[1]!))

const signatureOf = (token: string) =>
	(decodeJWTPayload(token).gamepass as { gid: { signature: string } }).gid.signature

/** The rules BoostX applies to a gamepass, after both signatures verify, up to the open of the game. */
function expectBoostxAccepts(claims: Claims) {
	expect(Number.isInteger(claims.iat)).toBe(true)
	expect(Math.abs(Date.now() / 1000 - (claims.iat as number))).toBeLessThanOrEqual(300)
	expect(claims.exp).toBeUndefined()
	expect(claims.nbf).toBeUndefined()
	const gp = claims.gamepass as Record<string, Record<string, unknown> | undefined>
	expect(typeof gp).toBe('object')
	parseGIDClaim(gp.gid)
	const { stake, xrange } = gp
	expect(typeof stake?.amount).toBe('number')
	expect(stake!.amount as number).toBeGreaterThanOrEqual(0.01)
	expect(typeof stake?.currency).toBe('string')
	expect(typeof xrange?.init).toBe('number')
	for (const bound of ['min', 'max']) expect(['undefined', 'number']).toContain(typeof xrange![bound])
	const { decimals } = xrange!
	if (decimals !== undefined)
		expect(Number.isInteger(decimals) && (decimals as number) >= 2 && (decimals as number) <= 6).toBe(true)
	expect(['undefined', 'boolean']).toContain(typeof gp.demo)
}

describe('createGamePassToken', () => {
	it('writes every field on the wire, in the documented shape', async () => {
		const before = Math.floor(Date.now() / 1000)
		const token = await createGamePassToken(priv, {
			partner: 'partner-xyz',
			user: 'user-12345',
			bet: 'bet-abc789',
			amount: 100,
			currency: 'USD',
			x: 2.5,
			xMin: 1.1,
			xMax: 5,
			xDecimals: 2,
			eventTitle: 'Real Madrid vs Barcelona — Match Winner: Real Madrid',
			demo: true,
		})
		const after = Math.floor(Date.now() / 1000)
		const { iat } = decodeJWTPayload(token)
		expect(iat).toBeGreaterThanOrEqual(before)
		expect(iat).toBeLessThanOrEqual(after)
		expect(rawPayload(token)).toBe(
			`{"iat":${iat},"gamepass":{"gid":{"partner":"partner-xyz","user":"user-12345","bet":"bet-abc789","signature":"${signatureOf(token)}"},` +
				`"stake":{"amount":100,"currency":"USD"},"xrange":{"init":2.5,"min":1.1,"max":5,"decimals":2},` +
				`"event":{"title":"Real Madrid vs Barcelona — Match Winner: Real Madrid"},"demo":true}}`,
		)
		expectBoostxAccepts(decodeJWTPayload(token))
	})

	it('omits every optional field that is unset', async () => {
		const token = await createGamePassToken(priv, { ...BASE, amount: 12.5 })
		const { iat } = decodeJWTPayload(token)
		expect(rawPayload(token)).toBe(
			`{"iat":${iat},"gamepass":{"gid":{"partner":"partner-123","user":"user-456","bet":"bet-789","signature":"${signatureOf(token)}"},` +
				`"stake":{"amount":12.5,"currency":"USD"},"xrange":{"init":2}}}`,
		)
		expectBoostxAccepts(decodeJWTPayload(token))
	})

	it('omits xMin, xMax and xDecimals of 0, an empty title and demo false', async () => {
		const token = await createGamePassToken(priv, {
			...BASE,
			xMin: 0,
			xMax: 0,
			xDecimals: 0,
			eventTitle: '',
			demo: false,
		})
		expect(decodeJWTPayload(token).gamepass).toEqual({
			gid: { partner: 'partner-123', user: 'user-456', bet: 'bet-789', signature: signatureOf(token) },
			stake: { amount: 100, currency: 'USD' },
			xrange: { init: 2 },
		})
	})

	it('sends a bound that is set and leaves out one that is not', async () => {
		const onlyMax = await createGamePassToken(priv, { ...BASE, xMax: 50 })
		expect((decodeJWTPayload(onlyMax).gamepass as Claims).xrange).toEqual({ init: 2, max: 50 })
		const onlyMin = await createGamePassToken(priv, { ...BASE, xMin: 1.5 })
		expect((decodeJWTPayload(onlyMin).gamepass as Claims).xrange).toEqual({ init: 2, min: 1.5 })
	})

	it('signs the token and the GID with the partner private key', async () => {
		const token = await createGamePassToken(priv, BASE)
		const claims = await verifyJWT(token, pub)
		await expect(verifyGID(parseGIDClaim((claims.gamepass as Claims).gid), pub)).resolves.toBeUndefined()
		const err = await verifyJWT(token, await loadPublicKeyFromPEM(OTHER.publicSPKI)).catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it.each([2, 3, 4, 5, 6])('accepts xDecimals %i', async (xDecimals) => {
		const token = await createGamePassToken(priv, { ...BASE, xDecimals })
		expect((decodeJWTPayload(token).gamepass as Claims).xrange).toEqual({ init: 2, decimals: xDecimals })
	})

	// BoostX refuses these at the open, but the SDK does not check the range of X, as the Go SDK.
	it('leaves the X range to BoostX', async () => {
		for (const params of [
			{ ...BASE, x: 0.5 },
			{ ...BASE, x: 500, xMin: 300, xMax: 250 },
		]) {
			await expect(createGamePassToken(priv, params)).resolves.toMatch(/^eyJ/)
		}
	})

	it.each(['USD', 'USDT', 'XAU'])('accepts the currency %s', async (currency) => {
		const token = await createGamePassToken(priv, { ...BASE, currency })
		expect((decodeJWTPayload(token).gamepass as Claims).stake).toEqual({ amount: 100, currency })
	})

	const rejected: [string, Record<string, unknown>, BoostxErrorCode, string][] = [
		['an empty partner', { partner: '' }, 'missing_claim', 'missing required claim: partner'],
		['an empty user', { user: '' }, 'missing_claim', 'missing required claim: user'],
		['an empty bet', { bet: '' }, 'missing_claim', 'missing required claim: bet'],
		['no user', { user: undefined }, 'missing_claim', 'missing required claim: user'],
		['a null partner', { partner: null }, 'missing_claim', 'missing required claim: partner'],
		['a null user', { user: null }, 'missing_claim', 'missing required claim: user'],
		['a null bet', { bet: null }, 'missing_claim', 'missing required claim: bet'],
		['a numeric user', { user: 12345 }, 'invalid_claim', 'invalid claim value: user must be a string'],
		[
			'an empty partner before every other field',
			{ partner: '', currency: '', amount: 0 },
			'missing_claim',
			'missing required claim: partner',
		],
		['a lone surrogate in user', { user: 'u' + String.fromCharCode(0xd800) }, 'invalid_claim', ''],
		['an empty currency', { currency: '' }, 'missing_claim', 'missing required claim: currency'],
		['no currency', { currency: undefined }, 'missing_claim', 'missing required claim: currency'],
		['a null currency', { currency: null }, 'missing_claim', 'missing required claim: currency'],
		...[840, 'usd', 'Usd', 'US', 'USDTX', 'U$D', ' USD', 'USD\n', 'ÜSD'].map(
			(currency): [string, Record<string, unknown>, BoostxErrorCode, string] => [
				`the currency ${JSON.stringify(currency)}`,
				{ currency },
				'invalid_claim',
				'invalid claim value: currency must be 3 or 4 uppercase letters',
			],
		),
		['a zero amount', { amount: 0 }, 'invalid_claim', 'invalid claim value: amount must be a finite number >= 0.01'],
		[
			'no amount',
			{ amount: undefined },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		['a null amount', { amount: null }, 'invalid_claim', 'invalid claim value: amount must be a finite number >= 0.01'],
		[
			'a negative amount',
			{ amount: -100 },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		[
			'an amount just below 0.01',
			{ amount: 0.009999999999999998 },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		[
			'an amount of 1e-308',
			{ amount: 1e-308 },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		['a NaN amount', { amount: NaN }, 'invalid_claim', 'invalid claim value: amount must be a finite number >= 0.01'],
		[
			'an infinite amount',
			{ amount: Infinity },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		[
			'a string amount',
			{ amount: '100' },
			'invalid_claim',
			'invalid claim value: amount must be a finite number >= 0.01',
		],
		['a negative x', { x: -2 }, 'invalid_claim', 'invalid claim value: x'],
		['a zero x', { x: 0 }, 'invalid_claim', 'invalid claim value: x'],
		['a null x', { x: null }, 'invalid_claim', 'invalid claim value: x'],
		['a negative zero x', { x: -0 }, 'invalid_claim', 'invalid claim value: x'],
		['a NaN x', { x: NaN }, 'invalid_claim', 'invalid claim value: x'],
		['an infinite x', { x: -Infinity }, 'invalid_claim', 'invalid claim value: x'],
		['a negative xMin', { xMin: -1.1 }, 'invalid_claim', 'invalid claim value: xmin'],
		['a NaN xMin', { xMin: NaN }, 'invalid_claim', 'invalid claim value: xmin'],
		['a negative xMax', { xMax: -10 }, 'invalid_claim', 'invalid claim value: xmax'],
		['an infinite xMax', { xMax: Infinity }, 'invalid_claim', 'invalid claim value: xmax'],
		...[1, 7, -1, 100, 2.5, NaN].map((xDecimals): [string, Record<string, unknown>, BoostxErrorCode, string] => [
			`xDecimals ${xDecimals}`,
			{ xDecimals },
			'invalid_claim',
			'invalid claim value: xdecimals',
		]),
		['a non-string title', { eventTitle: 42 }, 'invalid_claim', 'invalid claim value: eventTitle'],
		['a non-boolean demo', { demo: 'yes' }, 'invalid_claim', 'invalid claim value: demo'],
		['a numeric demo', { demo: 1 }, 'invalid_claim', 'invalid claim value: demo'],
	]

	it.each(rejected)('rejects %s', async (_, overrides, code, message) => {
		const err = await createGamePassToken(priv, { ...BASE, ...overrides } as GamePassParams).catch((e: unknown) => e)
		expect(isBoostxError(err, code)).toBe(true)
		if (message) expect((err as Error).message).toBe(message)
	})

	it('accepts a stake amount of exactly 0.01', async () => {
		const token = await createGamePassToken(priv, { ...BASE, amount: 0.01 })
		expect((decodeJWTPayload(token).gamepass as Claims).stake).toEqual({ amount: 0.01, currency: 'USD' })
	})

	it('reads a null optional parameter as unset', async () => {
		const token = await createGamePassToken(priv, {
			...BASE,
			xMin: null,
			xMax: null,
			xDecimals: null,
			eventTitle: null,
			demo: null,
		})
		expect(decodeJWTPayload(token).gamepass).toEqual({
			gid: { partner: 'partner-123', user: 'user-456', bet: 'bet-789', signature: signatureOf(token) },
			stake: { amount: 100, currency: 'USD' },
			xrange: { init: 2 },
		})
	})

	it('sends each lone surrogate of the title as U+FFFD and keeps a pair', async () => {
		const c = (...codes: number[]) => String.fromCharCode(...codes)
		for (const [title, want] of [
			['a' + c(0xd800) + 'b', 'a' + c(0xfffd) + 'b'],
			[c(0xdc00, 0xd83d), c(0xfffd, 0xfffd)],
			['goal ' + c(0xd83d, 0xde00), 'goal ' + c(0xd83d, 0xde00)],
		]) {
			const token = await createGamePassToken(priv, { ...BASE, eventTitle: title })
			expect((decodeJWTPayload(token).gamepass as Claims).event).toEqual({ title: want })
			const claims = await verifyJWT(token, pub)
			await expect(verifyGID(parseGIDClaim((claims.gamepass as Claims).gid), pub)).resolves.toBeUndefined()
		}
	})

	it('reads a missing parameter set as an empty one', async () => {
		for (const missing of [undefined, null, 42, 'bet-789']) {
			const params = missing as unknown as GamePassParams
			const err = await createGamePassToken(priv, params).catch((e: unknown) => e)
			expect(isBoostxError(err, 'missing_claim'), String(missing)).toBe(true)
			expect((err as Error).message).toBe('missing required claim: partner')
			const keyFirst = await createGamePassToken(undefined as unknown as CryptoKeyLike, params).catch((e: unknown) => e)
			expect(isBoostxError(keyFirst, 'invalid_private_key')).toBe(true)
		}
	})

	it('reports the first failing parameter in the documented order', async () => {
		const faults: [Record<string, unknown>, string][] = [
			[{ bet: '' }, 'missing required claim: bet'],
			[{ currency: 'usd' }, 'invalid claim value: currency must be 3 or 4 uppercase letters'],
			[{ amount: 0.001 }, 'invalid claim value: amount must be a finite number >= 0.01'],
			[{ x: 0 }, 'invalid claim value: x'],
			[{ xMin: -1 }, 'invalid claim value: xmin'],
			[{ xMax: -1 }, 'invalid claim value: xmax'],
			[{ xDecimals: 7 }, 'invalid claim value: xdecimals'],
			[{ eventTitle: 1 }, 'invalid claim value: eventTitle'],
			[{ demo: 'yes' }, 'invalid claim value: demo'],
			[{ user: 'u' + String.fromCharCode(0xd800) }, 'invalid claim value: user is not well-formed Unicode'],
		]
		for (let i = 0; i < faults.length; i++) {
			const params = Object.assign({ ...BASE }, ...faults.slice(i).map(([f]) => f)) as GamePassParams
			const err = await createGamePassToken(priv, params).catch((e: unknown) => e)
			expect((err as Error).message).toBe(faults[i]![1])
		}
	})

	it('rejects a key that cannot sign with invalid_private_key', async () => {
		for (const key of [pub, null]) {
			const err = await createGamePassToken(key as CryptoKeyLike, BASE).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		}
	})

	it('checks the key before any parameter', async () => {
		const bad = { ...BASE, partner: '', currency: 'usd', amount: -1 }
		for (const key of [pub, undefined]) {
			const err = await createGamePassToken(key as CryptoKeyLike, bad).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		}
		expect(isBoostxError(await createGamePassToken(priv, bad).catch((e: unknown) => e), 'missing_claim')).toBe(true)
	})
})
