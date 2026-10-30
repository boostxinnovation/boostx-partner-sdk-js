import { beforeAll, describe, expect, it } from 'vitest'

import { decodeBase64url } from '../src/base64url.js'
import { isBoostxError, type BoostxErrorCode } from '../src/errors.js'
import { parseGIDClaim, verifyGID } from '../src/gid.js'
import { decodeJWTPayload, verifyJWT, type Claims } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { createSettlementToken, SETTLEMENT_STATUSES, type SettlementParams } from '../src/settlement.js'
import { OTHER, PARTNER } from './fixtures.js'

let priv: CryptoKeyLike
let pub: CryptoKeyLike

beforeAll(async () => {
	priv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	pub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
})

const HOUR = 60 * 60 * 1000
const now = Date.now()

const BASE: SettlementParams = {
	partner: 'partner-xyz',
	user: 'user-12345',
	bet: 'bet-abc789',
	status: 'win',
	amount: 150,
	currency: 'USD',
	version: 1732032200000,
	xSettle: 2.5,
	settledAt: 1732032190000,
}

const rawPayload = (token: string) => new TextDecoder().decode(decodeBase64url(token.split('.')[1]!))

const settlementOf = (token: string) => decodeJWTPayload(token).settlement as Record<string, unknown>

const signatureOf = (token: string) => (settlementOf(token).gid as { signature: string }).signature

/** The rules BoostX applies to a settlement after both signatures verify; each failure is a 400. */
function expectBoostxAccepts(claims: Claims) {
	expect(Number.isInteger(claims.iat)).toBe(true)
	expect(claims.exp).toBeUndefined()
	expect(claims.nbf).toBeUndefined()
	const s = claims.settlement as Record<string, unknown>
	expect(typeof s).toBe('object')
	parseGIDClaim(s.gid)
	expect(SETTLEMENT_STATUSES).toContain(s.status)
	expect(Number.isSafeInteger(s.version) && (s.version as number) >= 0).toBe(true)
	if (s.xSettle != null) expect(Number.isFinite(s.xSettle) && (s.xSettle as number) >= 0).toBe(true)
	const settledAt = s.settledAt as number
	expect(Number.isSafeInteger(settledAt) && settledAt >= 1e12 && settledAt <= Date.now() + 24 * HOUR).toBe(true)
	const payout = s.payout as { amount: unknown; currency: unknown }
	expect(Number.isFinite(payout.amount) && (payout.amount as number) >= 0).toBe(true)
	expect(payout.currency).toMatch(/^[A-Z]{3,4}$/)
	if (s.status === 'unsettled') expect(payout.amount).toBe(0)
}

describe('createSettlementToken', () => {
	it('writes every field on the wire, in the documented shape', async () => {
		const before = Math.floor(Date.now() / 1000)
		const token = await createSettlementToken(priv, BASE)
		const { iat } = decodeJWTPayload(token)
		expect(iat).toBeGreaterThanOrEqual(before)
		expect(iat).toBeLessThanOrEqual(Math.floor(Date.now() / 1000))
		expect(rawPayload(token)).toBe(
			`{"iat":${iat},"settlement":{"gid":{"partner":"partner-xyz","user":"user-12345","bet":"bet-abc789","signature":"${signatureOf(token)}"},` +
				`"status":"win","payout":{"amount":150,"currency":"USD"},"version":1732032200000,"xSettle":2.5,"settledAt":1732032190000}}`,
		)
		expectBoostxAccepts(decodeJWTPayload(token))
	})

	it('omits xSettle when undefined or null and sends 0', async () => {
		for (const xSettle of [undefined, null]) {
			const token = await createSettlementToken(priv, { ...BASE, status: 'cancelled', amount: 100, xSettle })
			expect(settlementOf(token)).not.toHaveProperty('xSettle')
			expect(rawPayload(token)).not.toContain('xSettle')
			expectBoostxAccepts(decodeJWTPayload(token))
		}
		const zero = await createSettlementToken(priv, { ...BASE, status: 'lose', amount: 0, xSettle: 0 })
		expect(rawPayload(zero)).toContain('"version":1732032200000,"xSettle":0,"settledAt":1732032190000')
		expectBoostxAccepts(decodeJWTPayload(zero))
	})

	it('signs the token and the GID with the partner private key', async () => {
		const token = await createSettlementToken(priv, BASE)
		const claims = await verifyJWT(token, pub)
		await expect(verifyGID(parseGIDClaim((claims.settlement as Claims).gid), pub)).resolves.toBeUndefined()
		const err = await verifyJWT(token, await loadPublicKeyFromPEM(OTHER.publicSPKI)).catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_signature')).toBe(true)
	})

	it('lists the eight statuses and accepts each', async () => {
		expect(SETTLEMENT_STATUSES).toEqual([
			'win',
			'lose',
			'cancelled',
			'refund',
			'half_win',
			'half_lose',
			'cashout',
			'unsettled',
		])
		for (const status of SETTLEMENT_STATUSES) {
			const token = await createSettlementToken(priv, { ...BASE, status, amount: status === 'unsettled' ? 0 : 10 })
			expect(settlementOf(token).status).toBe(status)
			expectBoostxAccepts(decodeJWTPayload(token))
		}
	})

	it.each([
		['version 0', { version: 0 }],
		['version 1', { version: 1 }],
		['the largest safe version', { version: Number.MAX_SAFE_INTEGER }],
		['a zero payout', { status: 'lose', amount: 0 }],
		['an unsettled zero payout', { status: 'unsettled', amount: 0, xSettle: null }],
		['an xSettle below 1', { xSettle: 0.4 }],
		['a four-letter currency', { currency: 'USDT' }],
		['XAU', { currency: 'XAU' }],
		['settledAt at the floor', { settledAt: 1e12 }],
		['settledAt now', { settledAt: now }],
		['settledAt an hour ago', { settledAt: now - HOUR }],
		['settledAt 23 hours ahead', { settledAt: now + 23 * HOUR }],
	] as [string, Partial<SettlementParams>][])('accepts %s', async (_, overrides) => {
		const params = { ...BASE, ...overrides }
		const token = await createSettlementToken(priv, params)
		expect(settlementOf(token)).toMatchObject({ version: params.version, settledAt: params.settledAt })
		expectBoostxAccepts(decodeJWTPayload(token))
	})

	const STATUS_MESSAGE =
		'invalid claim value: status must be one of win, lose, cancelled, refund, half_win, half_lose, cashout, unsettled'

	const rejected: [string, Record<string, unknown>, BoostxErrorCode, string][] = [
		['an empty partner', { partner: '' }, 'missing_claim', 'missing required claim: partner'],
		['an empty user', { user: '' }, 'missing_claim', 'missing required claim: user'],
		['an empty bet', { bet: '' }, 'missing_claim', 'missing required claim: bet'],
		['a numeric bet', { bet: 42 }, 'invalid_claim', 'invalid claim value: bet must be a string'],
		['an object partner', { partner: {} }, 'invalid_claim', 'invalid claim value: partner must be a string'],
		['a null bet', { bet: null }, 'missing_claim', 'missing required claim: bet'],
		['no user', { user: undefined }, 'missing_claim', 'missing required claim: user'],
		[
			'an empty user before every other field',
			{ user: '', status: 'won', currency: 'usd' },
			'missing_claim',
			'missing required claim: user',
		],
		['a lone surrogate in bet', { bet: String.fromCharCode(0xdfff) }, 'invalid_claim', ''],
		...['won', 'lost', 'refunded', '', 'invalid', 'WIN', 'Win', 'half-win', 'halfwin', undefined].map(
			(status): [string, Record<string, unknown>, BoostxErrorCode, string] => [
				`status ${String(status)}`,
				{ status },
				'invalid_claim',
				STATUS_MESSAGE,
			],
		),
		['a negative amount', { amount: -100 }, 'invalid_claim', 'invalid claim value: amount'],
		['a NaN amount', { amount: NaN }, 'invalid_claim', 'invalid claim value: amount'],
		['an infinite amount', { amount: Infinity }, 'invalid_claim', 'invalid claim value: amount'],
		['a string amount', { amount: '150' }, 'invalid_claim', 'invalid claim value: amount'],
		['no amount', { amount: undefined }, 'invalid_claim', 'invalid claim value: amount'],
		['a null amount', { amount: null }, 'invalid_claim', 'invalid claim value: amount'],
		[
			'an unsettled payout',
			{ status: 'unsettled', amount: 100 },
			'invalid_claim',
			'invalid claim value: amount must be 0 when status is unsettled',
		],
		['an empty currency', { currency: '' }, 'missing_claim', 'missing required claim: currency'],
		['no currency', { currency: undefined }, 'missing_claim', 'missing required claim: currency'],
		['a null currency', { currency: null }, 'missing_claim', 'missing required claim: currency'],
		...['usd', 'Usd', 'usDT', 'US', 'DOLLAR', 'US1', 'US-D', 'доллар', 840].map(
			(currency): [string, Record<string, unknown>, BoostxErrorCode, string] => [
				`currency ${currency}`,
				{ currency },
				'invalid_claim',
				'invalid claim value: currency must be 3 or 4 uppercase letters',
			],
		),
		...[-1, 2 ** 53, 1.5, NaN, Infinity, '1', undefined, null].map(
			(version): [string, Record<string, unknown>, BoostxErrorCode, string] => [
				`version ${String(version)}`,
				{ version },
				'invalid_claim',
				'invalid claim value: version',
			],
		),
		...[-0.5, NaN, Infinity, -Infinity, '2.5'].map(
			(xSettle): [string, Record<string, unknown>, BoostxErrorCode, string] => [
				`xSettle ${xSettle}`,
				{ xSettle },
				'invalid_claim',
				'invalid claim value: xsettle',
			],
		),
		['settledAt 0', { settledAt: 0 }, 'missing_claim', 'missing required claim: settledAt'],
		['no settledAt', { settledAt: undefined }, 'missing_claim', 'missing required claim: settledAt'],
		['a null settledAt', { settledAt: null }, 'missing_claim', 'missing required claim: settledAt'],
		...[
			['negative', -1],
			['seconds-scale', Math.floor(now / 1000)],
			['one below the floor', 1e12 - 1],
			['not an integer', now + 0.5],
			['25 hours ahead', now + 25 * HOUR],
			['a year ahead', now + 365 * 24 * HOUR],
			['microsecond-scale', now * 1000],
			['nanosecond-scale', now * 1e6],
			['a string', String(now)],
		].map(([name, settledAt]): [string, Record<string, unknown>, BoostxErrorCode, string] => [
			`settledAt ${name}`,
			{ settledAt },
			'invalid_claim',
			'invalid claim value: settledAt',
		]),
	]

	it.each(rejected)('rejects %s', async (_, overrides, code, message) => {
		const err = await createSettlementToken(priv, { ...BASE, ...overrides } as SettlementParams).catch(
			(e: unknown) => e,
		)
		expect(isBoostxError(err, code)).toBe(true)
		if (message) expect((err as Error).message).toBe(message)
	})

	it('rejects a key that cannot sign with invalid_private_key', async () => {
		for (const key of [pub, null]) {
			const err = await createSettlementToken(key as CryptoKeyLike, BASE).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		}
	})

	it.each([
		['status before amount', { status: 'won', amount: -1 }, 'invalid_claim', STATUS_MESSAGE],
		[
			'amount before the unsettled rule',
			{ status: 'unsettled', amount: -1 },
			'invalid_claim',
			'invalid claim value: amount',
		],
		[
			'the unsettled rule before currency',
			{ status: 'unsettled', amount: 1, currency: 'usd' },
			'invalid_claim',
			'invalid claim value: amount must be 0 when status is unsettled',
		],
		['currency before version', { currency: '', version: -1 }, 'missing_claim', 'missing required claim: currency'],
		['version before xSettle', { version: -1, xSettle: -1 }, 'invalid_claim', 'invalid claim value: version'],
		['xSettle before settledAt', { xSettle: -1, settledAt: 0 }, 'invalid_claim', 'invalid claim value: xsettle'],
		[
			'settledAt before id well-formedness',
			{ settledAt: 0, bet: String.fromCharCode(0xd800) },
			'missing_claim',
			'missing required claim: settledAt',
		],
	] as [string, Record<string, unknown>, BoostxErrorCode, string][])(
		'reports %s',
		async (_, overrides, code, message) => {
			const err = await createSettlementToken(priv, { ...BASE, ...overrides } as SettlementParams).catch(
				(e: unknown) => e,
			)
			expect(isBoostxError(err, code)).toBe(true)
			expect((err as Error).message).toBe(message)
		},
	)

	it.each([
		['undefined', undefined],
		['null', null],
		['a string', 'win'],
	])('reads %s params as empty ones, after the key', async (_, params) => {
		const err = await createSettlementToken(priv, params as never).catch((e: unknown) => e)
		expect(isBoostxError(err, 'missing_claim')).toBe(true)
		expect((err as Error).message).toBe('missing required claim: partner')
		const keyErr = await createSettlementToken(pub, params as never).catch((e: unknown) => e)
		expect(isBoostxError(keyErr, 'invalid_private_key')).toBe(true)
	})

	it('checks the key before any parameter', async () => {
		const bad = { ...BASE, partner: '', status: 'won', amount: -1 } as unknown as SettlementParams
		for (const key of [pub, undefined]) {
			const err = await createSettlementToken(key as CryptoKeyLike, bad).catch((e: unknown) => e)
			expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		}
		expect(isBoostxError(await createSettlementToken(priv, bad).catch((e: unknown) => e), 'missing_claim')).toBe(true)
	})
})
