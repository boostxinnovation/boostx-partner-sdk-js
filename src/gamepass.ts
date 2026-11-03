import { buildGID } from './gid.js'
import { signJWT } from './jwt.js'
import { checkPrivateKey, type CryptoKeyLike } from './keys.js'
import { invalidClaim, isCurrencyCode, missingClaim, nonNegativeFinite, requireIds } from './validate.js'

/**
 * Parameters of {@link createGamePassToken}. An optional parameter that is `null` is unset, as if left out. On the
 * gamepass that starts a bet, BoostX requires `x`, `xMin` and `xMax` in [1.1, 200] and `xMin < xMax`; the SDK leaves
 * those ranges to BoostX.
 */
export interface GamePassParams {
	/**
	 * The partner id BoostX assigned you, the `gid.partner` of inbound tokens; no `:`, at most 32 code points; otherwise
	 * refused before signing (`invalid_claim`).
	 */
	partner: string
	/** Non-empty, no `:`, at most 64 code points; otherwise refused before signing (`invalid_claim`). */
	user: string
	/** Non-empty, no `:`, at most 96 code points; otherwise refused before signing (`invalid_claim`). */
	bet: string
	/** Stake in major units of `currency`; must be at least 0.01. */
	amount: number
	/** 3 or 4 uppercase letters, e.g. `USD` or `USDT`. */
	currency: string
	/** Your own coefficient for the bet before the boost (`xrange.init`), > 0; never an X derived from a `boost`. */
	x: number
	/** Lower bound of X; omitted when unset or 0 (BoostX defaults to 1.1). */
	xMin?: number | null
	/** Upper bound of X; omitted when unset or 0 (BoostX defaults to 200). */
	xMax?: number | null
	/** Decimal places X is floored to, an integer in [2, 6]; omitted when unset or 0 (BoostX defaults to 2). */
	xDecimals?: number | null
	/** Title shown on the game screen; omitted when unset or empty. A lone surrogate is sent as U+FFFD. */
	eventTitle?: string | null
	/** `true` marks a demo session; only `true` is sent. */
	demo?: boolean | null
}

const MIN_AMOUNT = 0.01

/**
 * Signs a GamePassJWT with the partner private key. Call it when the player opens the game:
 * BoostX accepts a gamepass only within 300 seconds of its `iat`.
 */
export async function createGamePassToken(privateKey: CryptoKeyLike, params: GamePassParams): Promise<string> {
	checkPrivateKey(privateKey)
	// A missing parameter set reads as an empty one, so the first failure is the partner id.
	const p = typeof params === 'object' && params !== null ? params : ({} as GamePassParams)
	const { partner, user, bet, amount, currency, x, xMin, xMax, xDecimals, eventTitle, demo } = p
	requireIds(p)
	if (currency == null || currency === '') throw missingClaim('currency')
	if (!isCurrencyCode(currency)) throw invalidClaim('currency must be 3 or 4 uppercase letters')
	if (!nonNegativeFinite(amount) || amount < MIN_AMOUNT) throw invalidClaim('amount must be a finite number >= 0.01')
	if (!nonNegativeFinite(x) || x === 0) throw invalidClaim('x')
	if (xMin != null && !nonNegativeFinite(xMin)) throw invalidClaim('xmin')
	if (xMax != null && !nonNegativeFinite(xMax)) throw invalidClaim('xmax')
	if (xDecimals != null && xDecimals !== 0 && !(Number.isInteger(xDecimals) && xDecimals >= 2 && xDecimals <= 6)) {
		throw invalidClaim('xdecimals')
	}
	if (eventTitle != null && typeof eventTitle !== 'string') throw invalidClaim('eventTitle')
	if (demo != null && typeof demo !== 'boolean') throw invalidClaim('demo')

	const gid = await buildGID(privateKey, partner, user, bet)
	const xrange: Record<string, number> = { init: x }
	if (xMin) xrange.min = xMin
	if (xMax) xrange.max = xMax
	if (xDecimals) xrange.decimals = xDecimals
	const gamepass: Record<string, unknown> = { gid, stake: { amount, currency }, xrange }
	// The title is display-only, outside the GID: each lone surrogate is sent as U+FFFD.
	if (eventTitle) gamepass.event = { title: eventTitle.toWellFormed() }
	if (demo) gamepass.demo = true
	return signJWT({ iat: Math.floor(Date.now() / 1000), gamepass }, privateKey)
}
