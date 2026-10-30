import { buildGID } from './gid.js'
import { signJWT } from './jwt.js'
import { checkPrivateKey, type CryptoKeyLike } from './keys.js'
import { invalidClaim, isCurrencyCode, missingClaim, nonNegativeFinite, requireIds } from './validate.js'

/** The eight settlement statuses BoostX accepts. */
export const SETTLEMENT_STATUSES = [
	'win',
	'lose',
	'cancelled',
	'refund',
	'half_win',
	'half_lose',
	'cashout',
	'unsettled',
] as const

/** A bet outcome; `unsettled` requires a payout of exactly 0. */
export type SettlementStatus = (typeof SETTLEMENT_STATUSES)[number]

/** Parameters of {@link createSettlementToken}. A `null` field counts as left out. */
export interface SettlementParams {
	/** The partner id BoostX assigned you, the `gid.partner` of inbound tokens. */
	partner: string
	/** Non-empty; keep `:` out of it (not checked). */
	user: string
	/** Non-empty; keep `:` out of it (not checked). */
	bet: string
	status: SettlementStatus
	/** What reached the player, in major units; >= 0, and exactly 0 when `status` is `unsettled`. */
	amount: number
	/** 3 or 4 uppercase letters, e.g. `USD` or `USDT`. */
	currency: string
	/** Orders repeated settlements of one bet, highest wins: an integer in [0, 2^53 − 1]. A ms timestamp works. */
	version: number
	/** Your own base X at settlement, before the boost; finite >= 0. Omitted when `undefined` or `null`, sent when 0. */
	xSettle?: number | null
	/** When you settled the bet, epoch ms: from 1e12 (2001-09-09) up to 24 hours ahead of now. */
	settledAt: number
}

const MIN_SETTLED_AT = 1e12
const MAX_SETTLED_AT_SKEW_MS = 24 * 60 * 60 * 1000

/**
 * Signs a SettlementJWT with the partner private key, signing the `gid` afresh. A token kept and sent after a partner
 * key rotation is answered 401: sign it again under the same `version` and values.
 */
export async function createSettlementToken(privateKey: CryptoKeyLike, params: SettlementParams): Promise<string> {
	checkPrivateKey(privateKey)
	// A missing parameter set reads as an empty one, so the first failure is the partner id.
	const p = typeof params === 'object' && params !== null ? params : ({} as SettlementParams)
	const { partner, user, bet, status, amount, currency, version, xSettle, settledAt } = p
	requireIds(p)
	if (!(SETTLEMENT_STATUSES as readonly unknown[]).includes(status)) {
		throw invalidClaim(`status must be one of ${SETTLEMENT_STATUSES.join(', ')}`)
	}
	if (!nonNegativeFinite(amount)) throw invalidClaim('amount')
	if (status === 'unsettled' && amount !== 0) throw invalidClaim('amount must be 0 when status is unsettled')
	if (currency == null || currency === '') throw missingClaim('currency')
	if (!isCurrencyCode(currency)) throw invalidClaim('currency must be 3 or 4 uppercase letters')
	if (!Number.isSafeInteger(version) || version < 0) throw invalidClaim('version')
	if (xSettle != null && !nonNegativeFinite(xSettle)) throw invalidClaim('xsettle')
	if (settledAt == null || settledAt === 0) throw missingClaim('settledAt')
	if (!Number.isInteger(settledAt) || settledAt < MIN_SETTLED_AT || settledAt > Date.now() + MAX_SETTLED_AT_SKEW_MS) {
		throw invalidClaim('settledAt')
	}

	const gid = await buildGID(privateKey, partner, user, bet)
	const settlement = {
		gid,
		status,
		payout: { amount, currency },
		version,
		...(xSettle == null ? {} : { xSettle }),
		settledAt,
	}
	return signJWT({ iat: Math.floor(Date.now() / 1000), settlement }, privateKey)
}
