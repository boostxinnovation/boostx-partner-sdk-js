import { extractGameTokenPartner, parseGameToken, type GameTokenKind, type GID } from './gid.js'
import type { CryptoKeyLike } from './keys.js'
import { invalidClaim, missingClaim } from './validate.js'

/** A verified BoosterJWT: the boost BoostX sends to `/set-boost` after each round. */
export interface Booster {
	/** The signed GID of the gamepass that created the game. */
	gid: GID
	/** 1-indexed round counter, an integer >= 1. A replayed round repeats it. */
	round: number
	/** Finite and > 0: the accumulated boost factor on a regular round, back-solved on a jackpot round. */
	boost: number
	/** True on the last round of the game. */
	final: boolean
	/** True on a jackpot round. */
	jackpot: boolean
	/** Issued-at, Unix seconds. A retried call re-sends the same token, so it can be older than the call. */
	iat: number
}

const BOOSTER: GameTokenKind<Omit<Booster, 'gid' | 'iat'>> = {
	root: 'booster',
	code: 'invalid_booster',
	name: 'Booster',
	read({ round, boost, final, jackpot }) {
		if (round === undefined) throw missingClaim('round')
		if (typeof round !== 'number' || !Number.isSafeInteger(round) || round < 1) {
			throw invalidClaim('round must be an integer >= 1')
		}
		if (boost === undefined) throw missingClaim('boost')
		if (typeof boost !== 'number' || !Number.isFinite(boost) || boost <= 0) {
			throw invalidClaim('boost must be a finite number > 0')
		}
		if (final === undefined) throw missingClaim('final')
		if (typeof final !== 'boolean') throw invalidClaim('final must be a boolean')
		if (jackpot === undefined) throw missingClaim('jackpot')
		if (typeof jackpot !== 'boolean') throw invalidClaim('jackpot must be a boolean')
		return { round, boost, final, jackpot }
	},
}

/** Returns the unverified `gid.partner` of a BoosterJWT. Only for choosing keys: verify with {@link parseBoosterToken}. */
export function extractBoosterPartner(boosterJWT: string): string {
	return extractGameTokenPartner(BOOSTER, boosterJWT)
}

/**
 * Verifies a BoosterJWT with the BoostX public key and its GID with the partner public key, or any of several
 * (keys still valid for games started before a rotation).
 */
export function parseBoosterToken(
	boosterJWT: string,
	boostxPublicKey: CryptoKeyLike,
	partnerPublicKeys: CryptoKeyLike | readonly CryptoKeyLike[],
): Promise<Booster> {
	return parseGameToken(BOOSTER, boosterJWT, boostxPublicKey, partnerPublicKeys)
}
