import { extractGameTokenPartner, parseGameToken, type GameTokenKind, type GID } from './gid.js'
import type { CryptoKeyLike } from './keys.js'

/** A verified CheckBetJWT: BoostX asking `/check-bet` whether a bet is still active. */
export interface CheckBet {
	/** The signed GID of the gamepass that created the game. */
	gid: GID
	/** Issued-at, Unix seconds. A retried call re-sends the same token, so it can be older than the call. */
	iat: number
}

const CHECKBET: GameTokenKind<object> = {
	root: 'checkbet',
	code: 'invalid_checkbet',
	name: 'CheckBet',
	read: () => ({}),
}

/** Returns the unverified `gid.partner` of a CheckBetJWT. Only for choosing keys: verify with {@link parseCheckBetToken}. */
export function extractCheckBetPartner(checkBetJWT: string): string {
	return extractGameTokenPartner(CHECKBET, checkBetJWT)
}

/**
 * Verifies a CheckBetJWT with the BoostX public key and its GID with the partner public key, or any of several
 * (keys still valid for games started before a rotation).
 */
export function parseCheckBetToken(
	checkBetJWT: string,
	boostxPublicKey: CryptoKeyLike,
	partnerPublicKeys: CryptoKeyLike | readonly CryptoKeyLike[],
): Promise<CheckBet> {
	return parseGameToken(CHECKBET, checkBetJWT, boostxPublicKey, partnerPublicKeys)
}
