import { describe, expect, it } from 'vitest'

import * as sdk from '../src/index.js'
import type { BoostxErrorCode, VerifyKeysReason } from '../src/index.js'

// The universal entry's runtime exports, exactly: an accidental export or removal fails here.
const EXPORTS = [
	'BOOSTX_IDENTITY',
	'BoostxAPIError',
	'BoostxClient',
	'BoostxError',
	'DEFAULT_BASE_URL',
	'DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS',
	'MemoryKeyStore',
	'RoundRejectedError',
	'SETTLEMENT_STATUSES',
	'buildGID',
	'createFetchHandler',
	'createGamePassToken',
	'createSettlementToken',
	'createVerifyKeysRequestToken',
	'createVerifyKeysResponseToken',
	'extractBoosterPartner',
	'extractCheckBetPartner',
	'extractVerifyKeysRequestPartner',
	'floorX',
	'handleCheckBet',
	'handleSetBoost',
	'handleVerifyKeys',
	'isBoostxError',
	'loadPrivateKeyFromPEM',
	'loadPublicKeyFromPEM',
	'parseBoosterToken',
	'parseCheckBetToken',
	'parseVerifyKeysRequestToken',
	'parseVerifyKeysResponseToken',
	'playerX',
	'verifyKeysReason',
]

describe('@boostxinnovation/partner-sdk', () => {
	it('exports exactly the public surface', () => {
		expect(Object.keys(sdk).sort()).toStrictEqual([...EXPORTS].sort())
	})

	it('keeps internals out', () => {
		for (const name of [
			'signJWT',
			'verifyJWT',
			'decodeJWTPayload',
			'encodeBase64url',
			'MAX_BODY_BYTES',
			'invalidClaim',
		]) {
			expect(sdk).not.toHaveProperty(name)
		}
	})

	it('exports the constants with their documented values', () => {
		expect(sdk.BOOSTX_IDENTITY).toBe('boostx')
		expect(sdk.DEFAULT_BASE_URL).toBe('https://partners-s2s.boostx.cloud')
		expect(sdk.DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS).toBe(30)
	})

	it('keeps the error codes and verify-keys reasons a closed set', () => {
		// A code or reason added to or removed from the types fails the type check here.
		const codes: Record<BoostxErrorCode, true> = {
			invalid_private_key: true,
			invalid_public_key: true,
			invalid_booster: true,
			invalid_checkbet: true,
			invalid_verify_keys: true,
			invalid_gid: true,
			invalid_signature: true,
			missing_claim: true,
			invalid_claim: true,
			unknown_partner: true,
			api_error: true,
		}
		const reasons: Record<VerifyKeysReason, true> = {
			signature: true,
			shape: true,
			'iss-aud': true,
			stale: true,
			'nonce-format': true,
		}
		expect(Object.keys(codes)).toHaveLength(11)
		expect(Object.keys(reasons)).toHaveLength(5)
	})
})
