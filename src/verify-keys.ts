import { BoostxError, isBoostxError, type VerifyKeysReason } from './errors.js'
import { decodeJWTPayload, signJWT, verifyJWT, type Claims } from './jwt.js'
import { checkPrivateKey, checkPublicKey, type CryptoKeyLike } from './keys.js'
import { invalidClaim, missingClaim } from './validate.js'

/** BoostX's identity in verify-keys tokens: `iss` on a request, `aud` on a response. */
export const BOOSTX_IDENTITY = 'boostx'

/** The accepted `|now - iat|` of a verify-keys token, in seconds: the handler's, and a parse function's by default. */
export const DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS = 30

const NONCE_MAX = 0x7fffffff

/** A verified BoostX → partner verify-keys request. `partnerID` is its `aud`; `iat` is in Unix seconds. */
export interface VerifyKeysRequest {
	partnerID: string
	nonce: number
	iat: number
}

/** A verified partner → BoostX verify-keys response. `partnerID` is its `iss`; `iat` is in Unix seconds. */
export interface VerifyKeysResponse {
	partnerID: string
	nonce: number
	iat: number
}

/** Signs a verify-keys request with the BoostX private key: `iss` `boostx`, `aud` partnerID, nonce in [1, 2^31-1]. */
export async function createVerifyKeysRequestToken(
	boostxPrivateKey: CryptoKeyLike,
	partnerID: string,
	nonce: number,
): Promise<string> {
	checkPrivateKey(boostxPrivateKey)
	checkPartnerID(partnerID)
	return createToken(boostxPrivateKey, BOOSTX_IDENTITY, partnerID, nonce)
}

/** Signs a verify-keys response with the partner private key: `iss` partnerID, `aud` `boostx`, the request's nonce. */
export async function createVerifyKeysResponseToken(
	partnerPrivateKey: CryptoKeyLike,
	partnerID: string,
	nonce: number,
): Promise<string> {
	checkPrivateKey(partnerPrivateKey)
	checkPartnerID(partnerID)
	return createToken(partnerPrivateKey, partnerID, BOOSTX_IDENTITY, nonce)
}

/**
 * Returns the unverified `aud` of a verify-keys request, after the payload's format and claim types (not the nonce).
 * Only for choosing keys: verify with {@link parseVerifyKeysRequestToken}.
 */
export function extractVerifyKeysRequestPartner(token: string): string {
	let payload: Claims
	try {
		payload = decodeJWTPayload(token)
	} catch (cause) {
		throw rejected('shape', errorMessage(cause), cause)
	}
	const { aud } = readClaims(payload)
	if (aud === '' || aud === BOOSTX_IDENTITY) throw rejected('shape', 'aud names no partner')
	return aud
}

/**
 * Verifies a BoostX → partner verify-keys request addressed to partnerID. Failures carry their wire reason:
 * read it with `verifyKeysReason(err)`. `maxSkewSeconds` absent, null or 0 is 30; a fraction is cut to whole seconds.
 */
export async function parseVerifyKeysRequestToken(
	token: string,
	boostxPublicKey: CryptoKeyLike,
	partnerID: string,
	options?: { maxSkewSeconds?: number | null } | null,
): Promise<VerifyKeysRequest> {
	checkPublicKey(boostxPublicKey)
	checkPartnerID(partnerID)
	const { aud, nonce, iat } = await parseToken(token, boostxPublicKey, BOOSTX_IDENTITY, partnerID, options)
	return { partnerID: aud, nonce, iat }
}

/** Verifies a partner → BoostX verify-keys response signed by partnerID. Same checks as the request; a test aid. */
export async function parseVerifyKeysResponseToken(
	token: string,
	partnerPublicKey: CryptoKeyLike,
	partnerID: string,
	options?: { maxSkewSeconds?: number | null } | null,
): Promise<VerifyKeysResponse> {
	checkPublicKey(partnerPublicKey)
	checkPartnerID(partnerID)
	const { iss, nonce, iat } = await parseToken(token, partnerPublicKey, partnerID, BOOSTX_IDENTITY, options)
	return { partnerID: iss, nonce, iat }
}

// A partner named "boostx" would make a request's iss/aud and a response's identical.
function checkPartnerID(partnerID: string): void {
	if (typeof partnerID !== 'string' || partnerID === '') throw missingClaim('partnerID')
	if (partnerID === BOOSTX_IDENTITY) throw invalidClaim(`partnerID must not be "${BOOSTX_IDENTITY}"`)
}

async function createToken(key: CryptoKeyLike, iss: string, aud: string, nonce: number): Promise<string> {
	if (!isValidNonce(nonce)) throw invalidClaim(`nonce must be an integer in [1, ${NONCE_MAX}]`)
	// One of iss/aud is the partner id; a lone surrogate would be signed as an escape every parser refuses.
	if (!iss.isWellFormed() || !aud.isWellFormed()) throw invalidClaim('partnerID is not well-formed Unicode')
	return signJWT({ verifyKeys: { nonce }, iss, aud, iat: Math.floor(Date.now() / 1000) }, key)
}

// The first failure wins: format and signature, claim types, iss/aud, time, then the nonce.
async function parseToken(
	token: string,
	key: CryptoKeyLike,
	iss: string,
	aud: string,
	options: { maxSkewSeconds?: number | null } | null | undefined,
): Promise<WireClaims & { nonce: number }> {
	const window = skewWindow(options?.maxSkewSeconds)
	let payload: Claims
	try {
		payload = await verifyJWT(token, key)
	} catch (cause) {
		if (isBoostxError(cause, 'invalid_public_key')) throw cause
		throw rejected(isBoostxError(cause, 'invalid_signature') ? 'signature' : 'shape', errorMessage(cause), cause)
	}
	const claims = readClaims(payload)
	if (claims.iss !== iss || claims.aud !== aud) throw rejected('iss-aud', 'iss/aud mismatch')
	const now = Math.floor(Date.now() / 1000)
	if (Math.abs(now - claims.iat) > window) throw rejected('stale', `iat outside the ${window} s skew window`)
	if (claims.exp !== undefined && claims.exp <= now) throw rejected('stale', 'exp is not after the current time')
	if (claims.nbf !== undefined && claims.nbf > now) throw rejected('stale', 'nbf is after the current time')
	const { nonce } = claims
	if (!isValidNonce(nonce)) throw rejected('nonce-format', `nonce must be an integer in [1, ${NONCE_MAX}]`)
	return { ...claims, nonce }
}

function isValidNonce(nonce: unknown): nonce is number {
	return typeof nonce === 'number' && Number.isInteger(nonce) && nonce >= 1 && nonce <= NONCE_MAX
}

// Absent, null and 0 mean the default; a positive fraction is cut toward zero to whole seconds.
function skewWindow(seconds: unknown): number {
	if (seconds == null || seconds === 0) return DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS
	if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) {
		throw invalidClaim('maxSkewSeconds must be a finite number >= 0')
	}
	return Math.trunc(seconds)
}

interface WireClaims {
	iss: string
	aud: string
	iat: number
	exp: number | undefined
	nbf: number | undefined
	nonce: unknown
}

// The claim types, a wrong one being `shape`. Absent or null iss, aud, iat and verifyKeys take their zero values,
// so they fail later as `iss-aud`, `stale` and `nonce-format`; a present exp or nbf must be a number, null included.
// The nonce is left to the caller, so extraction never judges it.
function readClaims(payload: Claims): WireClaims {
	const iss = payload.iss ?? ''
	const aud = payload.aud ?? ''
	const iat = payload.iat ?? 0
	const verifyKeys = payload.verifyKeys ?? {}
	const { exp, nbf } = payload
	if (typeof iss !== 'string') throw rejected('shape', 'iss is not a string')
	if (typeof aud !== 'string') throw rejected('shape', 'aud is not a string')
	if (typeof iat !== 'number' || !Number.isSafeInteger(iat)) throw rejected('shape', 'iat is not an integer')
	if (typeof verifyKeys !== 'object' || Array.isArray(verifyKeys))
		throw rejected('shape', 'verifyKeys is not an object')
	if (exp !== undefined && typeof exp !== 'number') throw rejected('shape', 'exp is not a number')
	if (nbf !== undefined && typeof nbf !== 'number') throw rejected('shape', 'nbf is not a number')
	return { iss, aud, iat, exp, nbf, nonce: (verifyKeys as Record<string, unknown>).nonce }
}

function rejected(reason: VerifyKeysReason, detail: string, cause?: unknown): BoostxError {
	return new BoostxError('invalid_verify_keys', `invalid verifyKeysJWT: ${reason} (${detail})`, { reason, cause })
}

function errorMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err)
}
