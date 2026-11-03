import { decodeBase64url, encodeBase64url } from './base64url.js'
import { BoostxError, isBoostxError, type BoostxErrorCode } from './errors.js'
import { decodeJWTPayload, verifyJWT, type Claims } from './jwt.js'
import { SIGN, checkPrivateKey, checkPublicKey, isP256, type CryptoKeyLike, type WebCryptoKey } from './keys.js'
import { invalidClaim, missingClaim, requireIds } from './validate.js'

/** The signed game id every game-flow token carries in its `gid` claim. */
export interface GID {
	partner: string
	user: string
	bet: string
	/** base64url of the raw ES256 signature (r || s) over {@link canonicalGIDPayload}. */
	signature: string
}

/**
 * The exact bytes a GID signature covers: `JSON.stringify` of a fresh `{partner, user, bet}`, in that order.
 * Never stringify an inbound object: it carries `signature`, and its key order is the sender's.
 */
export function canonicalGIDPayload(partner: string, user: string, bet: string): string {
	return JSON.stringify({ partner, user, bet })
}

/**
 * Signs `{partner, user, bet}` with the partner private key. Checks the key, then the ids' presence, then per id:
 * well-formed Unicode, no `:`, at most 32 (`partner`), 64 (`user`) or 96 (`bet`) code points.
 */
export async function buildGID(privateKey: CryptoKeyLike, partner: string, user: string, bet: string): Promise<GID> {
	checkPrivateKey(privateKey)
	requireIds({ partner, user, bet })
	for (const [name, value, max] of [
		['partner', partner, 32],
		['user', user, 64],
		['bet', bet, 96],
	] as const) {
		// A lone surrogate cannot round-trip through JSON as the same string on every side.
		if (!value.isWellFormed()) throw invalidClaim(`${name} is not well-formed Unicode`)
		if (value.includes(':')) throw invalidClaim(`${name} contains ':'`)
		// Code points, not UTF-16 units: an astral character counts as one.
		if ([...value].length > max) throw invalidClaim(`${name} is longer than ${max} code points`)
	}
	let signature: ArrayBuffer
	try {
		const data = new TextEncoder().encode(canonicalGIDPayload(partner, user, bet))
		signature = await crypto.subtle.sign(SIGN, privateKey as WebCryptoKey, data)
	} catch (cause) {
		throw new BoostxError('invalid_private_key', 'invalid private key: cannot sign with it', { cause })
	}
	return { partner, user, bet, signature: encodeBase64url(new Uint8Array(signature)) }
}

/**
 * Verifies a GID signature against the partner public key, or any of several (the current key and ones still
 * valid for games started before a rotation). Throws `invalid_signature`, with an `invalid_gid` cause, for a signature
 * that is not canonical or that no key verifies, and `invalid_public_key` when no listed key can verify.
 */
export async function verifyGID(gid: GID, partnerPublicKeys: CryptoKeyLike | readonly CryptoKeyLike[]): Promise<void> {
	const keys = partnerKeyList(partnerPublicKeys)
	const sig = decodeBase64url(gid.signature)
	if (sig === undefined || sig.length !== 64) throw invalidGIDSignature('not canonical base64url')
	const data = new TextEncoder().encode(canonicalGIDPayload(gid.partner, gid.user, gid.bet))
	// A key that cannot verify is skipped: a later one may be the one that signed.
	let refused = false
	let keyError: unknown
	for (const key of keys) {
		if (!isP256(key, 'public')) continue
		try {
			if (await crypto.subtle.verify(SIGN, key as WebCryptoKey, sig, data)) return
			refused = true
		} catch (cause) {
			keyError ??= cause
		}
	}
	if (!refused)
		throw new BoostxError('invalid_public_key', 'invalid public key: cannot verify with it', { cause: keyError })
	throw invalidGIDSignature()
}

// A GID signature that is malformed fails like one no key verifies: both codes.
function invalidGIDSignature(detail?: string): BoostxError {
	const message = detail === undefined ? 'invalid GID signature' : `invalid GID signature: ${detail}`
	return new BoostxError('invalid_signature', message, { cause: new BoostxError('invalid_gid', 'invalid GID') })
}

// The listed keys, at least one of them an ECDSA P-256 public key that can verify; verification skips the others.
function partnerKeyList(keys: CryptoKeyLike | readonly CryptoKeyLike[]): readonly CryptoKeyLike[] {
	const list: readonly CryptoKeyLike[] = Array.isArray(keys) ? keys : [keys]
	if (!list.some((k) => isP256(k, 'public'))) {
		throw new BoostxError(
			'invalid_public_key',
			'invalid public key: no partner public key is an ECDSA P-256 key that can verify',
		)
	}
	return list
}

/** Reads a `gid` claim, checking only its shape: an object with four string fields. */
export function parseGIDClaim(value: unknown): GID {
	const v = value as Partial<Record<keyof GID, unknown>> | null
	if (
		typeof v !== 'object' ||
		v === null ||
		typeof v.partner !== 'string' ||
		typeof v.user !== 'string' ||
		typeof v.bet !== 'string' ||
		typeof v.signature !== 'string'
	) {
		throw new BoostxError('invalid_gid', 'invalid GID: expected {partner, user, bet, signature} strings')
	}
	return { partner: v.partner, user: v.user, bet: v.bet, signature: v.signature }
}

/** A token BoostX signs whose root object carries a `gid` (Booster, CheckBet). Internal. */
export interface GameTokenKind<T> {
	root: string
	code: BoostxErrorCode
	name: string
	/** Checks the root object's own fields, after `gid` and before `iat`. */
	read: (body: Record<string, unknown>) => T
}

type GameToken<T> = T & { gid: GID; iat: number }

/** Returns the unverified `gid.partner` of a game-flow token. Internal. */
export function extractGameTokenPartner<T>(kind: GameTokenKind<T>, token: string): string {
	try {
		return readGameToken(kind, decodeJWTPayload(token)).gid.partner
	} catch (cause) {
		throw invalidGameToken(kind, cause)
	}
}

/**
 * Verifies a game-flow token with the BoostX public key and its GID with the partner public key(s). The keys are
 * checked before the token, the BoostX key first. Internal.
 */
export async function parseGameToken<T>(
	kind: GameTokenKind<T>,
	token: string,
	boostxPublicKey: CryptoKeyLike,
	partnerPublicKeys: CryptoKeyLike | readonly CryptoKeyLike[],
): Promise<GameToken<T>> {
	checkPublicKey(boostxPublicKey)
	partnerKeyList(partnerPublicKeys)
	let parsed: GameToken<T>
	try {
		parsed = readGameToken(kind, await verifyJWT(token, boostxPublicKey))
	} catch (cause) {
		throw invalidGameToken(kind, cause)
	}
	try {
		await verifyGID(parsed.gid, partnerPublicKeys)
	} catch (cause) {
		throw invalidGameToken(kind, cause, 'failed to verify GID: ')
	}
	return parsed
}

// A key the caller passed that cannot verify is a configuration error, not a bad token: it passes through.
function invalidGameToken(kind: GameTokenKind<unknown>, cause: unknown, prefix = ''): Error {
	if (isBoostxError(cause, 'invalid_public_key')) return cause
	const detail = cause instanceof Error ? cause.message : String(cause)
	return new BoostxError(kind.code, `invalid ${kind.name} token: ${prefix}${detail}`, { cause })
}

function readGameToken<T>(kind: GameTokenKind<T>, claims: Claims): GameToken<T> {
	const body = claims[kind.root]
	if (body === undefined) throw missingClaim(kind.root)
	if (typeof body !== 'object' || body === null || Array.isArray(body)) {
		throw invalidClaim(`${kind.root} is not an object`)
	}
	const { gid } = body as Record<string, unknown>
	if (gid === undefined) throw missingClaim('gid')
	const parsed = parseGIDClaim(gid)
	if (parsed.partner === '') throw missingClaim('gid.partner')
	const fields = kind.read(body as Record<string, unknown>)
	const { iat, exp, nbf } = claims
	if (iat === undefined) throw missingClaim('iat')
	if (typeof iat !== 'number' || !Number.isSafeInteger(iat)) throw invalidClaim('iat must be an integer')
	// Optional; when present, held to the clock in whole seconds with no leeway.
	const now = Math.floor(Date.now() / 1000)
	if (exp !== undefined) {
		if (typeof exp !== 'number') throw invalidClaim('exp must be a number')
		if (exp <= now) throw invalidClaim('exp is not after the current time')
	}
	if (nbf !== undefined) {
		if (typeof nbf !== 'number') throw invalidClaim('nbf must be a number')
		if (nbf > now) throw invalidClaim('nbf is after the current time')
	}
	return { gid: parsed, ...fields, iat }
}
