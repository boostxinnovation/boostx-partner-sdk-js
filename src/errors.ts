/**
 * Kinds of failure the SDK reports. Every error the SDK raises itself is a {@link BoostxError} with one of these codes;
 * a network failure from `fetch` propagates unchanged.
 */
export type BoostxErrorCode =
	| 'invalid_private_key'
	| 'invalid_public_key'
	| 'invalid_booster'
	| 'invalid_checkbet'
	| 'invalid_verify_keys'
	| 'invalid_gid'
	| 'invalid_signature'
	| 'missing_claim'
	| 'invalid_claim'
	| 'unknown_partner'
	| 'api_error'

/** Wire reason of a rejected verify-keys request: `{"error": "invalid verifyKeysJWT: <reason>"}`. */
export type VerifyKeysReason = 'shape' | 'iss-aud' | 'stale' | 'nonce-format' | 'signature'

export interface BoostxErrorOptions {
	cause?: unknown
	reason?: VerifyKeysReason
}

/** Error thrown by every SDK function. `cause` chains to the more specific error, as Go's `%w` wrapping does. */
export class BoostxError extends Error {
	readonly code: BoostxErrorCode
	/** Set on `invalid_verify_keys` errors. */
	readonly reason: VerifyKeysReason | undefined

	constructor(code: BoostxErrorCode, message: string, options: BoostxErrorOptions = {}) {
		super(message, options.cause === undefined ? undefined : { cause: options.cause })
		this.name = 'BoostxError'
		this.code = code
		this.reason = options.reason
	}
}

/** Reports whether `err` or any error in its `cause` chain is a {@link BoostxError}, with `code` when given. */
export function isBoostxError(err: unknown, code?: BoostxErrorCode): err is BoostxError {
	for (let e = err, depth = 0; e instanceof Error && depth < 16; e = e.cause, depth++) {
		if (e instanceof BoostxError && (code === undefined || e.code === code)) return true
	}
	return false
}

/**
 * Maps a verify-keys parse error to its wire reason. A key that cannot verify is `signature`, like a signature that
 * does not; anything unclassified is `shape`.
 */
export function verifyKeysReason(err: unknown): VerifyKeysReason {
	if (isBoostxError(err, 'invalid_signature') || isBoostxError(err, 'invalid_public_key')) return 'signature'
	for (let e = err, depth = 0; e instanceof Error && depth < 16; e = e.cause, depth++) {
		if (e instanceof BoostxError && e.reason !== undefined) return e.reason
	}
	return 'shape'
}
