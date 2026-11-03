// Shared value checks for the tokens the partner signs. Internal.

import { BoostxError } from './errors.js'

/** A finite number >= 0: the shared rule for amounts and coefficients. NaN, ±Infinity and non-numbers fail. */
export function nonNegativeFinite(v: unknown): v is number {
	return typeof v === 'number' && Number.isFinite(v) && v >= 0
}

/** 3 or 4 uppercase ASCII letters, e.g. `USD` or `USDT`. */
export function isCurrencyCode(s: unknown): s is string {
	return typeof s === 'string' && /^[A-Z]{3,4}$/.test(s)
}

/** The id checks, run after the key and before any other field; `buildGID` repeats them, then its per-id checks. */
export function requireIds(ids: { partner: unknown; user: unknown; bet: unknown }): void {
	for (const name of ['partner', 'user', 'bet'] as const) checkId(name, ids[name])
}

/** Absent, null or empty is `missing_claim`; any other non-string, such as a numeric bet id, is `invalid_claim`. */
export function checkId(name: string, v: unknown): asserts v is string {
	if (v === undefined || v === null || v === '') throw missingClaim(name)
	if (typeof v !== 'string') throw invalidClaim(`${name} must be a string`)
}

export function missingClaim(name: string): BoostxError {
	return new BoostxError('missing_claim', `missing required claim: ${name}`)
}

export function invalidClaim(detail: string): BoostxError {
	return new BoostxError('invalid_claim', `invalid claim value: ${detail}`)
}

/** A partner id as error messages show it, in JSON quotes. */
export function quote(s: unknown): string {
	return JSON.stringify(String(s))
}
