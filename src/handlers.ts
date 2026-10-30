import { extractBoosterPartner, parseBoosterToken, type Booster } from './booster.js'
import { extractCheckBetPartner, parseCheckBetToken, type CheckBet } from './checkbet.js'
import { BoostxError, isBoostxError, verifyKeysReason, type BoostxErrorCode } from './errors.js'
import type { GID } from './gid.js'
import type { HandlersKeyStore } from './key-store.js'
import type { CryptoKeyLike } from './keys.js'
import { quote } from './validate.js'
import {
	createVerifyKeysResponseToken,
	extractVerifyKeysRequestPartner,
	parseVerifyKeysRequestToken,
	type VerifyKeysRequest,
} from './verify-keys.js'

/** Your bet records, as the endpoint handlers reach them. */
export interface BetStore {
	/**
	 * Applies a verified round. Must be idempotent: a `round` at or below the stored one is a replay, so change
	 * nothing and resolve. Validate before you write; throw {@link RoundRejectedError} for a round you will not apply.
	 */
	setBoost(booster: Booster): Promise<void>
	/** Optional; with it, `/check-bet` is served. Resolve `false` for a bet you do not know. */
	checkBet?(gid: GID): Promise<boolean>
}

/**
 * Thrown by `BetStore.setBoost` for a round you have not applied and will not apply: answered 400 `round rejected`,
 * also when it is in the `cause` chain of what `setBoost` throws. Its message is never sent.
 */
export class RoundRejectedError extends Error {
	constructor(message = 'round rejected', options?: { cause?: unknown }) {
		super(message, options)
		this.name = 'RoundRejectedError'
	}
}

export interface HandlerOptions {
	betStore: BetStore
	keyStore: HandlersKeyStore
}

/** An answer to BoostX: the HTTP status and the JSON body. */
export interface HandlerResult {
	status: number
	body: unknown
}

/** The request body cap, as Go's `http.MaxBytesReader` sets it. Internal. */
export const MAX_BODY_BYTES = 64 * 1024

type Handler = (body: unknown, options: HandlerOptions) => Promise<HandlerResult>

/** Answers `POST /set-boost` for an already-parsed JSON body. */
export async function handleSetBoost(body: unknown, options: HandlerOptions): Promise<HandlerResult> {
	return answer(async () => {
		checkOptions(options)
		const { keyStore, betStore } = options
		const token = readToken(body, 'boosterJWT')
		const partner = extract(() => extractBoosterPartner(token), 'invalid booster token')
		const [boostxKey, partnerKeys] = await verifyingKeys(keyStore, partner)
		const booster = await verify(
			() => parseBoosterToken(token, boostxKey, partnerKeys),
			'invalid_booster',
			'invalid booster token',
		)
		try {
			await betStore.setBoost(booster)
		} catch (err) {
			return isRoundRejected(err) ? fail(400, 'round rejected') : fail(500, 'failed to set boost')
		}
		return { status: 200, body: { result: { ok: true } } }
	})
}

/** Answers `POST /check-bet` for an already-parsed JSON body; 404 when the bet store has no `checkBet`. */
export async function handleCheckBet(body: unknown, options: HandlerOptions): Promise<HandlerResult> {
	return answer(async () => {
		checkOptions(options)
		const { keyStore, betStore } = options
		if (typeof betStore.checkBet !== 'function') return fail(404, 'not found')
		const token = readToken(body, 'checkbetJWT')
		const partner = extract(() => extractCheckBetPartner(token), 'invalid checkbet token')
		const [boostxKey, partnerKeys] = await verifyingKeys(keyStore, partner)
		const checkBet: CheckBet = await verify(
			() => parseCheckBetToken(token, boostxKey, partnerKeys),
			'invalid_checkbet',
			'invalid checkbet token',
		)
		let active: unknown
		try {
			active = await betStore.checkBet(checkBet.gid)
		} catch {
			return fail(500, 'failed to check bet')
		}
		// No verdict rather than a guessed one: BoostX reads a non-boolean by its truthiness.
		if (typeof active !== 'boolean') return fail(500, 'failed to check bet')
		return { status: 200, body: { result: { active } } }
	})
}

/**
 * Answers `POST /verify-keys` for an already-parsed JSON body, signing the response as the partner the store matched.
 * A request's `iat` must be within 30 seconds of the clock. Needs no bet store, and of the key store only
 * `boostxPublicKey` and `partnerPrivateKey`.
 */
export async function handleVerifyKeys(
	body: unknown,
	options: { betStore?: BetStore; keyStore: Pick<HandlersKeyStore, 'boostxPublicKey' | 'partnerPrivateKey'> },
): Promise<HandlerResult> {
	return answer(async () => {
		checkKeyStore(options?.keyStore, ['boostxPublicKey', 'partnerPrivateKey'])
		const { keyStore } = options
		const token = readToken(body, 'verifyKeysJWT')
		const partner = extract(() => extractVerifyKeysRequestPartner(token), 'invalid verifyKeysJWT: shape')
		// An id this deployment does not serve is an id mismatch on the wire, as the Go SDK reports it.
		const unknown = fail(400, `invalid verifyKeysJWT: iss-aud (unknown partner ${quote(partner)})`)
		const boostxKey = await lookup(() => keyStore.boostxPublicKey(partner), 'boostx key', unknown)
		let request: VerifyKeysRequest
		try {
			request = await parseVerifyKeysRequestToken(token, boostxKey, partner)
		} catch (err) {
			if (!isBoostxError(err, 'invalid_verify_keys')) return fail(500, 'failed to verify token')
			return fail(400, `invalid verifyKeysJWT: ${verifyKeysReason(err)}`)
		}
		const partnerKey = await lookup(() => keyStore.partnerPrivateKey(partner), 'partner private key', unknown)
		let responseJWT: string
		try {
			responseJWT = await createVerifyKeysResponseToken(partnerKey, partner, request.nonce)
		} catch {
			return fail(500, 'failed to sign response')
		}
		return { status: 200, body: { result: { responseJWT } } }
	})
}

/**
 * A `fetch`-style handler for the three endpoints, dispatched on the last path segment: mount it under the path
 * of the API URL on your dashboard. `/check-bet` answers 404 unless the bet store has `checkBet`.
 * Throws `invalid_claim` for options that could not serve a request.
 */
export function createFetchHandler(options: HandlerOptions): (request: Request) => Promise<Response> {
	checkOptions(options)
	const routes = new Map<string, Handler>([
		['set-boost', handleSetBoost],
		['check-bet', handleCheckBet],
		['verify-keys', handleVerifyKeys],
	])
	return async (request) => {
		try {
			const name = new URL(request.url).pathname.split('/').pop() ?? ''
			const route = routes.get(name)
			if (route === undefined || (route === handleCheckBet && typeof options.betStore.checkBet !== 'function')) {
				return respond(fail(404, 'not found'))
			}
			if (request.method !== 'POST') return respond(fail(405, 'method not allowed'), { allow: 'POST' })
			const body = await readBody(request)
			return respond(body === INVALID ? fail(400, 'invalid request body') : await route(body, options))
		} catch {
			return respond(fail(500, 'internal server error'))
		}
	}
}

// At creation, so a misconfiguration fails at startup; the per-endpoint functions run it on each call, as a 500.
function checkOptions(options: HandlerOptions): void {
	const { betStore, keyStore } = options ?? {}
	if (typeof betStore?.setBoost !== 'function') {
		throw new BoostxError('invalid_claim', 'betStore must have a setBoost method')
	}
	checkKeyStore(keyStore, ['partnerPublicKeys', 'partnerPrivateKey', 'boostxPublicKey'])
}

function checkKeyStore(keyStore: Partial<HandlersKeyStore> | undefined, methods: (keyof HandlersKeyStore)[]): void {
	for (const method of methods) {
		if (typeof keyStore?.[method] !== 'function') {
			throw new BoostxError('invalid_claim', `keyStore must have a ${method} method`)
		}
	}
}

// Through the `cause` chain, as deep as `isBoostxError` walks it.
function isRoundRejected(err: unknown): boolean {
	for (let e = err, depth = 0; e instanceof Error && depth < 16; e = e.cause, depth++) {
		if (e instanceof RoundRejectedError) return true
	}
	return false
}

const INVALID = Symbol('invalid body')
// Strict UTF-8, keeping a byte order mark so that JSON.parse refuses it.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

// Reads at most MAX_BODY_BYTES, then stops reading: a longer body, or one that is not a single JSON value in strict
// UTF-8 without a byte order mark, is INVALID.
async function readBody(request: Request): Promise<unknown> {
	const chunks: Uint8Array[] = []
	let size = 0
	try {
		// Throws for a body something else has read or locked: that is a bad body too.
		const reader = request.body?.getReader()
		for (;;) {
			const chunk = reader === undefined ? { done: true as const } : await reader.read()
			if (chunk.done) break
			size += chunk.value.byteLength
			if (size > MAX_BODY_BYTES) {
				await reader?.cancel().catch(() => {})
				return INVALID
			}
			chunks.push(chunk.value)
		}
		const bytes = new Uint8Array(size)
		let offset = 0
		for (const c of chunks) {
			bytes.set(c, offset)
			offset += c.byteLength
		}
		return JSON.parse(decoder.decode(bytes))
	} catch {
		return INVALID
	}
}

function respond(result: HandlerResult, headers?: Record<string, string>): Response {
	return Response.json(result.body, { status: result.status, headers })
}

function fail(status: number, error: string): HandlerResult {
	return { status, body: { error } }
}

// Carries an early answer out of the helpers below.
class Answer {
	constructor(readonly result: HandlerResult) {}
}

async function answer(run: () => Promise<HandlerResult>): Promise<HandlerResult> {
	try {
		return await run()
	} catch (err) {
		return err instanceof Answer ? err.result : fail(500, 'internal server error')
	}
}

// As Go decodes the body into a struct: a non-object body or a non-string token is a bad body, a missing one ''.
function readToken(body: unknown, field: string): string {
	if (body === null) return ''
	if (typeof body !== 'object' || Array.isArray(body)) throw new Answer(fail(400, 'invalid request body'))
	const token = (body as Record<string, unknown>)[field] ?? ''
	if (typeof token !== 'string') throw new Answer(fail(400, 'invalid request body'))
	return token
}

function extract(read: () => string, error: string): string {
	try {
		return read()
	} catch {
		throw new Answer(fail(400, error))
	}
}

// Only `unknown_partner` is the caller's fault; any other store failure is ours.
async function lookup<T>(get: () => Promise<T>, what: string, unknown: HandlerResult): Promise<T> {
	try {
		return await get()
	} catch (err) {
		throw new Answer(isBoostxError(err, 'unknown_partner') ? unknown : fail(500, `failed to get ${what}`))
	}
}

// Both lookups run at once; a failure is reported in a fixed order, the BoostX key's first, as when they ran in turn.
async function verifyingKeys(
	keyStore: HandlersKeyStore,
	partner: string,
): Promise<[CryptoKeyLike, readonly CryptoKeyLike[]]> {
	const unknown = unknownPartner(partner)
	const [boostx, partnerKeys] = await Promise.allSettled([
		lookup(() => keyStore.boostxPublicKey(partner), 'boostx key', unknown),
		lookup(() => keyStore.partnerPublicKeys(partner), 'partner key', unknown),
	])
	if (boostx.status === 'rejected') throw boostx.reason
	if (partnerKeys.status === 'rejected') throw partnerKeys.reason
	return [boostx.value, partnerKeys.value]
}

// A token failure is 400; a key from the store that cannot verify (`invalid_public_key`) is ours, 500.
async function verify<T>(parse: () => Promise<T>, code: BoostxErrorCode, error: string): Promise<T> {
	try {
		return await parse()
	} catch (err) {
		throw new Answer(isBoostxError(err, code) ? fail(400, error) : fail(500, 'failed to verify token'))
	}
}

function unknownPartner(partner: string): HandlerResult {
	return fail(400, `unknown partner ${quote(partner)}`)
}
