import { BoostxError } from './errors.js'
import type { ClientKeyStore } from './key-store.js'
import { createSettlementToken, type SettlementParams } from './settlement.js'

/** The production BoostX partners S2S API. */
export const DEFAULT_BASE_URL = 'https://partners-s2s.boostx.cloud'

const DEFAULT_TIMEOUT_MS = 30_000
// setTimeout's maximum: Node runs a larger AbortSignal.timeout after 1 ms.
const MAX_TIMEOUT_MS = 2 ** 31 - 1
// Only this much of an answer is read; the rest is discarded.
const MAX_RESPONSE_BYTES = 64 * 1024
// Strict UTF-8, keeping a byte order mark so that JSON.parse refuses it.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

/**
 * Any answer but BoostX's acceptance (a `2xx` whose body is `{"result":{"ok":true}}`): whatever the status, the
 * settlement is not delivered yet, so send the same params again. `status` and `error` diagnose it.
 */
export class BoostxAPIError extends BoostxError {
	readonly status: number
	/** The body's `error` (e.g. `not-stored`); else `unexpected response` for a 2xx, and `HTTP <status>` otherwise. */
	readonly error: string

	constructor(status: number, error: string) {
		super('api_error', `boostx api error ${status}: ${error}`)
		this.name = 'BoostxAPIError'
		this.status = status
		this.error = error
	}
}

/** Options of {@link BoostxClient}; one that is `null` is unset, as if left out. */
export interface ClientOptions {
	/**
	 * `http://` or `https://` and a host, or the Settlement endpoint your dashboard shows; surrounding ASCII whitespace
	 * and trailing slashes are ignored. Defaults to {@link DEFAULT_BASE_URL}; an empty string is refused.
	 */
	baseURL?: string | null
	/** Defaults to the global `fetch`. */
	fetch?: typeof fetch | null
	/**
	 * Per-attempt limit in milliseconds, from the key store lookup to the answer's body: an integer from 1 to 2^31−1;
	 * unset or 0 is 30 000.
	 */
	timeoutMs?: number | null
}

/**
 * Sends settlements to BoostX. It makes a single attempt: sending again until BoostX accepts is yours. The constructor
 * throws `invalid_claim` for a key store without `partnerPrivateKey`, a `fetch` that is not a function, an invalid
 * `baseURL` or a `timeoutMs` out of range.
 */
export class BoostxClient {
	readonly #keyStore: ClientKeyStore
	readonly #baseURL: string
	readonly #fetch: typeof fetch | undefined
	readonly #timeoutMs: number

	constructor(keyStore: ClientKeyStore, options?: ClientOptions | null) {
		const opts = options ?? {}
		if (typeof keyStore?.partnerPrivateKey !== 'function')
			throw new BoostxError('invalid_claim', 'keyStore must have a partnerPrivateKey method')
		if (opts.fetch != null && typeof opts.fetch !== 'function')
			throw new BoostxError('invalid_claim', 'fetch must be a function')
		this.#keyStore = keyStore
		this.#baseURL = normalizeBaseURL(opts.baseURL ?? DEFAULT_BASE_URL)
		this.#fetch = opts.fetch ?? undefined
		this.#timeoutMs = opts.timeoutMs == null || opts.timeoutMs === 0 ? DEFAULT_TIMEOUT_MS : opts.timeoutMs
		if (!Number.isInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > MAX_TIMEOUT_MS)
			throw new BoostxError('invalid_claim', `timeoutMs must be 0 or an integer from 1 to ${MAX_TIMEOUT_MS}`)
	}

	/**
	 * Signs a settlement with the key the store holds for `params.partner` now, and sends it, following no redirect.
	 * Resolves on `{"result":{"ok":true}}`; throws {@link BoostxAPIError} on any other answer, and lets a network
	 * failure or abort propagate unchanged. An already aborted `signal` fails before the key store is consulted.
	 */
	async submitSettlement(params: SettlementParams, options?: { signal?: AbortSignal | null } | null): Promise<void> {
		const timeout = AbortSignal.timeout(this.#timeoutMs)
		const caller = options?.signal
		const signal = caller == null ? timeout : AbortSignal.any([timeout, caller])
		const key = await untilAborted(() => this.#keyStore.partnerPrivateKey(params?.partner), signal)
		const settlementJWT = await createSettlementToken(key, params)
		// Called unbound: Workers refuse a `fetch` invoked as a method of another object.
		const doFetch = this.#fetch ?? fetch
		const response = await doFetch(`${this.#baseURL}/api/integration/settlement`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ settlementJWT }),
			signal,
			// A followed 301/302/303 turns the POST into a bodiless GET; workerd has no 'error' mode.
			redirect: 'manual',
		})
		const body = await readJSON(response, signal)
		if (!response.ok) {
			const error = (body as { error?: unknown } | null | undefined)?.error
			throw new BoostxAPIError(
				response.status,
				typeof error === 'string' && error !== '' ? error : `HTTP ${response.status}`,
			)
		}
		if ((body as { result?: { ok?: unknown } } | undefined)?.result?.ok === true) return
		throw new BoostxAPIError(response.status, 'unexpected response')
	}
}

// Trims ASCII whitespace, trailing slashes and the endpoint path; then requires http(s), with a host right after `//`.
function normalizeBaseURL(baseURL: string): string {
	const url = String(baseURL)
		.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, '')
		.replace(/\/+$/, '')
		.replace(/\/api\/integration\/settlement$/, '')
	let host = ''
	try {
		if (/^https?:\/\/[^/\\]/i.test(url)) host = new URL(url).hostname
	} catch {
		// Not a URL: no host.
	}
	if (host === '') throw new BoostxError('invalid_claim', 'baseURL must be http:// or https:// followed by a host')
	return url
}

// The first MAX_RESPONSE_BYTES of the body as JSON, or undefined when they are not strict UTF-8 JSON (an SPA
// fallback page, say). The attempt's signal bounds each read, and a failed read propagates.
async function readJSON(response: Response, signal: AbortSignal): Promise<unknown> {
	const bytes = new Uint8Array(MAX_RESPONSE_BYTES)
	let size = 0
	const reader = response.body?.getReader()
	if (reader !== undefined) {
		try {
			while (size < MAX_RESPONSE_BYTES) {
				const chunk = await untilAborted(() => reader.read(), signal)
				if (chunk.done) break
				const part = chunk.value.subarray(0, MAX_RESPONSE_BYTES - size)
				bytes.set(part, size)
				size += part.byteLength
			}
		} finally {
			reader.cancel().catch(() => {})
		}
	}
	try {
		return JSON.parse(decoder.decode(bytes.subarray(0, size))) as unknown
	} catch {
		return undefined
	}
}

// A key store takes no signal: stop waiting for it once the attempt's signal aborts, with that signal's reason.
function untilAborted<T>(run: () => Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) return Promise.reject(signal.reason)
	return new Promise<T>((resolve, reject) => {
		const abort = () => reject(signal.reason)
		signal.addEventListener('abort', abort, { once: true })
		// Through a resolved promise, so a store that returns its key directly or throws synchronously still works.
		Promise.resolve()
			.then(run)
			.then(resolve, reject)
			.finally(() => signal.removeEventListener('abort', abort))
	})
}
