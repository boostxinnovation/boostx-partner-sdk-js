import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

import { BoostxAPIError, BoostxClient, DEFAULT_BASE_URL } from '../src/client.js'
import { BoostxError, isBoostxError } from '../src/errors.js'
import { verifyGID } from '../src/gid.js'
import { verifyJWT } from '../src/jwt.js'
import { MemoryKeyStore } from '../src/key-store.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import type { SettlementParams } from '../src/settlement.js'
import { OTHER, PARTNER } from './fixtures.js'

const PARTNER_ID = 'partner-xyz'

let partnerPub: CryptoKeyLike
let keyStore: MemoryKeyStore

beforeAll(async () => {
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	keyStore = new MemoryKeyStore()
	keyStore.register(PARTNER_ID, { partnerPrivateKey: await loadPrivateKeyFromPEM(PARTNER.privatePKCS8) })
})

function settlement(overrides: Partial<SettlementParams> = {}): SettlementParams {
	return {
		partner: PARTNER_ID,
		user: 'user-12345',
		bet: 'bet-abc789',
		status: 'win',
		amount: 150,
		currency: 'USD',
		version: 1732032200000,
		xSettle: 2.5,
		settledAt: 1732032190000,
		...overrides,
	}
}

interface Call {
	url: string
	init: RequestInit
}

// A fetch that records each call and answers with `answer`.
function stub(answer: (init: RequestInit) => Promise<Response> | Response): { fetch: typeof fetch; calls: Call[] } {
	const calls: Call[] = []
	const f = async (url: string | URL | Request, init: RequestInit = {}) => {
		calls.push({ url: String(url), init })
		return answer(init)
	}
	return { fetch: f as typeof fetch, calls }
}

// Never answers; rejects with the signal's reason once it aborts, as fetch does.
function hang(init: RequestInit): Promise<Response> {
	return new Promise((_, reject) => {
		const signal = init.signal as AbortSignal
		signal.addEventListener('abort', () => reject(signal.reason))
	})
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
	return p.then(
		() => {
			throw new Error('resolved')
		},
		(err: unknown) => err,
	)
}

describe('BoostxClient.submitSettlement', () => {
	it('posts {settlementJWT} to the settlement endpoint and resolves on 200 {result:{ok:true}}', async () => {
		const answer = Response.json({ result: { ok: true } })
		const { fetch, calls } = stub(() => answer)
		await new BoostxClient(keyStore, { fetch }).submitSettlement(settlement())
		expect(answer.bodyUsed).toBe(true)
		expect(calls).toHaveLength(1)
		const [{ url, init }] = calls as [Call]
		expect(url).toBe(`${DEFAULT_BASE_URL}/api/integration/settlement`)
		expect(url).toBe('https://partners-s2s.boostx.cloud/api/integration/settlement')
		expect(init.method).toBe('POST')
		expect(init.redirect).toBe('manual')
		expect(new Headers(init.headers).get('content-type')).toBe('application/json')
		const { settlementJWT } = JSON.parse(init.body as string) as { settlementJWT: string }
		const claims = await verifyJWT(settlementJWT, partnerPub)
		expect(claims.settlement).toMatchObject({ status: 'win', payout: { amount: 150, currency: 'USD' }, xSettle: 2.5 })
		await verifyGID((claims.settlement as { gid: never }).gid, partnerPub)
	})

	it('uses baseURL, trimming a trailing slash', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		await new BoostxClient(keyStore, { fetch, baseURL: 'https://boostx.example/' }).submitSettlement(settlement())
		expect(calls[0]?.url).toBe('https://boostx.example/api/integration/settlement')
	})

	it.each([
		[400, { status: 400, error: 'invalid-xsettle' }, 'invalid-xsettle'],
		[401, { status: 401, error: 'unauthorized' }, 'unauthorized'],
		[404, { status: 404, error: 'not found' }, 'not found'],
		[500, { status: 500, error: 'not-stored' }, 'not-stored'],
	])('throws BoostxAPIError for %i with the envelope error', async (status, body, message) => {
		const { fetch } = stub(() => Response.json(body, { status }))
		const err = await rejection(new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()))
		expect(err).toBeInstanceOf(BoostxAPIError)
		expect(err).toBeInstanceOf(BoostxError)
		expect(isBoostxError(err, 'api_error')).toBe(true)
		expect((err as BoostxAPIError).status).toBe(status)
		expect((err as BoostxAPIError).message).toBe(`boostx api error ${status}: ${message}`)
		expect((err as BoostxAPIError).error).toBe(message)
	})

	it.each([
		[502, 'Bad Gateway', '<html><body>502 Bad Gateway</body></html>'],
		[503, 'Service Unavailable', 'upstream connect error'],
		[500, '', ''],
		[404, 'Not Found', 'Not Found'],
		[599, '', null],
		[400, 'Bad Request', '{"error":""}'],
		[400, 'Bad Request', '{"error":400}'],
		[400, 'Bad Request', '{"error":null}'],
		[400, 'Bad Request', '{"Error":"invalid-currency"}'],
		[400, 'Bad Request', '{"error":"invalid-currency"} x'],
		[400, 'Bad Request', '"invalid-currency"'],
		[400, 'Bad Request', '{"error":"stale","error":null}'],
	])(
		'reads a %i body without an error envelope as HTTP <status>, never its status text: %j %j',
		async (status, statusText, text) => {
			const { fetch } = stub(
				() => new Response(text, { status, statusText, headers: { 'content-type': 'text/plain' } }),
			)
			const err = (await rejection(
				new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
			)) as BoostxAPIError
			expect(err.status).toBe(status)
			expect(err.message).toBe(`boostx api error ${status}: HTTP ${status}`)
			expect(err.error).toBe(`HTTP ${status}`)
		},
	)

	it('takes the last error member when it repeats', async () => {
		const { fetch } = stub(() => new Response('{"error":"stale","error":"invalid-version"}', { status: 400 }))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err.error).toBe('invalid-version')
	})

	it.each([
		['a byte order mark', [0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"error":"invalid-currency"}')]],
		['invalid UTF-8', [...new TextEncoder().encode('{"error":"invalid-currency","x":"'), 0xff, 0x22, 0x7d]],
		['an overlong form', [...new TextEncoder().encode('{"error":"invalid-currency","x":"'), 0xc0, 0xaf, 0x22, 0x7d]],
	])('reads an error envelope carrying %s as HTTP <status>', async (_, bytes) => {
		const { fetch } = stub(() => new Response(new Uint8Array(bytes), { status: 400, statusText: 'Bad Request' }))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err.error).toBe('HTTP 400')
	})

	it.each([
		[301, 'Moved Permanently'],
		[302, 'Found'],
		[307, 'Temporary Redirect'],
	])('throws BoostxAPIError for a %i redirect instead of following it', async (status, statusText) => {
		const { fetch } = stub(
			() => new Response(null, { status, statusText, headers: { location: 'https://boostx.example/' } }),
		)
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err).toBeInstanceOf(BoostxAPIError)
		expect(err.status).toBe(status)
		expect(err.error).toBe(`HTTP ${status}`)
	})

	it.each([
		['an HTML page (SPA fallback)', 200, '<!doctype html><html><body>app</body></html>'],
		['{result:{}}', 200, '{"result":{}}'],
		['{result:{ok:"true"}}', 200, '{"result":{"ok":"true"}}'],
		['{ok:true}', 200, '{"ok":true}'],
		['null', 200, 'null'],
		['no body', 204, null],
		['{Result:{ok:true}}', 200, '{"Result":{"ok":true}}'],
		['{result:{OK:true}}', 200, '{"result":{"OK":true}}'],
		['{result:{ok:1}}', 200, '{"result":{"ok":1}}'],
		['{result:[true]}', 200, '{"result":[true]}'],
		['a result repeated as null', 200, '{"result":{"ok":true},"result":null}'],
		['an ok repeated as false', 200, '{"result":{"ok":true,"ok":false}}'],
		['trailing data', 200, '{"result":{"ok":true}} {}'],
		['an acceptance under __proto__', 200, '{"__proto__":{"result":{"ok":true}}}'],
		['an error envelope', 200, '{"error":"not-stored"}'],
		['an error envelope beside a refusal', 202, '{"result":{"ok":false},"error":"not-stored"}'],
	])('throws BoostxAPIError for a 2xx carrying %s', async (_, status, body) => {
		const { fetch } = stub(() => new Response(body, { status }))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err).toBeInstanceOf(BoostxAPIError)
		expect(err.status).toBe(status)
		expect(err.error).toBe('unexpected response')
		expect(err.message).toBe(`boostx api error ${status}: unexpected response`)
	})

	it('aborts an attempt after timeoutMs', async () => {
		const { fetch } = stub(hang)
		const err = await rejection(new BoostxClient(keyStore, { fetch, timeoutMs: 20 }).submitSettlement(settlement()))
		expect((err as Error).name).toBe('TimeoutError')
		expect(err).not.toBeInstanceOf(BoostxError)
	})

	it('refuses an out-of-range timeoutMs when constructed', () => {
		for (const timeoutMs of [-1, NaN, Infinity, -Infinity, 1.5, 2 ** 31, '100' as never])
			expect(() => new BoostxClient(keyStore, { timeoutMs }), String(timeoutMs)).toThrow(
				expect.objectContaining({
					code: 'invalid_claim',
					message: 'timeoutMs must be 0 or an integer from 1 to 2147483647',
				}),
			)
		expect(() => new BoostxClient(keyStore, { timeoutMs: 1 })).not.toThrow()
		expect(() => new BoostxClient(keyStore, { timeoutMs: 2 ** 31 - 1 })).not.toThrow()
	})

	it.each([
		['left out', {}],
		['null', { timeoutMs: null }],
		['0', { timeoutMs: 0 }],
	])('gives each attempt 30 seconds when timeoutMs is %s', async (_, options) => {
		const timeout = vi.spyOn(AbortSignal, 'timeout')
		try {
			const { fetch } = stub(() => Response.json({ result: { ok: true } }))
			await new BoostxClient(keyStore, { fetch, ...options }).submitSettlement(settlement())
			expect(timeout).toHaveBeenCalledWith(30_000)
		} finally {
			timeout.mockRestore()
		}
	})

	it.each([
		['a 2xx', 200],
		['a non-2xx', 500],
	])('counts reading the body of %s against timeoutMs', async (_, status) => {
		const body = new ReadableStream<Uint8Array>({
			start: (controller) => controller.enqueue(new TextEncoder().encode('{"result":')),
		})
		const { fetch } = stub(() => new Response(body, { status }))
		const err = await rejection(new BoostxClient(keyStore, { fetch, timeoutMs: 20 }).submitSettlement(settlement()))
		expect((err as Error).name).toBe('TimeoutError')
		expect(err).not.toBeInstanceOf(BoostxError)
	})

	it('aborts on the caller signal, with its reason', async () => {
		let sent!: () => void
		const inFlight = new Promise<void>((resolve) => (sent = resolve))
		const { fetch } = stub((init) => {
			sent()
			return hang(init)
		})
		const controller = new AbortController()
		const reason = new Error('shutting down')
		const pending = rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement(), { signal: controller.signal }),
		)
		await inFlight
		controller.abort(reason)
		expect(await pending).toBe(reason)
	})

	it('fails on a signal aborted before the call, without consulting the key store', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const lookups: string[] = []
		const store = {
			partnerPrivateKey: (partner: string) => {
				lookups.push(partner)
				return keyStore.partnerPrivateKey(partner)
			},
		}
		const reason = new Error('shutting down')
		const err = await rejection(
			new BoostxClient(store, { fetch }).submitSettlement(settlement(), { signal: AbortSignal.abort(reason) }),
		)
		expect(err).toBe(reason)
		expect(lookups).toEqual([])
		expect(calls).toHaveLength(0)
	})

	it.each([
		['no options', undefined],
		['null options', null],
		['an empty options object', {}],
		['a null signal', { signal: null }],
		['an undefined signal', { signal: undefined }],
	])('reads %s as no signal of your own', async (_, options) => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		await new BoostxClient(keyStore, { fetch }).submitSettlement(settlement(), options)
		expect(calls).toHaveLength(1)
	})

	it('fails on an unknown partner before any HTTP', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const err = await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement({ partner: 'stranger' })),
		)
		expect(isBoostxError(err, 'unknown_partner')).toBe(true)
		expect((err as Error).message).toBe('unknown partner "stranger"')
		expect(calls).toHaveLength(0)
	})

	it('refuses invalid params before any HTTP', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const err = await rejection(new BoostxClient(keyStore, { fetch }).submitSettlement(settlement({ currency: 'usd' })))
		expect(isBoostxError(err, 'invalid_claim')).toBe(true)
		expect(calls).toHaveLength(0)
	})

	it('signs each attempt with the key the store holds at that moment', async () => {
		const store = new MemoryKeyStore()
		store.register(PARTNER_ID, { partnerPrivateKey: await loadPrivateKeyFromPEM(PARTNER.privatePKCS8) })
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const client = new BoostxClient(store, { fetch })
		await client.submitSettlement(settlement())
		store.register(PARTNER_ID, { partnerPrivateKey: await loadPrivateKeyFromPEM(OTHER.privatePKCS8) })
		await client.submitSettlement(settlement())
		const [first, second] = calls.map(
			(c) => (JSON.parse(c.init.body as string) as { settlementJWT: string }).settlementJWT,
		)
		await verifyJWT(first!, partnerPub)
		await verifyJWT(second!, await loadPublicKeyFromPEM(OTHER.publicSPKI))
	})
})

describe('BoostxClient options', () => {
	afterEach(() => {
		vi.unstubAllGlobals()
	})

	it.each([
		['https://h.example', '/api/integration/settlement'],
		['https://h.example//', '/api/integration/settlement'],
		['https://h.example/api/integration/settlement', '/api/integration/settlement'],
		['https://h.example/api/integration/settlement/', '/api/integration/settlement'],
		['https://h.example/pfx/api/integration/settlement', '/pfx/api/integration/settlement'],
		['https://h.example/api/integration/settlement\n', '/api/integration/settlement'],
		['https://h.example/api/integration/settlement ', '/api/integration/settlement'],
		['https://h.example/\r\n', '/api/integration/settlement'],
		['\t\n\v\f\r https://h.example/api/integration/settlement \t\n\v\f\r', '/api/integration/settlement'],
		['HTTPS://h.example', '/api/integration/settlement'],
		['http://h.example:8080/', '/api/integration/settlement'],
	])('takes the baseURL %j, the host or the endpoint the dashboard shows', async (baseURL, path) => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		await new BoostxClient(keyStore, { fetch, baseURL }).submitSettlement(settlement())
		expect(new URL(calls[0]!.url).pathname).toBe(path)
	})

	it.each([
		['left out', {}],
		['null', { baseURL: null }],
		['null options', null],
	])('sends to the default base URL when baseURL is %s', async (_, options) => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		vi.stubGlobal('fetch', fetch)
		await new BoostxClient(keyStore, options).submitSettlement(settlement())
		expect(calls[0]?.url).toBe(`${DEFAULT_BASE_URL}/api/integration/settlement`)
	})

	const nbsp = String.fromCharCode(0xa0)
	const bom = String.fromCharCode(0xfeff)
	const nel = String.fromCharCode(0x85)
	it.each([
		['empty', ''],
		['whitespace only', ' \t\r\n'],
		['only slashes', '//'],
		['a bare host', 'partners-s2s.boostx.cloud'],
		['a relative path', '/api/integration/settlement'],
		['another scheme', 'ftp://h.example'],
		['mailto:', 'mailto:x'],
		['one slash after the scheme', 'http:/h.example'],
		['no slash after the scheme', 'https:h.example'],
		['an empty host', 'https://'],
		['a third slash in place of the host', 'http:///h.example'],
		['a backslash in place of the host', 'http://\\h.example'],
		['a port without a host', 'https://:443'],
		['a space in the host', 'https://h .example'],
		['a leading byte order mark', `${bom}https://h.example`],
		['a leading no-break space', `${nbsp}https://h.example`],
		['a trailing no-break space', `https://h.example${nbsp}`],
		['a trailing next line', `https://h.example${nel}`],
	])('refuses a baseURL that is %s when constructed', (_, baseURL) => {
		expect(() => new BoostxClient(keyStore, { baseURL })).toThrow(
			expect.objectContaining({
				code: 'invalid_claim',
				message: 'baseURL must be http:// or https:// followed by a host',
			}),
		)
	})

	it.each([
		['no key store', () => new BoostxClient(undefined as never), 'keyStore must have a partnerPrivateKey method'],
		['a null key store', () => new BoostxClient(null as never), 'keyStore must have a partnerPrivateKey method'],
		[
			'a key store without partnerPrivateKey',
			() => new BoostxClient({} as never),
			'keyStore must have a partnerPrivateKey method',
		],
		[
			'a fetch that is not a function',
			() => new BoostxClient(keyStore, { fetch: 'fetch' as never }),
			'fetch must be a function',
		],
	])('refuses %s when constructed', (_, construct, message) => {
		expect(construct).toThrow(expect.objectContaining({ code: 'invalid_claim', message }))
	})

	it.each([
		['left out', {}],
		['null', { fetch: null as never }],
	])('sends through the global fetch when fetch is %s', async (_, options) => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		vi.stubGlobal('fetch', fetch)
		await new BoostxClient(keyStore, options).submitSettlement(settlement())
		expect(calls).toHaveLength(1)
	})
})

describe('BoostxClient key store lookup', () => {
	it('counts the key store lookup against timeoutMs', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const hanging = { partnerPrivateKey: () => new Promise<never>(() => {}) }
		const err = await rejection(new BoostxClient(hanging, { fetch, timeoutMs: 20 }).submitSettlement(settlement()))
		expect((err as Error).name).toBe('TimeoutError')
		expect(calls).toHaveLength(0)
	})

	it.each([
		['returns no key', () => Promise.resolve(undefined as never)],
		['returns null', () => Promise.resolve(null as never)],
	])('fails with invalid_private_key, before any HTTP, when the key store %s', async (_, partnerPrivateKey) => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const err = await rejection(new BoostxClient({ partnerPrivateKey }, { fetch }).submitSettlement(settlement()))
		expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		expect(calls).toHaveLength(0)
	})

	it('fails with invalid_private_key, before any HTTP, for a partner registered without a private key', async () => {
		const store = new MemoryKeyStore()
		store.register(PARTNER_ID, { partnerPublicKey: partnerPub })
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const err = await rejection(new BoostxClient(store, { fetch }).submitSettlement(settlement()))
		expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		expect((err as Error).message).toBe('no partner private key for partner "partner-xyz"')
		expect(calls).toHaveLength(0)
	})

	it('lets a key store error propagate unchanged, before any HTTP', async () => {
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const kms = new Error('kms')
		const failing = { partnerPrivateKey: () => Promise.reject(kms) }
		expect(await rejection(new BoostxClient(failing, { fetch }).submitSettlement(settlement()))).toBe(kms)
		expect(calls).toHaveLength(0)
	})

	it('stops waiting for the key store when the caller aborts, with its reason', async () => {
		const controller = new AbortController()
		const reason = new Error('shutting down')
		const hanging = {
			partnerPrivateKey: () => {
				queueMicrotask(() => controller.abort(reason))
				return new Promise<never>(() => {})
			},
		}
		const err = await rejection(new BoostxClient(hanging).submitSettlement(settlement(), { signal: controller.signal }))
		expect(err).toBe(reason)
	})

	it('takes a key store that returns its key without a promise', async () => {
		const key = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
		const { fetch, calls } = stub(() => Response.json({ result: { ok: true } }))
		const sync = { partnerPrivateKey: () => key as unknown as Promise<CryptoKeyLike> }
		await new BoostxClient(sync, { fetch }).submitSettlement(settlement())
		expect(calls).toHaveLength(1)
	})
})

describe('BoostxClient answer body', () => {
	const MAX = 64 * 1024
	const ACCEPTANCE = '{"result":{"ok":true}}'

	it.each([
		['surrounded by JSON whitespace', ` \t\r\n${ACCEPTANCE}\n`],
		['with other members', '{"result":{"ok":true,"note":"x"},"extra":1}'],
		['after a result repeated as null', '{"result":null,"result":{"ok":true}}'],
		['filling the first 64 KiB, with more after', ACCEPTANCE.padEnd(MAX, ' ') + 'trailing data'],
	])('accepts {result:{ok:true}} %s', async (_, body) => {
		const { fetch } = stub(() => new Response(body))
		await new BoostxClient(keyStore, { fetch }).submitSettlement(settlement())
	})

	it('reads only the first 64 KiB: an acceptance that ends after them is not one', async () => {
		const { fetch } = stub(() => new Response(ACCEPTANCE.padStart(MAX + 1, ' ')))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err.error).toBe('unexpected response')
	})

	it('reads only the first 64 KiB of an error envelope', async () => {
		const { fetch } = stub(() => new Response('{"error":"not-stored"}'.padStart(MAX + 1, ' '), { status: 500 }))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err.error).toBe('HTTP 500')
	})

	it('stops reading an endless body after 64 KiB and cancels it', async () => {
		let pulled = 0
		let cancelled = false
		const space = new Uint8Array(1000).fill(0x20)
		const body = new ReadableStream<Uint8Array>({
			start: (controller) => controller.enqueue(new TextEncoder().encode(ACCEPTANCE)),
			pull: (controller) => {
				pulled += space.byteLength
				controller.enqueue(space)
			},
			cancel: () => {
				cancelled = true
			},
		})
		const { fetch } = stub(() => new Response(body))
		await new BoostxClient(keyStore, { fetch }).submitSettlement(settlement())
		expect(cancelled).toBe(true)
		expect(pulled).toBeLessThan(2 * MAX)
	})

	it.each([
		['a byte order mark', [0xef, 0xbb, 0xbf, ...new TextEncoder().encode(ACCEPTANCE)]],
		['invalid UTF-8', [...new TextEncoder().encode('{"result":{"ok":true},"x":"'), 0xff, 0x22, 0x7d]],
		[
			'an encoded surrogate',
			[...new TextEncoder().encode('{"result":{"ok":true},"x":"'), 0xed, 0xa0, 0x80, 0x22, 0x7d],
		],
		['a character cut by the 64 KiB limit', [...new TextEncoder().encode(ACCEPTANCE.padEnd(MAX - 1, ' ')), 0xc3, 0xa9]],
	])('throws BoostxAPIError for a 2xx carrying %s', async (_, bytes) => {
		const { fetch } = stub(() => new Response(new Uint8Array(bytes)))
		const err = (await rejection(
			new BoostxClient(keyStore, { fetch }).submitSettlement(settlement()),
		)) as BoostxAPIError
		expect(err.status).toBe(200)
		expect(err.error).toBe('unexpected response')
	})
})
