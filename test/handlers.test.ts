import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

import { type Booster } from '../src/booster.js'
import { BoostxError, isBoostxError } from '../src/errors.js'
import { buildGID, type GID } from '../src/gid.js'
import {
	RoundRejectedError,
	createFetchHandler,
	handleCheckBet,
	handleSetBoost,
	handleVerifyKeys,
	type BetStore,
	type HandlerOptions,
} from '../src/handlers.js'
import { MemoryKeyStore, type HandlersKeyStore } from '../src/key-store.js'
import { signJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { BOOSTX_IDENTITY, createVerifyKeysRequestToken, parseVerifyKeysResponseToken } from '../src/verify-keys.js'
import { BOOSTX, OTHER, PARTNER, signParts } from './fixtures.js'

const PARTNER_ID = 'partner-xyz'
const BASE = 'https://partner.example/api/boostx'

let boostxPriv: CryptoKeyLike
let boostxPub: CryptoKeyLike
let partnerPriv: CryptoKeyLike
let partnerPub: CryptoKeyLike
let otherPriv: CryptoKeyLike
let otherPub: CryptoKeyLike
let gid: GID
let keyStore: MemoryKeyStore

beforeAll(async () => {
	boostxPriv = await loadPrivateKeyFromPEM(BOOSTX.privatePKCS8)
	boostxPub = await loadPublicKeyFromPEM(BOOSTX.publicSPKI)
	partnerPriv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	otherPriv = await loadPrivateKeyFromPEM(OTHER.privatePKCS8)
	otherPub = await loadPublicKeyFromPEM(OTHER.publicSPKI)
	gid = await buildGID(partnerPriv, PARTNER_ID, 'user-12345', 'bet-abc789')
})

beforeEach(() => {
	keyStore = new MemoryKeyStore()
	keyStore.register(PARTNER_ID, {
		partnerPublicKey: partnerPub,
		partnerPrivateKey: partnerPriv,
		boostxPublicKey: boostxPub,
	})
})

// A bet store that follows the replay rule, over one stored round per bet.
class FakeBetStore implements BetStore {
	rounds = new Map<string, number>()
	applied: Booster[] = []
	checked: GID[] = []
	active: unknown = true
	fail: unknown = undefined

	async setBoost(booster: Booster): Promise<void> {
		if (this.fail !== undefined) throw this.fail
		const key = JSON.stringify([booster.gid.partner, booster.gid.user, booster.gid.bet])
		if (booster.round <= (this.rounds.get(key) ?? 0)) return
		this.rounds.set(key, booster.round)
		this.applied.push(booster)
	}

	async checkBet(gid: GID): Promise<boolean> {
		if (this.fail !== undefined) throw this.fail
		this.checked.push(gid)
		return this.active as boolean
	}
}

// Signed as BoostX signs a BoosterJWT.
function boosterToken(overrides: Record<string, unknown> = {}, key = boostxPriv): Promise<string> {
	return signJWT({ booster: { gid, round: 1, boost: 1.5, final: false, jackpot: false, ...overrides }, iat: 1 }, key)
}

function checkBetToken(g: GID = gid, key = boostxPriv): Promise<string> {
	return signJWT({ checkbet: { gid: g }, iat: 1 }, key)
}

function post(path: string, body: unknown): Request {
	return new Request(`${BASE}/${path}`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: typeof body === 'string' ? body : JSON.stringify(body),
	})
}

async function call(
	options: HandlerOptions,
	request: Request,
): Promise<{ status: number; body: unknown; res: Response }> {
	const res = await createFetchHandler(options)(request)
	return { status: res.status, body: await res.json(), res }
}

describe('POST /set-boost', () => {
	it('verifies the round, hands it to the store and answers ok: true', async () => {
		const betStore = new FakeBetStore()
		const { status, body, res } = await call(
			{ betStore, keyStore },
			post('set-boost', { boosterJWT: await boosterToken() }),
		)
		expect(status).toBe(200)
		expect(body).toStrictEqual({ result: { ok: true } })
		expect(res.headers.get('content-type')).toMatch(/^application\/json/)
		expect(betStore.applied).toStrictEqual([{ gid, round: 1, boost: 1.5, final: false, jackpot: false, iat: 1 }])
	})

	it('answers a replayed round ok: true when the store resolves without applying it', async () => {
		const betStore = new FakeBetStore()
		const handle = createFetchHandler({ betStore, keyStore })
		const token = await boosterToken({ round: 3, boost: 2 })
		expect((await handle(post('set-boost', { boosterJWT: token }))).status).toBe(200)
		const replay = await handle(post('set-boost', { boosterJWT: await boosterToken({ round: 2, boost: 9 }) }))
		expect(replay.status).toBe(200)
		expect(await replay.json()).toStrictEqual({ result: { ok: true } })
		expect(betStore.applied.map((b) => b.round)).toStrictEqual([3])
	})

	it('answers RoundRejectedError 400 round rejected, never with its message', async () => {
		const betStore = new FakeBetStore()
		betStore.fail = new RoundRejectedError('bet 42 already settled in db-7')
		const { status, body } = await call({ betStore, keyStore }, post('set-boost', { boosterJWT: await boosterToken() }))
		expect(status).toBe(400)
		expect(body).toStrictEqual({ error: 'round rejected' })
		expect(new RoundRejectedError().message).toBe('round rejected')
	})

	it('finds RoundRejectedError through the cause chain, 16 errors deep', async () => {
		const wrapped = (depth: number) => {
			let err: Error = new RoundRejectedError()
			for (let i = 1; i < depth; i++) err = new Error(`layer ${i}`, { cause: err })
			return err
		}
		const betStore = new FakeBetStore()
		const token = await boosterToken()
		for (const [fail, want] of [
			[wrapped(2), { status: 400, body: { error: 'round rejected' } }],
			[wrapped(16), { status: 400, body: { error: 'round rejected' } }],
			[wrapped(17), { status: 500, body: { error: 'failed to set boost' } }],
			[new Error('db', { cause: 'round rejected' }), { status: 500, body: { error: 'failed to set boost' } }],
			[new AggregateError([new RoundRejectedError()]), { status: 500, body: { error: 'failed to set boost' } }],
		] as const) {
			betStore.fail = fail
			expect(await handleSetBoost({ boosterJWT: token }, { betStore, keyStore })).toStrictEqual(want)
		}
		expect(betStore.applied).toStrictEqual([])
	})

	it('answers any other store error 500 without its text', async () => {
		const betStore = new FakeBetStore()
		betStore.fail = new Error('connection to db-7.internal refused')
		const { status, body } = await call({ betStore, keyStore }, post('set-boost', { boosterJWT: await boosterToken() }))
		expect(status).toBe(500)
		expect(body).toStrictEqual({ error: 'failed to set boost' })
	})

	it('answers an id the key store does not serve 400, naming it', async () => {
		const stranger = await buildGID(partnerPriv, 'stranger', 'u', 'b')
		const token = await boosterToken({ gid: stranger })
		const { status, body } = await call(
			{ betStore: new FakeBetStore(), keyStore },
			post('set-boost', { boosterJWT: token }),
		)
		expect(status).toBe(400)
		expect(body).toStrictEqual({ error: 'unknown partner "stranger"' })
	})

	it('accepts a GID signed with a previous partner key the store still lists, and only then', async () => {
		const oldGID = await buildGID(otherPriv, PARTNER_ID, 'user-1', 'bet-1')
		const token = await boosterToken({ gid: oldGID })
		const betStore = new FakeBetStore()
		const refused = await call({ betStore, keyStore }, post('set-boost', { boosterJWT: token }))
		expect(refused).toMatchObject({ status: 400, body: { error: 'invalid booster token' } })
		keyStore.register(PARTNER_ID, {
			partnerPublicKey: [partnerPub, otherPub],
			partnerPrivateKey: partnerPriv,
			boostxPublicKey: boostxPub,
		})
		const accepted = await call({ betStore, keyStore }, post('set-boost', { boosterJWT: token }))
		expect(accepted).toMatchObject({ status: 200, body: { result: { ok: true } } })
		expect(betStore.applied[0]?.gid).toStrictEqual(oldGID)
	})

	it.each([
		['signed by another key than BoostX', () => boosterToken({}, otherPriv)],
		['malformed', async () => 'not.a.jwt'],
		['empty', async () => ''],
		['missing a claim', () => boosterToken({ jackpot: undefined })],
	])('answers a token %s 400 invalid booster token', async (_name, token) => {
		const betStore = new FakeBetStore()
		const { status, body } = await call({ betStore, keyStore }, post('set-boost', { boosterJWT: await token() }))
		expect(status).toBe(400)
		expect(body).toStrictEqual({ error: 'invalid booster token' })
		expect(betStore.applied).toStrictEqual([])
	})

	it('reads the token member by its exact name only', async () => {
		const token = await boosterToken()
		const betStore = new FakeBetStore()
		for (const body of [{ BoosterJWT: token }, { boosterjwt: token }, { boosterJWT: '', BOOSTERJWT: token }]) {
			expect(await handleSetBoost(body, { betStore, keyStore })).toStrictEqual({
				status: 400,
				body: { error: 'invalid booster token' },
			})
		}
		expect(betStore.applied).toStrictEqual([])
		expect((await handleSetBoost({ BoosterJWT: 'x', boosterJWT: token }, { betStore, keyStore })).status).toBe(200)
	})

	it('answers a missing or null token as an invalid token, as Go decodes them to ""', async () => {
		for (const body of [{}, { boosterJWT: null }, null]) {
			expect(await handleSetBoost(body, { betStore: new FakeBetStore(), keyStore })).toStrictEqual({
				status: 400,
				body: { error: 'invalid booster token' },
			})
		}
	})

	it.each([['not json'], ['[]'], ['"text"'], ['42'], ['{"boosterJWT": 5}'], ['']])(
		'answers the body %j 400 invalid request body',
		async (raw) => {
			const { status, body } = await call({ betStore: new FakeBetStore(), keyStore }, post('set-boost', raw))
			expect(status).toBe(400)
			expect(body).toStrictEqual({ error: 'invalid request body' })
		},
	)

	it('answers key store failures other than unknown_partner 500', async () => {
		const noBoostx = new MemoryKeyStore()
		noBoostx.register(PARTNER_ID, { partnerPublicKey: partnerPub })
		const token = await boosterToken()
		expect(
			await handleSetBoost({ boosterJWT: token }, { betStore: new FakeBetStore(), keyStore: noBoostx }),
		).toStrictEqual({
			status: 500,
			body: { error: 'failed to get boostx key' },
		})
		const throwing: HandlersKeyStore = {
			boostxPublicKey: async () => boostxPub,
			partnerPrivateKey: async () => partnerPriv,
			partnerPublicKeys: () => {
				throw new Error('vault sealed')
			},
		}
		expect(
			await handleSetBoost({ boosterJWT: token }, { betStore: new FakeBetStore(), keyStore: throwing }),
		).toStrictEqual({
			status: 500,
			body: { error: 'failed to get partner key' },
		})
	})

	it.each(['set-boost', 'check-bet'])('looks up both verifying keys of %s at once', async (path) => {
		const events: string[] = []
		const timed =
			<T>(name: string, value: T) =>
			async (): Promise<T> => {
				events.push(`start ${name}`)
				await new Promise((resolve) => setTimeout(resolve, 0))
				events.push(`end ${name}`)
				return value
			}
		const slow: HandlersKeyStore = {
			boostxPublicKey: timed('boostx', boostxPub),
			partnerPublicKeys: timed('partner', [partnerPub]),
			partnerPrivateKey: async () => partnerPriv,
		}
		const body = path === 'set-boost' ? { boosterJWT: await boosterToken() } : { checkbetJWT: await checkBetToken() }
		const { status } = await call({ betStore: new FakeBetStore(), keyStore: slow }, post(path, body))
		expect(status).toBe(200)
		expect(events).toStrictEqual(['start boostx', 'start partner', 'end boostx', 'end partner'])
	})

	it('reports the boostx key failure first when both lookups fail, whichever settles first', async () => {
		const later = (err: Error) => () => new Promise<never>((_, reject) => setTimeout(() => reject(err), 5))
		const now = (err: Error) => async () => Promise.reject(err)
		const unknown = new BoostxError('unknown_partner', 'no such partner')
		const sealed = new Error('vault sealed')
		const store = (boostxPublicKey: () => Promise<never>, partnerPublicKeys: () => Promise<never>) => ({
			betStore: new FakeBetStore(),
			keyStore: { boostxPublicKey, partnerPublicKeys, partnerPrivateKey: async () => partnerPriv },
		})
		const body = { boosterJWT: await boosterToken() }
		expect(await handleSetBoost(body, store(later(sealed), now(unknown)))).toStrictEqual({
			status: 500,
			body: { error: 'failed to get boostx key' },
		})
		expect(await handleSetBoost(body, store(later(unknown), now(sealed)))).toStrictEqual({
			status: 400,
			body: { error: `unknown partner "${PARTNER_ID}"` },
		})
	})

	it('answers a store with no usable partner public key 500 whatever the token, once extraction passes', async () => {
		const unusable: HandlersKeyStore = {
			boostxPublicKey: async () => boostxPub,
			partnerPrivateKey: async () => partnerPriv,
			partnerPublicKeys: async () => [partnerPriv],
		}
		const options = { betStore: new FakeBetStore(), keyStore: unusable }
		for (const token of [
			await boosterToken({}, otherPriv),
			await boosterToken({ gid: { ...gid, signature: 'abc' } }),
		]) {
			expect(await handleSetBoost({ boosterJWT: token }, options)).toStrictEqual({
				status: 500,
				body: { error: 'failed to verify token' },
			})
		}
		expect(await handleSetBoost({ boosterJWT: await boosterToken({ round: 0 }) }, options)).toStrictEqual({
			status: 400,
			body: { error: 'invalid booster token' },
		})
	})

	it('answers a token with an unpaired surrogate escape 400 before any key lookup', async () => {
		let lookups = 0
		const counting: HandlersKeyStore = {
			boostxPublicKey: async () => (lookups++, boostxPub),
			partnerPrivateKey: async () => (lookups++, partnerPriv),
			partnerPublicKeys: async () => (lookups++, [partnerPub]),
		}
		const payload = JSON.stringify({ booster: { gid, round: 1, boost: 1.5, final: false, jackpot: false }, iat: 1 })
		const lone = `${String.fromCharCode(92)}udc00`
		const user = `"user":"${gid.user}"`
		// The second one repeats user, keeping the signed value last.
		for (const raw of [payload.replace('user-', `user-${lone}`), payload.replace(user, `"user":"${lone}",${user}`)]) {
			const betStore = new FakeBetStore()
			const token = await signParts('{"alg":"ES256"}', raw, boostxPriv)
			expect(await handleSetBoost({ boosterJWT: token }, { betStore, keyStore: counting })).toStrictEqual({
				status: 400,
				body: { error: 'invalid booster token' },
			})
			expect(betStore.applied).toHaveLength(0)
		}
		expect(lookups).toBe(0)
	})

	it('answers a store key that cannot verify 500, not as a bad token', async () => {
		const broken: HandlersKeyStore = {
			boostxPublicKey: async () => partnerPriv,
			partnerPrivateKey: async () => partnerPriv,
			partnerPublicKeys: async () => [partnerPub],
		}
		expect(
			await handleSetBoost({ boosterJWT: await boosterToken() }, { betStore: new FakeBetStore(), keyStore: broken }),
		).toStrictEqual({
			status: 500,
			body: { error: 'failed to verify token' },
		})
	})
})

describe('POST /check-bet', () => {
	it.each([true, false])('answers the store verdict active: %s', async (active) => {
		const betStore = new FakeBetStore()
		betStore.active = active
		const { status, body } = await call(
			{ betStore, keyStore },
			post('check-bet', { checkbetJWT: await checkBetToken() }),
		)
		expect(status).toBe(200)
		expect(body).toStrictEqual({ result: { active } })
		expect(betStore.checked).toStrictEqual([gid])
	})

	it('answers 404 on every method when the store has no checkBet', async () => {
		const betStore: BetStore = { setBoost: async () => {} }
		const handle = createFetchHandler({ betStore, keyStore })
		expect((await handle(post('check-bet', { checkbetJWT: await checkBetToken() }))).status).toBe(404)
		expect((await handle(new Request(`${BASE}/check-bet`))).status).toBe(404)
		expect(await handleCheckBet({ checkbetJWT: await checkBetToken() }, { betStore, keyStore })).toStrictEqual({
			status: 404,
			body: { error: 'not found' },
		})
	})

	it('answers a store error, or a verdict that is not a boolean, 500', async () => {
		const betStore = new FakeBetStore()
		const options = { betStore, keyStore }
		const body = { checkbetJWT: await checkBetToken() }
		for (const active of ['yes', 'false', 1, 0, null, undefined, {}]) {
			betStore.active = active
			expect(await handleCheckBet(body, options)).toStrictEqual({ status: 500, body: { error: 'failed to check bet' } })
		}
		betStore.active = true
		betStore.fail = new Error('db down')
		expect(await handleCheckBet(body, options)).toStrictEqual({ status: 500, body: { error: 'failed to check bet' } })
	})

	it('answers an invalid token, an unknown partner and a bad body 400', async () => {
		const options = { betStore: new FakeBetStore(), keyStore }
		expect(await handleCheckBet({ checkbetJWT: await checkBetToken(gid, otherPriv) }, options)).toStrictEqual({
			status: 400,
			body: { error: 'invalid checkbet token' },
		})
		const stranger = await buildGID(partnerPriv, 'stranger', 'u', 'b')
		expect(await handleCheckBet({ checkbetJWT: await checkBetToken(stranger) }, options)).toStrictEqual({
			status: 400,
			body: { error: 'unknown partner "stranger"' },
		})
		expect(await handleCheckBet([], options)).toStrictEqual({ status: 400, body: { error: 'invalid request body' } })
	})
})

describe('POST /verify-keys', () => {
	it('answers a responseJWT signed as the partner, echoing the nonce', async () => {
		const token = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 1642938715)
		const { status, body } = await call(
			{ betStore: new FakeBetStore(), keyStore },
			post('verify-keys', { verifyKeysJWT: token }),
		)
		expect(status).toBe(200)
		const { responseJWT } = (body as { result: { responseJWT: string } }).result
		expect(await parseVerifyKeysResponseToken(responseJWT, partnerPub, PARTNER_ID)).toStrictEqual({
			partnerID: PARTNER_ID,
			nonce: 1642938715,
			iat: expect.any(Number),
		})
	})

	it('answers an aud naming a partner the store does not serve (the foreign-id probe) 400 iss-aud', async () => {
		const token = await createVerifyKeysRequestToken(boostxPriv, 'not-a-partner', 7)
		const result = await handleVerifyKeys({ verifyKeysJWT: token }, { betStore: new FakeBetStore(), keyStore })
		expect(result).toStrictEqual({
			status: 400,
			body: { error: 'invalid verifyKeysJWT: iss-aud (unknown partner "not-a-partner")' },
		})
		// How BoostX reads the reason back.
		expect(/invalid verifyKeysJWT:\s*([\w-]+)/.exec((result.body as { error: string }).error)?.[1]).toBe('iss-aud')
	})

	it.each([
		[
			'signed by an untrusted key (the invalid-signature probe)',
			() => createVerifyKeysRequestToken(otherPriv, PARTNER_ID, 7),
			'signature',
		],
		[
			'with a stale iat',
			() =>
				signJWT(
					{ verifyKeys: { nonce: 7 }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: Math.floor(Date.now() / 1000) - 60 },
					boostxPriv,
				),
			'stale',
		],
		[
			'from another issuer',
			() =>
				signJWT(
					{ verifyKeys: { nonce: 7 }, iss: 'mallory', aud: PARTNER_ID, iat: Math.floor(Date.now() / 1000) },
					boostxPriv,
				),
			'iss-aud',
		],
		[
			'with nonce 0',
			() =>
				signJWT(
					{ verifyKeys: { nonce: 0 }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: Math.floor(Date.now() / 1000) },
					boostxPriv,
				),
			'nonce-format',
		],
		['malformed', async () => 'garbage', 'shape'],
		[
			'with a string nonce',
			() =>
				signJWT(
					{ verifyKeys: { nonce: '7' }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: Math.floor(Date.now() / 1000) },
					boostxPriv,
				),
			'nonce-format',
		],
		[
			'with a string nonce, signed by an untrusted key',
			() =>
				signJWT(
					{ verifyKeys: { nonce: '7' }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: Math.floor(Date.now() / 1000) },
					otherPriv,
				),
			'signature',
		],
		[
			'with an nbf ahead of the clock',
			() =>
				signJWT(
					{
						verifyKeys: { nonce: 7 },
						iss: BOOSTX_IDENTITY,
						aud: PARTNER_ID,
						iat: Math.floor(Date.now() / 1000),
						nbf: Math.floor(Date.now() / 1000) + 60,
					},
					boostxPriv,
				),
			'stale',
		],
		[
			'addressed to boostx',
			() =>
				signJWT(
					{ verifyKeys: { nonce: 7 }, iss: BOOSTX_IDENTITY, aud: BOOSTX_IDENTITY, iat: Math.floor(Date.now() / 1000) },
					boostxPriv,
				),
			'shape',
		],
	])("answers a request %s 400 with Go's bare reason", async (_name, token, reason) => {
		const result = await handleVerifyKeys({ verifyKeysJWT: await token() }, { betStore: new FakeBetStore(), keyStore })
		expect(result).toStrictEqual({ status: 400, body: { error: `invalid verifyKeysJWT: ${reason}` } })
	})

	it('answers a null body, or a missing or null token, as shape and a non-string token as a bad body', async () => {
		for (const body of [null, {}, { verifyKeysJWT: null }]) {
			expect(await handleVerifyKeys(body, { keyStore })).toStrictEqual({
				status: 400,
				body: { error: 'invalid verifyKeysJWT: shape' },
			})
		}
		expect(await handleVerifyKeys({ verifyKeysJWT: 7 }, { keyStore })).toStrictEqual({
			status: 400,
			body: { error: 'invalid request body' },
		})
	})

	it('accepts a request iat 30 seconds from the clock and refuses 31 as stale, with no option to change it', async () => {
		const now = 1_800_000_000
		vi.spyOn(Date, 'now').mockReturnValue(now * 1000 + 500)
		try {
			const at = (age: number) =>
				signJWT({ verifyKeys: { nonce: 7 }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: now - age }, boostxPriv)
			// The window is fixed: an option of another name, or the parse function's, changes nothing.
			const options = { betStore: new FakeBetStore(), keyStore, verifyKeysMaxSkewSeconds: 120, maxSkewSeconds: 120 }
			for (const age of [30, -30]) {
				expect((await handleVerifyKeys({ verifyKeysJWT: await at(age) }, options)).status).toBe(200)
			}
			for (const age of [31, -31]) {
				expect(await handleVerifyKeys({ verifyKeysJWT: await at(age) }, options)).toStrictEqual({
					status: 400,
					body: { error: 'invalid verifyKeysJWT: stale' },
				})
			}
		} finally {
			vi.restoreAllMocks()
		}
	})

	it('answers a payload of the wrong claim type shape before the key store, whatever the signature', async () => {
		const lookups: string[] = []
		const watched: HandlersKeyStore = {
			boostxPublicKey: async (p) => (lookups.push(p), keyStore.boostxPublicKey(p)),
			partnerPublicKeys: async (p) => keyStore.partnerPublicKeys(p),
			partnerPrivateKey: async (p) => keyStore.partnerPrivateKey(p),
		}
		const now = Math.floor(Date.now() / 1000)
		for (const claims of [{ exp: null }, { iat: now + 0.5 }, { verifyKeys: 7 }]) {
			const token = await signJWT(
				{ verifyKeys: { nonce: 7 }, iss: BOOSTX_IDENTITY, aud: PARTNER_ID, iat: now, ...claims },
				otherPriv,
			)
			expect(
				await handleVerifyKeys({ verifyKeysJWT: token }, { betStore: new FakeBetStore(), keyStore: watched }),
			).toStrictEqual({ status: 400, body: { error: 'invalid verifyKeysJWT: shape' } })
		}
		expect(lookups).toStrictEqual([])
	})

	it('needs no bet store, and of the key store only boostxPublicKey and partnerPrivateKey', async () => {
		const token = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 7)
		const twoMethods = {
			boostxPublicKey: (p: string) => keyStore.boostxPublicKey(p),
			partnerPrivateKey: (p: string) => keyStore.partnerPrivateKey(p),
		}
		expect((await handleVerifyKeys({ verifyKeysJWT: token }, { keyStore: twoMethods })).status).toBe(200)
		const internal = { status: 500, body: { error: 'internal server error' } }
		for (const options of [
			{ keyStore: { boostxPublicKey: twoMethods.boostxPublicKey } },
			{ keyStore: { partnerPrivateKey: twoMethods.partnerPrivateKey } },
			{ betStore: new FakeBetStore() },
			undefined,
		]) {
			expect(await handleVerifyKeys({ verifyKeysJWT: token }, options as unknown as HandlerOptions)).toStrictEqual(
				internal,
			)
		}
		// The fetch handler serves every endpoint, so it still needs the whole of both stores.
		expect(() =>
			createFetchHandler({
				keyStore: { ...twoMethods, partnerPublicKeys: async () => [] },
			} as unknown as HandlerOptions),
		).toThrow('betStore must have a setBoost method')
	})

	it('answers a missing private key 500', async () => {
		const verifyOnly = new MemoryKeyStore()
		verifyOnly.register(PARTNER_ID, { boostxPublicKey: boostxPub })
		const token = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 7)
		expect(
			await handleVerifyKeys({ verifyKeysJWT: token }, { betStore: new FakeBetStore(), keyStore: verifyOnly }),
		).toStrictEqual({
			status: 500,
			body: { error: 'failed to get partner private key' },
		})
	})
})

describe('createFetchHandler', () => {
	it.each([
		['no betStore', { betStore: undefined }, 'betStore must have a setBoost method'],
		[
			'a betStore without setBoost',
			{ betStore: { checkBet: async () => true } },
			'betStore must have a setBoost method',
		],
		['no keyStore', { keyStore: undefined }, 'keyStore must have a partnerPublicKeys method'],
		[
			'a keyStore without boostxPublicKey',
			{ keyStore: { partnerPublicKeys: async () => [], partnerPrivateKey: async () => partnerPriv } },
			'keyStore must have a boostxPublicKey method',
		],
	])('throws invalid_claim at creation for %s', (_name, overrides, message) => {
		const err = catching(() =>
			createFetchHandler({ betStore: new FakeBetStore(), keyStore, ...overrides } as unknown as HandlerOptions),
		)
		expect(isBoostxError(err, 'invalid_claim')).toBe(true)
		expect((err as Error).message).toBe(message)
	})

	it('throws invalid_claim at creation for no options', () => {
		const err = catching(() => createFetchHandler(undefined as unknown as HandlerOptions))
		expect(isBoostxError(err, 'invalid_claim')).toBe(true)
	})

	it.each([
		['already read', async (r: Request) => void (await r.text())],
		['locked by another reader', async (r: Request) => void r.body?.getReader()],
	])('answers a body %s 400 invalid request body', async (_name, consume) => {
		const request = post('set-boost', { boosterJWT: await boosterToken() })
		await consume(request)
		const { status, body } = await call({ betStore: new FakeBetStore(), keyStore }, request)
		expect(status).toBe(400)
		expect(body).toStrictEqual({ error: 'invalid request body' })
	})

	it('dispatches on the last path segment, wherever it is mounted', async () => {
		const handle = createFetchHandler({ betStore: new FakeBetStore(), keyStore })
		const body = JSON.stringify({ boosterJWT: await boosterToken() })
		for (const url of ['https://h/set-boost', 'https://h/a/b/c/set-boost?x=1']) {
			expect((await handle(new Request(url, { method: 'POST', body }))).status).toBe(200)
		}
	})

	it.each([
		'unknown',
		'',
		'set-boost/',
		'Set-Boost',
		'SET-BOOST',
		'set-boost.json',
		'constructor',
		'__proto__',
		'toString',
	])('answers the path %j 404', async (path) => {
		const { status, body } = await call({ betStore: new FakeBetStore(), keyStore }, post(path, '{}'))
		expect(status).toBe(404)
		expect(body).toStrictEqual({ error: 'not found' })
	})

	it.each(['GET', 'PUT', 'DELETE', 'OPTIONS'])('answers %s 405 with Allow: POST', async (method) => {
		const res = await createFetchHandler({ betStore: new FakeBetStore(), keyStore })(
			new Request(`${BASE}/set-boost`, { method }),
		)
		expect(res.status).toBe(405)
		expect(res.headers.get('allow')).toBe('POST')
		expect(await res.json()).toStrictEqual({ error: 'method not allowed' })
	})

	// A /set-boost body whose extra string member holds the given bytes.
	async function bodyWith(bytes: number[], before: number[] = [], after: number[] = []): Promise<Request> {
		const head = JSON.stringify({ boosterJWT: await boosterToken() }).slice(0, -1) + ',"note":"'
		const encode = (text: string) => [...new TextEncoder().encode(text)]
		const body = new Uint8Array([...before, ...encode(head), ...bytes, ...encode('"}'), ...after])
		return new Request(`${BASE}/set-boost`, { method: 'POST', body })
	}

	it.each([
		['a byte order mark', () => bodyWith([], [0xef, 0xbb, 0xbf])],
		['an invalid UTF-8 byte', () => bodyWith([0xff])],
		['an overlong encoding', () => bodyWith([0xc0, 0xaf])],
		['an encoded surrogate', () => bodyWith([0xed, 0xa0, 0x80])],
		['a code point above U+10FFFF', () => bodyWith([0xf4, 0x90, 0x80, 0x80])],
		['trailing data', () => bodyWith([], [], [0x20, 0x7b, 0x7d])],
	])('answers a body with %s 400 invalid request body', async (_name, request) => {
		const betStore = new FakeBetStore()
		const res = await createFetchHandler({ betStore, keyStore })(await request())
		expect(res.status).toBe(400)
		expect(await res.json()).toStrictEqual({ error: 'invalid request body' })
		expect(betStore.applied).toStrictEqual([])
	})

	it('accepts a body of strict UTF-8 with surrounding JSON whitespace and characters beyond ASCII', async () => {
		const text = [...new TextEncoder().encode('\u00e9 \u20ac \u{1f600}')]
		const res = await createFetchHandler({ betStore: new FakeBetStore(), keyStore })(
			await bodyWith(text, [0x0d, 0x0a, 0x09, 0x20], [0x20, 0x0a]),
		)
		expect(res.status).toBe(200)
	})

	it('accepts a body of exactly 64 KiB and refuses one byte more', async () => {
		const handle = createFetchHandler({ betStore: new FakeBetStore(), keyStore })
		const json = JSON.stringify({ boosterJWT: await boosterToken(), pad: '' })
		const sized = (n: number) => json.replace('"pad":""', `"pad":"${'x'.repeat(n - json.length)}"`)
		expect(new TextEncoder().encode(sized(65536)).length).toBe(65536)
		expect((await handle(post('set-boost', sized(65536)))).status).toBe(200)
		const over = await handle(post('set-boost', sized(65537)))
		expect(over.status).toBe(400)
		expect(await over.json()).toStrictEqual({ error: 'invalid request body' })
	})

	it('stops reading an endless body once past the cap', async () => {
		let pulled = 0
		const endless = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulled++
				controller.enqueue(new Uint8Array(1024).fill(0x20))
			},
		})
		const request = new Request(`${BASE}/set-boost`, { method: 'POST', body: endless, duplex: 'half' } as RequestInit)
		const res = await createFetchHandler({ betStore: new FakeBetStore(), keyStore })(request)
		expect(res.status).toBe(400)
		expect(pulled).toBeLessThan(80)
	})

	it('answers 500, never rejecting, when anything throws', async () => {
		let armed = false
		const options = {
			keyStore,
			get betStore(): BetStore {
				if (armed) throw new BoostxError('invalid_claim', 'boom')
				return new FakeBetStore()
			},
		}
		const handle = createFetchHandler(options)
		armed = true
		for (const path of ['check-bet', 'set-boost']) {
			const res = await handle(post(path, { boosterJWT: await boosterToken() }))
			expect(res.status).toBe(500)
			expect(await res.json()).toStrictEqual({ error: 'internal server error' })
		}
	})
})

function catching(run: () => unknown): unknown {
	try {
		run()
	} catch (e) {
		return e
	}
	return undefined
}

// A custom store can hand back any CryptoKey; Web Crypto signs and verifies ES256 on any curve.
describe('keys that are not ECDSA P-256', () => {
	let p384: { publicKey: CryptoKeyLike; privateKey: CryptoKeyLike }

	beforeAll(async () => {
		p384 = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, [
			'sign',
			'verify',
		])) as typeof p384
	})

	function store(keys: Partial<Record<keyof HandlersKeyStore, unknown>>): HandlersKeyStore {
		return {
			partnerPublicKeys: async () => (keys.partnerPublicKeys ?? [partnerPub]) as readonly CryptoKeyLike[],
			partnerPrivateKey: async () => (keys.partnerPrivateKey ?? partnerPriv) as CryptoKeyLike,
			boostxPublicKey: async () => (keys.boostxPublicKey ?? boostxPub) as CryptoKeyLike,
		}
	}

	const failedToVerify = { status: 500, body: { error: 'failed to verify token' } }

	it('answers a P-384 BoostX public key 500 on every endpoint', async () => {
		const options = { betStore: new FakeBetStore(), keyStore: store({ boostxPublicKey: p384.publicKey }) }
		expect(await handleSetBoost({ boosterJWT: await boosterToken() }, options)).toStrictEqual(failedToVerify)
		expect(await handleCheckBet({ checkbetJWT: await checkBetToken() }, options)).toStrictEqual(failedToVerify)
		const verifyKeysJWT = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 7)
		expect(await handleVerifyKeys({ verifyKeysJWT }, options)).toStrictEqual(failedToVerify)
	})

	it('answers a P-384 partner public key 500, and skips it next to a key that verifies', async () => {
		const betStore = new FakeBetStore()
		const only = { betStore, keyStore: store({ partnerPublicKeys: [p384.publicKey] }) }
		expect(await handleSetBoost({ boosterJWT: await boosterToken() }, only)).toStrictEqual(failedToVerify)
		const both = { betStore, keyStore: store({ partnerPublicKeys: [p384.publicKey, partnerPub] }) }
		expect((await handleSetBoost({ boosterJWT: await boosterToken() }, both)).status).toBe(200)
	})

	it('answers a P-384 partner private key 500 on /verify-keys', async () => {
		const options = { betStore: new FakeBetStore(), keyStore: store({ partnerPrivateKey: p384.privateKey }) }
		const verifyKeysJWT = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 7)
		expect(await handleVerifyKeys({ verifyKeysJWT }, options)).toStrictEqual({
			status: 500,
			body: { error: 'failed to sign response' },
		})
	})

	it('refuses to sign a GID or a token with a P-384 private key', async () => {
		for (const sign of [() => buildGID(p384.privateKey, PARTNER_ID, 'u', 'b'), () => signJWT({}, p384.privateKey)]) {
			const err = await sign().then(
				() => undefined,
				(e: unknown) => e,
			)
			expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		}
	})
})

describe('per-endpoint functions with invalid options', () => {
	it('answers 500 from the core function when the options have no key store', async () => {
		const options = { betStore: new FakeBetStore() } as unknown as HandlerOptions
		const internal = { status: 500, body: { error: 'internal server error' } }
		expect(await handleSetBoost({ boosterJWT: await boosterToken() }, options)).toStrictEqual(internal)
		expect(await handleCheckBet({ checkbetJWT: await checkBetToken() }, options)).toStrictEqual(internal)
	})
})
