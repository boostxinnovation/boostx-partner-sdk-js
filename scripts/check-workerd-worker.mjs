// The Worker scripts/check-workerd.mjs runs in plain workerd: it drives the built package through each flow and
// answers { checks, failures } as JSON. Tokens from BoostX are signed here by hand, as BoostX signs them.

import {
	BoostxAPIError,
	BoostxClient,
	DEFAULT_BASE_URL,
	MemoryKeyStore,
	createFetchHandler,
	createGamePassToken,
	createSettlementToken,
	createVerifyKeysRequestToken,
	isBoostxError,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	parseVerifyKeysResponseToken,
} from '../dist/index.js'

const ES256 = { name: 'ECDSA', hash: 'SHA-256' }
const encoder = new TextEncoder()

const b64url = (bytes) =>
	btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
const unb64url = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))

async function sign(claims, privateKey) {
	const input = `${b64url(encoder.encode('{"alg":"ES256"}'))}.${b64url(encoder.encode(JSON.stringify(claims)))}`
	const signature = new Uint8Array(await crypto.subtle.sign(ES256, privateKey, encoder.encode(input)))
	return `${input}.${b64url(signature)}`
}

// Verifies an ES256 JWT and its GID with Web Crypto alone, then returns the payload.
async function verify(token, publicKey, claim) {
	const [header, payload, signature] = token.split('.')
	const data = encoder.encode(`${header}.${payload}`)
	if (!(await crypto.subtle.verify(ES256, publicKey, unb64url(signature), data))) throw new Error('bad JWT signature')
	const claims = JSON.parse(new TextDecoder().decode(unb64url(payload)))
	const { partner, user, bet, signature: gidSignature } = claims[claim].gid
	const gidData = encoder.encode(JSON.stringify({ partner, user, bet }))
	if (!(await crypto.subtle.verify(ES256, publicKey, unb64url(gidSignature), gidData)))
		throw new Error('bad GID signature')
	return claims
}

const post = (path, body) =>
	new Request(`https://partner.example/api/boostx/${path}`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(body),
	})

async function run(keys, check) {
	check('plain workerd: no Buffer', typeof globalThis.Buffer === 'undefined')
	check('plain workerd: no process', typeof globalThis.process === 'undefined')

	const partner = 'check-workerd'
	const partnerPrivate = await loadPrivateKeyFromPEM(keys.PARTNER.privatePKCS8)
	const partnerPrivateSEC1 = await loadPrivateKeyFromPEM(keys.PARTNER.privateSEC1)
	const partnerPublic = await loadPublicKeyFromPEM(keys.PARTNER.publicSPKI)
	const boostxPrivate = await loadPrivateKeyFromPEM(keys.BOOSTX.privatePKCS8)
	const boostxPublic = await loadPublicKeyFromPEM(keys.BOOSTX.publicSPKI)
	const store = new MemoryKeyStore()
	store.register(partner, {
		partnerPrivateKey: partnerPrivate,
		partnerPublicKey: partnerPublic,
		boostxPublicKey: boostxPublic,
	})

	const gamepassJWT = await createGamePassToken(partnerPrivateSEC1, {
		partner,
		user: 'user-1',
		bet: 'bet-1',
		amount: 10,
		currency: 'USD',
		x: 2.5,
		xDecimals: 2,
		eventTitle: 'Final',
		demo: true,
	})
	const { gamepass } = await verify(gamepassJWT, partnerPublic, 'gamepass')
	check(
		'gamepass claims',
		gamepass.gid.partner === partner &&
			gamepass.stake.amount === 10 &&
			gamepass.xrange.init === 2.5 &&
			gamepass.event.title === 'Final',
		JSON.stringify(gamepass),
	)

	const settlementParams = {
		partner,
		user: 'user-1',
		bet: 'bet-1',
		status: 'win',
		amount: 25,
		currency: 'USD',
		version: 1,
		xSettle: 0,
		settledAt: Date.now(),
	}
	const { settlement } = await verify(
		await createSettlementToken(partnerPrivate, settlementParams),
		partnerPublic,
		'settlement',
	)
	check('settlement claims', settlement.status === 'win' && settlement.xSettle === 0, JSON.stringify(settlement))

	// The game keeps the GID of the gamepass that created it; BoostX sends it back on every round.
	const rounds = []
	const handler = createFetchHandler({ keyStore: store, betStore: { setBoost: async (b) => void rounds.push(b) } })
	const booster = { gid: gamepass.gid, round: 1, boost: 1.25, final: false, jackpot: false }
	const iat = Math.floor(Date.now() / 1000)
	let res = await handler(post('set-boost', { boosterJWT: await sign({ booster, iat }, boostxPrivate) }))
	let body = await res.text()
	check('set-boost answers 200 ok', res.status === 200 && body === '{"result":{"ok":true}}', `${res.status} ${body}`)
	check('set-boost reaches the store', rounds.length === 1 && rounds[0].boost === 1.25 && rounds[0].round === 1)

	res = await handler(post('set-boost', { boosterJWT: await sign({ booster, iat }, partnerPrivate) }))
	body = await res.text()
	check(
		'set-boost refuses a forged token',
		res.status === 400 && body === '{"error":"invalid booster token"}' && rounds.length === 1,
		`${res.status} ${body}`,
	)

	const nonce = 123456789
	res = await handler(
		post('verify-keys', { verifyKeysJWT: await createVerifyKeysRequestToken(boostxPrivate, partner, nonce) }),
	)
	body = await res.text()
	if (res.status !== 200) throw new Error(`verify-keys answered ${res.status} ${body}`)
	const response = await parseVerifyKeysResponseToken(JSON.parse(body).result.responseJWT, partnerPublic, partner)
	check(
		'verify-keys echoes the nonce',
		response.nonce === nonce && response.partnerID === partner,
		JSON.stringify(response),
	)

	let sent
	const client = new BoostxClient(store, {
		fetch: async (input, init) => {
			sent = new Request(input, init)
			return Response.json({ result: { ok: true } })
		},
	})
	await client.submitSettlement(settlementParams)
	check('settlement URL', sent?.url === `${DEFAULT_BASE_URL}/api/integration/settlement`, sent?.url)
	check('settlement follows no redirect', sent?.redirect === 'manual', sent?.redirect)
	await verify((await sent.json()).settlementJWT, partnerPublic, 'settlement')

	const refusing = new BoostxClient(store, {
		fetch: async () => Response.json({ error: 'not-stored' }, { status: 404 }),
	})
	const err = await refusing.submitSettlement(settlementParams).catch((e) => e)
	check(
		'settlement refusal',
		err instanceof BoostxAPIError && err.status === 404 && isBoostxError(err, 'api_error'),
		String(err),
	)
}

export default {
	async fetch(_request, env) {
		const failures = []
		let checks = 0
		const check = (name, ok, detail) => {
			checks++
			if (!ok) failures.push(detail === undefined ? name : `${name}: ${detail}`)
		}
		try {
			await run(env.KEYS, check)
		} catch (err) {
			failures.push(`threw: ${err?.stack ?? err}`)
		}
		return Response.json({ checks, failures })
	},
}
