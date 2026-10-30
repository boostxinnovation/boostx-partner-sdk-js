// A partner Worker: the BoostX endpoints under /api/boostx/, keys from secrets, settlements sent with BoostxClient.
// Put the PEM keys with `wrangler secret put PARTNER_PRIVATE_KEY` (and the other two); no nodejs_compat needed.

import {
	BoostxClient,
	MemoryKeyStore,
	RoundRejectedError,
	createFetchHandler,
	loadPrivateKeyFromPEM,
	loadPublicKeyFromPEM,
	type BetStore,
	type GID,
	type SettlementParams,
} from '../src/index.js'

interface Env {
	PARTNER_ID: string
	PARTNER_PRIVATE_KEY: string
	PARTNER_PUBLIC_KEY: string
	BOOSTX_PUBLIC_KEY: string
}

// Stands in for your database (D1, a Durable Object, your own API): isolate memory is not durable.
const bets = new Map<string, { round: number; boost: number; active: boolean }>()
const betKey = (gid: GID) => JSON.stringify([gid.partner, gid.user, gid.bet])

const betStore: BetStore = {
	async setBoost(booster) {
		const bet = bets.get(betKey(booster.gid))
		if (bet === undefined) throw new RoundRejectedError('unknown bet') // answered 400, the bet is untouched
		if (booster.round <= bet.round) return // a replay: answered ok, nothing changes
		bet.round = booster.round
		bet.boost = booster.boost
	},
	async checkBet(gid) {
		return bets.get(betKey(gid))?.active ?? false
	},
}

// Built once per isolate; a failed load is retried on the next request.
let keys: Promise<MemoryKeyStore> | undefined
function keyStore(env: Env): Promise<MemoryKeyStore> {
	keys ??= (async () => {
		const store = new MemoryKeyStore()
		store.register(env.PARTNER_ID, {
			partnerPrivateKey: await loadPrivateKeyFromPEM(env.PARTNER_PRIVATE_KEY),
			partnerPublicKey: await loadPublicKeyFromPEM(env.PARTNER_PUBLIC_KEY),
			boostxPublicKey: await loadPublicKeyFromPEM(env.BOOSTX_PUBLIC_KEY),
		})
		return store
	})().catch((err: unknown) => {
		keys = undefined
		throw err
	})
	return keys
}

/**
 * Sends one settlement; on 'retry', send the same params again from your own queue, never re-stamped, with a backoff
 * until BoostX accepts them (e.g. over 3 days), and alert if the window ends first. Each attempt is signed with the
 * keys loaded then, so a retry after a partner key change signs with the new key.
 */
export async function sendSettlement(env: Env, params: SettlementParams): Promise<'sent' | 'retry'> {
	try {
		await new BoostxClient(await keyStore(env)).submitSettlement(params)
		return 'sent'
	} catch (err) {
		console.warn('settlement not accepted yet', err) // its status and error diagnose an alert
		return 'retry' // any error, a 4xx included: BoostX has not accepted it yet
	}
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		if (!new URL(request.url).pathname.startsWith('/api/boostx/')) return new Response('Not Found', { status: 404 })
		const handle = createFetchHandler({ betStore, keyStore: await keyStore(env) })
		return handle(request)
	},
}
