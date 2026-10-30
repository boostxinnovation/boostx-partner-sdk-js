// A partner server on node:http: the BoostX endpoints under /api/boostx/, keys read from PEM files.
// Set the API URL on your dashboard to https://<your host>/api/boostx and serve this behind TLS.

import { createServer } from 'node:http'

import { MemoryKeyStore, RoundRejectedError, type BetStore, type GID } from '../src/index.js'
import { createNodeHandler, loadPrivateKeyFromFile, loadPublicKeyFromFile } from '../src/node/index.js'

const PARTNER_ID = 'your-partner-id' // exactly as your dashboard shows it

const keyStore = new MemoryKeyStore()
keyStore.register(PARTNER_ID, {
	partnerPrivateKey: await loadPrivateKeyFromFile('keys/private.pem'),
	partnerPublicKey: await loadPublicKeyFromFile('keys/public.pem'),
	boostxPublicKey: await loadPublicKeyFromFile('keys/boostx_public.pem'),
})

// Stands in for your bet records: one row per bet, keyed by partner, user and bet ids together.
interface Bet {
	round: number
	boost: number
	active: boolean
}
const bets = new Map<string, Bet>()
const betKey = (gid: GID) => JSON.stringify([gid.partner, gid.user, gid.bet])

const betStore: BetStore = {
	async setBoost(booster) {
		const bet = bets.get(betKey(booster.gid))
		if (bet === undefined) throw new RoundRejectedError('unknown bet') // answered 400, the bet is untouched
		if (booster.round <= bet.round) return // a replay: answered ok, nothing changes
		bet.round = booster.round
		bet.boost = booster.boost
	},
	// Optional: with it, /check-bet is served. Tick /check-bet on your dashboard only if you keep it.
	async checkBet(gid) {
		return bets.get(betKey(gid))?.active ?? false
	},
}

const boostx = createNodeHandler({ betStore, keyStore })

createServer((req, res) => {
	if (req.url?.startsWith('/api/boostx/')) return void boostx(req, res)
	res.writeHead(404).end()
}).listen(8080)
