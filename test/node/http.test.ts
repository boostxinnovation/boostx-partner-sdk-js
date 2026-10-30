import { Agent, createServer, request, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'

import { afterEach, beforeAll, describe, expect, it } from 'vitest'

import { buildGID, type GID } from '../../src/gid.js'
import type { BetStore } from '../../src/handlers.js'
import { signJWT } from '../../src/jwt.js'
import { MemoryKeyStore } from '../../src/key-store.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../../src/keys.js'
import * as nodeEntry from '../../src/node/index.js'
import { createNodeHandler, type NodeRequest } from '../../src/node/index.js'
import { createVerifyKeysRequestToken, parseVerifyKeysResponseToken } from '../../src/verify-keys.js'
import { BOOSTX, PARTNER } from '../fixtures.js'

const PARTNER_ID = 'partner-xyz'

let boostxPriv: CryptoKeyLike
let partnerPub: CryptoKeyLike
let keyStore: MemoryKeyStore
let gid: GID
let server: Server | undefined

beforeAll(async () => {
	boostxPriv = await loadPrivateKeyFromPEM(BOOSTX.privatePKCS8)
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	const partnerPriv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	keyStore = new MemoryKeyStore()
	keyStore.register(PARTNER_ID, {
		partnerPublicKey: partnerPub,
		partnerPrivateKey: partnerPriv,
		boostxPublicKey: await loadPublicKeyFromPEM(BOOSTX.publicSPKI),
	})
	gid = await buildGID(partnerPriv, PARTNER_ID, 'user-1', 'bet-1')
})

afterEach(async () => {
	await new Promise((resolve) => (server ? server.close(resolve) : resolve(undefined)))
	server = undefined
})

const rounds: number[] = []
const betStore: BetStore = {
	async setBoost(b) {
		rounds.push(b.round)
	},
}

// Serves `listener` on an ephemeral port and returns its base URL.
async function serve(listener: (req: IncomingMessage, res: ServerResponse) => void): Promise<string> {
	server = createServer(listener)
	await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve))
	return `http://127.0.0.1:${(server.address() as AddressInfo).port}`
}

function boosterBody(round = 1): Promise<string> {
	return signJWT({ booster: { gid, round, boost: 1.5, final: false, jackpot: false }, iat: 1 }, boostxPriv).then(
		(boosterJWT) => JSON.stringify({ boosterJWT }),
	)
}

// Reads the body itself and hands on what a body parser would leave in req.body.
function preParsed(parse: (raw: Buffer) => unknown, handler: (req: NodeRequest, res: ServerResponse) => Promise<void>) {
	return (req: NodeRequest, res: ServerResponse) => {
		const chunks: Buffer[] = []
		req.on('data', (c: Buffer) => chunks.push(c))
		req.on('end', () => {
			req.body = parse(Buffer.concat(chunks))
			void handler(req, res)
		})
	}
}

describe('createNodeHandler', () => {
	it('serves set-boost and verify-keys under a prefix on a plain node:http server', async () => {
		const base = await serve(createNodeHandler({ betStore, keyStore }))
		const res = await fetch(`${base}/api/boostx/set-boost`, { method: 'POST', body: await boosterBody(7) })
		expect(res.status).toBe(200)
		expect(res.headers.get('content-type')).toMatch(/^application\/json/)
		expect(await res.json()).toStrictEqual({ result: { ok: true } })
		expect(rounds).toContain(7)

		const verifyKeysJWT = await createVerifyKeysRequestToken(boostxPriv, PARTNER_ID, 99)
		const vk = await fetch(`${base}/api/boostx/verify-keys`, {
			method: 'POST',
			body: JSON.stringify({ verifyKeysJWT }),
		})
		const { responseJWT } = ((await vk.json()) as { result: { responseJWT: string } }).result
		expect(await parseVerifyKeysResponseToken(responseJWT, partnerPub, PARTNER_ID)).toStrictEqual({
			partnerID: PARTNER_ID,
			nonce: 99,
			iat: expect.any(Number),
		})
	})

	it('answers 405 with Allow, 404 for other paths and 404 for check-bet without checkBet', async () => {
		const base = await serve(createNodeHandler({ betStore, keyStore }))
		const get = await fetch(`${base}/api/boostx/set-boost`)
		expect(get.status).toBe(405)
		expect(get.headers.get('allow')).toBe('POST')
		for (const method of ['PUT', 'DELETE']) expect((await fetch(`${base}/set-boost`, { method })).status).toBe(405)
		// fetch refuses to send TRACE, which a web Request cannot carry either.
		const trace = await new Promise<number | undefined>((resolve, reject) => {
			request(`${base}/set-boost`, { method: 'TRACE' }, (res) => resolve(res.resume().statusCode))
				.on('error', reject)
				.end()
		})
		expect(trace).toBe(405)
		expect((await fetch(`${base}/api/boostx/other`, { method: 'POST', body: '{}' })).status).toBe(404)
		expect((await fetch(`${base}/api/boostx/check-bet`, { method: 'POST', body: '{}' })).status).toBe(404)
	})

	it('refuses an oversized body and keeps the connection usable', async () => {
		const base = await serve(createNodeHandler({ betStore, keyStore }))
		let connections = 0
		server!.on('connection', () => connections++)
		const agent = new Agent({ keepAlive: true, maxSockets: 1 })
		const post = (body: string) =>
			new Promise<{ status?: number; body: string }>((resolve, reject) => {
				const req = request(`${base}/set-boost`, { method: 'POST', agent }, (res) => {
					let text = ''
					res.setEncoding('utf8')
					res.on('data', (c: string) => (text += c))
					res.on('end', () => resolve({ status: res.statusCode, body: text }))
				})
				req.on('error', reject)
				req.end(body)
			})
		try {
			expect(await post('x'.repeat(1024 * 1024))).toStrictEqual({
				status: 400,
				body: JSON.stringify({ error: 'invalid request body' }),
			})
			expect((await post(await boosterBody())).status).toBe(200)
			expect(connections).toBe(1)
		} finally {
			agent.destroy()
		}
	})

	it('reads the stream when a parser left req.body = {} without reading it', async () => {
		// What Express 4 body parsers do on a content type they do not handle (urlencoded, text).
		const handler = createNodeHandler({ betStore, keyStore })
		const base = await serve((req: NodeRequest, res) => {
			req.body = {}
			void handler(req, res)
		})
		const res = await fetch(`${base}/set-boost`, { method: 'POST', body: await boosterBody(4) })
		expect(res.status).toBe(200)
		expect(await res.json()).toStrictEqual({ result: { ok: true } })
	})

	it('answers 400 at once when the stream was read and left no req.body', async () => {
		const handler = createNodeHandler({ betStore, keyStore })
		const base = await serve((req, res) => req.resume().on('end', () => void handler(req, res)))
		const res = await fetch(`${base}/set-boost`, {
			method: 'POST',
			body: await boosterBody(),
			signal: AbortSignal.timeout(2000),
		})
		expect(res.status).toBe(400)
		expect(await res.json()).toStrictEqual({ error: 'invalid request body' })
	})

	it('reads a stream that setEncoding turned into string chunks', async () => {
		const handler = createNodeHandler({ betStore, keyStore })
		const base = await serve((req, res) => void handler(req.setEncoding('utf8'), res))
		const res = await fetch(`${base}/set-boost`, { method: 'POST', body: await boosterBody(5) })
		expect(res.status).toBe(200)
		expect(await res.json()).toStrictEqual({ result: { ok: true } })
	})

	it('uses a body a framework already parsed: an object, a Buffer or a string', async () => {
		for (const parse of [
			(raw: Buffer) => JSON.parse(raw.toString()),
			(raw: Buffer) => raw,
			(raw: Buffer) => raw.toString(),
		]) {
			const base = await serve(preParsed(parse, createNodeHandler({ betStore, keyStore })))
			const res = await fetch(`${base}/api/boostx/set-boost`, { method: 'POST', body: await boosterBody(3) })
			expect(res.status).toBe(200)
			expect(await res.json()).toStrictEqual({ result: { ok: true } })
			await new Promise((resolve) => server!.close(resolve))
			server = undefined
		}
	})

	it('still caps a pre-parsed body', async () => {
		const base = await serve(preParsed((raw) => JSON.parse(raw.toString()), createNodeHandler({ betStore, keyStore })))
		const body = JSON.stringify({ boosterJWT: 'x', pad: 'y'.repeat(70 * 1024) })
		const res = await fetch(`${base}/set-boost`, { method: 'POST', body })
		expect(res.status).toBe(400)
		expect(await res.json()).toStrictEqual({ error: 'invalid request body' })
	})

	it('answers 500 rather than rejecting when anything throws', async () => {
		const handler = createNodeHandler({
			keyStore,
			betStore: {
				setBoost: betStore.setBoost,
				get checkBet(): BetStore['checkBet'] {
					throw new Error('boom')
				},
			},
		})
		const base = await serve((req, res) => {
			handler(req, res).catch(() => res.end('rejected'))
		})
		const res = await fetch(`${base}/check-bet`, { method: 'POST', body: '{}' })
		expect(res.status).toBe(500)
		expect(await res.json()).toStrictEqual({ error: 'internal server error' })
	})

	it('is exported from the node entry with the key file loaders, and nothing else', () => {
		expect(Object.keys(nodeEntry).sort()).toStrictEqual([
			'createNodeHandler',
			'loadPrivateKeyFromFile',
			'loadPublicKeyFromFile',
		])
	})
})
