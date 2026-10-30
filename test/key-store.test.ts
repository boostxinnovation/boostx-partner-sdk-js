import { beforeAll, describe, expect, it } from 'vitest'

import { isBoostxError } from '../src/errors.js'
import { buildGID, verifyGID } from '../src/gid.js'
import { MemoryKeyStore, type ClientKeyStore, type HandlersKeyStore } from '../src/key-store.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../src/keys.js'
import { BOOSTX, OTHER, PARTNER, publicKeyWithoutUsages } from './fixtures.js'

let partnerPub: CryptoKeyLike
let partnerPriv: CryptoKeyLike
let boostxPub: CryptoKeyLike
let otherPub: CryptoKeyLike
let otherPriv: CryptoKeyLike

beforeAll(async () => {
	partnerPub = await loadPublicKeyFromPEM(PARTNER.publicSPKI)
	partnerPriv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
	boostxPub = await loadPublicKeyFromPEM(BOOSTX.publicSPKI)
	otherPub = await loadPublicKeyFromPEM(OTHER.publicSPKI)
	otherPriv = await loadPrivateKeyFromPEM(OTHER.privatePKCS8)
})

async function rejection(p: Promise<unknown>): Promise<unknown> {
	return p.then(
		() => undefined,
		(err: unknown) => err,
	)
}

function thrown(fn: () => void): unknown {
	try {
		fn()
	} catch (err) {
		return err
	}
	return undefined
}

describe('MemoryKeyStore', () => {
	it('satisfies both store interfaces and returns each partner its own keys', async () => {
		const store = new MemoryKeyStore()
		const handlers: HandlersKeyStore = store
		const client: ClientKeyStore = store
		store.register('partner-a', {
			partnerPublicKey: partnerPub,
			partnerPrivateKey: partnerPriv,
			boostxPublicKey: boostxPub,
		})
		store.register('partner-b', { partnerPublicKey: otherPub, partnerPrivateKey: otherPriv, boostxPublicKey: otherPub })

		expect(await handlers.partnerPublicKeys('partner-a')).toEqual([partnerPub])
		expect((await handlers.partnerPublicKeys('partner-a'))[0]).toBe(partnerPub)
		expect(await handlers.partnerPrivateKey('partner-a')).toBe(partnerPriv)
		expect(await handlers.boostxPublicKey('partner-a')).toBe(boostxPub)
		expect(await client.partnerPrivateKey('partner-b')).toBe(otherPriv)
		expect(await handlers.boostxPublicKey('partner-b')).toBe(otherPub)
	})

	it('throws unknown_partner for an id it does not serve', async () => {
		const store = new MemoryKeyStore()
		store.register('p', { partnerPublicKey: partnerPub })
		for (const lookup of [
			store.partnerPublicKeys('nope'),
			store.partnerPrivateKey('nope'),
			store.boostxPublicKey('nope'),
			store.partnerPublicKeys('constructor'),
			store.partnerPublicKeys('__proto__'),
		]) {
			const err = await rejection(lookup)
			expect(isBoostxError(err, 'unknown_partner')).toBe(true)
		}
		expect(await rejection(store.partnerPrivateKey('nope'))).toHaveProperty('message', 'unknown partner "nope"')
	})

	it('keeps a key list in order and keeps it from later changes to the caller array', async () => {
		const store = new MemoryKeyStore()
		const list = [otherPub, partnerPub]
		store.register('p', { partnerPublicKey: list })
		list.length = 0
		const keys = await store.partnerPublicKeys('p')
		expect(keys).toEqual([otherPub, partnerPub])
		expect(Object.isFrozen(keys)).toBe(true)
	})

	it('verifies a GID signed before a rotation with the key list', async () => {
		const store = new MemoryKeyStore()
		store.register('p', { partnerPublicKey: [otherPub, partnerPub] })
		const gid = await buildGID(partnerPriv, 'p', 'u', 'b')
		await expect(verifyGID(gid, await store.partnerPublicKeys('p'))).resolves.toBeUndefined()
	})

	it('errors only for the role a partial registration lacks', async () => {
		const store = new MemoryKeyStore()
		store.register('p', { partnerPrivateKey: partnerPriv })
		expect(await store.partnerPrivateKey('p')).toBe(partnerPriv)

		const pub = await rejection(store.partnerPublicKeys('p'))
		expect(isBoostxError(pub, 'invalid_public_key')).toBe(true)
		expect(pub).toHaveProperty('message', 'no partner public key for partner "p"')
		const bx = await rejection(store.boostxPublicKey('p'))
		expect(isBoostxError(bx, 'invalid_public_key')).toBe(true)
		expect(bx).toHaveProperty('message', 'no boostx public key for partner "p"')

		store.register('q', { boostxPublicKey: boostxPub })
		const priv = await rejection(store.partnerPrivateKey('q'))
		expect(isBoostxError(priv, 'invalid_private_key')).toBe(true)
		expect(priv).toHaveProperty('message', 'no partner private key for partner "q"')
	})

	it('reads a null role as left out, and still checks the roles given', async () => {
		const store = new MemoryKeyStore()
		store.register('p', { partnerPublicKey: null, partnerPrivateKey: partnerPriv, boostxPublicKey: null })
		expect(await store.partnerPrivateKey('p')).toBe(partnerPriv)
		expect(isBoostxError(await rejection(store.partnerPublicKeys('p')), 'invalid_public_key')).toBe(true)
		expect(isBoostxError(await rejection(store.boostxPublicKey('p')), 'invalid_public_key')).toBe(true)

		store.register('q', { partnerPublicKey: partnerPub, partnerPrivateKey: null, boostxPublicKey: boostxPub })
		expect(await store.partnerPublicKeys('q')).toEqual([partnerPub])
		expect(isBoostxError(await rejection(store.partnerPrivateKey('q')), 'invalid_private_key')).toBe(true)

		const err = thrown(() => store.register('q', { partnerPublicKey: null, boostxPublicKey: partnerPriv }))
		expect(isBoostxError(err, 'invalid_public_key')).toBe(true)
		expect(await store.partnerPublicKeys('q')).toEqual([partnerPub])
	})

	it('replaces a registration whole on re-register', async () => {
		const store = new MemoryKeyStore()
		store.register('p', { partnerPublicKey: otherPub, partnerPrivateKey: otherPriv })
		store.register('p', { partnerPublicKey: partnerPub })
		expect(await store.partnerPublicKeys('p')).toEqual([partnerPub])
		expect(isBoostxError(await rejection(store.partnerPrivateKey('p')), 'invalid_private_key')).toBe(true)
	})

	it('refuses an empty partner id', () => {
		const store = new MemoryKeyStore()
		const err = thrown(() => store.register('', { partnerPublicKey: partnerPub }))
		expect(isBoostxError(err, 'missing_claim')).toBe(true)
		expect(err).toHaveProperty('message', 'partner must not be empty')
	})

	it('refuses a key that does not fit its role and keeps the previous registration', async () => {
		const p384 = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign', 'verify'])
		const bare = await publicKeyWithoutUsages(PARTNER.publicSPKI)
		const store = new MemoryKeyStore()
		store.register('p', { partnerPublicKey: partnerPub })
		const cases: [Parameters<MemoryKeyStore['register']>[1], 'invalid_public_key' | 'invalid_private_key'][] = [
			[{ partnerPublicKey: partnerPriv }, 'invalid_public_key'],
			[{ partnerPublicKey: [partnerPub, partnerPriv] }, 'invalid_public_key'],
			[{ partnerPublicKey: [] }, 'invalid_public_key'],
			[{ boostxPublicKey: partnerPriv }, 'invalid_public_key'],
			[{ boostxPublicKey: p384.publicKey }, 'invalid_public_key'],
			[{ partnerPublicKey: [partnerPub, bare] }, 'invalid_public_key'],
			[{ boostxPublicKey: bare }, 'invalid_public_key'],
			[{ partnerPrivateKey: partnerPub }, 'invalid_private_key'],
			[{ partnerPrivateKey: p384.privateKey }, 'invalid_private_key'],
			[{ partnerPrivateKey: 'pem' as unknown as CryptoKeyLike }, 'invalid_private_key'],
		]
		for (const [keys, code] of cases) {
			expect(
				isBoostxError(
					thrown(() => store.register('p', { ...keys, partnerPublicKey: keys.partnerPublicKey ?? otherPub })),
					code,
				),
			).toBe(true)
		}
		expect(await store.partnerPublicKeys('p')).toEqual([partnerPub])
	})
})
