import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { isBoostxError } from '../../src/errors.js'
import { signJWT, verifyJWT } from '../../src/jwt.js'
import { loadPrivateKeyFromFile, loadPublicKeyFromFile } from '../../src/node/keys.js'
import { PARTNER } from '../fixtures.js'

let dir: string

beforeAll(async () => {
	dir = await mkdtemp(join(tmpdir(), 'boostx-keys-'))
	await writeFile(join(dir, 'private.pem'), PARTNER.privatePKCS8)
	await writeFile(join(dir, 'sec1.pem'), PARTNER.privateSEC1)
	await writeFile(join(dir, 'public.pem'), PARTNER.publicSPKI)
})

afterAll(async () => {
	await rm(dir, { recursive: true, force: true })
})

describe('loadPrivateKeyFromFile / loadPublicKeyFromFile', () => {
	it('loads a key pair from PEM files', async () => {
		const pub = await loadPublicKeyFromFile(join(dir, 'public.pem'))
		for (const file of ['private.pem', 'sec1.pem']) {
			const token = await signJWT({ iat: 1 }, await loadPrivateKeyFromFile(join(dir, file)))
			expect(await verifyJWT(token, pub)).toEqual({ iat: 1 })
		}
	})

	it('wraps a read failure in the key error, keeping the cause', async () => {
		const missing = join(dir, 'missing.pem')
		const priv = await loadPrivateKeyFromFile(missing).catch((e: unknown) => e)
		expect(isBoostxError(priv, 'invalid_private_key')).toBe(true)
		expect(priv).toHaveProperty('message', expect.stringMatching(/^invalid private key: ENOENT/))
		expect(priv).toHaveProperty('cause.code', 'ENOENT')

		const pub = await loadPublicKeyFromFile(missing).catch((e: unknown) => e)
		expect(isBoostxError(pub, 'invalid_public_key')).toBe(true)
		expect(pub).toHaveProperty('cause.code', 'ENOENT')
	})

	it('refuses a file holding the wrong kind of key', async () => {
		const err = await loadPublicKeyFromFile(join(dir, 'private.pem')).catch((e: unknown) => e)
		expect(isBoostxError(err, 'invalid_public_key')).toBe(true)
	})
})
