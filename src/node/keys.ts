import { readFile } from 'node:fs/promises'

import { BoostxError } from '../errors.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from '../keys.js'

/** Reads an ECDSA P-256 private key from a PEM file: PKCS#8 or SEC1. */
export async function loadPrivateKeyFromFile(path: string): Promise<CryptoKeyLike> {
	return loadPrivateKeyFromPEM(await read(path, 'invalid_private_key', 'invalid private key'))
}

/** Reads an ECDSA P-256 public key from an SPKI PEM file. */
export async function loadPublicKeyFromFile(path: string): Promise<CryptoKeyLike> {
	return loadPublicKeyFromPEM(await read(path, 'invalid_public_key', 'invalid public key'))
}

async function read(
	path: string,
	code: 'invalid_private_key' | 'invalid_public_key',
	what: string,
): Promise<Uint8Array> {
	try {
		return await readFile(path)
	} catch (cause) {
		throw new BoostxError(code, `${what}: ${cause instanceof Error ? cause.message : String(cause)}`, { cause })
	}
}
