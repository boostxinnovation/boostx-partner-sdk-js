// Compact ES256 JWTs over Web Crypto, whose ECDSA signature is already the raw r || s form JWS requires.
// Internal: format failures throw plain Errors that each token's parser wraps in its own BoostxError.

import { decodeBase64url, encodeBase64url } from './base64url.js'
import { BoostxError } from './errors.js'
import { SIGN, checkPrivateKey, checkPublicKey, type CryptoKeyLike, type WebCryptoKey } from './keys.js'

const encoder = new TextEncoder()
// Strict UTF-8, keeping a byte order mark so that JSON.parse refuses it.
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
const HEADER = encodeBase64url(encoder.encode('{"alg":"ES256","typ":"JWT"}'))

export type Claims = Record<string, unknown>

export async function signJWT(claims: object, privateKey: CryptoKeyLike): Promise<string> {
	checkPrivateKey(privateKey)
	const input = `${HEADER}.${encodeBase64url(encoder.encode(JSON.stringify(claims)))}`
	let signature: ArrayBuffer
	try {
		signature = await crypto.subtle.sign(SIGN, privateKey as WebCryptoKey, encoder.encode(input))
	} catch (cause) {
		throw new BoostxError('invalid_private_key', 'invalid private key: cannot sign with it', { cause })
	}
	return `${input}.${encodeBase64url(new Uint8Array(signature))}`
}

/** Verifies the ES256 signature, then returns the payload object. */
export async function verifyJWT(token: string, publicKey: CryptoKeyLike): Promise<Claims> {
	checkPublicKey(publicKey)
	const [header, payload, signature] = splitJWT(token)
	const head = decodeJSONObject(header, 'header')
	const { alg } = head
	if (alg !== 'ES256') {
		const got = typeof alg === 'string' ? alg : alg === null ? 'null' : typeof alg
		throw new BoostxError('invalid_signature', `invalid token signature: expected ES256, got ${got}`)
	}
	// No extension is understood, so a crit member of any value leaves the signature unverifiable.
	if (Object.hasOwn(head, 'crit'))
		throw new BoostxError('invalid_signature', 'invalid token signature: crit is not supported')
	const sig = decodeBase64url(signature)
	if (sig === undefined || sig.length !== 64) {
		throw new BoostxError('invalid_signature', 'invalid token signature: not a 64-byte ES256 signature')
	}
	let valid: boolean
	try {
		valid = await crypto.subtle.verify(SIGN, publicKey as WebCryptoKey, sig, encoder.encode(`${header}.${payload}`))
	} catch (cause) {
		throw new BoostxError('invalid_public_key', 'invalid public key: cannot verify with it', { cause })
	}
	if (!valid) throw new BoostxError('invalid_signature', 'invalid token signature')
	return decodeJSONObject(payload, 'payload')
}

/** Returns the payload without verifying anything. Only for choosing the key to verify with. */
export function decodeJWTPayload(token: string): Claims {
	return decodeJSONObject(splitJWT(token)[1], 'payload')
}

function splitJWT(token: string): [string, string, string] {
	const parts = typeof token === 'string' ? token.split('.') : []
	if (parts.length !== 3) throw new Error('invalid token format')
	return parts as [string, string, string]
}

function decodeJSONObject(segment: string, what: string): Claims {
	const bytes = decodeBase64url(segment)
	if (bytes === undefined) throw new Error(`invalid token ${what}: not base64url`)
	let text: string
	let value: unknown
	try {
		text = decoder.decode(bytes)
		value = JSON.parse(text)
	} catch {
		throw new Error(`invalid token ${what}: not JSON`)
	}
	if (hasLoneSurrogate(text)) throw new Error(`invalid token ${what}: not well-formed Unicode`)
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new Error(`invalid token ${what}: not a JSON object`)
	}
	return value as Claims
}

// Whether valid JSON text escapes a surrogate that is not a high one directly followed by an escaped low one. The bytes
// being strict UTF-8, that is the only way in for a lone surrogate, including one in a member a repeated name replaces.
function hasLoneSurrogate(text: string): boolean {
	let highEnd = -1 // where the pending high-surrogate escape ends
	for (const { 1: hex, index } of text.matchAll(/\\(?:u([0-9A-Fa-f]{4})|[^u])/g)) {
		const unit = hex === undefined ? -1 : parseInt(hex, 16)
		const low = unit >= 0xdc00 && unit <= 0xdfff
		if (highEnd >= 0) {
			if (!low || index !== highEnd) return true
			highEnd = -1
		} else if (low) {
			return true
		} else if (unit >= 0xd800 && unit <= 0xdbff) {
			highEnd = index + 6
		}
	}
	return highEnd >= 0
}
