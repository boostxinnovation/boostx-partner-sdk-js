import { decodeBase64, decodeBase64url } from './base64url.js'
import { BoostxError } from './errors.js'

const P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const
/** ES256 sign/verify parameters. Internal. */
export const SIGN = { name: 'ECDSA', hash: 'SHA-256' } as const
/** The key type `crypto.subtle` takes, for casting a {@link CryptoKeyLike}. Internal. */
export type WebCryptoKey = Parameters<typeof crypto.subtle.sign>[1]

/**
 * Whether `key` is an ECDSA P-256 key of the given type with its role's usage, `verify` or `sign`: Web Crypto signs
 * ES256 with a key on any curve. Internal.
 */
export function isP256(key: unknown, type: 'public' | 'private'): boolean {
	const k = key as { type?: unknown; algorithm?: { name?: unknown; namedCurve?: unknown }; usages?: unknown } | null
	return (
		typeof k === 'object' &&
		k !== null &&
		k.type === type &&
		k.algorithm?.name === 'ECDSA' &&
		k.algorithm.namedCurve === 'P-256' &&
		Array.isArray(k.usages) &&
		k.usages.includes(type === 'public' ? 'verify' : 'sign')
	)
}

/** Throws `invalid_private_key` unless `key` is an ECDSA P-256 private key: every signer checks it first. Internal. */
export function checkPrivateKey(key: unknown): void {
	if (!isP256(key, 'private'))
		throw new BoostxError('invalid_private_key', 'invalid private key: not an ECDSA P-256 private key that can sign')
}

/** Throws `invalid_public_key` unless `key` is an ECDSA P-256 public key: every verifier checks it first. Internal. */
export function checkPublicKey(key: unknown): void {
	if (!isP256(key, 'public'))
		throw new BoostxError('invalid_public_key', 'invalid public key: not an ECDSA P-256 public key that can verify')
}

/**
 * A Web Crypto `CryptoKey`. Typed structurally so these declarations need neither the DOM library
 * nor one runtime's types; any `CryptoKey` is assignable to it.
 */
export interface CryptoKeyLike {
	readonly type: string
	readonly extractable: boolean
	readonly algorithm: object
	readonly usages: readonly string[]
}

// DER AlgorithmIdentifier { id-ecPublicKey, prime256v1 }: the fixed part of a P-256 PKCS#8 PrivateKeyInfo.
const P256_ALGORITHM = [
	0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07,
]

function derLength(n: number): number[] {
	return n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]
}

function bytesEqual(a: Uint8Array, b: readonly number[]): boolean {
	return a.length === b.length && b.every((x, i) => a[i] === x)
}

// [0] { namedCurve prime256v1 }: the curve OID of P256_ALGORITHM, as SEC1 parameters.
const SEC1_P256_PARAMETERS = [0xa0, 0x0a, ...P256_ALGORITHM.slice(11)]
// [1] { BIT STRING, no unused bits, 0x04 }: the start of an embedded uncompressed P-256 point, 64 octets follow.
const UNCOMPRESSED_PUBLIC_KEY = [0xa1, 0x44, 0x03, 0x42, 0x00, 0x04]

interface DerElement {
	tag: number
	start: number
	end: number
}

// The DER element at `at`, which must end by `limit`: its tag and the [start, end) of its content. The length must be
// definite and minimal.
function derElement(der: Uint8Array, at: number, limit: number): DerElement | undefined {
	const tag = der[at]
	const first = der[at + 1]
	if (tag === undefined || first === undefined || first === 0x80 || first > 0x83) return undefined
	let start = at + 2
	let length = first
	if (first > 0x80) {
		const octets = first - 0x80
		length = 0
		for (let i = 0; i < octets; i++) length = length * 0x100 + (der[start + i] ?? 0)
		start += octets
		if (length < 0x80 || length < 0x100 ** (octets - 1)) return undefined
	}
	return start + length <= limit ? { tag, start, end: start + length } : undefined
}

// A PKCS#8 PrivateKeyInfo spanning all of `der`: SEQUENCE { INTEGER 0, AlgorithmIdentifier for P-256, OCTET STRING
// privateKey, [0] attributes OPTIONAL }, the attributes not read. Returns the privateKey content.
function readPrivateKeyInfo(der: Uint8Array): DerElement | undefined {
	const seq = derElement(der, 0, der.length)
	if (seq?.tag !== 0x30 || seq.end !== der.length) return undefined
	if (!bytesEqual(der.subarray(seq.start, seq.start + 24), [0x02, 0x01, 0x00, ...P256_ALGORITHM])) return undefined
	const key = derElement(der, seq.start + 24, seq.end)
	if (key?.tag !== 0x04) return undefined
	const attributes = key.end < seq.end ? derElement(der, key.end, seq.end) : undefined
	return (attributes?.tag === 0xa0 ? attributes.end : key.end) === seq.end ? key : undefined
}

interface ECPrivateKey {
	scalar: Uint8Array
	parameters: boolean
	publicKey: Uint8Array | undefined
}

// A SEC1 ECPrivateKey spanning exactly [at, limit): SEQUENCE { INTEGER 1, OCTET STRING scalar, [0] parameters
// OPTIONAL, [1] public key OPTIONAL }, in this order and nothing else, the parameters naming P-256.
function readECPrivateKey(der: Uint8Array, at: number, limit: number): ECPrivateKey | undefined {
	const seq = derElement(der, at, limit)
	if (seq?.tag !== 0x30 || seq.end !== limit) return undefined
	const version = derElement(der, seq.start, seq.end)
	if (version?.tag !== 0x02 || !bytesEqual(der.subarray(version.start, version.end), [1])) return undefined
	const scalar = derElement(der, version.end, seq.end)
	if (scalar?.tag !== 0x04) return undefined
	let next = scalar.end
	const field = (tag: number) => {
		const e = next < seq.end ? derElement(der, next, seq.end) : undefined
		if (e?.tag !== tag) return undefined
		const bytes = der.subarray(next, e.end)
		next = e.end
		return bytes
	}
	const parameters = field(0xa0)
	const publicKey = field(0xa1)
	if (next !== seq.end || (parameters && !bytesEqual(parameters, SEC1_P256_PARAMETERS))) return undefined
	return { scalar: der.subarray(scalar.start, scalar.end), parameters: parameters !== undefined, publicKey }
}

// The PrivateKeyInfo Web Crypto imports: the scalar alone, as 32 octets, so that what the platform reads never
// depends on how it parses the rest. Undefined when the scalar has more than 32 significant octets.
function scalarPkcs8(scalar: Uint8Array): Uint8Array | undefined {
	let first = 0
	while (scalar[first] === 0) first++
	const significant = scalar.subarray(first)
	if (significant.length > 32) return undefined
	const sec1 = [0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20, ...new Uint8Array(32 - significant.length), ...significant]
	const body = [0x02, 0x01, 0x00, ...P256_ALGORITHM, 0x04, ...derLength(sec1.length), ...sec1]
	return new Uint8Array([0x30, ...derLength(body.length), ...body])
}

interface PemBlock {
	label: string
	der: Uint8Array
}

// Returns the block that opens at the earliest BEGIN line of one of `labels` and runs to the first END line of the
// same label; text around it, on the same line or not, is ignored. A literal "\n" or "\r\n" is read as a newline:
// keys kept in environment variables often arrive that way. Only RFC 7468 whitespace is removed from the body.
function readPemBlock(
	pem: unknown,
	labels: readonly string[],
	code: 'invalid_private_key' | 'invalid_public_key',
): PemBlock {
	const fail = (detail: string) =>
		new BoostxError(code, `invalid ${code === 'invalid_private_key' ? 'private' : 'public'} key: ${detail}`)
	if (typeof pem !== 'string' && !(pem instanceof Uint8Array)) throw fail('expected PEM text or bytes')
	const text = (typeof pem === 'string' ? pem : new TextDecoder().decode(pem)).replace(/\\r\\n|\\n/g, '\n')
	let label: string | undefined
	let begin = -1
	for (const l of labels) {
		const at = text.indexOf(`-----BEGIN ${l}-----`)
		if (at !== -1 && (begin === -1 || at < begin)) [label, begin] = [l, at]
	}
	if (label === undefined) {
		const others = Array.from(text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----/g), (m) => m[1] ?? '')
		if (code === 'invalid_private_key' && others.includes('ENCRYPTED PRIVATE KEY')) {
			throw fail('an ENCRYPTED PRIVATE KEY is not supported, decrypt it first')
		}
		if (others.length === 0) throw fail('no PEM block')
		throw fail(`expected a ${labels.join(' or ')} PEM block, got ${others.join(', ')}`)
	}
	const start = begin + `-----BEGIN ${label}-----`.length
	const end = text.indexOf(`-----END ${label}-----`, start)
	if (end === -1) throw fail(`the ${label} PEM block has no END line`)
	const body = text.slice(start, end)
	if (/Proc-Type: *4, *ENCRYPTED/.test(body)) throw fail(`an encrypted ${label} is not supported, decrypt it first`)
	const der = decodeBase64(body.replace(/[\t\n\v\f\r ]+/g, ''))
	if (der === undefined) throw fail(`the ${label} PEM body is not base64`)
	return { label, der }
}

/** Loads an ECDSA P-256 private key from PEM: PKCS#8 (`BEGIN PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`). */
export async function loadPrivateKeyFromPEM(pem: string | Uint8Array): Promise<CryptoKeyLike> {
	const block = readPemBlock(pem, ['PRIVATE KEY', 'EC PRIVATE KEY'], 'invalid_private_key')
	const fail = (detail: string, cause?: unknown) =>
		new BoostxError('invalid_private_key', `invalid private key: ${detail}`, { cause })
	const sec1 = block.label === 'EC PRIVATE KEY' ? { start: 0, end: block.der.length } : readPrivateKeyInfo(block.der)
	if (sec1 === undefined) throw fail('a PRIVATE KEY must be a PKCS#8 PrivateKeyInfo for P-256')
	const ec = readECPrivateKey(block.der, sec1.start, sec1.end)
	if (ec === undefined) throw fail('malformed ECPrivateKey')
	if (block.label === 'EC PRIVATE KEY' && !ec.parameters) throw fail('an EC PRIVATE KEY must name the P-256 curve')
	const uncompressed = ec.publicKey?.length === 70 && bytesEqual(ec.publicKey.subarray(0, 6), UNCOMPRESSED_PUBLIC_KEY)
	if (ec.publicKey && !uncompressed) throw fail('the embedded public key must be an uncompressed point')
	const pkcs8 = scalarPkcs8(ec.scalar)
	if (pkcs8 === undefined) throw fail('the scalar is longer than 32 octets')
	let key: WebCryptoKey
	try {
		key = await crypto.subtle.importKey('pkcs8', pkcs8, P256, ec.publicKey !== undefined, ['sign'])
	} catch (cause) {
		throw fail('not an ECDSA P-256 key', cause)
	}
	if (ec.publicKey === undefined) return key
	// The embedded point is compared here because the platform never sees it.
	const { x = '', y = '' } = await crypto.subtle.exportKey('jwk', key)
	const point = [...(decodeBase64url(x) ?? []), ...(decodeBase64url(y) ?? [])]
	if (!bytesEqual(ec.publicKey.subarray(6), point))
		throw fail("the embedded public key is not the private key's own point")
	return await crypto.subtle.importKey('pkcs8', pkcs8, P256, false, ['sign'])
}

/** Loads an ECDSA P-256 public key from SPKI PEM (`BEGIN PUBLIC KEY`) with an uncompressed point. */
export async function loadPublicKeyFromPEM(pem: string | Uint8Array): Promise<CryptoKeyLike> {
	const block = readPemBlock(pem, ['PUBLIC KEY'], 'invalid_public_key')
	// A P-256 SPKI with an uncompressed point (0x04 || X || Y) is 91 bytes, the point starting at offset 26 after the
	// BIT STRING's unused-bits octet, which must be 0: Node.js's import would clear declared unused bits and accept.
	if (block.der.length !== 91 || block.der[25] !== 0x00 || block.der[26] !== 0x04) {
		throw new BoostxError('invalid_public_key', 'invalid public key: not an ECDSA P-256 key with an uncompressed point')
	}
	try {
		return await crypto.subtle.importKey('spki', block.der, P256, false, ['verify'])
	} catch (cause) {
		throw new BoostxError('invalid_public_key', 'invalid public key: not an ECDSA P-256 key', { cause })
	}
}
