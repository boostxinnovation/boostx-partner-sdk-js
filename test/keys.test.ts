import { describe, expect, it } from 'vitest'

import { isBoostxError } from '../src/errors.js'
import { signJWT, verifyJWT } from '../src/jwt.js'
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM } from '../src/keys.js'
import { OTHER, P384_PRIVATE_PKCS8, PARTNER } from './fixtures.js'

// `openssl ecparam -name prime256v1 -genkey` (no -noout): SEC1 behind an "EC PARAMETERS" block.
const SEC1_WITH_PARAMS = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHJ4yncjx1jf3cgmBODG/CsX2DwfLS2zk3AOA27OiIFKoAoGCCqGSM49
AwEHoUQDQgAEBxB/Rm+Is84hNP4jMkMg7rZaPujc5xovAOo0UqAXbZgNLz5vpKo+
GtKA05qGEsnoaD56UQRmuaiM/r6HZmVFZA==
-----END EC PRIVATE KEY-----
`
const SEC1_WITH_PARAMS_PUBLIC = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBxB/Rm+Is84hNP4jMkMg7rZaPujc
5xovAOo0UqAXbZgNLz5vpKo+GtKA05qGEsnoaD56UQRmuaiM/r6HZmVFZA==
-----END PUBLIC KEY-----
`
// `openssl ecparam -name secp384r1 -genkey -noout` and its `openssl ec -pubout`.
const P384_PRIVATE_SEC1 = `-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCp3kZpEi8yJEXQEVXjkYbenpo23i6vheELywfO9PfHLxpg2VZ5GA3S
fDmBx2drajqgBwYFK4EEACKhZANiAATT4gqFPVz+r2snURUhH/yUmA485Y+HnRa6
cdLSzu3/vntK8qvZOaReBY1CdO5oluUqSSKZ2dijLZFJ95i5wa2s69OAgWKBdtAn
b71fK14Whqfz9Qg+ZSBGETQCYUaJvsU=
-----END EC PRIVATE KEY-----
`
const P384_PUBLIC = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE0+IKhT1c/q9rJ1EVIR/8lJgOPOWPh50W
unHS0s7t/757SvKr2TmkXgWNQnTuaJblKkkimdnYoy2RSfeYucGtrOvTgIFigXbQ
J2+9XyteFoan8/UIPmUgRhE0AmFGib7F
-----END PUBLIC KEY-----
`
// Throwaway P-256 keys encrypted with the password "x": `openssl pkcs8 -topk8 -v2 aes-256-cbc`, `openssl ec -aes256`.
const ENCRYPTED_PKCS8 = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHeMEkGCSqGSIb3DQEFDTA8MBsGCSqGSIb3DQEFDDAOBAgITxsAjF4PAgICCAAw
HQYJYIZIAWUDBAEqBBBnISWRmNCeY1FG/la8bY/cBIGQi+0/eOm9+IUWhRW/17kG
uxq09N1bY0NeH04rkZlt4oH/H4k1X/StK+clB+1/zBTVHKZEAAiA31BNDqoRODzH
k14nWRogDFZ8gEXDsQ2B7RdNxrzvMT8VlGWZwScZgO5bcCqyhe9xNZ6ryXlXnGzp
+mFPaHsoopPUzMJg98SochGeAemTyB8hQ7akjYunSy2Y
-----END ENCRYPTED PRIVATE KEY-----
`
const ENCRYPTED_SEC1 = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,3D3748D93892E25185AF43B87AC832EA

uCkOa/aHG9fv/8w7xp93ekB2/DTUWm9Aou16wgpxMj0UBvqKBiDJ4WzSBCIPmjgt
FjCrQsOF6iZ1nNkZR+1bN3NqKhEWKhVpb/LBfvODBMhw700OVwOt+ICGvpMOVquY
3dpR0ftcU4CWXpibVgxTuyEIDv0xV1BHoXpx22n86b4=
-----END EC PRIVATE KEY-----
`

// PARTNER's public key with its point compressed: `openssl ec -pubin -pubout -conv_form compressed`.
const COMPRESSED_PUBLIC = `-----BEGIN PUBLIC KEY-----
MDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgACefDJRjf/8FsMFyIrw1O4j8w6/kue
ZtgNwdZsi7xgyGA=
-----END PUBLIC KEY-----
`
// PARTNER's SEC1 key without its [0] curve parameters, without its [1] public key, and naming secp256k1.
const SEC1_NO_PARAMS = `-----BEGIN EC PRIVATE KEY-----
MGsCAQEEILFG9daiaywXJGZd5NdPIutwERKmbLuoWWkPYYQizQpioUQDQgAEefDJ
Rjf/8FsMFyIrw1O4j8w6/kueZtgNwdZsi7xgyGDpJiOWTYr9cXKmrvnHMb0XNPMr
EjcoUVFwMHCqaUVAGg==
-----END EC PRIVATE KEY-----
`
const SEC1_NO_PUBLIC = `-----BEGIN EC PRIVATE KEY-----
MDECAQEEILFG9daiaywXJGZd5NdPIutwERKmbLuoWWkPYYQizQpioAoGCCqGSM49
AwEH
-----END EC PRIVATE KEY-----
`
const SEC1_SECP256K1 = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEILFG9daiaywXJGZd5NdPIutwERKmbLuoWWkPYYQizQpioAcGBSuBBAAK
oUQDQgAEefDJRjf/8FsMFyIrw1O4j8w6/kueZtgNwdZsi7xgyGDpJiOWTYr9cXKm
rvnHMb0XNPMrEjcoUVFwMHCqaUVAGg==
-----END EC PRIVATE KEY-----
`

// One DER element whose content is the concatenation of `content`.
function tlv(tag: number, ...content: (readonly number[])[]): number[] {
	const c = content.flat()
	return [tag, ...(c.length < 0x80 ? [c.length] : [0x81, c.length]), ...c]
}
const P256_ALGORITHM = [
	0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07,
]
const P256_PARAMETERS = tlv(0xa0, P256_ALGORITHM.slice(11))
const der = (pem: string) => Uint8Array.from(atob(pem.replace(/-----[^-]+-----|\s/g, '')), (c) => c.charCodeAt(0))
const pem = (label: string, bytes: number[]) =>
	`-----BEGIN ${label}-----\n${btoa(String.fromCharCode(...bytes))}\n-----END ${label}-----\n`
// A version 1 ECPrivateKey holding `scalar` and then `fields`.
const ecKey = (scalar: number[], ...fields: (readonly number[])[]) =>
	tlv(0x30, [0x02, 0x01, 0x01], tlv(0x04, scalar), ...fields)
// A version 0 P-256 PrivateKeyInfo holding `sec1` and then `after`.
const privateKeyInfo = (sec1: number[], ...after: number[][]) =>
	tlv(0x30, [0x02, 0x01, 0x00], P256_ALGORITHM, tlv(0x04, sec1), ...after)
const embeddedPublicKey = (point: number[]) => tlv(0xa1, tlv(0x03, [0], point))
// PARTNER's SEC1 key: 30 77 02 01 01 04 20 <scalar> [0] parameters [1] { BIT STRING 00 04 || X || Y }.
function partnerParts(): { scalar: number[]; x: number[]; y: number[] } {
	const sec1 = [...der(PARTNER.privateSEC1)]
	return { scalar: sec1.slice(7, 39), x: sec1.slice(-64, -32), y: sec1.slice(-32) }
}

async function rejection(p: Promise<unknown>): Promise<unknown> {
	return p.then(
		() => undefined,
		(err: unknown) => err,
	)
}

async function expectPair(privatePEM: string | Uint8Array, publicPEM: string | Uint8Array): Promise<void> {
	const token = await signJWT({ iat: 1 }, await loadPrivateKeyFromPEM(privatePEM))
	expect(await verifyJWT(token, await loadPublicKeyFromPEM(publicPEM))).toEqual({ iat: 1 })
}

describe('loadPrivateKeyFromPEM / loadPublicKeyFromPEM', () => {
	it('loads PKCS#8 and SEC1 private keys that sign for the SPKI public key', async () => {
		const priv = await loadPrivateKeyFromPEM(PARTNER.privatePKCS8)
		expect(priv.type).toBe('private')
		expect(priv.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' })
		expect([priv.extractable, (await loadPrivateKeyFromPEM(SEC1_NO_PUBLIC)).extractable]).toEqual([false, false])
		expect((await loadPublicKeyFromPEM(PARTNER.publicSPKI)).type).toBe('public')
		await expectPair(PARTNER.privatePKCS8, PARTNER.publicSPKI)
		await expectPair(PARTNER.privateSEC1, PARTNER.publicSPKI)
	})

	it('skips an "EC PARAMETERS" block before the SEC1 key', async () => {
		await expectPair(SEC1_WITH_PARAMS, SEC1_WITH_PARAMS_PUBLIC)
	})

	it('reads literal "\\n" sequences as newlines, as environment variables carry them', async () => {
		const flat = (pem: string) => pem.replace(/\n/g, '\\n')
		expect(flat(PARTNER.privatePKCS8)).not.toContain('\n')
		await expectPair(flat(PARTNER.privatePKCS8), flat(PARTNER.publicSPKI))
		await expectPair(flat(PARTNER.privateSEC1), flat(PARTNER.publicSPKI))
	})

	it('reads literal "\\r\\n" sequences as newlines too', async () => {
		const flat = (pem: string) => pem.replace(/\n/g, '\\r\\n')
		expect(flat(PARTNER.privatePKCS8)).not.toMatch(/[\r\n]/)
		await expectPair(flat(PARTNER.privatePKCS8), flat(PARTNER.publicSPKI))
		await expectPair(flat(PARTNER.privateSEC1), flat(PARTNER.publicSPKI))
	})

	it('accepts CRLF line endings and Uint8Array input', async () => {
		const crlf = (pem: string) => pem.replace(/\n/g, '\r\n')
		await expectPair(crlf(PARTNER.privateSEC1), crlf(PARTNER.publicSPKI))
		const bytes = (pem: string) => new TextEncoder().encode(pem)
		await expectPair(bytes(PARTNER.privatePKCS8), bytes(PARTNER.publicSPKI))
	})

	it('reads the block by its markers alone: text around it, indentation and a one-line body', async () => {
		const variants = (pem: string) => [
			`PARTNER_KEY=${pem}`,
			`# partner key\n\n${pem}trailing text`,
			pem.replace(/^/gm, '\t  '),
			pem.replace(/\n/g, ''),
			pem.replace(/\n(?!-)/g, '\v\f \n'),
			`-----BEGIN NOTE-----\n${pem}-----END NOTE-----\n`,
		]
		const pub = variants(PARTNER.publicSPKI)
		for (const [i, priv] of variants(PARTNER.privatePKCS8).entries()) await expectPair(priv, pub[i]!)
		for (const [i, priv] of variants(PARTNER.privateSEC1).entries()) await expectPair(priv, pub[i]!)
	})

	it('uses the earliest block with a private key label', async () => {
		await expectPair(PARTNER.privateSEC1 + OTHER.privatePKCS8, PARTNER.publicSPKI)
		await expectPair(OTHER.privatePKCS8 + PARTNER.privateSEC1, OTHER.publicSPKI)
	})

	it('removes only RFC 7468 whitespace from the body, and needs padded base64', async () => {
		for (const c of [0xa0, 0x2028, 0xfeff, 0x85]) {
			const pem = PARTNER.publicSPKI.replace('\nZtgN', `\n${String.fromCharCode(c)}ZtgN`)
			expect(isBoostxError(await rejection(loadPublicKeyFromPEM(pem)), 'invalid_public_key'), c.toString(16)).toBe(true)
		}
		const unpadded = PARTNER.publicSPKI.replace('Gg==', 'Gg')
		expect(isBoostxError(await rejection(loadPublicKeyFromPEM(unpadded)), 'invalid_public_key')).toBe(true)
	})

	it('refuses a public key with a compressed point', async () => {
		expect(isBoostxError(await rejection(loadPublicKeyFromPEM(COMPRESSED_PUBLIC)), 'invalid_public_key')).toBe(true)
	})

	it('refuses a public key whose BIT STRING declares unused bits, even bits that are already zero', async () => {
		const spki = [...der(PARTNER.publicSPKI)]
		expect(spki[90]! & 1).toBe(0) // Y is even, so the point is unchanged with its last bit declared unused
		spki[25] = 1
		const pemText = pem('PUBLIC KEY', spki)
		expect(isBoostxError(await rejection(loadPublicKeyFromPEM(pemText)), 'invalid_public_key')).toBe(true)
	})

	it('refuses a public key whose point is off the curve, the point at infinity or out of range', async () => {
		const der = Uint8Array.from(atob(PARTNER.publicSPKI.replace(/-----[^-]+-----|\s/g, '')), (c) => c.charCodeAt(0))
		const P = [
			0xff,
			0xff,
			0xff,
			0xff,
			0,
			0,
			0,
			1,
			...new Array<number>(12).fill(0),
			...new Array<number>(12).fill(0xff),
		]
		for (const [name, x, y] of [
			['(1, 1)', [...new Array<number>(31).fill(0), 1], [...new Array<number>(31).fill(0), 1]],
			['(0, 0)', new Array<number>(32).fill(0), new Array<number>(32).fill(0)],
			['x = p', P, [...der.slice(59)]],
		] as const) {
			const bad = Uint8Array.from([...der.slice(0, 27), ...x, ...y])
			const pem = `-----BEGIN PUBLIC KEY-----\n${btoa(String.fromCharCode(...bad))}\n-----END PUBLIC KEY-----\n`
			expect(isBoostxError(await rejection(loadPublicKeyFromPEM(pem)), 'invalid_public_key'), name).toBe(true)
		}
	})

	it('needs the P-256 curve parameters in a SEC1 key, but not its public key', async () => {
		for (const pem of [SEC1_NO_PARAMS, SEC1_SECP256K1]) {
			expect(isBoostxError(await rejection(loadPrivateKeyFromPEM(pem)), 'invalid_private_key')).toBe(true)
		}
		await expectPair(SEC1_NO_PUBLIC, PARTNER.publicSPKI)
	})

	it("loads a private key only when its embedded public key is a BIT STRING of the scalar's own uncompressed point", async () => {
		const { scalar, x, y } = partnerParts()
		const own = [0x04, ...x, ...y]
		const forms = (field: number[]) => [
			['SEC1', pem('EC PRIVATE KEY', ecKey(scalar, P256_PARAMETERS, field))],
			['PKCS#8', pem('PRIVATE KEY', privateKeyInfo(ecKey(scalar, field)))],
		]
		for (const field of [embeddedPublicKey(own), []]) {
			for (const [, text] of forms(field)) await expectPair(text!, PARTNER.publicSPKI)
		}

		const other = [...der(OTHER.publicSPKI).slice(26)]
		const uncompressed = 'the embedded public key must be an uncompressed point'
		const notOwn = "the embedded public key is not the private key's own point"
		for (const [name, field, message] of [
			["another key's point", embeddedPublicKey(other), notOwn],
			['off the curve', embeddedPublicKey([...own.slice(0, 64), own[64]! ^ 1]), notOwn],
			['compressed', embeddedPublicKey([0x02 | (y[31]! & 1), ...x]), uncompressed],
			['hybrid', embeddedPublicKey([0x06 | (y[31]! & 1), ...x, ...y]), uncompressed],
			['point at infinity', embeddedPublicKey([0]), uncompressed],
			['no 0x04 prefix', embeddedPublicKey([...x, ...y]), uncompressed],
			['66 octets', embeddedPublicKey([...own, 0]), uncompressed],
			['empty BIT STRING', tlv(0xa1, tlv(0x03)), uncompressed],
			['one unused bit', tlv(0xa1, tlv(0x03, [1], own)), uncompressed],
			['OCTET STRING', tlv(0xa1, tlv(0x04, other)), uncompressed],
			['constructed BIT STRING', tlv(0xa1, tlv(0x23, tlv(0x03, [0], other))), uncompressed],
			['implicit [1]', tlv(0x81, [0], other), 'malformed ECPrivateKey'],
		] as const) {
			for (const [form, text] of forms([...field])) {
				const err = await rejection(loadPrivateKeyFromPEM(text!))
				expect(isBoostxError(err, 'invalid_private_key'), `${form}, ${name}`).toBe(true)
				expect((err as Error).message, `${form}, ${name}`).toBe(`invalid private key: ${message}`)
			}
		}
	})

	it('loads a private key only when its DER is exactly the structure its label names', async () => {
		const { scalar, x, y } = partnerParts()
		const own = embeddedPublicKey([0x04, ...x, ...y])
		const sec1 = ecKey(scalar, P256_PARAMETERS, own)
		const inner = ecKey(scalar, own)
		const info = (version: number, algorithm: number[], key: number[], ...after: number[][]) =>
			tlv(0x30, [0x02, 0x01, version], algorithm, tlv(0x04, key), ...after)
		const idECPublicKey = tlv(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
		const withScalar = (s: number[]) => tlv(0x30, [0x02, 0x01, 0x01], tlv(0x04, s), P256_PARAMETERS, own)

		for (const [name, label, bytes] of [
			['SEC1', 'EC PRIVATE KEY', sec1],
			['PKCS#8 with attributes', 'PRIVATE KEY', privateKeyInfo(inner, tlv(0xa0))],
			['PKCS#8 with inner P-256 [0]', 'PRIVATE KEY', privateKeyInfo(sec1)],
			['scalar with leading zero octets', 'EC PRIVATE KEY', withScalar([0, 0, ...scalar])],
		] as const) {
			await expectPair(pem(label, [...bytes]), PARTNER.publicSPKI).catch((err: unknown) => {
				throw new Error(name, { cause: err })
			})
		}
		for (const [name, label, bytes] of [
			['SEC1, octets after it', 'EC PRIVATE KEY', [...sec1, 0, 0]],
			['SEC1, non-minimal length', 'EC PRIVATE KEY', [0x30, 0x81, ...sec1.slice(1)]],
			['SEC1, version 2', 'EC PRIVATE KEY', tlv(0x30, [0x02, 0x01, 0x02], tlv(0x04, scalar), P256_PARAMETERS, own)],
			['SEC1, [0] twice', 'EC PRIVATE KEY', ecKey(scalar, P256_PARAMETERS, P256_PARAMETERS, own)],
			['SEC1, [1] twice', 'EC PRIVATE KEY', ecKey(scalar, P256_PARAMETERS, own, own)],
			['SEC1, [0] after [1]', 'EC PRIVATE KEY', ecKey(scalar, own, P256_PARAMETERS)],
			['SEC1, [2] after [1]', 'EC PRIVATE KEY', ecKey(scalar, P256_PARAMETERS, own, tlv(0xa2, [0x05, 0x00]))],
			['SEC1, 33 significant scalar octets', 'EC PRIVATE KEY', withScalar([1, ...scalar])],
			['PKCS#8, octets after it', 'PRIVATE KEY', [...privateKeyInfo(inner), 0, 0]],
			['PKCS#8, octets after the inner key', 'PRIVATE KEY', privateKeyInfo([...inner, 0, 0])],
			['PKCS#8 version 1', 'PRIVATE KEY', info(1, P256_ALGORITHM, inner)],
			[
				'PKCS#8 version 1, public key',
				'PRIVATE KEY',
				info(1, P256_ALGORITHM, inner, tlv(0x81, [0], [0x04, ...x, ...y])),
			],
			['PKCS#8 version 2', 'PRIVATE KEY', info(2, P256_ALGORITHM, inner)],
			['PKCS#8, public key after privateKey', 'PRIVATE KEY', privateKeyInfo(inner, tlv(0x81, [0], [0x04, ...x, ...y]))],
			['PKCS#8, element after attributes', 'PRIVATE KEY', privateKeyInfo(inner, tlv(0xa0), tlv(0xa1))],
			['PKCS#8, stray octet after privateKey', 'PRIVATE KEY', privateKeyInfo(inner, [0x05])],
			['PKCS#8, algorithm without curve', 'PRIVATE KEY', info(0, tlv(0x30, idECPublicKey), sec1)],
			['PKCS#8, algorithm with NULL', 'PRIVATE KEY', info(0, tlv(0x30, idECPublicKey, [0x05, 0x00]), sec1)],
			['PKCS#8, inner version 2', 'PRIVATE KEY', privateKeyInfo(tlv(0x30, [0x02, 0x01, 0x02], tlv(0x04, scalar), own))],
			[
				'PKCS#8, inner [0] naming P-384',
				'PRIVATE KEY',
				privateKeyInfo(ecKey(scalar, tlv(0xa0, tlv(0x06, [0x2b, 0x81, 0x04, 0x00, 0x22])), own)),
			],
			[
				'PKCS#8, inner explicit parameters',
				'PRIVATE KEY',
				privateKeyInfo(ecKey(scalar, tlv(0xa0, tlv(0x30, [0x02, 0x01, 0x01])), own)),
			],
		] as const) {
			expect(
				isBoostxError(await rejection(loadPrivateKeyFromPEM(pem(label, [...bytes]))), 'invalid_private_key'),
				name,
			).toBe(true)
		}
	})

	it('reads a PRIVATE KEY body only as PKCS#8, never as SEC1', async () => {
		const pem = PARTNER.privateSEC1.replaceAll('EC PRIVATE KEY', 'PRIVATE KEY')
		const err = await rejection(loadPrivateKeyFromPEM(pem))
		expect(isBoostxError(err, 'invalid_private_key')).toBe(true)
		expect((err as Error).message).toBe('invalid private key: a PRIVATE KEY must be a PKCS#8 PrivateKeyInfo for P-256')
	})

	it('refuses input that is neither text nor bytes with the key error', async () => {
		for (const pem of [null, 42, {}, ['pem'], true]) {
			const priv = await rejection(loadPrivateKeyFromPEM(pem as string))
			expect(isBoostxError(priv, 'invalid_private_key')).toBe(true)
			expect((priv as Error).message).toBe('invalid private key: expected PEM text or bytes')
			const pub = await rejection(loadPublicKeyFromPEM(pem as string))
			expect(isBoostxError(pub, 'invalid_public_key')).toBe(true)
			expect((pub as Error).message).toBe('invalid public key: expected PEM text or bytes')
		}
	})

	it('refuses P-384 keys', async () => {
		for (const pem of [P384_PRIVATE_PKCS8, P384_PRIVATE_SEC1]) {
			expect(isBoostxError(await rejection(loadPrivateKeyFromPEM(pem)), 'invalid_private_key')).toBe(true)
		}
		expect(isBoostxError(await rejection(loadPublicKeyFromPEM(P384_PUBLIC)), 'invalid_public_key')).toBe(true)
	})

	it('refuses a public key as private and a private key as public', async () => {
		expect(isBoostxError(await rejection(loadPrivateKeyFromPEM(PARTNER.publicSPKI)), 'invalid_private_key')).toBe(true)
		for (const pem of [PARTNER.privatePKCS8, PARTNER.privateSEC1]) {
			expect(isBoostxError(await rejection(loadPublicKeyFromPEM(pem)), 'invalid_public_key')).toBe(true)
		}
	})

	it('refuses garbage, a corrupt body and a missing value', async () => {
		const corrupt = PARTNER.privatePKCS8.replace('MIGHAgEAMBMG', 'MIGHAgEAMBMH')
		const badBase64 = PARTNER.privatePKCS8.replace('MIGHAgEA', 'MIGH*gEA')
		const truncated = PARTNER.publicSPKI.replace('ZtgNwdZsi7xgyGDpJiOWTYr9cXKmrvnHMb0XNPMrEjcoUVFwMHCqaUVAGg==\n', '')
		for (const pem of ['', 'not a key', corrupt, badBase64, undefined as unknown as string]) {
			expect(isBoostxError(await rejection(loadPrivateKeyFromPEM(pem)), 'invalid_private_key')).toBe(true)
		}
		for (const pem of ['', 'not a key', truncated, undefined as unknown as string]) {
			expect(isBoostxError(await rejection(loadPublicKeyFromPEM(pem)), 'invalid_public_key')).toBe(true)
		}
	})

	it('names the cause of a PEM failure', async () => {
		const message = async (p: Promise<unknown>) => ((await rejection(p)) as Error).message
		const badBase64 = PARTNER.privatePKCS8.replace('MIGHAgEA', 'MIGH*gEA')
		for (const [pem, want] of [
			[ENCRYPTED_PKCS8, 'invalid private key: an ENCRYPTED PRIVATE KEY is not supported, decrypt it first'],
			[ENCRYPTED_SEC1, 'invalid private key: an encrypted EC PRIVATE KEY is not supported, decrypt it first'],
			[PARTNER.publicSPKI, 'invalid private key: expected a PRIVATE KEY or EC PRIVATE KEY PEM block, got PUBLIC KEY'],
			[badBase64, 'invalid private key: the PRIVATE KEY PEM body is not base64'],
			['not a key', 'invalid private key: no PEM block'],
			[SEC1_NO_PARAMS, 'invalid private key: an EC PRIVATE KEY must name the P-256 curve'],
		] as const) {
			expect(await message(loadPrivateKeyFromPEM(pem))).toBe(want)
		}
		for (const [pem, want] of [
			[PARTNER.privateSEC1, 'invalid public key: expected a PUBLIC KEY PEM block, got EC PRIVATE KEY'],
			[SEC1_WITH_PARAMS, 'invalid public key: expected a PUBLIC KEY PEM block, got EC PARAMETERS, EC PRIVATE KEY'],
			['', 'invalid public key: no PEM block'],
			[
				PARTNER.publicSPKI.replace('-----END PUBLIC KEY-----', ''),
				'invalid public key: the PUBLIC KEY PEM block has no END line',
			],
			[COMPRESSED_PUBLIC, 'invalid public key: not an ECDSA P-256 key with an uncompressed point'],
		] as const) {
			expect(await message(loadPublicKeyFromPEM(pem))).toBe(want)
		}
	})
})
