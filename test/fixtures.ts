// Test-only key pairs (P-256), generated for this suite. Not secrets: they sign nothing outside the tests.

import { encodeBase64url } from '../src/base64url.js'
import type { CryptoKeyLike } from '../src/keys.js'

/** Signs a header and a payload given as JSON text or raw bytes, for tokens the SDK never writes. */
export async function signParts(
	header: string | number[],
	payload: string | number[],
	key: CryptoKeyLike,
): Promise<string> {
	const bytes = (part: string | number[]) =>
		typeof part === 'string' ? new TextEncoder().encode(part) : new Uint8Array(part)
	const input = `${encodeBase64url(bytes(header))}.${encodeBase64url(bytes(payload))}`
	const sig = await crypto.subtle.sign(
		{ name: 'ECDSA', hash: 'SHA-256' },
		key as Parameters<typeof crypto.subtle.sign>[1],
		new TextEncoder().encode(input),
	)
	return `${input}.${encodeBase64url(new Uint8Array(sig))}`
}

/** Imports an SPKI PEM with no usages: a P-256 public key Web Crypto refuses to verify with. */
export function publicKeyWithoutUsages(spkiPEM: string): Promise<CryptoKeyLike> {
	const der = Uint8Array.from(atob(spkiPEM.replace(/-----[A-Z ]+-----|\s/g, '')), (c) => c.charCodeAt(0))
	return crypto.subtle.importKey('spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, [])
}

export const PARTNER = {
	privatePKCS8: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsUb11qJrLBckZl3k
108i63AREqZsu6hZaQ9hhCLNCmKhRANCAAR58MlGN//wWwwXIivDU7iPzDr+S55m
2A3B1myLvGDIYOkmI5ZNiv1xcqau+ccxvRc08ysSNyhRUXAwcKppRUAa
-----END PRIVATE KEY-----
`,
	privateSEC1: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILFG9daiaywXJGZd5NdPIutwERKmbLuoWWkPYYQizQpioAoGCCqGSM49
AwEHoUQDQgAEefDJRjf/8FsMFyIrw1O4j8w6/kueZtgNwdZsi7xgyGDpJiOWTYr9
cXKmrvnHMb0XNPMrEjcoUVFwMHCqaUVAGg==
-----END EC PRIVATE KEY-----
`,
	publicSPKI: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEefDJRjf/8FsMFyIrw1O4j8w6/kue
ZtgNwdZsi7xgyGDpJiOWTYr9cXKmrvnHMb0XNPMrEjcoUVFwMHCqaUVAGg==
-----END PUBLIC KEY-----
`,
}

export const BOOSTX = {
	privatePKCS8: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgLNt5HsW1EYt5+VaN
s8X2yAYIyUITPNYpYR/95F918E2hRANCAAQz9m7VhZC6R5LW6FElMKFIU3lQ9gX9
b0pdOqwmdDGMl2KVN8P2LNDicp4wjqZn8JQl9JXPr33dT/hd4jfgTeon
-----END PRIVATE KEY-----
`,
	privateSEC1: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICzbeR7FtRGLeflWjbPF9sgGCMlCEzzWKWEf/eRfdfBNoAoGCCqGSM49
AwEHoUQDQgAEM/Zu1YWQukeS1uhRJTChSFN5UPYF/W9KXTqsJnQxjJdilTfD9izQ
4nKeMI6mZ/CUJfSVz6993U/4XeI34E3qJw==
-----END EC PRIVATE KEY-----
`,
	publicSPKI: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM/Zu1YWQukeS1uhRJTChSFN5UPYF
/W9KXTqsJnQxjJdilTfD9izQ4nKeMI6mZ/CUJfSVz6993U/4XeI34E3qJw==
-----END PUBLIC KEY-----
`,
}

export const OTHER = {
	privatePKCS8: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8lgAU8GJKxw0KK5M
px32lOYIaFh82BbhLuy93kubrAuhRANCAAR0KGFp+pE+zQ4zaMhHnrFJganLgstf
vje1lJqou6y94/RtdGph2oFspdJAbDeeYy8szU7Hs1ba4ATxcgs08Ccb
-----END PRIVATE KEY-----
`,
	privateSEC1: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPJYAFPBiSscNCiuTKcd9pTmCGhYfNgW4S7svd5Lm6wLoAoGCCqGSM49
AwEHoUQDQgAEdChhafqRPs0OM2jIR56xSYGpy4LLX743tZSaqLusveP0bXRqYdqB
bKXSQGw3nmMvLM1Ox7NW2uAE8XILNPAnGw==
-----END EC PRIVATE KEY-----
`,
	publicSPKI: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdChhafqRPs0OM2jIR56xSYGpy4LL
X743tZSaqLusveP0bXRqYdqBbKXSQGw3nmMvLM1Ox7NW2uAE8XILNPAnGw==
-----END PUBLIC KEY-----
`,
}

/** A P-384 key, which every loader must refuse. */
export const P384_PRIVATE_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAh4TGgZbDIrsiLmmg0
pNGtmsKvWEv0Ii9hhw3qx5rRonn7JmjF9wa1kfxRKD00y/+hZANiAAR4IZ82PzHW
Zv5riMo7xRWIp1I7kinu2wWX9NktEtY6FRyVCVS+WJxY5b6mBRT4laXiz5rUWeGN
q3D0fHSQIBHixz/02cYIThYUrdzQulA0DeCq/2EXMtRbv0EgqXs9nXg=
-----END PRIVATE KEY-----
`
