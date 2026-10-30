// Strict base64url without padding. atob/btoa keep this free of Buffer, which Workers lack without nodejs_compat.

const ALPHABET = /^[A-Za-z0-9_-]*$/

export function encodeBase64url(bytes: Uint8Array): string {
	let binary = ''
	for (const b of bytes) binary += String.fromCharCode(b)
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Decodes unpadded base64url. Returns undefined for any character outside the alphabet, an impossible length, or
 * non-zero unused trailing bits: only the canonical encoding decodes, so one byte string has one token text.
 */
export function decodeBase64url(s: string): Uint8Array | undefined {
	if (!ALPHABET.test(s) || s.length % 4 === 1) return undefined
	const binary = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
	const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0))
	return encodeBase64url(bytes) === s ? bytes : undefined
}

/** Decodes standard base64, the body of a PEM block. */
export function decodeBase64(s: string): Uint8Array | undefined {
	if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return undefined
	const binary = atob(s)
	return Uint8Array.from(binary, (c) => c.charCodeAt(0))
}
