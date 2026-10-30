import { describe, expect, it } from 'vitest'

import { decodeBase64url, encodeBase64url } from '../src/base64url.js'

describe('decodeBase64url', () => {
	it('round-trips every remainder length', () => {
		for (let n = 0; n <= 66; n++) {
			const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff)
			expect(decodeBase64url(encodeBase64url(bytes))).toStrictEqual(bytes)
		}
	})

	// 'AA' and 'AAA' are the only encodings of one and two zero bytes; the others set unused trailing bits.
	it('refuses an encoding whose unused trailing bits are not zero', () => {
		expect(decodeBase64url('AA')).toStrictEqual(new Uint8Array(1))
		expect(decodeBase64url('AAA')).toStrictEqual(new Uint8Array(2))
		for (const s of ['AB', 'AP', 'AAB', 'AAD', 'AAAAAB']) expect(decodeBase64url(s), s).toBeUndefined()
	})

	it('refuses characters outside the alphabet and an impossible length', () => {
		for (const s of ['AA==', 'A+', 'A/', 'A A', 'A']) expect(decodeBase64url(s), s).toBeUndefined()
	})
})
