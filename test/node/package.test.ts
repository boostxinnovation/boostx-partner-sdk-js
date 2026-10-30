import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'))

describe('package.json', () => {
	// TypeScript under node10 resolution (`module: commonjs`) ignores `exports` and reads these instead.
	it('points the node10 fallbacks at the same files as exports', () => {
		expect(pkg.main).toBe(pkg.exports['.'].default)
		expect(pkg.types).toBe(pkg.exports['.'].types)
		expect(pkg.typesVersions).toEqual({ '*': { node: [pkg.exports['./node'].types] } })
	})

	it('ships the sources its source maps name, and the changelog', () => {
		expect(pkg.files).toEqual(['dist', 'src', 'CHANGELOG.md'])
	})
})
