// Proves the runtime rule on the built package: dist/ outside dist/node/ names no node: module, Buffer or process,
// and it runs in plain workerd (no compatibility flags). Run `npm run build` first.

import { readFileSync, readdirSync } from 'node:fs'
import { join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Miniflare, convertV4MiniflareOptions } from 'miniflare'
import ts from 'typescript'

const root = fileURLToPath(new URL('..', import.meta.url))
const dist = join(root, 'dist')
const failures = []

// (a) Static: identifiers and string literals, so prose in comments does not count.
let files
try {
	files = readdirSync(dist, { recursive: true }).filter((f) => !f.startsWith(`node${sep}`) && /\.[cm]?[jt]s$/.test(f))
} catch {
	console.error('check:workerd: dist/ not found; run `npm run build` first')
	process.exit(1)
}
for (const file of files) {
	const source = ts.createSourceFile(file, readFileSync(join(dist, file), 'utf8'), ts.ScriptTarget.Latest, true)
	const visit = (node) => {
		const hit =
			(ts.isIdentifier(node) && (node.text === 'Buffer' || node.text === 'process')) ||
			(ts.isStringLiteralLike(node) && node.text.startsWith('node:'))
		if (hit) {
			const { line } = source.getLineAndCharacterOfPosition(node.getStart())
			failures.push(`dist/${file.split(sep).join('/')}:${line + 1}: ${node.getText()}`)
		}
		ts.forEachChild(node, visit)
	}
	visit(source)
}
if (files.length === 0) failures.push('dist/ holds no built files')

// (b) Dynamic: the test key pairs, read from test/fixtures.ts.
const keys = {}
const fixtures = readFileSync(join(root, 'test/fixtures.ts'), 'utf8')
for (const [, name, block] of fixtures.matchAll(/export const (PARTNER|BOOSTX) = \{([^}]*)\}/g)) {
	keys[name] = Object.fromEntries([...block.matchAll(/(\w+): `([^`]*)`/g)].map(([, k, pem]) => [k, pem]))
}
if (!keys.PARTNER?.privatePKCS8 || !keys.BOOSTX?.privatePKCS8) {
	console.error('check:workerd: PARTNER and BOOSTX key pairs not found in test/fixtures.ts')
	process.exit(1)
}

let checks = 0
if (files.length > 0) {
	let mf
	try {
		// The entry module comes first. dist/node/ is left out, so an import reaching into it fails too.
		const modules = [
			'scripts/check-workerd-worker.mjs',
			...files.filter((f) => f.endsWith('.js')).map((f) => join('dist', f)),
		]
		mf = new Miniflare(
			convertV4MiniflareOptions({
				modules: modules.map((path) => ({ type: 'ESModule', path: join(root, path) })),
				modulesRoot: root,
				compatibilityDate: '2026-07-25',
				bindings: { KEYS: keys },
			}),
		)
		const res = await mf.dispatchFetch('http://localhost/')
		const text = await res.text()
		if (res.status !== 200) failures.push(`worker answered ${res.status}: ${text}`)
		else {
			const result = JSON.parse(text)
			checks = result.checks
			failures.push(...result.failures)
		}
	} catch (err) {
		failures.push(`workerd failed to run dist/: ${err?.stack ?? err}`)
	} finally {
		await mf?.dispose().catch(() => {})
	}
}

if (failures.length > 0) {
	console.error(`check:workerd failed:\n${failures.map((f) => `  - ${f}`).join('\n')}`)
	process.exit(1)
}
console.log(`check:workerd: ${files.length} dist files clean; ${checks} checks passed in plain workerd`)
