// Checks that test/spec/ is a byte-for-byte mirror of the spec repository's vectors/:
// node scripts/check-spec.mjs [specRepoPath], default ../boostx-partner-sdk-spec. Exits 1 listing every difference.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const mirror = join(root, 'test', 'spec')
const master = join(resolve(process.argv[2] ?? join(root, '..', 'boostx-partner-sdk-spec')), 'vectors')
if (!existsSync(master)) {
	console.error(`check:spec: ${master} does not exist`)
	process.exit(1)
}

const files = (dir) =>
	readdirSync(dir, { recursive: true })
		.filter((f) => statSync(join(dir, f)).isFile())
		.sort()
const mine = files(mirror)
const theirs = files(master)
const differences = [
	...theirs.filter((f) => !mine.includes(f)).map((f) => `missing from test/spec: ${f}`),
	...mine.filter((f) => !theirs.includes(f)).map((f) => `not in ${master}: ${f}`),
	...mine
		.filter((f) => theirs.includes(f) && !readFileSync(join(mirror, f)).equals(readFileSync(join(master, f))))
		.map((f) => `differs: ${f}`),
]
if (differences.length > 0) {
	console.error(`check:spec: test/spec differs from ${master}\n${differences.join('\n')}`)
	process.exit(1)
}
console.log(`check:spec: test/spec matches ${master} (${mine.length} files)`)
