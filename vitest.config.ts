import { cloudflareTest } from '@cloudflare/vitest-plugin'
import { defineConfig } from 'vitest/config'

// The same suite runs twice: in Node and in workerd (Cloudflare Workers, no nodejs_compat).
// Tests under test/node/ cover the Node-only entry and run in Node alone.
export default defineConfig({
	test: {
		projects: [
			{ test: { name: 'node', environment: 'node', include: ['test/**/*.test.ts'] } },
			{
				plugins: [cloudflareTest({ miniflare: { compatibilityDate: '2026-07-25' } })],
				test: { name: 'workerd', include: ['test/**/*.test.ts'], exclude: ['test/node/**'] },
			},
		],
	},
})
