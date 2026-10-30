import { describe, expect, it } from 'vitest'

import { isBoostxError } from '../src/errors.js'
import { floorX, playerX } from '../src/x.js'
import floorVectors from './spec/golden/floor-x.json' with { type: 'json' }
import playerVectors from './spec/golden/player-x.json' with { type: 'json' }

describe('floorX', () => {
	it('floors where a plain floor lands one step low', () => {
		expect(floorX(1 + (1.13 - 1) * 1, 2)).toBe(1.13)
		expect(floorX(1 + (2.03 - 1) * 1, 2)).toBe(2.03)
		expect(floorX(1 + (14.95 - 1) * 1.2, 2)).toBe(17.74)
		expect(floorX(1 + (49.503282 - 1) * 1.5, 6)).toBe(73.754923)
	})

	it('treats unset decimals as 2', () => {
		expect(floorX(17.749)).toBe(17.74)
		expect(floorX(17.749, 0)).toBe(17.74)
	})

	it('matches every BoostX vector in floor-x.json', () => {
		expect(floorVectors.length).toBeGreaterThanOrEqual(3000)
		const failures = floorVectors.flatMap((v, i) => {
			const rawX = 1 + (v.xBase - 1) * v.boost
			const got = [rawX, floorX(v.rawX, v.decimals), floorX(rawX, v.decimals)]
			return got[0] === v.rawX && got[1] === v.x && got[2] === v.x ? [] : [{ i, ...v, got }]
		})
		expect(failures).toEqual([])
	})

	it('refuses decimals outside 2–6 and non-finite x', () => {
		for (const d of [1, 7, -2, 2.5, Number.NaN]) {
			expect(() => floorX(1.5, d), `decimals ${d}`).toThrow(/decimals/)
			expect(
				isBoostxError(
					catchError(() => floorX(1.5, d)),
					'invalid_claim',
				),
			).toBe(true)
		}
		for (const x of [Number.NaN, Infinity, -Infinity, '1.5' as unknown as number]) {
			expect(
				isBoostxError(
					catchError(() => floorX(x, 2)),
					'invalid_claim',
				),
				`x ${x}`,
			).toBe(true)
		}
	})
})

describe('playerX', () => {
	it('reproduces the Flooring X examples', () => {
		expect(playerX(1.13, 1, 2)).toBe(1.13)
		expect(playerX(2.03, 1, 2)).toBe(2.03)
		expect(playerX(14.95, 1.2, 2)).toBe(17.74)
		expect(playerX(49.503282, 1.5, 6)).toBe(73.754923)
		expect(playerX(1.857, 1.5, 2)).toBe(2.27)
	})

	it('floors xBase to the default 2 places when decimals is unset', () => {
		expect(playerX(1.857, 1)).toBe(1.85)
		expect(playerX(1.857, 1, 0)).toBe(1.85)
	})

	it('matches every BoostX vector in player-x.json', () => {
		expect(playerVectors.length).toBeGreaterThanOrEqual(2000)
		const failures = playerVectors.flatMap((v, i) => {
			const got = [floorX(v.init, v.decimals), playerX(v.init, v.boost, v.decimals)]
			return got[0] === v.xBase && got[1] === v.x ? [] : [{ i, ...v, got }]
		})
		expect(failures).toEqual([])
	})

	it('refuses non-finite inputs and decimals outside 2–6', () => {
		expect(
			isBoostxError(
				catchError(() => playerX(Number.NaN, 1, 2)),
				'invalid_claim',
			),
		).toBe(true)
		expect(
			isBoostxError(
				catchError(() => playerX(2, Infinity, 2)),
				'invalid_claim',
			),
		).toBe(true)
		expect(
			isBoostxError(
				catchError(() => playerX(2, 1, 7)),
				'invalid_claim',
			),
		).toBe(true)
	})
})

function catchError(fn: () => unknown): unknown {
	try {
		fn()
	} catch (err) {
		return err
	}
	return undefined
}
