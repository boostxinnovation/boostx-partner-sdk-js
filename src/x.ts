import { invalidClaim } from './validate.js'

// `decimals` unset (undefined, null or 0, as Go's zero value) is xrange.decimals' default.
function checkDecimals(decimals: number | undefined): number {
	const d = decimals ?? 0
	if (d === 0) return 2
	if (!Number.isInteger(d) || d < 2 || d > 6) throw invalidClaim('decimals must be an integer from 2 to 6')
	return d
}

function checkFinite(name: string, n: number): void {
	if (typeof n !== 'number' || !Number.isFinite(n)) throw invalidClaim(`${name} must be a finite number`)
}

function floor(x: number, decimals: number): number {
	const scale = Math.pow(10, decimals)
	return Math.floor(+(x * scale).toPrecision(15)) / scale
}

/**
 * Floors `x` to `decimals` places as BoostX does: `x × 10^decimals` rounded to 15 significant digits first.
 * `decimals` is `xrange.decimals`, 2–6; unset (or 0) means the default 2.
 */
export function floorX(x: number, decimals?: number): number {
	checkFinite('x', x)
	return floor(x, checkDecimals(decimals))
}

/**
 * The X the player saw: `floorX(1 + (floorX(xBase) - 1) × boost)`. `xBase` is the entry's `xrange.init` as you
 * signed it (BoostX floors it first), `boost` the Booster's, `decimals` the `xrange.decimals` you issued.
 */
export function playerX(xBase: number, boost: number, decimals?: number): number {
	checkFinite('xBase', xBase)
	checkFinite('boost', boost)
	const d = checkDecimals(decimals)
	return floor(1 + (floor(xBase, d) - 1) * boost, d)
}
