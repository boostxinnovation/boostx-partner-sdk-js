import { BoostxError } from './errors.js'
import { isP256, type CryptoKeyLike } from './keys.js'
import { quote } from './validate.js'

/**
 * The keys the endpoint handlers look up by the partner id a token carries. Treat `partner` as authoritative and
 * throw `unknown_partner` for an id you do not serve; never fall back to a fixed key set. Match `partner` byte for
 * byte: no case-folding, trimming or normalisation, and no case-insensitive database collation.
 */
export interface HandlersKeyStore {
	/** Keys that verify GID signatures: the current key first, then keys still valid for games started before a rotation. */
	partnerPublicKeys(partner: string): Promise<readonly CryptoKeyLike[]>
	/** Signs the `/verify-keys` response. */
	partnerPrivateKey(partner: string): Promise<CryptoKeyLike>
	/** Verifies the Booster, CheckBet and VerifyKeys tokens BoostX sends. */
	boostxPublicKey(partner: string): Promise<CryptoKeyLike>
}

/**
 * The key the settlement client signs with, looked up by `partner`. Throw `unknown_partner` for an id you do not
 * serve, never a default key. Any error leaves the settlement unsent, to send again later.
 */
export interface ClientKeyStore {
	partnerPrivateKey(partner: string): Promise<CryptoKeyLike>
}

/** One partner's keys. Any may be left out, or `null`, by a store that fills only some roles (e.g. sign-only). */
export interface PartnerKeys {
	/** The current key, or a list: the current key first, then keys still valid for games started before a rotation. */
	partnerPublicKey?: CryptoKeyLike | readonly CryptoKeyLike[] | null
	partnerPrivateKey?: CryptoKeyLike | null
	boostxPublicKey?: CryptoKeyLike | null
}

interface KeySet {
	partnerPublicKeys: readonly CryptoKeyLike[] | undefined
	partnerPrivateKey: CryptoKeyLike | undefined
	boostxPublicKey: CryptoKeyLike | undefined
}

/**
 * Holds each partner id's keys in memory; satisfies {@link HandlersKeyStore} and {@link ClientKeyStore}.
 * `register` may run while requests are served (onboarding, rotation): a lookup sees one registration whole.
 */
export class MemoryKeyStore implements HandlersKeyStore, ClientKeyStore {
	readonly #byID = new Map<string, KeySet>()

	/** Adds or replaces a partner's keys. Throws for an empty `partner` or a key that does not fit its role. */
	register(partner: string, keys: PartnerKeys): void {
		if (typeof partner !== 'string' || partner === '')
			throw new BoostxError('missing_claim', 'partner must not be empty')
		const { partnerPublicKey, partnerPrivateKey, boostxPublicKey } = keys ?? {}
		let partnerPublicKeys: readonly CryptoKeyLike[] | undefined
		if (partnerPublicKey != null) {
			const list: readonly unknown[] = Array.isArray(partnerPublicKey) ? partnerPublicKey : [partnerPublicKey]
			if (list.length === 0)
				throw new BoostxError('invalid_public_key', 'invalid public key: partnerPublicKey is an empty list')
			partnerPublicKeys = Object.freeze(list.map((k) => checkKey(k, 'public', 'partnerPublicKey')))
		}
		this.#byID.set(partner, {
			partnerPublicKeys,
			partnerPrivateKey:
				partnerPrivateKey == null ? undefined : checkKey(partnerPrivateKey, 'private', 'partnerPrivateKey'),
			boostxPublicKey: boostxPublicKey == null ? undefined : checkKey(boostxPublicKey, 'public', 'boostxPublicKey'),
		})
	}

	async partnerPublicKeys(partner: string): Promise<readonly CryptoKeyLike[]> {
		const keys = this.#lookup(partner).partnerPublicKeys
		if (keys === undefined)
			throw new BoostxError('invalid_public_key', `no partner public key for partner ${quote(partner)}`)
		return keys
	}

	async partnerPrivateKey(partner: string): Promise<CryptoKeyLike> {
		const key = this.#lookup(partner).partnerPrivateKey
		if (key === undefined)
			throw new BoostxError('invalid_private_key', `no partner private key for partner ${quote(partner)}`)
		return key
	}

	async boostxPublicKey(partner: string): Promise<CryptoKeyLike> {
		const key = this.#lookup(partner).boostxPublicKey
		if (key === undefined)
			throw new BoostxError('invalid_public_key', `no boostx public key for partner ${quote(partner)}`)
		return key
	}

	#lookup(partner: string): KeySet {
		const set = this.#byID.get(partner)
		if (set === undefined) throw new BoostxError('unknown_partner', `unknown partner ${quote(partner)}`)
		return set
	}
}

function checkKey(key: unknown, type: 'public' | 'private', role: string): CryptoKeyLike {
	if (!isP256(key, type)) {
		const code = type === 'public' ? 'invalid_public_key' : 'invalid_private_key'
		const use = type === 'public' ? 'verify' : 'sign'
		throw new BoostxError(code, `invalid ${type} key: ${role} is not an ECDSA P-256 ${type} key that can ${use}`)
	}
	return key as CryptoKeyLike
}
