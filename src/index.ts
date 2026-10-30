// The universal entry, `@boostxinnovation/partner-sdk`: what partners call or receive.

export { BoostxError, isBoostxError, verifyKeysReason } from './errors.js'
export type { BoostxErrorCode, BoostxErrorOptions, VerifyKeysReason } from './errors.js'

export { loadPrivateKeyFromPEM, loadPublicKeyFromPEM, type CryptoKeyLike } from './keys.js'
export { MemoryKeyStore, type ClientKeyStore, type HandlersKeyStore, type PartnerKeys } from './key-store.js'

export { buildGID, type GID } from './gid.js'
export { createGamePassToken, type GamePassParams } from './gamepass.js'
export {
	SETTLEMENT_STATUSES,
	createSettlementToken,
	type SettlementParams,
	type SettlementStatus,
} from './settlement.js'
export { extractBoosterPartner, parseBoosterToken, type Booster } from './booster.js'
export { extractCheckBetPartner, parseCheckBetToken, type CheckBet } from './checkbet.js'
export {
	BOOSTX_IDENTITY,
	DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS,
	createVerifyKeysRequestToken,
	createVerifyKeysResponseToken,
	extractVerifyKeysRequestPartner,
	parseVerifyKeysRequestToken,
	parseVerifyKeysResponseToken,
	type VerifyKeysRequest,
	type VerifyKeysResponse,
} from './verify-keys.js'
export { floorX, playerX } from './x.js'

export {
	RoundRejectedError,
	createFetchHandler,
	handleCheckBet,
	handleSetBoost,
	handleVerifyKeys,
	type BetStore,
	type HandlerOptions,
	type HandlerResult,
} from './handlers.js'
export { BoostxAPIError, BoostxClient, DEFAULT_BASE_URL, type ClientOptions } from './client.js'
