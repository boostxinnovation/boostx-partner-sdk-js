# @boostxinnovation/partner-sdk

[![npm](https://img.shields.io/npm/v/@boostxinnovation/partner-sdk?logo=npm)](https://www.npmjs.com/package/@boostxinnovation/partner-sdk)
[![Node 22.12+](https://img.shields.io/badge/Node-22.12+-5FA04E?logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/boostxinnovation/boostx-partner-sdk-js/actions/workflows/ci.yml/badge.svg)](https://github.com/boostxinnovation/boostx-partner-sdk-js/actions/workflows/ci.yml)

SDK for integrating with BoostX as a partner, for Node.js, Cloudflare Workers and other runtimes with Web Crypto.

It implements the partner side of the BoostX contract: the `/set-boost`, `/check-bet` and `/verify-keys` endpoints, the five token types with the signed GID they carry, and the settlement client. It conforms to [boostx-partner-sdk-spec v1.2.0](https://github.com/boostxinnovation/boostx-partner-sdk-spec/tree/v1.2.0), the specification of how a BoostX partner SDK behaves. You do not need the spec to use the SDK: this README says what you must do yourself and which errors you will see, and links the spec's rule where you may want the exact behaviour. The partner docs, which BoostX opens to its partners, describe the integration itself.

## Installation

```bash
npm install @boostxinnovation/partner-sdk
```

- **Node.js 22.12 or later.** The package is ESM with TypeScript declarations; `require()` works too, through Node's `require(esm)`. In TypeScript compiled to CommonJS, set `"module"` to `"commonjs"`, `"nodenext"` (TypeScript 5.8+) or `"node20"` (TypeScript 5.9+): `node16` and `node18` cannot import an ESM-only package.
- **Cloudflare Workers**, with no compatibility flag: the main entry uses only web-standard APIs: Web Crypto, `fetch`, `Request`/`Response` (including static `Response.json` and streamed request and response bodies), `URL`, `AbortSignal.timeout`/`AbortSignal.any`, `TextEncoder`/`TextDecoder` and `atob`/`btoa`, on an ES2024 engine (`String.prototype.isWellFormed` and `toWellFormed`).
- **Other runtimes** that provide those APIs, such as Deno or Bun. The test suite runs in Node and in workerd.

| Entry | Runs on | Contents |
|-------|---------|----------|
| `@boostxinnovation/partner-sdk` | every runtime above | everything but the three functions below |
| `@boostxinnovation/partner-sdk/node` | Node.js only | `loadPrivateKeyFromFile`, `loadPublicKeyFromFile`, and `createNodeHandler` for `node:http` and Express |

## Quick Start

You need the three keys of the partner ID BoostX assigned you — your partner private key, your partner public key and the BoostX public key from your dashboard — and a bet store of your own (see [Implementing BetStore](#implementing-betstore)).

### Node.js

```ts
import { createServer } from 'node:http'

import { MemoryKeyStore } from '@boostxinnovation/partner-sdk'
import { createNodeHandler, loadPrivateKeyFromFile, loadPublicKeyFromFile } from '@boostxinnovation/partner-sdk/node'

// Register your partner ID's keys, the ID exactly as your dashboard shows it.
// (BoostX assigns the ID and the BoostX key pair.)
const keyStore = new MemoryKeyStore()
keyStore.register('your-partner-id', {
  partnerPrivateKey: await loadPrivateKeyFromFile('partner_private.pem'),
  partnerPublicKey: await loadPublicKeyFromFile('partner_public.pem'),
  boostxPublicKey: await loadPublicKeyFromFile('boostx_public.pem'),
})

const boostx = createNodeHandler({ betStore: new YourBetStore(), keyStore })

// API URL on your dashboard: https://api.example.com/api/boostx
createServer((req, res) => {
  if (req.url?.startsWith('/api/boostx/')) return void boostx(req, res)
  res.writeHead(404).end()
}).listen(8080)
```

Your API URL must be HTTPS, so serve this behind your TLS front end. With Express, the same handler is a route handler, behind any body parser or none: when a parser has already read the body into `req.body` (`express.json()`, `express.raw()`, or `express.text()` on a matching content type), the handler uses that body, and otherwise it reads the request stream itself:

```ts
app.post('/api/boostx/:endpoint', boostx)
```

### Cloudflare Workers

```ts
import { MemoryKeyStore, createFetchHandler, loadPrivateKeyFromPEM, loadPublicKeyFromPEM } from '@boostxinnovation/partner-sdk'

interface Env {
  PARTNER_ID: string
  PARTNER_PRIVATE_KEY: string // PEM secrets: wrangler secret put PARTNER_PRIVATE_KEY < partner_private.pem
  PARTNER_PUBLIC_KEY: string
  BOOSTX_PUBLIC_KEY: string
}

async function createHandler(env: Env) {
  const keyStore = new MemoryKeyStore()
  keyStore.register(env.PARTNER_ID, {
    partnerPrivateKey: await loadPrivateKeyFromPEM(env.PARTNER_PRIVATE_KEY),
    partnerPublicKey: await loadPublicKeyFromPEM(env.PARTNER_PUBLIC_KEY),
    boostxPublicKey: await loadPublicKeyFromPEM(env.BOOSTX_PUBLIC_KEY),
  })
  return createFetchHandler({ betStore: new YourBetStore(env), keyStore })
}

let handler: ReturnType<typeof createHandler> | undefined // built once per isolate

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!new URL(request.url).pathname.startsWith('/api/boostx/')) return new Response('Not Found', { status: 404 })
    handler ??= createHandler(env).catch((err: unknown) => {
      handler = undefined // load the keys again on the next request
      throw err
    })
    return (await handler)(request)
  },
}
```

## Implementing BetStore

The handlers hand your bet store what each call from BoostX is about:

```ts
interface BetStore {
  setBoost(booster: Booster): Promise<void>
  checkBet?(gid: GID): Promise<boolean>
}

interface Booster {
  gid: GID          // { partner, user, bet, signature }: the GID of the gamepass that created the game
  round: number     // 1-indexed; a round sent again repeats it
  boost: number     // > 0: the round's accumulated boost, a jackpot round's included; never divide consecutive boosts
  final: boolean    // the last round of the game
  jackpot: boolean  // a jackpot round
  iat: number       // issued-at, Unix seconds
}
```

- **setBoost** - Applies the boost of a round. Required.
- **checkBet** - Says whether a bet is active. Optional: with it, `/check-bet` is served.

The handlers verify both signatures on every call before your store sees it — the BoostX signature on the token and your own on its GID — but they do not reject replays: BoostX's tokens carry no expiry, and the SDK does not track rounds. BoostX can send a round again, or deliver an older round late, so the replay rule ([INBOUND-51](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#inbound-51)) is yours to enforce in `setBoost`:

- Find the bet by `gid.partner`, `gid.user` and `gid.bet` together; a bet id alone is not unique across partner ids. Key your records by those three and the round, never by the token text or `gid.signature`: an ECDSA signature has more than one valid form, so the same call can arrive with another signature text.
- Apply the update only when `booster.round` is greater than the last round you applied for that bet. For any other round resolve without changing anything, and the SDK answers `200` with `{"result": {"ok": true}}`. That includes a jackpot round sent again under the round number you already recorded, with the same `boost`.
- Check and write atomically (one transaction, or one conditional update such as `UPDATE … WHERE round < ?`), so a late round cannot overwrite a newer one.
- Validate before you write, and throw `RoundRejectedError` for a round you have not applied and will not apply: the SDK answers `400` with `round rejected`, also when the error you throw carries a `RoundRejectedError` in its `cause` chain (up to 16 errors deep). Its message is for your own logs and is never sent. Any other error is answered `500`, with `failed to set boost` and not its own text. Either way the round is voided: it does not count, and BoostX sends it again with the player's first spin after reopening the game. So a bet you updated before refusing would fail the round check on every replay.
- Fail fast. BoostX applies no timeout of its own to a single request, and the call sits inside the player's spin, so a slow store delays the player for its full duration ([HTTP-52](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#http-52)).

Derive the X the player saw with [`playerX`](#calculating-x), from the `x` you signed into the gamepass of the entry that sent the round. Record that `x` for each entry into a bet: after a re-entry that changed it, the new one applies, except to a `final: true` regular round sent again, which keeps the one it was first sent with, and to a jackpot round, which keeps the one on which BoostX fixed its result ([GAMEPASS-44](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-44)).

```ts
import { RoundRejectedError, playerX, type BetStore } from '@boostxinnovation/partner-sdk'

const betStore: BetStore = {
  async setBoost(booster) {
    const { partner, user, bet } = booster.gid
    const row = await db.findBet(partner, user, bet)
    if (row === undefined) throw new RoundRejectedError('unknown bet') // answered 400 round rejected, nothing written
    if (booster.round <= row.round) return // a round you already applied: answered 200, nothing changes
    const x = playerX(row.xBase, booster.boost, row.xDecimals) // xDecimals as on the gamepass, or undefined
    await db.saveRoundIfNewer(row.id, booster.round, booster.boost, x, booster.final)
  },
  async checkBet({ partner, user, bet }) {
    const row = await db.findBet(partner, user, bet)
    return row?.active ?? false // a bet you do not know is not active
  },
}
```

BoostX calls `/check-bet` only when you switch it on under Partner-side API on your dashboard, then before each round and each time the player opens the game ([INBOUND-52](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#inbound-52)). Resolve `false` for a bet you do not know or no longer accept: rounds on it are refused until you answer `true` again. A `checkBet` that throws, or resolves anything but a boolean, is answered `500` with `failed to check bet`; before a round BoostX then refuses the spin with `503 GAME_UNAVAILABLE`, and at a game open it reads the bet as active.

> **Warning:** switch `/check-bet` on only once your `BetStore` has `checkBet`. Without it the SDK answers `/check-bet` with `404`, and with the switch on BoostX refuses every round it gets no verdict for: every round fails with `503 GAME_UNAVAILABLE`. The same happens when you wrap your store in another object (for logging or metrics, say) that has no `checkBet` of its own: a wrapper must pass `checkBet` on too.

`booster.iat` is there for an age check of your own. If you add one, allow for retries: a retried call re-sends the same token, so its `iat` can be older than the call ([HTTP-30](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#http-30)).

The bet stores in [examples/](examples/) follow these rules.

## API Endpoints

`createFetchHandler` and `createNodeHandler` dispatch on the last segment of the request path, so mount them under the path of the API URL on your dashboard: with `https://api.example.com/boostx`, BoostX calls `POST /boostx/set-boost`. They do not check the prefix, so route only that path to them.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `{prefix}/set-boost` | POST | Receive the boost after each round |
| `{prefix}/check-bet` | POST | Say whether a bet is active *(optional, requires `checkBet`)* |
| `{prefix}/verify-keys` | POST | Signed round-trip key-pair verification |

Every answer is JSON: `{"result": …}` on success, `{"error": "…"}` otherwise. A body over 64 KiB is answered `400` as soon as it passes the cap: `createFetchHandler` stops reading it, while `createNodeHandler` discards the rest, as Node does for any request body left unread, so the connection stays usable; `server.requestTimeout` bounds how long that can take.

### POST /set-boost

Request body:
```json
{"boosterJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

Response body, once your `setBoost` resolves:
```json
{"result": {"ok": true}}
```

### POST /check-bet

Request body:
```json
{"checkbetJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

Response body, with the boolean your `checkBet` resolved:
```json
{"result": {"active": true}}
```

### POST /verify-keys

Signed round trip that confirms BoostX and you hold each other's public keys ([Verify-keys](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#10-verify-keys-verifykeys)). BoostX calls it only when Test integration runs, from your dashboard or by BoostX on your behalf, and never during play. Each run sends three requests at once, two of them deliberately invalid: do not rate-limit, serialize or block it.

Request body:
```json
{"verifyKeysJWT": "eyJhbGciOiJFUzI1NiJ9..."}
```

Response body:
```json
{"result": {"responseJWT": "eyJhbGciOiJFUzI1NiJ9..."}}
```

The response token is signed with your partner private key. Its `iss` is the partner ID your key store matched the request's `aud` to: the SDK signs only after the store has returned keys for exactly that ID, so nothing is signed for an ID you do not serve. That makes the store's matching the check, and it must match IDs byte for byte ([Key Stores](#key-stores)). Its `aud` is `boostx`, its nonce is the request's and its `iat` is fresh.

Error body (400): `{"error": "invalid verifyKeysJWT: <reason>"}`. Test integration reads the reason to choose the stage and the hint it reports ([HTTP-53](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#http-53)):

| Reason | Usual cause |
|--------|-------------|
| `signature` | The token does not verify with the BoostX public key your store holds for that partner ID: check it against the one on your dashboard. One of the two invalid requests in each run is signed with another key and expects this answer |
| `iss-aud` | `aud` names a partner ID your key store does not serve, answered `invalid verifyKeysJWT: iss-aud (unknown partner "<id>")`. The other invalid request in each run does this and expects this answer |
| `stale` | `iat` is more than 30 seconds from your clock: keep it NTP-synced. The handlers offer no option to change the window |
| `shape` | A malformed token (see [Token Format](#token-format)) or a claim of the wrong type |
| `nonce-format` | A nonce that is not an integer in `[1, 2147483647]` |

A token with several faults gets the reason of the first check it fails, in the handler's order ([HTTP-21](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#http-21)): it reads the payload's format and claim types and looks up your BoostX public key before it verifies the token ([VERIFYKEYS-46](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#verifykeys-46)), so a payload fault is `shape`, and an `aud` you do not serve `iss-aud`, even when the signature is bad too.

### Answers

Every status the handlers answer with, and its `error`:

| Status | `error` | When |
|--------|---------|------|
| 400 | `invalid request body` | The body is not strict UTF-8, starts with a byte order mark, is not a single JSON value, is a JSON value other than an object or `null`, is over 64 KiB, or its token field is present and neither a string nor `null`; or something in front of the handler already read it and, on Node, left nothing in `req.body` |
| 400 | `invalid booster token`, `invalid checkbet token` | The token fails to parse, or either signature fails to verify. A `null` body, or a token field that is missing or `null`, is read as an empty token, answered here or as `invalid verifyKeysJWT: shape` |
| 400 | `unknown partner "<id>"` | Your key store does not serve the token's partner ID (`unknown_partner`) |
| 400 | `round rejected` | Your `setBoost` threw `RoundRejectedError`, or an error with one in its `cause` chain |
| 400 | `invalid verifyKeysJWT: <reason>` | A `/verify-keys` request fails, see above |
| 404 | `not found` | An unknown path; `/check-bet` when your `BetStore` has no `checkBet` |
| 405 | `method not allowed` | A method other than `POST` on a known path, with `Allow: POST` |
| 500 | `failed to get boostx key`, `failed to get partner key`, `failed to get partner private key` | Your key store failed with anything but `unknown_partner` |
| 500 | `failed to verify token` | The BoostX public key from your store cannot verify, or none of the partner public keys it lists can (not an ECDSA P-256 public key with the `verify` usage), whatever the token's signatures and claims |
| 500 | `failed to set boost` | Your `setBoost` threw anything else |
| 500 | `failed to check bet` | Your `checkBet` threw, or resolved a value that is not a boolean |
| 500 | `failed to sign response` | The `/verify-keys` response could not be signed |
| 500 | `internal server error` | Anything unexpected, or invalid options passed to a per-endpoint function; the handlers never reject |

### Other Frameworks

On a framework built on `Request`/`Response`, pass the request to `createFetchHandler`, e.g. with Hono:

```ts
const handle = createFetchHandler({ betStore, keyStore })
app.post('/api/boostx/*', (c) => handle(c.req.raw))
```

On a framework that parses the body itself, call the per-endpoint functions with the parsed JSON body. Each resolves to `{ status, body }` and never rejects; routing, the method and the body size are then yours:

```ts
const options = { betStore, keyStore }
fastify.post('/api/boostx/set-boost', async (request, reply) => {
  const { status, body } = await handleSetBoost(request.body, options)
  return reply.code(status).send(body)
})
// the same for handleVerifyKeys, and for handleCheckBet if your BetStore has checkBet
```

The options are `betStore` and `keyStore`. `createFetchHandler` and `createNodeHandler` check them when you create the handler, and throw `invalid_claim` for a `betStore` without `setBoost` or a `keyStore` missing `partnerPublicKeys`, `partnerPrivateKey` or `boostxPublicKey`. The per-endpoint functions check them on each call instead, and answer every call `500` with `internal server error` while what they use is invalid. `handleVerifyKeys` uses no bet store, and only `boostxPublicKey` and `partnerPrivateKey` of the key store, so `handleVerifyKeys(body, { keyStore })` works on its own. A `/verify-keys` request is always held to the 30 seconds the partner docs require.

## Error Handling

Every error the SDK raises is a `BoostxError` with a `code`:

| Code | Raised for |
|------|------------|
| `invalid_private_key` | A private key that cannot be loaded or cannot sign; a key store holding no private key for the partner ID |
| `invalid_public_key` | A public key that cannot be loaded or cannot verify (not an ECDSA P-256 public key with the `verify` usage); a key list none of whose keys can verify, or an empty one; a key store holding no such public key for the partner ID. Keys are checked before the token, so this error points at your configuration whatever the token holds |
| `invalid_booster` / `invalid_checkbet` | A Booster or CheckBet token that fails to parse or to verify; `cause` says why |
| `invalid_verify_keys` | A verify-keys token that fails; `reason` carries its wire reason |
| `invalid_gid` | A `gid` claim that is not four strings. Also in the `cause` chain, together with `invalid_signature`, when the GID signature is malformed ([INBOUND-25](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#inbound-25)) or verifies under none of the partner public keys: that pair tells a GID failure from a token-signature failure |
| `invalid_signature` | A token or GID signature that does not verify or is malformed, a token whose header `alg` is not `ES256`, or one whose header carries `crit` |
| `missing_claim` | A required value that is missing or empty |
| `invalid_claim` | A value of the wrong type or out of range; a client option (`timeoutMs`, `baseURL`, `fetch`), or a missing key store or one without `partnerPrivateKey`, thrown by the `BoostxClient` constructor; a handler option, thrown by `createFetchHandler` or `createNodeHandler` |
| `unknown_partner` | A key store that does not serve the partner ID |
| `api_error` | Any answer to a settlement but BoostX's acceptance, `{"result": {"ok": true}}`: `BoostxAPIError` |

A call with several faults fails with the first check in a fixed order: a signing function or a parser checks its key before anything else, and a parser checks a token's format and signature before its claims ([P-check-order](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#p-check-order) links each function's order).

A parser wraps the lower-level failure in `cause`, and `isBoostxError(err, code)` walks that chain, as Go's `errors.Is` does:

```ts
try {
  await parseBoosterToken(boosterJWT, boostxPublicKey, partnerPublicKeys)
} catch (err) {
  isBoostxError(err, 'invalid_booster') // true for any token this function refuses
  isBoostxError(err, 'invalid_signature') // true when the token's signature or its GID's failed
  isBoostxError(err, 'invalid_gid') // also true when the GID's signature failed, but not the token's (a GID signed with a key you no longer list)
}
```

`verifyKeysReason(err)` maps a verify-keys parse error to its wire reason: `signature`, `iss-aud`, `stale`, `shape` or `nonce-format`. It maps `invalid_public_key` to `signature` too, the reason Test integration reads as a wrong BoostX public key; the handlers answer that case `500` instead.

`BoostxAPIError` carries the HTTP `status`, and as `error` the body's `error` text, `unexpected response` for a `2xx` that is not BoostX's acceptance, or otherwise `HTTP <status>` (e.g. `HTTP 502`), never the status text; its message reads `boostx api error <status>: <error>`, e.g. `boostx api error 400: invalid-currency`. Whatever its `status`, it means the settlement is not delivered yet, so send it again: see [Submitting Settlements](#submitting-settlements). A network failure, a timeout (a `TimeoutError`), an abort from your own signal and an error your key store throws all propagate unchanged.

`createGamePassToken`, `createSettlementToken` and `buildGID` reject an empty `partner`, `user` or `bet` with `missing_claim`, before signing ([GID-07](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gid-07)): the partner docs require `user` and `bet` to be non-empty.

Some checks fire earlier than BoostX would:

- **Ill-formed Unicode.** An id containing a lone surrogate, a partner ID given to a verify-keys creator included, is rejected with `invalid_claim`, and an inbound token carrying one is malformed ([Token Format](#token-format)). The partner docs require well-formed ids, and BoostX refuses a gamepass with such an id (`401`). `eventTitle` is only displayed and is not part of the GID, so each lone surrogate in it is sent as U+FFFD, the replacement character, instead.
- **Ids.** `buildGID`, `createGamePassToken` and `createSettlementToken`, and so `submitSettlement`, reject a `partner`, `user` or `bet` that contains `:` or is longer than 32 (`partner`), 64 (`user`) or 96 (`bet`) code points with `invalid_claim` naming the id, before signing; a character outside the Basic Multilingual Plane, such as an emoji, counts as one. Only `:` itself is refused, not a look-alike such as the full-width `：`, and nothing is trimmed or normalised first. BoostX refuses a gamepass with such an id (`401`) ([GID-09](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gid-09), [GID-10](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gid-10)). The settlement builder refuses them too, so a settlement is only ever built for ids a gamepass can carry: such an id is a fault in your own code, and sending the settlement again does not clear it. Parsing an inbound token checks neither rule.
- **Stake currency.** `createGamePassToken` rejects a `currency` that is not 3 or 4 uppercase letters with `invalid_claim`, as `createSettlementToken` does for the payout currency, and maps no case: `usd` fails before signing rather than when the game opens. That is the form the partner docs give `stake.currency` ([GAMEPASS-14](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-14)).
- **Inbound tokens.** A Booster token must carry `iat`, an integer `round` of at least `1`, a finite `boost` above `0`, and `final` and `jackpot` as JSON booleans; a CheckBet token must carry `iat`. BoostX always sends them, but a token you sign for an offline test must too, or it is refused with `missing_claim` or `invalid_claim` inside `invalid_booster` or `invalid_checkbet`. BoostX sends no `exp` or `nbf`; a token that carries one is held to it with no leeway ([KEYS-42](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#keys-42)).
- **The partner ID `boostx`** is rejected by the verify-keys functions with `invalid_claim`, and a request addressed to it is answered `shape`: it would make a request's `iss` and `aud` the same as a response's.
- **`floorX` and `playerX`** reject a `decimals` other than `2` to `6` (or unset, or `0`) and a non-finite input with `invalid_claim`.
- **`settledAt`** is checked against your own clock, up to 24 hours ahead of it, as BoostX checks it against its own.
- **An `x` of `0`** is rejected with `invalid_claim`: BoostX refuses it on the gamepass that starts a bet, but adopts it on a later entry, and the game then cannot be played.

On the gamepass the SDK checks less than BoostX does, and leaves to BoostX the `[1.1, 200]` range of `x`, `xMin` and `xMax` and `xMin < xMax` (checked on the gamepass that starts a bet), and whether BoostX serves the stake `currency`.

### Token Format

Every token the SDK parses is a compact JWS, read strictly: three canonical base64url segments, a header and a payload that are each one JSON object in strict UTF-8, and of the header only `alg`, which must be `ES256`, and `crit`, which is refused. BoostX's tokens always pass, so this matters for the tokens you sign in tests. A token that fails is malformed (`invalid_booster` or `invalid_checkbet`, `shape` on `/verify-keys`, `400` from the handlers), except that a wrong `alg`, a `crit`, or a signature segment that is not 64 bytes of canonical base64url is a signature failure (`invalid_signature`, `signature`). [KEYS-67](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#keys-67) gives every rule and their order.

## Advanced Usage

### Key Loading

Load ECDSA P-256 keys from PEM files, or from PEM text or bytes:

```ts
import { loadPrivateKeyFromPEM, loadPublicKeyFromPEM } from '@boostxinnovation/partner-sdk'
import { loadPrivateKeyFromFile, loadPublicKeyFromFile } from '@boostxinnovation/partner-sdk/node'

const privateKey = await loadPrivateKeyFromFile('partner_private.pem')
const publicKey = await loadPublicKeyFromFile('boostx_public.pem')

// Or from PEM text or a Uint8Array, e.g. a secret
const privateKeyFromSecret = await loadPrivateKeyFromPEM(env.PARTNER_PRIVATE_KEY)
const publicKeyFromSecret = await loadPublicKeyFromPEM(env.BOOSTX_PUBLIC_KEY)
```

- A private key is PKCS#8 (`-----BEGIN PRIVATE KEY-----`, what the commands in the partner docs for creating the partner key pair write) or SEC1 (`-----BEGIN EC PRIVATE KEY-----`), including `openssl ecparam -genkey` output. A key saved with `-conv_form compressed` is refused: rewrite it with `openssl ec -conv_form uncompressed`.
- A public key is SPKI (`-----BEGIN PUBLIC KEY-----`) with an uncompressed point, the form your dashboard shows and accepts. A compressed point (`openssl ec -conv_form compressed`) is refused.
- Text before and after the key block is ignored, and an indented key or one whose body is on a single line loads. So does a PEM whose line breaks arrive as a literal `\n` or `\r\n`, as they often do through environment variables.
- An encrypted key (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, or an `EC PRIVATE KEY` with a `Proc-Type: 4,ENCRYPTED` header) is not supported: decrypt it first, e.g. with `openssl pkey -in encrypted.pem -out partner_private.pem`, which writes PKCS#8.
- A loader takes a string or a `Uint8Array`. Anything else, and a key that fails to load, throws the role's key error (`invalid_private_key` or `invalid_public_key`), whose message says why, e.g. an encrypted key, a PEM block of another type, or an embedded public key that does not match the private key.

The SDK checks the PEM and the key's structure itself, so a key loads or fails the same way on every runtime; the exact rules start at [KEYS-01](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#keys-01).

The loaders return non-extractable Web Crypto `CryptoKey`s. Wherever the SDK takes a key, an ECDSA P-256 `CryptoKey` you imported yourself works too, e.g. from a JWK, provided it has the `sign` or `verify` usage its role needs.

### Creating GamePass Tokens

Create a GamePass token with `createGamePassToken`.

**Call it when the player opens the game, not before.** BoostX accepts a GamePassJWT only within 300 seconds of its `iat`, and only at the moment the game is opened — a URL built ahead of time and clicked later will not start ([GAMEPASS-04](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-04)).

`createGamePassToken` stamps `iat` with the time of the call and adds no `exp`, which BoostX would enforce with no tolerance for skew. The window is therefore entirely a question of when you call it. The check is two-sided, so keep the clocks of every host that calls it NTP-synced: a host running fast fails the same way a stale token does.

```ts
const gamePassJWT = await createGamePassToken(privateKey, {
  partner: 'your-partner-id',
  user: 'user-id',
  bet: 'bet-id',
  amount: 100, // in major units: 12.5 is twelve euros fifty
  currency: 'USD',
  x: 2, // your own coefficient for the bet, never an X derived from a boost
  xMax: 10,
  eventTitle: 'Real Madrid vs Barcelona — Match Winner: Real Madrid', // optional
})
const gameURL = `https://wheel.boostx.cloud/?gamepass=${encodeURIComponent(gamePassJWT)}`
```

Load the game URL in an iframe on your page, as the partner docs describe.

| Field | Required | Notes |
|-------|----------|-------|
| `partner`, `user`, `bet` | yes | The same on every entry into a bet. Non-empty, without `:`, at most 32 (`partner`), 64 (`user`) or 96 (`bet`) code points, all checked before signing (see [Error Handling](#error-handling)). `partner` is the ID BoostX assigned you (see [Submitting Settlements](#submitting-settlements)) |
| `amount` / `currency` | yes | The stake in major units, a finite number of at least `0.01` (BoostX refuses a smaller one), and a currency code BoostX serves, e.g. `USD` or `USDT`: confirm the codes you send during onboarding. The code must be 3 or 4 uppercase letters, checked before signing |
| `x` | yes | Your own coefficient for the bet before the boost, sent as `xrange.init`. Finite and `> 0` |
| `xMin`, `xMax` | no | Left out of the token when unset, `null` or `0`, and BoostX applies `1.1` and `200`. If your own limits cap X below `200`, set `xMax` |
| `xDecimals` | no | The decimal places X is floored to, an integer from `2` to `6`. Left out when unset, `null` or `0`, and BoostX applies `2` |
| `eventTitle` | no | The title shown on the game screen; left out when unset, `null` or empty. Each lone surrogate in it is sent as U+FFFD |
| `demo` | no | `true` opens a demo game, for your tests; only `true` is sent, and `false` or `null` is left out |

BoostX refuses a gamepass that starts a bet unless `x`, `xMin` and `xMax` lie within `[1.1, 200]` and `xMin < xMax` (compared after flooring to `xDecimals`); of these, the SDK checks only `xDecimals` ([GAMEPASS-19](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-19)). A later entry's `x` is not range-checked again: BoostX adopts any finite value, and while X lies outside `[xMin, xMax]` the game is view-only, with no round playable. Keep every `x` you issue inside `[1.1, 200]` yourself. A later gamepass for a bet already in play changes only its `x` ([GAMEPASS-28](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-28)): record the `x` of each entry, since your `setBoost` derives X from it.

### Calculating X

`playerX(xBase, boost, decimals)` returns the X the player saw for a Booster token's `boost`: `1 + (xBase - 1) × boost`, floored to the bet's `xrange.decimals`. BoostX floors `xBase` onto that grid when it receives the gamepass and boosts the floored value, and floors by its own rule ([GAMEPASS-38](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-38)), which a plain `Math.floor(x * 100) / 100` does not reproduce in every round:

```ts
const x = playerX(xBase, booster.boost, decimals)
```

`xBase` is the `x` of the gamepass of the entry that sends the round: after the player reopens the game on a new `x`, BoostX boosts that one, a `final: false` round sent again included. There are two exceptions. A `final: true` regular round sent again keeps the `x` of the entry during which it was first sent. A jackpot round keeps, on every attempt, the `x` of the entry during which BoostX fixed its result, normally the entry that first sent it ([GAMEPASS-44](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-44)). The token carries no `xBase`: if the first attempt never reached you and a later entry changed `x`, the token alone cannot tell which entry's `x` applies. `decimals` is the bet's `xDecimals`; unset or `0` floors to the default `2`. With `xBase` `1.857`, `boost` `1.5` and two decimals, the player saw `2.27`, not the `2.28` that flooring only the result gives. `floorX(x, decimals)` is the flooring step alone. Both are checked against the spec's golden vectors for this rule ([GAMEPASS-38](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-38)). On a jackpot round too, the X you derive is the one the player saw.

### Submitting Settlements

Use the client to sign and submit settlement tokens to BoostX:

```ts
import { BoostxClient, MemoryKeyStore, type SettlementParams } from '@boostxinnovation/partner-sdk'
import { loadPrivateKeyFromFile } from '@boostxinnovation/partner-sdk/node'

const keyStore = new MemoryKeyStore()
keyStore.register('your-partner-id', {
  partnerPrivateKey: await loadPrivateKeyFromFile('partner_private.pem'), // outbound needs only the signing key
})
const client = new BoostxClient(keyStore)

// Build once when the bet settles and store it with the bet: a retry sends exactly these values.
const params: SettlementParams = {
  partner: 'your-partner-id',
  user: 'user-id',
  bet: 'bet-id',
  status: 'win',
  amount: 150,
  currency: 'USD',
  version: Date.now(),
  xSettle: 2.5, // your own coefficient, before the BoostX boost
  settledAt: Date.now(),
}
await client.submitSettlement(params)
```

| Field | Required | Notes |
|-------|----------|-------|
| `status` | yes | One of `win`, `lose`, `cancelled`, `refund`, `half_win`, `half_lose`, `cashout`, `unsettled` (`SETTLEMENT_STATUSES`) |
| `amount` / `currency` | yes | What actually reached the player, in major units; `0` for a loss, and `0` is the only accepted amount when `status` is `unsettled`. Currency is 3 or 4 uppercase letters, e.g. `USD` or `USDT` |
| `version` | yes | Increases per bet, need not be sequential — a millisecond timestamp works. An integer in `[0, 2^53−1]` |
| `xSettle` | no | Your own coefficient the stake is multiplied by, before the boost. Finite and `>= 0` when supplied |
| `settledAt` | yes | When **you** settled the bet, epoch milliseconds. An integer no earlier than `1e12` (2001-09-09, which rejects seconds-scale timestamps) and no more than 24 hours ahead — clocks are expected to stay in sync with BoostX |

`partner` must be the partner ID **assigned by BoostX** — the same value every inbound Booster and CheckBet token carries in `gid.partner` — not an internal ID of your own. The SDK cannot tell the two apart (both are valid strings, and your key store may well hold a key under either), but BoostX rejects a settlement signed under an ID it did not assign with HTTP `404`, and a gamepass with `401 UNAUTHORIZED`. The same rule applies to `GamePassParams.partner`.

`version` orders repeated settlements of the same bet: the highest one counts. Correcting a settlement that already went through means sending it again under a strictly higher version — if a correction can land in the same millisecond as the original, bump the timestamp by one. Versions of different bets are unrelated. `0` is a legal version.

`xSettle` is optional, and `0` is a legal value. Leave it `undefined` or `null` when there is no settled coefficient to report — most often for `cancelled`, `refund` and `unsettled` — and the field is left out of the token. `0` is sent: it means the coefficient really was `0` (the player lost everything), which is not the same as leaving the field out. Values below `1` are legal; the boost only ever applies to the part of a coefficient above `1` ([SETTLE-27](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#settle-27), [SETTLE-28](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#settle-28), [GAMEPASS-49](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gamepass-49)).

`submitSettlement` makes a single attempt and resolves only on BoostX's acceptance, a `2xx` answer whose body is `{"result": {"ok": true}}` ([SETTLE-50](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#settle-50)): member names exactly as written, the last one counting when a name repeats, and `ok` the JSON `true`. Only the first 64 KiB of an answer are read; if they are not strict UTF-8, or start with a byte order mark, the answer is neither an acceptance nor an `error` envelope. Every other outcome — any HTTP status, a `4xx` included, a network failure, a timeout, an error from your key store, even a field refused before sending — means the settlement is not delivered yet. Keep it in your own queue and send it again with a backoff until BoostX accepts it: for example over 3 days, after 1 minute, 5 minutes and 30 minutes, then hourly. If the window ends without acceptance, raise an alert and contact BoostX.

Send it again with **exactly the same fields** — the same `version`, `status`, `amount`, `currency`, `xSettle` and `settledAt`. Never re-stamp `settledAt`, or change any of them, on a retry: a re-send under a version BoostX already holds is answered `200` and its new values are silently discarded. Build the settlement once and keep it with the bet.

Never decide from a status code that a settlement is lost. A `4xx` can come from a BoostX release that a later fix undoes, and once BoostX holds the settlement, sending it again under the same version answers `200` and the duplicate is discarded, so retrying costs nothing. The `status` and `error` of a `BoostxAPIError` are for diagnosing an alert:

- **`401`:** the partner key pair or the partner ID. BoostX checks each settlement against the partner public key it holds when the settlement arrives, so once you save a new one, a settlement signed with the old private key is refused until your key store holds the new partner private key ([SETTLE-65](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#settle-65)); `submitSettlement` signs each attempt, and the `gid` inside it, with the key your key store holds at that moment. A `401` that persists once your key store and your dashboard hold the same key pair means the settlement is signed with a key BoostX does not hold for that partner ID: a wrong key, or the wrong partner ID.
- **`404` whose `error` is `not found`:** a partner ID BoostX did not assign.
- **A `3xx`, a `404` with any other `error`, or a `2xx` with any other body:** the base URL. The client follows no redirect, since a followed redirect can turn the `POST` into a request without its body. Check `baseURL` — an `http://` URL that redirects, a path BoostX does not serve (its plain-text `404`), or a host that answers with an HTML page. `error` is `HTTP <status>` for a `3xx` and such a `404`, and `unexpected response` for a `2xx`.
- **`400` whose `error` is `invalid-*`:** the field it names, e.g. `invalid-currency`.
- **`5xx`:** the BoostX side.
- **`missing_claim`, `invalid_claim` or `unknown_partner`:** refused before sending, for a field the SDK refuses or a partner ID your key store does not serve. Any other error from your key store, or from a key it holds that cannot sign, also stops the attempt before anything is sent.

```ts
try {
  await client.submitSettlement(params)
} catch (err) {
  console.warn('settlement not accepted yet', err) // its status and error diagnose an alert
  retryLater(params) // the same params, whatever the error; the next attempt signs with the key your store holds then
}
```

Keep the settlement's fields in your retry queue, not a signed token, so every retry picks up a rotated key. The client takes options, each unset when left out or `null`: `baseURL` (default `https://partners-s2s.boostx.cloud`; the Settlement endpoint your dashboard shows, which ends in `/api/integration/settlement`, works as it is), `fetch` (default the global one) and `timeoutMs` (per attempt, from the key store lookup to the answer's body, an integer number of milliseconds from `1` to `2147483647`; unset or `0` is `30000`). `baseURL` must start with `http://` or `https://` (in any case) followed by a host; spaces, tabs, line breaks, vertical tabs and form feeds around it are removed, then trailing slashes, and no other character. An empty string is refused, not read as the default. An invalid `baseURL`, `timeoutMs` or `fetch`, or a key store without `partnerPrivateKey`, throws `invalid_claim` when the client is constructed. `submitSettlement(params, { signal })` takes an `AbortSignal` of your own (`null` is none); one already aborted fails before your key store is consulted.

To create a settlement token directly without submitting (after a partner key rotation, sign it again with the new key under the same `version` and values, or it is answered `401`):

```ts
const settlementJWT = await createSettlementToken(privateKey, {
  partner: 'your-partner-id',
  user: 'user-id',
  bet: 'bet-id',
  status: 'cancelled',
  amount: 100,
  currency: 'USD',
  version: Date.now(),
  xSettle: null, // no settled coefficient for this status
  settledAt: Date.now(),
})
```

### Key Stores

The key store maps each partner ID to its keys; the handlers pass the partner ID the request names, so the store returns the right set. It is the same store as in the [Quick Start](#quick-start) — serving several partner IDs is just calling `register` more than once.

The SDK ships **`MemoryKeyStore`**, an in-memory store you preload. It satisfies both `HandlersKeyStore` and `ClientKeyStore`:

```ts
const ks = new MemoryKeyStore()
// partnerPublicKey verifies GID signatures, partnerPrivateKey signs your tokens and the
// /verify-keys response, boostxPublicKey verifies the tokens BoostX sends.
ks.register('partner-a', { partnerPublicKey: partnerAPub, partnerPrivateKey: partnerAPriv, boostxPublicKey: boostxPubForA })
ks.register('partner-b', { partnerPublicKey: partnerBPub, partnerPrivateKey: partnerBPriv, boostxPublicKey: boostxPubForB })
```

`register` replaces the whole set for that ID — a key you leave out is cleared — and is safe to call while the handlers serve requests (onboarding, rotation). A store can hold some roles only, such as the signing key alone for outbound calls: leave the others out, or set them to `null`. A lookup of a role you left out throws `invalid_public_key` or `invalid_private_key`, which the handlers answer `500`. `register` rejects an empty partner ID with `missing_claim`, and with the role's key error a key that is not ECDSA P-256 or not of its role's type (a private key as `boostxPublicKey`, say) and an empty key list, keeping the previous registration.

**Several partner public keys.** `partnerPublicKey` takes one key or a list, the current key first. After you rotate the partner key pair, BoostX accepts only the new key on what you sign, but the `gid` in `/check-bet` and `/set-boost` stays the one from the gamepass that created the game, so every game started before the rotation keeps arriving with a GID signed by the old private key ([KEYS-45](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#keys-45)). Keep the old public key in the list until those games have ended. A GID is accepted when any listed key verifies it, and a listed key that cannot verify at all is skipped:

```ts
ks.register('partner-a', {
  partnerPrivateKey: newPartnerAPriv, // signs everything from now on
  partnerPublicKey: [newPartnerAPub, oldPartnerAPub], // games started before the rotation carry the old signature
  boostxPublicKey: boostxPubForA,
})
```

For keys that live outside the process — a database or a secret manager — implement `HandlersKeyStore` yourself (and `ClientKeyStore` for outbound). It is three small async methods keyed on the partner ID:

```ts
interface HandlersKeyStore {
  partnerPublicKeys(partner: string): Promise<readonly CryptoKeyLike[]> // the current key first
  partnerPrivateKey(partner: string): Promise<CryptoKeyLike>
  boostxPublicKey(partner: string): Promise<CryptoKeyLike>
}
```

A custom store must treat its `partner` argument as authoritative: throw a `BoostxError` with the code `unknown_partner` (which the handlers answer `400`) for an ID you do not serve, never return a fixed key set regardless of the ID. Any other error is answered `500`; for the settlement client, any error your store throws, `unknown_partner` included, leaves the settlement unsent, to send again. Return ECDSA P-256 keys only. The handlers answer `500` to a BoostX public key or a partner private key on another curve, and the signing functions reject such a private key with `invalid_private_key`; a listed partner public key on another curve is skipped like any key that cannot verify, so it goes unnoticed until no listed key is P-256, and `500` is answered then. Match the ID byte for byte: no case-folding, trimming or Unicode normalisation, and no case-insensitive database collation (such as MySQL's `utf8mb4_0900_ai_ci` or SQL Server's `*_CI_*`; use a binary one). The `/verify-keys` response `iss` is the request's `aud` once your store accepts it, so a store that also accepts a differently written ID passes every Test integration stage while BoostX refuses your gamepasses (`401`) and settlements (`404`). A store that ignores the argument answers for whatever ID the inbound token names — so if the partner ID in your own configuration ever disagrees with the one BoostX assigned, every inbound check still passes locally and the mismatch only surfaces as rejected outbound calls. Even a single-tenant store therefore gates on the ID — either a `MemoryKeyStore` with one `register` call, or an explicit check:

```ts
interface PartnerKeySet {
  partnerPublicKey: CryptoKeyLike
  partnerPrivateKey: CryptoKeyLike
  boostxPublicKey: CryptoKeyLike
}

function singlePartnerKeyStore(partnerID: string, keys: PartnerKeySet): HandlersKeyStore {
  // partnerID: the ID BoostX assigned, from your own config
  const check = (partner: string) => {
    if (partner !== partnerID) throw new BoostxError('unknown_partner', `unknown partner ${JSON.stringify(partner)}`)
  }
  return {
    async partnerPublicKeys(partner) {
      check(partner)
      return [keys.partnerPublicKey]
    },
    async partnerPrivateKey(partner) {
      check(partner)
      return keys.partnerPrivateKey
    },
    async boostxPublicKey(partner) {
      check(partner)
      return keys.boostxPublicKey
    },
  }
}
```

With the store gating honestly, a token addressed to any other ID is rejected with `unknown partner "<id>"` — reported on `/verify-keys` as an `iss-aud` failure — and your own outbound signing fails just as loudly, so a wrong configured ID becomes an immediate, visible error in both directions instead of a silent echo.

### Outbound Signing

To create a token for a specific partner ID, resolve that partner's key from the same store the handlers use, then call the token factory:

```ts
async function signGamePass(params: GamePassParams): Promise<string> {
  const key = await ks.partnerPrivateKey(params.partner) // unknown_partner for an ID ks does not serve
  return createGamePassToken(key, params)
}
```

### Parsing Tokens Yourself

The handlers are built from functions you can call directly, for example in a handler of your own:

| Function | Does |
|----------|------|
| `extractBoosterPartner(boosterJWT)`, `extractCheckBetPartner(checkBetJWT)` | Return the unverified `gid.partner`, only to choose the keys to verify with |
| `parseBoosterToken(boosterJWT, boostxPublicKey, partnerPublicKeys)` | Verify a BoosterJWT and its GID; resolve to a `Booster` |
| `parseCheckBetToken(checkBetJWT, boostxPublicKey, partnerPublicKeys)` | Verify a CheckBetJWT and its GID; resolve to a `CheckBet`, `{ gid, iat }` |
| `extractVerifyKeysRequestPartner(token)` | Return the unverified `aud` of a verify-keys request |
| `parseVerifyKeysRequestToken(token, boostxPublicKey, partnerID, { maxSkewSeconds })` | Verify a verify-keys request; resolve to `{ partnerID, nonce, iat }` |
| `createVerifyKeysResponseToken(partnerPrivateKey, partnerID, nonce)` | Sign the response; `nonce` must be an integer in `[1, 2147483647]` |
| `createVerifyKeysRequestToken(boostxPrivateKey, partnerID, nonce)`, `parseVerifyKeysResponseToken(token, partnerPublicKey, partnerID, { maxSkewSeconds })` | The BoostX side of the round trip, for tests |
| `buildGID(privateKey, partner, user, bet)` | Sign a GID over its canonical bytes ([GID-02](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#gid-02)) |

There is no function to verify a gamepass of your own or a standalone GID: decode those with any JWT library, such as `jose`.

`partnerPublicKeys` is one key or a list, as in a key store. `maxSkewSeconds` is `30` (`DEFAULT_VERIFY_KEYS_MAX_SKEW_SECONDS`) when left out, `null` or `0`; a fraction is cut to whole seconds, and a negative or non-finite value throws `invalid_claim`. A verify-keys parse resolves to the token's `iat` too, in Unix seconds; its check order is [VERIFYKEYS-46](https://github.com/boostxinnovation/boostx-partner-sdk-spec/blob/v1.2.0/SPEC.md#verifykeys-46). `BOOSTX_IDENTITY` is `boostx`, the `iss` of a request and the `aud` of a response.

`createVerifyKeysRequestToken` and `parseVerifyKeysResponseToken` are test aids. They apply the SDK's own rules, the ones in [POST /verify-keys](#post-verify-keys), and do not emulate BoostX; those rules are never more lenient than BoostX's, and stricter where they differ, so a response `parseVerifyKeysResponseToken` accepts is one BoostX would accept at the same moment.

## Testing

In a clone of this repository, `npm test` runs the test suite in Node.js and in workerd, the Cloudflare Workers runtime:

```bash
npm test
```

To test your own handlers offline, play BoostX's part with a stand-in key pair: register its public key as `boostxPublicKey` in a test key store, sign tokens with its private key, and pass them to the per-endpoint functions. The SDK does not sign Booster or CheckBet tokens, so sign those with any ES256 JWT library, such as [jose](https://github.com/panva/jose); `buildGID` signs their `gid` with your own key, as in a real call:

```ts
import { SignJWT } from 'jose'

const standIn = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
keyStore.register('your-partner-id', { partnerPrivateKey, partnerPublicKey, boostxPublicKey: standIn.publicKey })

const gid = await buildGID(partnerPrivateKey, 'your-partner-id', 'user-id', 'bet-id')
const boosterJWT = await new SignJWT({ booster: { gid, round: 1, boost: 1.25, final: false, jackpot: false } })
  .setProtectedHeader({ alg: 'ES256' })
  .setIssuedAt()
  .sign(standIn.privateKey)
await handleSetBoost({ boosterJWT }, { betStore, keyStore }) // { status: 200, body: { result: { ok: true } } }

const verifyKeysJWT = await createVerifyKeysRequestToken(standIn.privateKey, 'your-partner-id', 1642938715)
await handleVerifyKeys({ verifyKeysJWT }, { betStore, keyStore }) // { status: 200, body: { result: { responseJWT } } }
```

Cover the cases the docs call out: a replayed round, a jackpot pair (round N, then round N + 1 with `jackpot: true, final: true`, then that jackpot round again), and a token signed with another key.

## Examples

- [examples/node-server.ts](examples/node-server.ts) — a `node:http` server with keys read from files and a bet store that follows the replay rule.
- [examples/cloudflare-worker.ts](examples/cloudflare-worker.ts) — a Worker with keys from secrets, which also sends settlements with `BoostxClient` and reports any that BoostX has not accepted, for your own queue to send again.

They import from `../src/`; in your own code, import from `@boostxinnovation/partner-sdk`.

## Questions

Questions about this SDK: sdk@boostxinnovation.com. Issues are disabled in this repository. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
