# Conformance vector format

These files are language-neutral test data for every BoostX partner SDK. Each SDK keeps an identical copy and runs them
with a small runner of its own. A runner is a table of operations: for each case it builds the inputs, calls the SDK,
and compares the outcome with `want`. Nothing in a vector file depends on one language.

The definitions here are neutral. Where a passage or a table also names JS and Go, it shows how the two reference
SDKs meet the definition, as an example for a runner in any language; the section "Bringing up a new language" lists
the decisions a new runner makes for itself.

| File | Content |
|------|---------|
| `FORMAT.md` | This document |
| `testkeys.json` | The shared test keys and fixed GID signatures (`keys.json` is taken by the KEYS group) |
| `keys.json` | Key loaders, key stores, JWS segment and header rules (`KEYS-*`) |
| `gidgp.json` | `buildGID`, the gamepass builder and the X helpers (`GID-*`, `GAMEPASS-*`) |
| `inbound.json` | Booster and CheckBet extraction and parsing (`INBOUND-*`) |
| `settle.json` | The settlement builder and the settlement client (`SETTLE-*`) |
| `verifykeys.json` | Verify-keys builders, extraction and parsing (`VERIFYKEYS-*`) |
| `http.json` | The endpoint handlers behind a router (`HTTP-*`) |

A rule id (`KEYS-12`) names a rule of the SDK spec. A case sits in the file of the group it was written for, whatever
operation it calls: a `KEYS-*` header rule run through the Booster parser sits in `keys.json`, and its `rules` may
also cite the rules of other groups it covers.

## 1. Files and cases

Every group file is one JSON object:

```json
{ "group": "inbound", "cases": [] }
```

Each case is an object with these members:

| Member | Required | Meaning |
|--------|----------|---------|
| `name` | yes | Unique across all files. Lowercase, digits and `-`, starting with the group name: `inbound-round-null` |
| `rules` | yes | Rule ids the case exercises, e.g. `["INBOUND-33", "KEYS-34"]` |
| `needs` | no | Tags naming inputs that some SDKs' parameter types cannot express (section 7); a runner may skip the case on them |
| `op` | yes | One operation from section 6 |
| `input` | yes | The operation's inputs; a member a case leaves out takes the default section 6 lists for it, and is absent (section 4) where section 6 lists none |
| `sigs` | no | Named GID signatures for placeholders (section 3.3) |
| `want` | yes | The expected outcome (section 5) |
| `wantZeroValue` | no | The outcome for a runner whose parameters cannot be absent (section 7) |
| `note` | no | Free text for readers; runners ignore it |

A case with several faults expects the first one in the spec's check order: check orders are normative.

The vector files themselves are plain JSON in UTF-8. They never contain a lone surrogate escape (`"\ud800"`) as a
string value, because some decoders replace it on reading: a token text that must carry one writes it escaped once
more (`"{\"bet\":\"\\ud800\"}"`, which is the six characters `\ud800` inside the token's JSON), and an ill-formed SDK
input uses `{"$illFormed": …}` (section 4). No vector file repeats a member name.

### 1.1 Shared defaults

These are the values the format falls back on where it needs one. The three ids are those of the predefined GID
signatures (3.3), and `acme` is also the partner of the default key stores (6.6, 6.7) and the default `partnerID` of
the verify-keys parsers (6.5); they are not defaults for every id input. An operation input takes a default only where
section 6 lists one, so an id or nonce a case leaves out of `gid.build`, the verify-keys builders or
`keystore.register` is absent, as in `gidgp-gid-build-bet-left-out`.

| Thing | Default |
|-------|---------|
| Partner id, user id, bet id | `acme`, `u-1`, `b-1` |
| Signing key of an inbound token | `boostx`, except a verify-keys response: `partner` |
| BoostX public key given to a parser | `boostx` |
| Partner public keys given to a parser | `["partner"]` |
| Handler mount | `/boostx` |
| Client base URL | `https://boostx.test` |

## 2. Keys

`testkeys.json` holds the key material:

```json
{
	"keys": { "partner": { "pkcs8": "…", "sec1": "…", "spki": "…", "spkiCompressed": "…" } },
	"gidSignatures": [{ "key": "partner", "partner": "acme", "user": "u-1", "bet": "b-1", "canonical": "…", "signature": "…" }]
}
```

The P-256 key pairs are `partner`, `partner2`, `boostx` and `other`, each as a PKCS#8 private PEM (`pkcs8`), a SEC1
private PEM (`sec1`) and an SPKI public PEM (`spki`). `partner` also has `spkiCompressed`, the same public key with a
compressed point (KEYS-12). `p384` is a key pair on P-384 that every loader refuses. The keys are test data and sign
nothing else. Where this document says "the platform's crypto", a runner may use any vetted ECDSA implementation, the
platform's own or a library's, but never the SDK under test.

In `input`, a member that takes a key holds a **key reference**:

- A key name (`"partner"`). The parameter's role picks the half: a private-key parameter gets the private key, a
  public-key parameter the public key. A runner loads them once with its SDK's loaders, from `pkcs8` and `spki`.
- `"@unusable"`: a value of the type the SDK's key parameter takes that is not a usable P-256 key: the `p384` key of
  that role, loaded with the platform's crypto, since the SDK's loaders refuse it. For example JS
  `crypto.subtle.importKey` with `namedCurve: 'P-384'`; Go `x509.ParsePKCS8PrivateKey` / `x509.ParsePKIXPublicKey`.
- `null`: no key, passed as section 4 says for `null` (for example JS `null`, Go `nil`). A member left out means the
  operation's default, not `null`.
- A list of references, where the parameter takes a list (partner public keys), passed in the SDK's list type.

A **PEM input** (key loaders) is one of: `"pem"`, the text itself; `"pemRef": "<name>.<form>"`, a PEM from
`testkeys.json` (`"partner.sec1"`, `"partner.spkiCompressed"`); `"pemHex"`, the bytes in lowercase hex. With `pem` or
`pemRef`, `"replace": [["from", "to"], …]` applies plain string replacements in order, every occurrence, before the
text is used: `[["\n", "\\n"]]` turns the line breaks into the two characters `\n`, as keys kept in environment
variables arrive. A runner passes `pem` and `pemRef` as text and `pemHex` as bytes where the loader takes both (for
example JS's); a loader that takes only bytes (for example Go's) gets a text input as its UTF-8 bytes, and one that
takes only text gets `pemHex` decoded as UTF-8. A vector author keeps every `pemHex` input valid UTF-8 for that
reason.

## 3. Placeholders

`${…}` placeholders make vectors independent of the clock and of ECDSA's random nonces. They are expanded in two
kinds of place:

- **Text fields**: a token's `header`, `payload` and `raw`, a request `body`, a canned response `body`, a signature's
  `text`. Every placeholder is replaced where it stands, and the result is a byte string: literal text is encoded as
  UTF-8, and `${hex:…}` inserts raw bytes.
- **JSON values** in `input` and `want`: a string that is exactly one placeholder and nothing else is replaced by the
  placeholder's value, a number for a time and a string otherwise (for `${gid:NAME}`, its JSON text). Any other string
  is literal, one that holds `${$}` beside other text included.

Nothing else is expanded: the texts of the `insert` and `append` transforms (6.8) and the hex forms (3.2) are literal.

| Placeholder | Value |
|-------------|-------|
| `${now}`, `${now+N}`, `${now-N}` | The runner's clock in whole Unix seconds, plus or minus the integer N |
| `${nowMs}`, `${nowMs+N}`, `${nowMs-N}` | `now × 1000`, plus or minus N: milliseconds from the same reading |
| `${sig:NAME}` | The base64url text of the named GID signature (3.3) |
| `${gid:NAME}` | The JSON text of a gid object for the named signature: `{"partner":…,"user":…,"bet":…,"signature":…}` with that signature's ids, members in this order, strings escaped in any valid JSON way |
| `${gid}` | `${gid:gid}` |
| `${hex:HH…}` | Raw bytes, two lowercase hex digits each (text fields only) |
| `${token}` | The case's token (6.7), JSON-string-escaped without quotes: `"`, `\` and C0 controls are escaped, each in any valid JSON escape (`\n` and `\u000a` alike, since the body decodes them the same), and nothing else (text fields of `http.serve` only) |
| `${$}` | A literal `$`: in a text field `${$}{now}` is the text `${now}`; in a JSON value only the string `"${$}"` itself becomes `$`, and `"${$}{now}"`, not one placeholder, stays as written |

### 3.1 The clock

A runner reads its clock **once per case**, before it builds anything, and uses that `now` for every expansion in the
case. The SDK reads its own clock later, so it sees some `now'` with `now ≤ now' ≤ now + 5`. Every vector is written
to have the same outcome for every such `now'`:

- A boundary is allowed when it holds as time moves forward. `exp: ${now}` is refused at `now` and after it; `nbf:
  ${now}` is accepted at `now` and after it; a verify-keys `iat: ${now+30}` is inside the 30 s window from `now` to
  `now + 60`.
- A boundary that time moves across is not allowed: `iat: ${now-30}` leaves the window one second later, and `nbf:
  ${now+1}` enters it. Such cases keep at least 10 seconds from the edge (`${now-40}` is stale, `${now-20}` is not).
- The same holds for milliseconds (`settledAt` may be at most 24 h ahead): `${nowMs+86400000}` is accepted at every
  later instant, and a refused value keeps 10 s of margin, `${nowMs+86410000}`.

No SDK needs a clock hook for this. An SDK may accept an optional clock that defaults to the system time, but a runner
never sets it: the vectors run against the clock the SDK reads by default. A runner may still pin the platform's own
time source at `now × 1000 + 500` ms for repeatable runs, from outside the SDK (for example a JS runner with
`vi.spyOn(Date, 'now')`); otherwise it uses the real clock (for example a Go runner).

In `want`, a time expression matches any integer `t` from its value to 5 seconds after it (`value + 5` for `now`
expressions, `value + 5000` for `nowMs` ones), since the SDK reads its clock after the runner did: `"iat": "${now}"`
on a builder's payload accepts the `iat` the SDK stamped.

### 3.2 Bytes

`${hex:…}` is how a vector writes bytes that are not text: `${hex:efbbbf}` is a byte order mark, `${hex:ff}` and
`${hex:c0af}` are invalid UTF-8. A whole segment may be given in hex instead (`headerHex`, `payloadHex`, `bodyHex`);
those are not expanded.

### 3.3 GID signatures

A signature placeholder names an entry of the case's `sigs`, or one of the predefined names:

| Name | Value |
|------|-------|
| `gid` | The fixed signature in `testkeys.json` by `partner` over `acme`, `u-1`, `b-1` |
| `gid2` | The fixed signature in `testkeys.json` by `partner2` over the same ids |

The fixed signatures are canonical and each contains both `-` and `_`, so a hand-written variant (standard alphabet,
padding, stray trailing bits) is a literal edit. A case's `sigs` entry is one of:

- `{"key": "partner", "partner": "acme", "user": "u-2", "bet": "b-9"}`: the runner calls its SDK's GID builder (the
  operation `gid.build`) with the private key and those ids and takes the signature. The ids must be ones the builder
  accepts.
- `{"key": "partner", "text": "…"}`: an ES256 signature over exactly the bytes of `text` (expanded), made with the
  platform's crypto, as base64url of the 64-byte `r || s`. This is how a vector signs bytes the GID builder would not.
- `{"fixed": "…"}`: the text as given.

`${gid:NAME}` needs the ids form or a predefined name.

## 4. Special input values

| Value | Meaning |
|-------|---------|
| member left out | Absent: the language's "not given", an argument not passed or an option or parameter-set member not set. Where a parameter cannot be absent, its zero value (section 7). For example JS: property not set; Python: argument not passed; Go: the zero value. Where the SDK's signature makes an argument required, so that the language refuses a call leaving it out before the SDK runs (a Python positional parameter without a default), the runner passes null for it: the spec reads null as absent, so the outcome is the same, and such a case carries no `needs` tag (`gidgp-gid-build-bet-left-out`, `verifykeys-create-response-nonce-left-out`) |
| `null` | The language's null (for example JS `null`, Python `None`, Go `nil`). Where a parameter cannot hold null, the same as left out (for example a Go struct field: its zero value). The spec reads null as absent; vectors check that |
| `{"$number": "NaN"}`, `"Infinity"`, `"-Infinity"`, `"-0"` | Numbers JSON cannot write, as binary64 values. They appear in `want` too (5.3) |
| `{"$illFormed": "abc"}` | The string `abc` followed by one unit that makes it ill-formed Unicode, in the SDK's string type: a lone surrogate U+D800 where a string is a sequence of UTF-16 code units or of code points (for example JS, Java, C#, Python `str`), the byte `0xFF` where it is a sequence of bytes (for example Go, PHP). Where the SDK replaces it (an event title), it becomes exactly one U+FFFD. Every case that uses it carries the `needs` tag `ill-formed-string`, so an SDK whose string type cannot hold ill-formed text may skip it (section 7) |
| `"${…}"` | A placeholder (section 3) |

## 5. Expected outcomes

`want` has exactly one of `ok`, `error` or `failure`, plus checks that apply to either.

### 5.1 Errors

```json
{ "error": ["invalid_booster", "missing_claim"], "field": "round" }
```

`error` is the **set** of taxonomy categories the error carries, through its whole cause chain, and it must match
exactly: no category missing, none extra. A runner computes the set by testing the error for each category below with
the check its SDK records for that category ("Bringing up a new language"), which finds the category anywhere in the
cause chain: the language's standard chain walk where it has one, otherwise the SDK's own check. For example JS
`isBoostxError(err, code)`; Go `errors.Is(err, sentinel)`, and `errors.As` for the API error. The JS and Go columns
show how those two SDKs spell each category. An empty set, `"error": []`, is an error that carries none of them: one
from outside the SDK, such as a store's own error, that the SDK lets through (SPEC SETTLE-58); the call must still
fail with an error.

| Category | JS (`BoostxError.code`) | Go |
|----------|------------------------|----|
| `invalid_private_key` | `invalid_private_key` | `ErrInvalidPrivateKey` |
| `invalid_public_key` | `invalid_public_key` | `ErrInvalidPublicKey` |
| `invalid_booster` | `invalid_booster` | `ErrInvalidBooster` |
| `invalid_checkbet` | `invalid_checkbet` | `ErrInvalidCheckBet` |
| `invalid_verify_keys` | `invalid_verify_keys` | `ErrInvalidVerifyKeys` (the reason errors `ErrVerifyKeysShape`, `…IssAud`, `…Stale`, `…Nonce` wrap it) |
| `invalid_gid` | `invalid_gid` | `ErrInvalidGID` |
| `invalid_signature` | `invalid_signature` | `ErrInvalidSignature` |
| `missing_claim` | `missing_claim` | `ErrMissingClaim` |
| `invalid_claim` | `invalid_claim` | `ErrInvalidClaim` |
| `unknown_partner` | `unknown_partner` | `ErrUnknownPartner` (package `keys`) |
| `api_error` | `api_error` (`BoostxAPIError`) | `*client.APIError`, by `errors.As` |

No other category is in conformance: an `invalid_gamepass` belongs to a gamepass parser, which is outside it, and the
bet store's round rejection is raised by the partner's store, not by the SDK. (In Go the sentinels live in package
`tokens` unless noted, the `boostx` facade re-exports each under the same name, and those two are `ErrInvalidGamePass`
and `ErrRoundRejected`.)

Further error checks, each compared only when present:

| Member | Check |
|--------|-------|
| `field` | The claim or parameter the error names. An error about one named claim or parameter carries `missing required claim: <field>` or `invalid claim value: <field>…` in its message, with the field tokens the spec lists for these messages; the runner takes the message of the error the operation raised (the outermost of the chain), takes the text after the **last** of those two phrases, and reads the longest run of `[A-Za-z0-9_.]` (the `.` is there for `gid.partner`, so a message that puts a full stop right after the token, `invalid claim value: amount.`, reads as `amount.`; SPEC HTTP-72). Give `field` only with `missing_claim` or `invalid_claim`, and only where the error is about one named claim or parameter |
| `reason` | The verify-keys wire reason, as the SDK's reason mapper returns it for the error (for example JS `verifyKeysReason(err)`, Go `tokens.VerifyKeysReason(err)`) |
| `status` | `api_error` only: the HTTP status the API error carries (for example JS `.status`, Go `.StatusCode`) |
| `apiError` | `api_error` only: the error text the API error carries, exactly (for example JS `.error`, Go `.Message`) |
| `at` | `"construct"`: the error comes from building the client or the handler, before any call (6.6, 6.7). An SDK that refuses construction by panicking or aborting rather than raising an error (the spec allows either; Go panics) has its runner expect that, and check nothing else about it |

### 5.2 Failures outside the taxonomy

`"failure": "cancelled" | "timeout" | "network"` is an error outside the taxonomy that the SDK lets through,
unchanged or wrapped so that the platform's standard check for that kind of failure still matches it. Each is defined
by what happened, and a runner recognises it with the check its SDK records for it ("Bringing up a new language"):

| Failure | What happened | JS | Go |
|---------|---------------|----|----|
| `cancelled` | The caller cancelled the call (`cancel`, 6.6), before or during it; the error is the platform's cancellation error, or that of the SDK's own token type | the abort signal's reason (an `AbortError` for `controller.abort()`) | `errors.Is(err, context.Canceled)` |
| `timeout` | The call's time limit expired (`options.timeoutMs`, 6.6); the error is the platform's timeout error, or the one its HTTP stack raises when a request's time limit expires | a `TimeoutError` (`AbortSignal.timeout`) | `errors.Is(err, context.DeadlineExceeded)`, or a `net.Error` whose `Timeout()` is true |
| `network` | The transport failed before any answer (`networkError`, 6.6); the error is the transport's own | the transport's error (a `TypeError` from `fetch`) | an error from the HTTP transport (`*url.Error`) |

### 5.3 Accepted results

`ok` is what the operation returned, in the neutral names of section 6. Only the members listed are compared; others are
not. Objects compare member by member the same way, recursively; arrays compare element by element and must have the
same length; numbers compare as binary64 with `==` (so `-0` equals `0`); strings compare code unit for code unit. A
placeholder in `want` is expanded first, and a time expression matches as section 3.1 says; a `{"$number": …}` in `want`
is the number it names (section 4).

For a builder, `ok` describes the token it returned (6.2): `payload` is compared as above against the decoded payload
JSON, and `absent` lists dotted member paths (`"gamepass.xrange.min"`) that must not exist in it. Every accepted builder
result is also checked, with no member needed: the token has three canonical base64url segments; the header is a JSON
object whose only members are `alg` `"ES256"` and `typ` `"JWT"`, in any order; the signature verifies with the public
half of the signing key; and a payload `gid`, the `gid` member of the payload's root claim (`gamepass.gid`,
`settlement.gid`; a verify-keys token has none), verifies against that same public key: the runner rebuilds the
canonical GID bytes (GID-02) from the gid's ids and verifies its `signature` over them with the platform's crypto, or
calls a GID verifier of the SDK's own, public or internal (for example Go's public `tokens.VerifyGID`, or the JS SDK's
internal one). This check is the runner's, not an operation under test, so it is the one place a runner may reach past
the SDK's public API.

### 5.4 Store checks

Handlers and the client record what they asked of the stores. `"keyStoreCalled": false` means no key-store method
ran at all; `true` means at least one did. `"betStoreCalled"` is the same for the bet store. Which lookups run and in
what order is not compared, since a handler may run them concurrently (KEYS-52).

## 6. Operations

Inputs use neutral names. A runner passes each to its SDK's counterpart, the spec's required surface for that
operation, with the SDK's own names, argument order and idiom. The JS and Go columns show the two reference SDKs'
counterparts.

### 6.1 Keys: `key.loadPrivate`, `key.loadPublic`, `keystore.register`

`key.loadPrivate` / `key.loadPublic` take a PEM input (section 2) and call the SDK's PEM loaders: for example JS
`loadPrivateKeyFromPEM(text)` / `loadPublicKeyFromPEM(text)` (bytes for `pemHex`); Go
`keys.LoadPrivateKeyFromPEM([]byte)` / `keys.LoadPublicKeyFromPEM([]byte)`. `ok`: `{"matches": "<key name>"}`, the
loaded key is that key pair's half: the runner signs a message with one side and verifies it with the other, using the
platform's crypto.

`keystore.register` registers one partner in the SDK's in-memory key store, then runs lookups:

| Input | Meaning | JS `MemoryKeyStore.register(partner, keys)` | Go `MemoryKeyStore` |
|-------|---------|---------------------------------------------|---------------------|
| `partner` | The partner id | `partner` | first argument |
| `partnerPublicKey`: reference, list, `null` or left out | The partner public key or keys; a list stays a list, and an SDK with a separate list registration uses it for a list. A single reference goes to the SDK's single-key form or, where the registration takes only a list, in a one-element list, which registers the same key set (SPEC section 3.1, `keystore.register`) | `keys.partnerPublicKey` | a list: `RegisterWithPartnerPublicKeys`; otherwise `Register` with the key or `nil` |
| `partnerPrivateKey` | The partner private key | `keys.partnerPrivateKey` | `partnerPriv` |
| `boostxPublicKey` | The BoostX public key | `keys.boostxPublicKey` | `boostxPub` |
| `lookups`: `[{"method", "partner", "want"}]` | Lookups run in order after the registration, through the lookups `partnerPublicKeys`, `partnerPrivateKey` and `boostxPublicKey` of the handler key-store contract, with no cancellation | same names | `PartnerPublicKeys`, `PartnerPrivateKey`, `BoostxPublicKey` (with `context.Background()`) |

`want` is the registration's outcome (`{"ok": {}}` when it succeeds), and each lookup's `want` its own. A lookup's
`ok` is `{"keys": ["partner"]}` for `partnerPublicKeys` and `{"key": "partner"}` for the others, compared by key
identity: the lookup returns the key the runner registered for that role. JS and Go compare the handle itself (`===`,
pointer equality); a runner whose SDK stores or returns a copy or a wrapper of the key compares the key material instead
(the public point, or the private scalar).

### 6.2 Builders: `gid.build`, `gamepass.create`, `settlement.create`, `verifykeys.createRequest`, `verifykeys.createResponse`

Each takes `key`, the private-key reference it signs with, and its parameters, and calls the SDK's builder for that
operation.

| Op | Parameters | JS | Go |
|----|-----------|----|----|
| `gid.build` | `partner`, `user`, `bet` | `buildGID(key, partner, user, bet)` | `tokens.BuildGID(partner, user, bet, key)` |
| `gamepass.create` | `params` | `createGamePassToken(key, params)` | `tokens.CreateGamePassToken(key, params)` |
| `settlement.create` | `params` | `createSettlementToken(key, params)` | `tokens.CreateSettlementToken(key, params)` |
| `verifykeys.createRequest` | `partnerID`, `nonce` | `createVerifyKeysRequestToken(key, partnerID, nonce)` | `tokens.CreateVerifyKeysRequestToken(key, partnerID, int32(nonce))` |
| `verifykeys.createResponse` | `partnerID`, `nonce` | `createVerifyKeysResponseToken(key, partnerID, nonce)` | `tokens.CreateVerifyKeysResponseToken(key, partnerID, int32(nonce))` |

Default `key`: `partner` for all but `verifykeys.createRequest`, whose default is `boostx`. `params` is an object of
the neutral names below, from which the runner builds the SDK's parameter set, leaving out what the case leaves out.
`"params": null` is a missing parameter set, passed as the language's null (for example JS `null`); a runner that
cannot pass one may skip the case by its `missing-params` tag, and one that can passes it (section 7).

| Neutral | JS | Go `GamePassParams` |
|---------|----|---------------------|
| `partner`, `user`, `bet` | same | `Partner`, `User`, `Bet` |
| `amount`, `currency` | same | `Amount`, `Currency` |
| `x` | `x` | `X` |
| `xMin`, `xMax`, `xDecimals` | same | `XMin`, `XMax`, `XDecimals` |
| `eventTitle`, `demo` | same | `EventTitle`, `Demo` |

| Neutral | JS | Go `SettlementParams` |
|---------|----|-----------------------|
| `partner`, `user`, `bet` | same | `Partner`, `User`, `Bet` |
| `status` | `status` | `Status` |
| `amount`, `currency` | same | `Amount`, `Currency` |
| `version` | `version` | `Version` (`int64`) |
| `xSettle` | `xSettle` | `XSettle` (`*float64`: left out or `null` is `nil`; a number is a pointer to it) |
| `settledAt` | `settledAt` | `SettledAt` (`int64`) |

`ok` for `gid.build`: `{"gid": {"partner", "user", "bet"}, "canonical": "…"}`. The ids compare as usual, and when
`canonical` is given, the returned signature must verify, with the platform's crypto and the key's public half, over
exactly the UTF-8 bytes of `canonical`: that is how a vector pins the canonical GID bytes without a function to
export them. Without `canonical`, only the ids are compared (JS and Go check nothing more); a runner may also verify
the signature over canonical bytes it rebuilds itself, as 5.3 does for a payload `gid`. `ok` for the token builders:
`{"payload": {…}, "absent": […]}` (5.3).

### 6.3 X helpers: `x.floor`, `x.player`

| Op | Inputs | JS | Go |
|----|--------|----|----|
| `x.floor` | `x`, `decimals` | `floorX(x, decimals)` | `tokens.FloorX(x, decimals)` |
| `x.player` | `xBase`, `boost`, `decimals` | `playerX(xBase, boost, decimals)` | `tokens.PlayerX(xBase, boost, decimals)` |

`decimals` left out or `null` is passed as absent, or as `0` where the parameter cannot be absent (for example Go),
which the spec reads the same way. `ok`: `{"value": n}`. An error is `invalid_claim`. The spec lets a helper signal
that error with a non-finite result instead: `NaN` for an out-of-domain `decimals` (SPEC GAMEPASS-40, for example
Go's), and `NaN` or an infinity for a non-finite input (GAMEPASS-41). So where `want` is `{"error": ["invalid_claim"]}`,
a runner accepts a non-finite result as that error, and a finite one fails the case; where `want` is `ok`, the result
compares as it is (`gidgp-x-player-overflow-infinity` expects +Infinity). Both rules leave the choice between raising
and the non-finite result to the SDK, in their `Implementation-defined:` paragraphs (SPEC GAMEPASS-40, GAMEPASS-41), so
the vectors accept either.

### 6.4 Inbound: `booster.extract`, `booster.parse`, `checkbet.extract`, `checkbet.parse`

| Op | Inputs | JS | Go |
|----|--------|----|----|
| `booster.extract` | `token` | `extractBoosterPartner(token)` | `tokens.ExtractBoosterPartner(token)` |
| `booster.parse` | `token`, `boostxKey`, `partnerKeys` | `parseBoosterToken(token, boostxKey, partnerKeys)` | `tokens.ParseBoosterTokenWithKeys(token, boostxKey, partnerKeys)` |
| `checkbet.extract` | `token` | `extractCheckBetPartner(token)` | `tokens.ExtractCheckBetPartner(token)` |
| `checkbet.parse` | `token`, `boostxKey`, `partnerKeys` | `parseCheckBetToken(…)` | `tokens.ParseCheckBetTokenWithKeys(…)` |

`token` is a token spec (6.8). `boostxKey` defaults to `"boostx"` and `partnerKeys` to `["partner"]`; `partnerKeys` is
always a list, passed in the SDK's list type.

`ok` for an extraction: `{"partner": "acme"}`. For a Booster: `{"gid": {"partner", "user", "bet", "signature"},
"round", "boost", "final", "jackpot", "iat"}`; for a CheckBet: `{"gid": {…}, "iat"}`. These are the spec's neutral
result fields, onto which the runner maps its SDK's result: for example JS returns `gid` nested and `iat`; Go embeds
the GID's `Partner`, `User`, `Bet`, `Signature` and names the rest `Round`, `Boost`, `Final`, `Jackpot`, `IssuedAt`.

### 6.5 Verify-keys: `verifykeys.extractRequest`, `verifykeys.parseRequest`, `verifykeys.parseResponse`

| Op | Inputs | JS | Go |
|----|--------|----|----|
| `verifykeys.extractRequest` | `token` | `extractVerifyKeysRequestPartner(token)` | `tokens.ExtractVerifyKeysRequestPartner(token)` |
| `verifykeys.parseRequest` | `token`, `key`, `partnerID`, `windowSeconds` | `parseVerifyKeysRequestToken(token, key, partnerID, {maxSkewSeconds})` | `tokens.ParseVerifyKeysRequestToken(token, key, partnerID, maxSkew)` |
| `verifykeys.parseResponse` | same | `parseVerifyKeysResponseToken(…)` | `tokens.ParseVerifyKeysResponseToken(…)` |

`key` is the verifying public key: default `boostx` for a request and `partner` for a response, which are also the
default signing keys of the token. `partnerID` defaults to `"acme"`. `windowSeconds` is the parse function's window
(VERIFYKEYS-38) in seconds, passed in the SDK's own window type and unit without rounding (`0.5` stays half a second,
`60.9` stays above 60). Left out, no window is given; `null` is passed as section 4 says. For example JS passes no
options when it is left out, `{maxSkewSeconds: null}` for `null` and `{maxSkewSeconds: windowSeconds}` for a number; Go
passes `0` for left out and `null`, and `time.Duration(windowSeconds × 1e9)` for a number.

`ok`: `{"partner": "acme"}` for an extraction; `{"partnerID", "nonce", "iat"}` for a parse (for example Go
`PartnerID`, `Nonce`, `IssuedAt`). Every verify-keys error case also gives `reason` when the error is
`invalid_verify_keys`.

### 6.6 Settlement client: `client.submit`

| Input | Meaning | JS | Go |
|-------|---------|----|----|
| `keyStore` | `{"<partner>": <role value>}`: a fake of the SDK's client key-store contract, answering by the role values of 6.7; default `{"acme": "partner"}`. `"keyStore": null` is no store, a construction error | an object with `partnerPrivateKey` | a `client.KeyStore` |
| `options.baseURL` | The base URL construction option. Left out: `https://boostx.test`; `null`: none given, so the SDK default | `new BoostxClient(store, {baseURL})` | `client.WithBaseURL`, not passed for `null` |
| `options.timeoutMs` | The per-attempt time limit in milliseconds, passed in the SDK's own unit and type; left out: none given | `timeoutMs` | the `Timeout` of the injected client, `client.WithHTTPClient(&http.Client{Timeout: ms, Transport: fake})` |
| `params` | Settlement parameters (6.2), given to the SDK's submit call | `submitSettlement(params, {signal})` | `SubmitSettlement(ctx, params)` |
| `cancel` | The call's cancellation: the platform's standard primitive (a handle passed to the call, or cancelling the task that runs it, where that is the platform's way), or a token type the SDK defines where the platform has none. `"before"`: cancelled before the call; `{"afterMs": n}`: cancelled n ms after the call starts; `null`: passed as section 4 says; left out: no handle. Where cancelling the task is the primitive (for example Python's asyncio), there is no handle, so `null` and left out are the same, no cancellation; `"before"` cancels the task before it starts, so the call never runs and no store is consulted, which is what SPEC SETTLE-59 step 2 asks | `AbortController` | `context.WithCancel` |
| `response` | The canned answer the fake transport serves (below) | a fake `fetch` | a fake `http.RoundTripper` |

The runner always injects its fake transport through the SDK's transport injection (SETTLE-68), so nothing reaches
the network: for example JS through `options.fetch`, Go through `WithHTTPClient` (with `Timeout` left 0 when
`timeoutMs` is not given, which the SDK reads as its default). The fake serves `response`:

| Member | Meaning |
|--------|---------|
| `status` | HTTP status; default 200 |
| `headers` | Response headers; default `{"content-type": "application/json"}` |
| `body` | Text with placeholders, or `bodyHex`; default empty |
| `padTo`, `padAt` | Insert `0x20` bytes at byte offset `padAt` (negative counts from the end; default the end) until the body is `padTo` bytes long |
| `delayMs` | Wait before answering with status and headers. When the SDK cancels the request first (the caller's cancellation or the time limit), the wait ends at once and the request fails as the platform's transport fails a cancelled request, with the reason the SDK cancelled it (for example a JS fake rejects with the signal's `reason`; a Go fake returns the request context's error) |
| `bodyDelayMs` | Wait after the headers before the first body byte, ending early the same way, as a failed body read |
| `networkError` | `true`: fail the request instead, with the error the platform's transport raises when it gets no answer (for example a JS fake throws a `TypeError`; a Go fake returns an error, which the client wraps in a `*url.Error`) |

A redirect status is served like any other, and the runner checks that the SDK does not follow it (SETTLE-49), in
whichever way fits where the fake sits. Where the fake replaces the layer that would follow redirects, that layer is
gone and never follows, so the runner reads the SDK's no-follow setting on every request: for example a JS fake `fetch`
checks `init.redirect === 'manual'`. Where the fake sits below a layer that would follow, the runner observes that no
follow-up request reaches the fake (the redirect cases carry a `location` header to follow): for example a Go fake
`http.RoundTripper` fails the case when a request arrives with `req.Response` set, which `http.Client` does only when
following, and a fake mounted under any HTTP client that can follow (for example as an `httpx` transport) works the
same way. Which layer the SDK lets the caller inject at is the SDK's choice (SPEC SETTLE-68); the vectors pass through
either. `want` may add:

| Member | Check |
|--------|-------|
| `requests` | The number of HTTP requests sent |
| `request` | The one request sent: `url`, `method` and `contentType` compare exactly; the body must be a JSON object whose only member is `settlementJWT`, a token that passes the builder checks of 5.3, and `payload` and `absent` compare its payload as 5.3 does for a builder |
| `keyStoreCalled` | As in 5.4 |

### 6.7 Handlers: `http.serve`

The runner builds the SDK's router, the one that serves all three endpoints (HTTP-66), over a fake key store and a
fake bet store, sends one request, and compares the response. The conformance target is this framework-neutral core:

```
handle(method, path, bodyBytes, cancel?) -> {status, headers, body}
```

`method` is the request method; `path` the request target as sent, the path with its query if any and no scheme or host
(`/boostx/set-boost?x=1`); `bodyBytes` the body, empty when there is none; and `cancel` the request's own cancellation,
which the router passes to the stores where the platform does. Where cancelling the task that runs the request is the
platform's cancellation (for example Python's asyncio), the core takes no `cancel`: cancelling that task cancels the
store call it awaits. No case cancels a request, so a runner passes none. The answer is the status, the response headers
(names compared ASCII case-insensitively) and the body bytes. An SDK need not offer `handle` itself, and no public API
has to change for it: the runner reaches the core through an adapter of its own over the router the SDK offers. For
example, a JS runner calls
`createFetchHandler({betStore, keyStore})(new Request('https://partner.test' + path, {method, body}))` and reads the
`Response`; a Go runner calls `handlers.Mount(mux, mount, betStore, keyStore)` on a new `http.ServeMux`, then
`mux.ServeHTTP` with an `httptest.NewRecorder()`. Building the router is construction (`at`, 5.1).

| Input | Meaning; default |
|-------|------------------|
| `mount` | The mount path, given to a router that takes a prefix (HTTP-68); `/boostx`. A router that dispatches on the last path segment takes none (for example JS's) |
| `endpoint` | `set-boost`, `check-bet` or `verify-keys`; sets the default request below |
| `token` | A token spec (6.8), for `${token}` |
| `request.method` | `POST` |
| `request.path` | The mount with one trailing `/` removed (HTTP-68), then `/<endpoint>`: `/boostx/set-boost`, and `/set-boost` for the mount `/` or the empty mount |
| `request.body` | Text with placeholders, or `bodyHex`; default, when `token` is given, `{"boosterJWT":"${token}"}`, `{"checkbetJWT":"${token}"}` or `{"verifyKeysJWT":"${token}"}` by endpoint, and otherwise empty. A `GET` or `HEAD` request carries no body: the runner sends none, whatever `request.body` says (the cases that give one give the empty text, and the method check answers before any body is read) |
| `request.padTo`, `request.padAt` | As for a response body |
| `keyStore` | `{"<partner>": {"partnerPublicKeys": …, "partnerPrivateKey": …, "boostxPublicKey": …}}`; default `{"acme": {"partnerPublicKeys": ["partner"], "partnerPrivateKey": "partner", "boostxPublicKey": "boostx"}}`. Every entry gives all three roles; a runner reads a role an entry leaves out as `null`. `"keyStore": null` is no store, a construction error |
| `betStore` | `{"setBoost": …, "checkBet": …}`; default `{"setBoost": "ok", "checkBet": true}`, member by member: a member the case leaves out takes its default, so `{"setBoost": "reject"}` still has the check, answering `true` (only `"checkBet": "absent"` removes it) |

**Role values** in either key store: a key reference, which for `partnerPublicKeys` is a list of references (the
vectors always give a list there, and a single reference there would stand for a one-element list); `"@unusable"`;
`null`, which fails the lookup with the role's invalid-key error as an in-memory store does for a role it was not
given; `{"error": "unknown_partner"}`; `{"error": "other"}`, a plain error from outside the SDK; or
`{"key": <reference>, "delayMs": n}`, which answers after n ms; where the store contract passes a cancellation handle,
a handle cancelled or expired before then ends the wait at once and fails the lookup with the handle's error. A
partner id the store does not list fails with `unknown_partner`. A fake implements every lookup of the SDK's key-store
contract from these values, optional and single-key forms included: for example a Go fake implements
`PartnerPublicKeys`, and `PartnerPublicKey` answering the list's first key; JS fakes are async functions.

For `null`, a fake raises the role's invalid-key error the way its SDK lets a store raise an SDK error: for example a
JS fake throws `new BoostxError('invalid_private_key', …)` and a Go fake returns an error that wraps
`tokens.ErrInvalidPrivateKey`. An SDK need not offer stores a way to raise any category but `unknown_partner` (SPEC
section 3.1, `keystore.lookup`); a runner whose SDK offers none asks the SDK's in-memory store, registered for that
partner without the role, and passes on the error its lookup raises. Nothing more is observable: a handler answers
every lookup error but `unknown_partner` alike (SPEC KEYS-50), and a client whose store returns no key fails with the
same `invalid_private_key`, from the builder's key check (SPEC SETTLE-60). A handler store that returns no key is a
different case, which SPEC KEYS-53 answers with another text, so a handler fake never answers `null` that way.

**Bet store** `setBoost`: `"ok"`; `"reject"`, the SDK's round rejection (for example JS
`throw new RoundRejectedError()`, Go `return handlers.ErrRoundRejected`); `"reject-wrapped"`, a plain error whose
cause chain holds the round rejection (for example JS `new Error('x', {cause: new RoundRejectedError()})`, Go
`fmt.Errorf("x: %w", handlers.ErrRoundRejected)`); `"error"`, a plain error. `checkBet`: `true` or `false`, the
verdict; `"error"`, a plain error; `"absent"`, the store does not offer the optional check (for example JS leaves out
`checkBet`; Go's store does not implement `BetStoreChecker`); any other value, `null` included, is the verdict the check
returns as it is (the cases tagged `untyped-bool`).

`want`:

| Member | Check |
|--------|-------|
| `status` | The HTTP status; required, except in a construction case (`at`), where no request is sent |
| `error` | A string: the body is exactly `{"error": "<text>"}`. An array, which comes with `at: "construct"`: the category set of the construction error (5.1), and no request is sent |
| `errorPrefix` | The body is an object whose only member is `error`, a string starting with this text: for answers that echo an id, whose escaping is free |
| `body` | The body, parsed as JSON, equals this value exactly (no subset rule here) |
| `allow` | The `Allow` header |
| `routerMayAnswer` | `true`: a host router may answer this request before the SDK (404, 405). Where the runner's router leaves this answer to a host router (for example Go's `ServeMux` under `Mount`), the body is not compared; `status` and `allow` still are. Where the SDK answers it itself (for example JS's `createFetchHandler`), `error` is compared as usual, since SPEC HTTP-03 and HTTP-04 fix those texts. The runner records which answers a host router gives in its SDK's place ("Bringing up a new language") |
| `setBoostArg` | The value the bet store's `setBoost` received, compared as a Booster `ok` (6.4) |
| `checkBetArg` | The gid `checkBet` received: `{"partner", "user", "bet", "signature"}` |
| `responseJWT` | `{"key", "partnerID", "nonce"}`: the body's `result.responseJWT` passes `verifykeys.parseResponse` with that public key and partner id, and carries that nonce |
| `keyStoreCalled`, `betStoreCalled` | As in 5.4 |

### 6.8 Token specs

A token spec builds the token text an inbound operation receives. Either:

```json
{ "raw": "a.b.c" }
```

the token text as given (placeholders expanded, no signing), or a token assembled and signed by the runner:

| Member | Meaning; default |
|--------|------------------|
| `header` / `headerHex` | Header JSON text with placeholders, or its bytes in hex; `{"alg":"ES256","typ":"JWT"}` |
| `payload` / `payloadHex` | Payload JSON text with placeholders, or its bytes in hex; required |
| `headerSegment`, `payloadSegment` | Transforms of the encoded segment, applied **before** signing, so the signature covers the transformed text |
| `key` | The signing key reference; the operation's default signing key |
| `signature` | Transforms of the signature segment, applied after signing |
| `transform` | Transforms of the whole token text, applied last |

The runner encodes header and payload bytes as canonical unpadded base64url, applies the segment transforms, signs
`header + "." + payload` (the transformed texts as UTF-8 bytes, which are ASCII unless a transform inserted other
characters) with ES256 using the platform's crypto, encodes the 64-byte `r || s` signature, applies the signature
transforms, joins the three with `.` and applies the token transforms. Any ES256 library will do, as long as the
runner ends up with the raw `r || s`, each half left-padded to 32 bytes: a library that returns a DER signature needs
its two integers taken out and padded. For example JS
`crypto.subtle.sign` returns `r || s` as it is; Go's `ecdsa.Sign` returns `r` and `s`, written with `FillBytes` into
32-byte halves.

Transforms, each a string or a one-member object, apply in list order, each to the text the previous one left. `flip`
decodes that text, so it needs a canonical one: no vector puts `flip` after a transform that makes the text
non-canonical, and a runner may fail such a list as a broken vector. A negative offset `n` in `insert` means the
offset `length + n`, counted in characters, so `-1` inserts before the last character and `0` at the start; the end is
reached with `append`. Offsets and `truncate` counts are in characters of the text, never in bytes, and no vector
applies `insert` or `truncate` to a text that holds a character outside ASCII, so a runner whose strings count UTF-16
code units and one whose strings count code points agree.

| Transform | Applies to | Effect |
|-----------|-----------|--------|
| `"pad"` | segments, signature | Append `=` until the length is a multiple of 4; if it already is, append `====` |
| `"std-alphabet"` | segments, signature | Replace `-` with `+` and `_` with `/` |
| `"trailing-bits"` | segments, signature | Replace the last character with the next one in the base64url alphabet (`A`–`Z`, `a`–`z`, `0`–`9`, `-`, `_`), setting an unused bit; only valid when the length is not a multiple of 4 and the last character is not `_`, which a canonical text of such a length never ends with |
| `{"insert": "<text>", "at": n}` | segments, signature, token | Insert the text at character offset `n` (negative counts from the end) |
| `{"append": "<text>"}` | segments, signature, token | Append the text |
| `{"truncate": n}` | segments, signature, token | Drop the last `n` characters |
| `"empty"` | signature | The empty segment |
| `"zero"` | signature | The canonical encoding of 64 zero bytes |
| `"flip"` | signature | Flip the lowest bit of the first byte, and encode canonically: well-formed, and wrong |
| `{"segments": n}` | token | Keep only the first `n` dot-separated segments |

A transform that leaves its text unchanged is a broken vector and fails the case: a runner re-signs, up to 64 times,
until `std-alphabet` on a signature changes it, and a vector author makes sure a segment it transforms contains what
the transform needs.

## Bringing up a new language

A runner in a new language makes a few decisions this format cannot make for it, because they depend on the
language's types and its platform. The SDK records each one in its runner, and in its documentation where a partner
meets it too (how to check an error, cancel a call, recognise a time-out). The reference SDKs' choices appear
throughout this document as examples.

- **Ill-formed strings.** Which value `{"$illFormed": "abc"}` becomes in the SDK's string type (section 4): `abc`
  with a lone surrogate U+D800 for strings of UTF-16 code units or of code points, `abc` with the byte `0xFF` for
  strings of bytes. Where the SDK's string parameters cannot hold ill-formed text at all (a string type that is always
  valid Unicode), the runner may skip the cases tagged `ill-formed-string` (section 7).
- **Absent versus null.** For each kind of input (an argument, an option, a parameter-set member, a key-store role,
  the cancellation handle), what a member left out and a `null` become (section 4). Where a parameter cannot be absent
  and its absence becomes its zero value, the runner uses `wantZeroValue` (section 7). Absent and `null` being
  indistinguishable needs nothing, since the spec reads `null` as absent.
- **Numbers and keys.** How `{"$number": …}` reaches a numeric parameter; how `windowSeconds` and `timeoutMs` become
  the SDK's own types without rounding (a window type that holds only whole seconds cannot take the fraction cases,
  which carry no `needs`); and how the runner builds `@unusable`, a P-384 key of the type the SDK's key parameters take
  (section 2). "Without rounding" means onto no coarser unit: a limit kept in whole seconds cannot take 50 ms. A
  conversion between units in binary64 arithmetic, such as `timeoutMs / 1000` for an SDK that takes seconds, is not
  rounding in this sense: its error is far below the margins every case keeps.
- **Error checks.** For each category of 5.1, the check that finds it anywhere in the cause chain: the language's
  standard walk (for example Python's `__cause__`, Java's `getCause()`, .NET's `InnerException`), or the SDK's own
  check, which walks at least 16 levels. How the runner reads `reason`, `status` and `apiError`. That the outermost
  error's message carries the `field` phrase: an SDK whose messages do not repeat their cause's text (Python's `str()`
  of an exception does not) writes the phrase into the outer message. Whether a construction error is raised or ends
  in a panic or abort (`at`).
- **Cancellation and time-out failures.** How the submit call is cancelled: the platform's standard primitive (an
  abort signal, a context or a cancellation token passed to the call, or cancelling the task that runs it), or a token
  type the SDK defines where the platform has none; and how the runner cancels before the call and n ms into it. The
  vectors cancel, and let the time limit expire, during the key-store lookup, while waiting for the answer and while
  reading the body, so the cancellation must stop each of those at once. Then, for each of `cancelled`, `timeout`
  and `network` (5.2), the error the SDK lets through and the check that recognises it. Where the platform reports a
  caller's cancellation and an expired time limit with the same error type (.NET raises an
  `OperationCanceledException` for both), the SDK records how a caller tells them apart, and the runner checks exactly
  that.
- **The fake transport.** Where it plugs into the SDK's transport injection; how it counts `requests` and captures
  `request`; how it ends `delayMs` and `bodyDelayMs` when the SDK cancels the request; which error it raises for
  `networkError`; and which no-redirect check it makes (6.6): reading the SDK's no-follow setting where the fake
  replaces the layer that would follow, or seeing that no follow-up request arrives where it sits below that layer.
- **The HTTP core.** The adapter from `handle(method, path, bodyBytes, cancel?)` to the SDK's router (6.7): which
  entry point it builds and how, how it turns the inputs into the request that entry point takes and its answer into
  `{status, headers, body}`, whether that entry point takes a mount, and which answers a host router gives in the
  SDK's place, so that the runner compares the body of a `routerMayAnswer` case only where the SDK answers it (6.7).

## 7. What a runner may skip

Some inputs cannot be passed through a language's static types, or held in its string type. A case that needs one
carries `needs`, a list of tags from this vocabulary:

| Tag | The case gives |
|-----|----------------|
| `untyped-string` | A string parameter another JSON type (ids as numbers, GID-35) |
| `untyped-number` | A number parameter another type (a string where the API takes a number) |
| `fixed-int` | An integer parameter a fraction, or a value outside a fixed-size type (Go's `int32` nonce, `int64` version) |
| `non-finite` | `NaN` or an infinity (Go defines no result for converting one to an integer or a `time.Duration`) |
| `missing-params` | The parameter set `null`, absent or not an object (a Go struct cannot be missing) |
| `untyped-bool` | A boolean parameter another type (a non-boolean `checkBet` verdict) |
| `ill-formed-string` | A string parameter ill-formed Unicode, `{"$illFormed": …}` (section 4) |

The first six name inputs a statically typed language may be unable to write. A runner like Go's skips all 55 cases
that carry at least one of them, since its types express none of their inputs. A tag can stand for several inputs,
and a runner whose types express some of them runs those cases: a Java runner whose parameter set may be `null` and
whose nonce is a `Long` runs `gidgp-gamepass-params-null` and `verifykeys-create-response-nonce-above-max`, and may
still skip `gidgp-gamepass-params-not-object`, whose parameter set is the number 7. The last tag names an input a
language whose strings are always well-formed Unicode (for example Rust's `String` or Swift's `String`) cannot hold,
whether it is typed statically or not, where the SDK's parameter takes that string type; JavaScript, Python, Java, C#,
Go and PHP strings can all hold one (section 4), so they skip no case on this tag. A case may carry
`ill-formed-string` beside another tag.

A skip is permitted, never required. A runner may skip a case when at least one tag in its `needs` names an input its
SDK cannot express, judged for that case's actual input, not for everything the tag can stand for: a case needs every
input its tags name, so one input the SDK cannot take is enough. Where the SDK can express a tagged case's input, the
runner runs the case, and running a case it could have skipped is always fine. It never skips a case that has no
`needs`, and it reports every skip as skipped, with the case's tags, never as passed. Two SDKs in one language can
therefore skip different numbers of cases; compare the names skipped, not the count.

A runner whose parameter structs cannot express absence (Go: an absent and a zero `Amount` are the same value) uses
`wantZeroValue` instead of `want` when a case has one. The spec allows the difference where 0 is a legal value
(settlement `amount` and `version`): such an SDK sends the zero value and documents it.

## 8. Copies and formatting

This repository holds the master copy of `vectors/`, and a change starts here, never in a copy. An SDK keeps an exact,
byte-for-byte mirror of the whole directory, golden files included, and checks it against a pinned commit of this
repository, https://github.com/boostxinnovation/boostx-partner-sdk-spec, the one that carries the spec version it
implements (each release is tagged `vX.Y.Z` there): for example a CI step that fetches that commit and compares the two
directories, failing on any difference. An SDK changes its mirror only by moving the pin and mirroring again.

The group files and `testkeys.json` are laid out as Prettier lays out JSON with tabs and a print width of 120; the
golden files in `golden/` keep the layout of the tool that generated them. An edit here keeps the layout; a mirror
copies the bytes and never reformats them.

Writing a case: pick the operation, leave every input at its default but the one under test, give one fault (or
several, to pin the check order), name the rule ids, and write `want` from the spec rather than from what one SDK
does today. Keep `rules` precise, since the spec's rule sections link to the cases that cite them.
