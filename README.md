# Information Flow

> Privacy-preserving verified reviews and dispute resolution on Midnight.

This project is built on the Midnight Network.

Information Flow gives every person the same account at registration. What
they can do changes only after real events: a merchant records a purchase, a
buyer receives a private purchase credential, a customer publishes a verified
review or requests support, and an independent reviewer receives a specific
escalated case. Public readers can verify the minimum public result without
seeing the customer's identity, order details, or private support history.

The Wave 1 MVP includes a working account-first web demo, a Compact contract
that stores append-only public commitments, a live Midnight deployment and
reconnection test, and 26 passing automated tests across the domain, UI,
provider, wallet, and contract boundaries.

The MVP treats `InformationFlow` as the aggregate root of the ontology:

`Actor + Context + Record + Claim + View -> InformationFlow`

The MVP validates private flows off-chain and stores only their public
commitments on Midnight. A commitment is a cryptographic fingerprint: it can
later prove that private flow data has not changed without publishing that data
on-chain. The contract retains an append-only sequence of action commitments
and the latest value for backward-compatible readers.

## Domain layer

`src/information-flow.ts` defines the complete private aggregate and provides:

- strict runtime validation of ontology relationships;
- canonical serialization with stable ordering and Unicode normalization;
- a cryptographically secure, 32-byte nonce generator;
- a versioned, length-delimited SHA-256 commitment function.

The private `InformationFlow` and nonce stay off-chain. Only the resulting
64-character commitment is passed to the Compact contract.

## Behavior-derived four-actor slice

`src/behavior-derived-system.ts` implements the concrete Acme Audio H1
acceptance scenario. All accounts register with the same neutral schema. The
system derives contextual actions from signed authority grants, signed purchase
credentials, organization control, credential control, and case relationships;
there is no `setRole` operation.

The scenario exercises four accounts from a blank state:

1. Actor B receives authority to issue H1 purchase credentials.
2. B signs Actor A's private credential for order `ORD-88421`.
3. A publishes one verified H1 review without exposing A or the order.
4. Actor C reads the public review but gains no private access.
5. A opens support case `CASE-992`; B sees only the required eligibility facts.
6. B records an integrity-protected support decision.
7. Actor D receives regulatory authority.
8. A authorizes a recipient-, case-, purpose-, and record-bound bridge for
   `REG-443`; only D can verify it.

`src/four-actor-scenario.ts` remains the deterministic protocol fixture used by
the live commitment test. The user-facing application is implemented by
`src/platform-demo.ts`, `src/demo-server.ts`, and `web/`. It opens on a normal
login and registration screen, creates every user with the same account schema,
uses an HTTP-only session cookie, and reveals purchase, business, support, or
case tools only after the corresponding credential, authority grant, or case
relationship exists. The separate `manager` demo account configures the Acme
workspace after users register; it is not a role option on user registration.

Run it locally with:

```powershell
npm run demo
```

Then open `http://127.0.0.1:4173`. User and manager demo passwords are
`123456`. The server keeps accounts, password hashes, sessions, signing keys,
and scenario data only in memory; it is not a production identity or credential
service. Ed25519 signatures and disclosure policy are currently verified in the
off-chain domain layer; the Compact contract anchors commitments but does not
itself prove those policy decisions.

## Registration use case

`src/register-information-flow.ts` connects the private domain layer to a
minimal `CommitmentAnchor` boundary. Registration deliberately has two phases:

1. Prepare and retain the private nonce before making an unreliable network
   call.
2. Submit only the public commitment and return a public transaction receipt.

Reusing the prepared registration retries the same commitment. The application
tests use an in-memory fake anchor, while `src/midnight-commitment-anchor.ts`
adapts the real Midnight `callTx.registerFlow` shape without exposing the
privacy-sensitive remainder of its result. `src/midnight-providers.ts` composes
the official provider set, `src/midnight-wallet.ts` provides a local-only wallet
factory, and `src/midnight-composition.ts` assembles those pieces with a
connected contract interface. `src/midnight-contract-connection.ts` supplies
the stateless deployment and public-address reconnection boundary. Persistent
application storage is not implemented, so the caller remains responsible for
securely retaining the private flow and nonce.

## Midnight contract definition

`src/midnight-information-flow-contract.ts` combines the compiler-generated
contract binding with its prover, verifier, and ZKIR artifacts as a typed
`CompiledContract`. This definition contains no wallet, private flow, nonce, or
network connection; later composition code will use it to deploy or connect to
the contract.

`contracts/information-flow.compact` stores each disclosed commitment under an
append-only `Uint<64>` sequence and increments `flowCount`. It also retains
`flowCommitment` as the latest value so the original single-commitment reader
continues to work. No actor ID, credential, review, support record, regulatory
record, or nonce is stored in public ledger state.

`src/midnight-providers.ts` assembles the Midnight.js provider set from public
indexer and proof-server endpoints plus an already-created wallet capability.
It derives a local storage scope from the wallet's public coin key and receives
the private-state encryption password only as a callback. Provider construction
does not read that password, contact the network, or submit a transaction.

`src/midnight-wallet.ts` is the local-only wallet boundary. It accepts a seed or
mnemonic only through an injected callback, uses the official Midnight testkit
builder without its seed-logging convenience method, starts the wallet, waits
for `waitForSyncedState()`, and returns a stoppable wallet capability. The
factory refuses non-`undeployed` networks and never returns the supplied secret.

`src/midnight-composition.ts` creates the application-facing runtime from an
already connected contract interface. Deployment and lookup remain explicit
operations: `deployInformationFlowContract` deploys the stateless compiled
contract without application data, and `connectInformationFlowContract`
reconnects using only its public contract address. Both return the official
Midnight.js `callTx` interface consumed by the narrow commitment adapter.

Midnight.js 4.1.1 requires one shared `@midnight-ntwrk/onchain-runtime-v3`
instance across the compiler runtime and transaction runtime. The package
override pins that transitive dependency to 3.0.0; without deduplication, two
WASM class instances cause valid contract state to fail identity checks.

## Verify

Run inside Ubuntu WSL:

```bash
npm install
npm run compile
npm run typecheck
npm test
```

The ordinary suite uses injected fakes and makes no network requests. After the
disposable services are healthy and the example accounts have been funded, run
either opt-in live check from Windows PowerShell:

```powershell
npm run test:live
npm run test:live:scenario
```

Both live checks read the first disposable account from the adjacent Local Dev
checkout in memory, create a random compliant storage password and isolated
temporary LevelDB path, deploy the contract, and reconnect by public address.
`test:live` submits one fixed 64-character commitment and checks both the latest
value and sequence position zero. `test:live:scenario` executes the four-actor
domain journey, submits its four action commitments, and asserts that indexed
positions zero through three equal the prepared review, support request, signed
decision, and regulatory-bridge commitments. The scripts print only public
addresses, transaction IDs, commitments, and aggregate test evidence; they
never print or copy the mnemonic.

## Local Midnight environment

The official
[Midnight Local Dev](https://github.com/midnightntwrk/midnight-local-dev)
checkout lives beside this repository at `../midnight-local-dev` and is pinned
for this MVP at commit `902561ddc27a4b096f19835ab1528f38ace515f1`.
It runs three localhost-only services:

| Service | Endpoint | Pinned image |
| --- | --- | --- |
| Midnight node | `http://127.0.0.1:9944` | `midnight-node:1.0.0` |
| Indexer GraphQL | `http://127.0.0.1:8088/api/v4/graphql` | `indexer-standalone:4.3.3` |
| Proof server | `http://127.0.0.1:6300` | `proof-server:8.1.0` |

Start or resume the network from Windows PowerShell:

```powershell
cd ..\midnight-local-dev
docker compose -p midnight-local-dev -f standalone.yml up -d
docker compose -p midnight-local-dev -f standalone.yml ps
```

For a fresh local ledger, initialize the repository's local-only example
accounts with NIGHT and DUST:

```powershell
npm start -- --fund-config .\accounts.example.json
```

Never reuse those example mnemonics outside this disposable local network, and
never copy them into this repository. To stop the services without deliberately
resetting the ledger:

```powershell
docker compose -p midnight-local-dev -f standalone.yml stop
```

Copy `.env.example` to an ignored `.env` only when an application adapter needs
the endpoint values. It contains no wallet seed or signing secret.

On this workstation, run Local Dev and Docker commands from Windows PowerShell;
Docker integration is not enabled inside Ubuntu WSL. Continue to run this
repository's TypeScript and Compact checks inside WSL.

### Docker startup note

Docker Desktop 4.91.0 is installed, but this Windows host can still hit Docker's
open stale AF_UNIX socket issue after an interrupted shutdown. The safe recovery
used here was to stop Docker completely, rename the exact `Docker\run` and
`docker-secrets-engine` runtime directories to timestamped backups, create a new
empty `Docker\run` directory, and start Docker again. Do not use **Reset to
factory defaults** for this symptom; consult the recorded procedure in
`AGENTS.md` and the
[upstream issue](https://github.com/docker/desktop-feedback/issues/554) first.

## Compile

Run inside Ubuntu WSL:

```bash
npm run compile
```

The generated contract bindings are written to
`contracts/managed/information-flow/` and are intentionally not committed.
