import { WebSocket } from "ws";

import {
  FluentWalletBuilder,
  type DustWalletOptions,
} from "@midnight-ntwrk/testkit-js";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  type CoinPublicKey,
  DustSecretKey,
  type EncPublicKey,
  type FinalizedTransaction,
  LedgerParameters,
  ZswapSecretKeys,
} from "@midnight-ntwrk/midnight-js-protocol/ledger";
import type { UnboundTransaction } from "@midnight-ntwrk/midnight-js-types";
import type { WalletFacade } from "@midnight-ntwrk/wallet-sdk";
import type { Logger } from "pino";
import pino from "pino";

import type { MidnightWalletCapability } from "./midnight-providers.js";

/**
 * A secret used only to derive a disposable local-development wallet.
 * The value must come from an injected provider and must never be logged,
 * returned, or committed to source control.
 */
export type MidnightWalletSecret =
  | { readonly kind: "mnemonic"; readonly value: string }
  | { readonly kind: "seed"; readonly value: string };

/** A callback boundary for retrieving a local-only wallet secret. */
export type MidnightWalletSecretProvider = () =>
  | MidnightWalletSecret
  | Promise<MidnightWalletSecret>;

/**
 * The environment shape consumed by the official Midnight testkit wallet
 * builder. `undeployed` is the disposable local network identifier.
 */
export interface MidnightWalletEnvironment {
  readonly walletNetworkId: string;
  readonly networkId: string;
  readonly indexer: string;
  readonly indexerWS: string;
  readonly node: string;
  readonly nodeWS: string;
  readonly proofServer: string;
  readonly faucet: string | undefined;
}

/** A started wallet capability that can also be stopped by its owner. */
export interface ManagedMidnightWallet extends MidnightWalletCapability {
  stop(): Promise<void>;
}

/**
 * Injectable wallet implementation used by tests and controlled composition.
 * The default implementation below uses the official Midnight APIs.
 */
export type MidnightWalletBuilder = (
  secret: MidnightWalletSecret,
  environment: MidnightWalletEnvironment,
  logger: Logger,
) => Promise<ManagedMidnightWallet>;

export interface CreateLocalMidnightWalletOptions {
  readonly environment: MidnightWalletEnvironment;
  readonly secretProvider: MidnightWalletSecretProvider;
  readonly logger?: Logger;
  readonly buildAndSynchronize?: MidnightWalletBuilder;
}

const SILENT_LOGGER = pino({ level: "silent" });

function invalid(message: string): never {
  throw new TypeError(`local wallet: ${message}`);
}

function assertLocalEnvironment(
  environment: MidnightWalletEnvironment,
): void {
  if (
    environment.walletNetworkId !== "undeployed" ||
    environment.networkId !== "undeployed"
  ) {
    throw new Error(
      "local wallet: refusing a non-undeployed network; use the disposable local Midnight network",
    );
  }
}

async function readSecret(
  provider: MidnightWalletSecretProvider,
): Promise<MidnightWalletSecret> {
  if (typeof provider !== "function") {
    invalid("secretProvider must be a function");
  }

  const secret = await provider();
  if (
    typeof secret !== "object" ||
    secret === null ||
    Array.isArray(secret)
  ) {
    invalid("secretProvider must return a seed or mnemonic descriptor");
  }

  if (secret.kind !== "seed" && secret.kind !== "mnemonic") {
    invalid("secretProvider returned an unsupported secret kind");
  }
  if (typeof secret.value !== "string" || secret.value.trim().length === 0) {
    invalid("secretProvider returned an empty secret");
  }

  // Preserve the exact secret text for the SDK (notably mnemonic spacing),
  // while returning only the discriminated descriptor to the next boundary.
  return { kind: secret.kind, value: secret.value };
}

function installNodeWebSocket(): void {
  if (typeof globalThis.WebSocket === "function") {
    return;
  }

  Object.defineProperty(globalThis, "WebSocket", {
    configurable: true,
    enumerable: false,
    value: WebSocket,
    writable: true,
  });
}

function ttlOneHour(): Date {
  return new Date(Date.now() + 60 * 60 * 1000);
}

/**
 * Wallet provider compatible with wallet-sdk 1.2.0. The Midnight 4.1.1
 * example finalizes the balancing recipe directly; the older testkit
 * provider adds a separate `signRecipe` pass on its wallet-sdk 1.1.0 path.
 */
class OfficialMidnightWalletProvider implements ManagedMidnightWallet {
  readonly #logger: Logger;
  readonly #wallet: WalletFacade;
  readonly #shieldedSecretKeys: ZswapSecretKeys;
  readonly #dustSecretKey: DustSecretKey;

  constructor(
    logger: Logger,
    wallet: WalletFacade,
    shieldedSecretKeys: ZswapSecretKeys,
    dustSecretKey: DustSecretKey,
  ) {
    this.#logger = logger;
    this.#wallet = wallet;
    this.#shieldedSecretKeys = shieldedSecretKeys;
    this.#dustSecretKey = dustSecretKey;
  }

  getCoinPublicKey(): CoinPublicKey {
    return this.#shieldedSecretKeys.coinPublicKey;
  }

  getEncryptionPublicKey(): EncPublicKey {
    return this.#shieldedSecretKeys.encryptionPublicKey;
  }

  async balanceTx(
    tx: UnboundTransaction,
    ttl: Date = ttlOneHour(),
  ): Promise<FinalizedTransaction> {
    const recipe = await this.#wallet.balanceUnboundTransaction(
      tx,
      {
        shieldedSecretKeys: this.#shieldedSecretKeys,
        dustSecretKey: this.#dustSecretKey,
      },
      { ttl },
    );

    return this.#wallet.finalizeRecipe(recipe);
  }

  submitTx(tx: FinalizedTransaction): Promise<string> {
    return this.#wallet.submitTransaction(tx);
  }

  async start(): Promise<void> {
    this.#logger.info("Starting wallet...");
    await this.#wallet.start(
      this.#shieldedSecretKeys,
      this.#dustSecretKey,
    );
  }

  stop(): Promise<void> {
    return this.#wallet.stop();
  }
}

/**
 * Build, start, and fully synchronize an official local Midnight wallet.
 * This deliberately avoids `MidnightWalletProvider.build`, whose convenience
 * implementation logs the derived seed. The seed remains inside this function
 * and is never returned.
 */
export const buildAndSynchronizeOfficialWallet: MidnightWalletBuilder =
  async (secret, environment, logger): Promise<ManagedMidnightWallet> => {
    installNodeWebSocket();
    setNetworkId(environment.networkId);

    const dustOptions: DustWalletOptions = {
      ledgerParams: LedgerParameters.initialParameters(),
      additionalFeeOverhead: 1_000n,
      feeBlocksMargin: 5,
    };
    const baseBuilder = FluentWalletBuilder.forEnvironment(
      environment,
    ).withDustOptions(dustOptions);
    const configuredBuilder =
      secret.kind === "mnemonic"
        ? baseBuilder.withMnemonic(secret.value)
        : baseBuilder.withSeed(secret.value);
    const { wallet, seeds } =
      await configuredBuilder.buildWithoutStarting();

    const shieldedSecretKeys = ZswapSecretKeys.fromSeed(seeds.shielded);
    const dustSecretKey = DustSecretKey.fromSeed(seeds.dust);
    const walletProvider = new OfficialMidnightWalletProvider(
      logger,
      wallet,
      shieldedSecretKeys,
      dustSecretKey,
    );

    try {
      await walletProvider.start();
      await wallet.waitForSyncedState();
      return walletProvider;
    } catch (error) {
      // Do not leave network subscriptions alive when initialization fails.
      await walletProvider.stop().catch(() => undefined);
      throw error;
    }
  };

/**
 * Create the local wallet capability needed by the Midnight provider factory.
 * The caller owns the returned wallet and must call `stop()` during shutdown.
 */
export async function createLocalMidnightWallet(
  options: CreateLocalMidnightWalletOptions,
): Promise<ManagedMidnightWallet> {
  if (typeof options !== "object" || options === null) {
    invalid("options must be an object");
  }

  assertLocalEnvironment(options.environment);
  const secret = await readSecret(options.secretProvider);
  const builder =
    options.buildAndSynchronize ?? buildAndSynchronizeOfficialWallet;

  return builder(
    secret,
    options.environment,
    options.logger ?? SILENT_LOGGER,
  );
}
