import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { WalletProvider } from "@midnight-ntwrk/midnight-js-types";

import {
  createLocalMidnightWallet,
  type ManagedMidnightWallet,
  type MidnightWalletEnvironment,
  type MidnightWalletSecret,
} from "../src/midnight-wallet.js";

const LOCAL_ENVIRONMENT: MidnightWalletEnvironment = {
  walletNetworkId: "undeployed",
  networkId: "undeployed",
  indexer: "http://127.0.0.1:8088/api/v4/graphql",
  indexerWS: "ws://127.0.0.1:8088/api/v4/graphql/ws",
  node: "http://127.0.0.1:9944",
  nodeWS: "ws://127.0.0.1:9944",
  proofServer: "http://127.0.0.1:6300",
  faucet: undefined,
};

function fakeManagedWallet(): ManagedMidnightWallet {
  return {
    async balanceTx() {
      throw new Error("not used in wallet-factory unit tests");
    },
    getCoinPublicKey() {
      return "00".repeat(32) as ReturnType<
        WalletProvider["getCoinPublicKey"]
      >;
    },
    getEncryptionPublicKey() {
      return "ff".repeat(32) as ReturnType<
        WalletProvider["getEncryptionPublicKey"]
      >;
    },
    async submitTx() {
      throw new Error("not used in wallet-factory unit tests");
    },
    async stop() {},
  };
}

describe("local Midnight wallet factory", () => {
  it("reads the injected secret once and returns only the managed capability", async () => {
    const secret: MidnightWalletSecret = {
      kind: "mnemonic",
      value: "unit-test-only-secret",
    };
    const wallet = fakeManagedWallet();
    let reads = 0;
    let observedSecret: MidnightWalletSecret | undefined;

    const result = await createLocalMidnightWallet({
      environment: LOCAL_ENVIRONMENT,
      secretProvider: () => {
        reads += 1;
        return secret;
      },
      buildAndSynchronize: async (receivedSecret, environment, logger) => {
        observedSecret = receivedSecret;
        assert.equal(environment, LOCAL_ENVIRONMENT);
        assert.equal(typeof logger.info, "function");
        return wallet;
      },
    });

    assert.equal(reads, 1);
    assert.deepEqual(observedSecret, secret);
    assert.equal(result, wallet);
    assert.equal("value" in result, false);
    assert.equal("zswapSecretKeys" in result, false);
    assert.equal("unshieldedKeystore" in result, false);
  });

  it("rejects a non-local network before asking for a secret", async () => {
    let reads = 0;

    await assert.rejects(
      createLocalMidnightWallet({
        environment: { ...LOCAL_ENVIRONMENT, networkId: "preprod" },
        secretProvider: () => {
          reads += 1;
          return { kind: "seed", value: "not-used" };
        },
        buildAndSynchronize: async () => fakeManagedWallet(),
      }),
      /non-undeployed network/,
    );

    assert.equal(reads, 0);
  });

  it("rejects an empty secret without invoking wallet construction", async () => {
    let builds = 0;

    await assert.rejects(
      createLocalMidnightWallet({
        environment: LOCAL_ENVIRONMENT,
        secretProvider: () => ({ kind: "seed", value: "   " }),
        buildAndSynchronize: async () => {
          builds += 1;
          return fakeManagedWallet();
        },
      }),
      /empty secret/,
    );

    assert.equal(builds, 0);
  });
});
