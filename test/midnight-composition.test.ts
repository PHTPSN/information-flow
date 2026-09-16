import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { WalletProvider } from "@midnight-ntwrk/midnight-js-types";

import {
  createInformationFlowComposition,
  type InformationFlowComposition,
} from "../src/midnight-composition.js";
import type { MidnightRegisterFlowContract } from "../src/midnight-commitment-anchor.js";
import type {
  ManagedMidnightWallet,
  MidnightWalletEnvironment,
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

function fakeWallet(stopCalls: { value: number }): ManagedMidnightWallet {
  return {
    async balanceTx() {
      throw new Error("not used while composing the runtime");
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
      throw new Error("not used while composing the runtime");
    },
    async stop() {
      stopCalls.value += 1;
    },
  };
}

function fakeContract(calls: { value: number }): MidnightRegisterFlowContract {
  return {
    callTx: {
      async registerFlow() {
        calls.value += 1;
        return { public: { txId: "not-called-during-composition" } };
      },
    },
  };
}

describe("Information Flow composition", () => {
  it("assembles providers and the adapter without deploying or calling the contract", async () => {
    const stopCalls = { value: 0 };
    const contractCalls = { value: 0 };
    const wallet = fakeWallet(stopCalls);
    const contract = fakeContract(contractCalls);
    let passwordReads = 0;

    const composition = await createInformationFlowComposition({
      environment: LOCAL_ENVIRONMENT,
      secretProvider: () => ({ kind: "seed", value: "unit-test-only-secret" }),
      buildAndSynchronize: async () => wallet,
      contract,
      privateStoragePasswordProvider: () => {
        passwordReads += 1;
        return "unit-test-only-password";
      },
    });

    assert.equal(composition.contract, contract);
    assert.equal(composition.wallet, wallet);
    assert.equal(composition.providers.walletProvider, wallet);
    assert.equal(composition.providers.midnightProvider, wallet);
    assert.equal(composition.anchor.constructor.name, "MidnightCommitmentAnchor");
    assert.equal(passwordReads, 0);
    assert.equal(contractCalls.value, 0);
    assert.equal(typeof composition.compiledContract.tag, "string");

    await composition.close();
    await composition.close();
    assert.equal(stopCalls.value, 1);
  });

  it("rejects an invalid contract before creating a wallet", async () => {
    let walletBuilds = 0;

    await assert.rejects(
      createInformationFlowComposition({
        environment: LOCAL_ENVIRONMENT,
        secretProvider: () => ({ kind: "seed", value: "not-used" }),
        buildAndSynchronize: async () => {
          walletBuilds += 1;
          return fakeWallet({ value: 0 });
        },
        contract: {} as MidnightRegisterFlowContract,
        privateStoragePasswordProvider: () => "not-used",
      }),
      /contract must expose callTx\.registerFlow/,
    );

    assert.equal(walletBuilds, 0);
  });

  it("keeps the application composition type narrow", () => {
    const typeCheck: Pick<InformationFlowComposition, "anchor" | "providers"> =
      {} as Pick<InformationFlowComposition, "anchor" | "providers">;
    assert.equal("anchor" in typeCheck, false);
  });
});
