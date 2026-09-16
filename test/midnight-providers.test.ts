import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type { WalletProvider } from "@midnight-ntwrk/midnight-js-types";

import { INFORMATION_FLOW_COMPILED_ASSETS_PATH } from "../src/midnight-information-flow-contract.js";
import {
  createInformationFlowProviders,
  type MidnightWalletCapability,
} from "../src/midnight-providers.js";

const ENDPOINTS = {
  indexer: "http://127.0.0.1:8088/api/v4/graphql",
  indexerWS: "ws://127.0.0.1:8088/api/v4/graphql/ws",
  proofServer: "http://127.0.0.1:6300",
} as const;

function unusedWalletCapability(): MidnightWalletCapability {
  return {
    async balanceTx() {
      throw new Error("not used while composing providers");
    },
    getCoinPublicKey() {
      return "00".repeat(32) as ReturnType<WalletProvider["getCoinPublicKey"]>;
    },
    getEncryptionPublicKey() {
      return "ff".repeat(32) as ReturnType<
        WalletProvider["getEncryptionPublicKey"]
      >;
    },
    async submitTx() {
      throw new Error("not used while composing providers");
    },
  };
}

describe("Information Flow Midnight providers", () => {
  it("assembles providers without reading secrets or contacting the network", () => {
    const wallet = unusedWalletCapability();
    let passwordReads = 0;

    const providers = createInformationFlowProviders({
      endpoints: ENDPOINTS,
      wallet,
      privateStoragePasswordProvider() {
        passwordReads += 1;
        return "Local-only_Strong-Password_987!";
      },
    });

    assert.equal(providers.walletProvider, wallet);
    assert.equal(providers.midnightProvider, wallet);
    assert.equal(passwordReads, 0);
    assert.equal(
      providers.zkConfigProvider instanceof NodeZkConfigProvider,
      true,
    );
    assert.equal(
      (providers.zkConfigProvider as NodeZkConfigProvider<string>).directory,
      INFORMATION_FLOW_COMPILED_ASSETS_PATH,
    );
    assert.equal(
      typeof providers.publicDataProvider.queryContractState,
      "function",
    );
    assert.equal(typeof providers.proofProvider.proveTx, "function");
    assert.equal(typeof providers.privateStateProvider.get, "function");
  });
});
