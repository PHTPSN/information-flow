import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { ledger } from "../contracts/managed/information-flow/contract/index.js";
import { MidnightCommitmentAnchor } from "../src/midnight-commitment-anchor.js";
import {
  connectInformationFlowContract,
  deployInformationFlowContract,
} from "../src/midnight-contract-connection.js";
import { createInformationFlowProviders } from "../src/midnight-providers.js";
import {
  createLocalMidnightWallet,
  type MidnightWalletEnvironment,
} from "../src/midnight-wallet.js";

interface LocalAccountFile {
  readonly accounts: readonly {
    readonly name: string;
    readonly mnemonic: string;
  }[];
}

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

function randomStoragePassword(): string {
  const alphabets = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*",
  ] as const;
  return [...randomBytes(32)]
    .map((value, index) => {
      const alphabet = alphabets[index % alphabets.length]!;
      return alphabet[value % alphabet.length];
    })
    .join("");
}

function milestone(
  event: string,
  evidence: Readonly<Record<string, unknown>>,
): void {
  process.stdout.write(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      event,
      ...evidence,
    }) + "\n",
  );
}

async function main(): Promise<void> {
  const accountFilePath = path.resolve(
    process.argv[2] ?? "../midnight-local-dev/accounts.example.json",
  );
  const parsed = JSON.parse(
    await readFile(accountFilePath, "utf8"),
  ) as LocalAccountFile;
  const account = parsed.accounts[0];
  assert(account, "the local account file must contain a funded account");

  const wallet = await createLocalMidnightWallet({
    environment: LOCAL_ENVIRONMENT,
    secretProvider: () => ({ kind: "mnemonic", value: account.mnemonic }),
  });

  try {
    const privateStoragePassword = randomStoragePassword();
    const providers = createInformationFlowProviders({
      endpoints: LOCAL_ENVIRONMENT,
      wallet,
      privateStoragePasswordProvider: () => privateStoragePassword,
      privateStateDatabaseName: path.join(
        tmpdir(),
        `information-flow-live-${randomBytes(16).toString("hex")}`,
      ),
    });
    const deployed = await deployInformationFlowContract(providers);
    const contractAddress = deployed.deployTxData.public.contractAddress;
    milestone("contract-deployed", { contractAddress });

    const connected = await connectInformationFlowContract(
      providers,
      contractAddress,
    );
    assert.equal(
      connected.deployTxData.public.contractAddress,
      contractAddress,
    );
    milestone("contract-reconnected", { contractAddress });

    const commitment = "ab".repeat(32);
    assert.match(commitment, /^[0-9a-f]{64}$/);
    milestone("commitment-ready", {
      commitment,
      commitmentLength: commitment.length,
    });

    const receipt = await new MidnightCommitmentAnchor(
      connected,
    ).registerFlow(commitment);
    assert.match(receipt.transactionId, /^[0-9a-f]+$/i);
    milestone("commitment-submitted", {
      commitment,
      commitmentLength: commitment.length,
      transactionId: receipt.transactionId,
    });

    const contractState = await providers.publicDataProvider.queryContractState(
      contractAddress,
    );

    assert(contractState, "the finalized contract state must be indexed");
    const indexedLedger = ledger(contractState.data);
    const indexedCommitment = indexedLedger.flowCommitment;
    assert.equal(indexedCommitment, commitment);
    assert.equal(indexedLedger.flowCount, 1n);
    assert.equal(indexedLedger.flowCommitments.size(), 1n);
    assert.equal(indexedLedger.flowCommitments.lookup(0n), commitment);
    milestone("indexed-state-verified", {
      contractAddress,
      transactionId: receipt.transactionId,
      commitment,
      indexedCommitment,
      indexedSequence: 0,
      indexedCommitmentCount: Number(indexedLedger.flowCount),
      indexedStateEqualsCommitment: true,
    });
  } finally {
    await wallet.stop();
  }
}

await main();
