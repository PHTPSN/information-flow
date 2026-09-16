import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { ledger } from "../contracts/managed/information-flow/contract/index.js";
import { FourActorScenario } from "../src/four-actor-scenario.js";
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

  const scenario = new FourActorScenario();
  const completed = scenario.runToCompletion();
  assert.equal(completed.complete, true);
  assert.equal(completed.privacyChecks.every(({ passed }) => passed), true);
  assert.equal(scenario.commitmentAuditPassed(), true);
  const commitments = scenario.commitmentRecords();
  assert.equal(commitments.length, 4);
  milestone("four-actor-scenario-prepared", {
    actorCount: completed.counts.actors,
    actionCount: completed.stage,
    commitmentCount: commitments.length,
    privacyAssertionsPassed: completed.privacyChecks.length,
  });

  const wallet = await createLocalMidnightWallet({
    environment: LOCAL_ENVIRONMENT,
    secretProvider: () => ({ kind: "mnemonic", value: account.mnemonic }),
  });

  try {
    const privateStoragePassword = randomStoragePassword();
    const privateStateDatabaseName = path.join(
      tmpdir(),
      `information-flow-four-actor-live-${randomBytes(16).toString("hex")}`,
    );
    const providers = createInformationFlowProviders({
      endpoints: LOCAL_ENVIRONMENT,
      wallet,
      privateStoragePasswordProvider: () => privateStoragePassword,
      privateStateDatabaseName,
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

    const anchor = new MidnightCommitmentAnchor(connected);
    const transactionIds: string[] = [];
    for (const [sequence, record] of commitments.entries()) {
      assert.match(record.commitment, /^[0-9a-f]{64}$/);
      const receipt = await anchor.registerFlow(record.commitment);
      assert.match(receipt.transactionId, /^[0-9a-f]+$/i);
      transactionIds.push(receipt.transactionId);
      milestone("action-commitment-submitted", {
        sequence,
        actionId: record.actionId,
        commitment: record.commitment,
        commitmentLength: record.commitment.length,
        transactionId: receipt.transactionId,
      });
    }

    const contractState = await providers.publicDataProvider.queryContractState(
      contractAddress,
    );
    assert(contractState, "the finalized contract state must be indexed");
    const indexedLedger = ledger(contractState.data);
    assert.equal(indexedLedger.flowCount, BigInt(commitments.length));
    assert.equal(
      indexedLedger.flowCommitments.size(),
      BigInt(commitments.length),
    );
    for (const [sequence, record] of commitments.entries()) {
      assert.equal(
        indexedLedger.flowCommitments.lookup(BigInt(sequence)),
        record.commitment,
      );
    }
    assert.equal(
      indexedLedger.flowCommitment,
      commitments.at(-1)!.commitment,
    );
    milestone("indexed-four-actor-state-verified", {
      contractAddress,
      commitmentCount: commitments.length,
      indexedCommitmentCount: Number(indexedLedger.flowCount),
      allIndexedCommitmentsEqualPreparedActions: true,
      latestCommitmentEqualsLastAction: true,
      transactionIds,
    });
  } finally {
    await wallet.stop();
  }
}

await main();
