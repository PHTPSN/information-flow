import {
  commitInformationFlow,
  generateFlowNonce,
} from "./information-flow.js";

const FLOW_COMMITMENT_PATTERN = /^[0-9a-f]{64}$/;

/** Public result returned by the blockchain integration. */
export interface CommitmentAnchorReceipt {
  readonly transactionId: string;
}

/**
 * The only capability the application layer needs from a blockchain adapter.
 * Private InformationFlow data and its nonce must never be added here.
 */
export interface CommitmentAnchor {
  registerFlow(commitment: string): Promise<CommitmentAnchorReceipt>;
}

/**
 * Prepared before an unreliable network call so the same commitment can be
 * retried. privateNonce must remain off-chain and be stored securely.
 */
export interface PreparedInformationFlowRegistration {
  readonly commitment: string;
  readonly privateNonce: Uint8Array;
}

/** The public, privacy-safe outcome of a successful registration. */
export interface InformationFlowRegistrationReceipt {
  readonly commitment: string;
  readonly transactionId: string;
}

export function prepareInformationFlowRegistration(
  input: unknown,
  nonce: Uint8Array = generateFlowNonce(),
): PreparedInformationFlowRegistration {
  const commitment = commitInformationFlow(input, nonce);

  return {
    commitment,
    privateNonce: Uint8Array.from(nonce),
  };
}

export async function registerInformationFlow(
  registration: Pick<PreparedInformationFlowRegistration, "commitment">,
  anchor: CommitmentAnchor,
): Promise<InformationFlowRegistrationReceipt> {
  if (!FLOW_COMMITMENT_PATTERN.test(registration.commitment)) {
    throw new TypeError(
      "registration.commitment: expected a 64-character lowercase hex value",
    );
  }

  // This is the privacy boundary: the adapter receives only the commitment.
  const anchorReceipt = await anchor.registerFlow(registration.commitment);
  if (
    typeof anchorReceipt !== "object" ||
    anchorReceipt === null ||
    typeof anchorReceipt.transactionId !== "string" ||
    anchorReceipt.transactionId.trim().length === 0
  ) {
    throw new TypeError(
      "anchor receipt: expected a non-empty transaction identifier",
    );
  }

  return {
    commitment: registration.commitment,
    transactionId: anchorReceipt.transactionId,
  };
}
