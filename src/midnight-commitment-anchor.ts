import type {
  CommitmentAnchor,
  CommitmentAnchorReceipt,
} from "./register-information-flow.js";

/** The public fragment of a finalized Midnight circuit-call result. */
export interface MidnightRegisterFlowResult {
  readonly public: {
    readonly txId: string;
  };
}

/**
 * The smallest part of a deployed Information Flow contract used by this
 * adapter. The concrete Midnight.js contract may return additional private
 * transaction data, which must not cross the CommitmentAnchor boundary.
 */
export interface MidnightRegisterFlowContract {
  readonly callTx: {
    registerFlow(commitment: string): Promise<MidnightRegisterFlowResult>;
  };
}

/** Adapts the generated Midnight contract call to the application boundary. */
export class MidnightCommitmentAnchor implements CommitmentAnchor {
  readonly #contract: MidnightRegisterFlowContract;

  constructor(contract: MidnightRegisterFlowContract) {
    this.#contract = contract;
  }

  async registerFlow(commitment: string): Promise<CommitmentAnchorReceipt> {
    const result = await this.#contract.callTx.registerFlow(commitment);

    // Never return or log the complete result: Midnight call results can carry
    // private transaction data alongside this public transaction identifier.
    return { transactionId: result.public.txId };
  }
}
