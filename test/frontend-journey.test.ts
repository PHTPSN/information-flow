import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";

import { createInformationFlowDemoServer } from "../src/demo-server.js";
import type { PlatformDashboard } from "../src/platform-demo.js";

interface ApiResult<T> {
  readonly status: number;
  readonly payload: T;
}

class BrowserSession {
  #cookie: string | null = null;

  constructor(readonly origin: string) {}

  async request<T>(
    path: string,
    options: { readonly method?: string; readonly body?: unknown } = {},
  ): Promise<ApiResult<T>> {
    const headers: Record<string, string> = {};
    if (options.body !== undefined) headers["content-type"] = "application/json";
    if (this.#cookie !== null) headers.cookie = this.#cookie;
    const requestInit: RequestInit = {
      method: options.method ?? "GET",
      headers,
    };
    if (options.body !== undefined) {
      requestInit.body = JSON.stringify(options.body);
    }
    const response = await fetch(`${this.origin}${path}`, requestInit);
    const setCookie = response.headers.get("set-cookie");
    if (setCookie !== null) {
      const cookie = setCookie.split(";", 1)[0]!;
      this.#cookie = cookie.endsWith("=") ? null : cookie;
    }
    return {
      status: response.status,
      payload: (await response.json()) as T,
    };
  }

  async login(username: string): Promise<PlatformDashboard> {
    const result = await this.request<PlatformDashboard>("/api/login", {
      method: "POST",
      body: { username, password: "123456" },
    });
    assert.equal(result.status, 200);
    return result.payload;
  }

  async dashboard(): Promise<PlatformDashboard> {
    const result = await this.request<PlatformDashboard>("/api/dashboard");
    assert.equal(result.status, 200);
    return result.payload;
  }

  async action(path: string, body: unknown): Promise<PlatformDashboard> {
    const result = await this.request<PlatformDashboard>(path, {
      method: "POST",
      body,
    });
    assert.equal(result.status, 200);
    return result.payload;
  }
}

describe("registered-user browser journey", () => {
  const server = createInformationFlowDemoServer();
  let origin = "";

  before(async () => {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address() as AddressInfo;
    origin = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("opens as a normal login and registration site", async () => {
    const response = await fetch(origin);
    const html = await response.text();

    assert.equal(response.status, 200);
    assert.match(html, /Log in to your account/);
    assert.match(html, /Create your account/);
    assert.match(html, /Log in as manager/);
    assert.match(html, /name="username"/);
    assert.match(html, /name="password"/);
    assert.doesNotMatch(html, /Actor A|Actor B|Actor C|Actor D/);
    assert.doesNotMatch(html, /Current viewpoint|Run all|Scenario control/);
    assert.doesNotMatch(html, /registers as a buyer, merchant, or regulator/i);
    assert.doesNotMatch(html, /name=["']role["']/);
  });

  it("registers four equal users, logs into each account, and completes the real workflow", async () => {
    const registration = new BrowserSession(origin);
    const anonymousDashboard = await registration.request<{ code: string }>(
      "/api/dashboard",
    );
    assert.equal(anonymousDashboard.status, 401);
    assert.equal(anonymousDashboard.payload.code, "AUTH_REQUIRED");

    const users = [
      { username: "alice", displayName: "Alice Chen" },
      { username: "ben", displayName: "Ben Wu" },
      { username: "clara", displayName: "Clara Lee" },
      { username: "david", displayName: "David Lin" },
    ] as const;
    for (const user of users) {
      const result = await registration.request<{
        account: Record<string, unknown>;
      }>("/api/register", {
        method: "POST",
        body: { ...user, password: "123456" },
      });
      assert.equal(result.status, 201);
      assert.deepEqual(Object.keys(result.payload.account).sort(), [
        "createdAt",
        "displayName",
        "userId",
        "username",
      ]);
      assert.equal("role" in result.payload.account, false);
    }

    const wrongPassword = await new BrowserSession(origin).request<{
      code: string;
    }>("/api/login", {
      method: "POST",
      body: { username: "alice", password: "wrong" },
    });
    assert.equal(wrongPassword.status, 401);
    assert.equal(wrongPassword.payload.code, "LOGIN_FAILED");

    const alice = new BrowserSession(origin);
    const ben = new BrowserSession(origin);
    const clara = new BrowserSession(origin);
    const david = new BrowserSession(origin);
    const manager = new BrowserSession(origin);

    for (const [browser, username] of [
      [alice, "alice"],
      [ben, "ben"],
      [clara, "clara"],
      [david, "david"],
    ] as const) {
      const dashboard = await browser.login(username);
      assert.equal(dashboard.account.username, username);
      assert.equal(dashboard.account.kind, "user");
      assert.equal(dashboard.manager, null);
      assert.deepEqual(dashboard.purchases, []);
      assert.equal(dashboard.canIssuePurchases, false);
    }

    const managerLogin = await manager.request<PlatformDashboard>(
      "/api/login/manager",
      { method: "POST", body: { password: "123456" } },
    );
    assert.equal(managerLogin.status, 200);
    assert.equal(managerLogin.payload.account.kind, "manager");
    assert.equal(managerLogin.payload.manager?.users.length, 4);

    const configured = await manager.action("/api/manager/configure", {
      merchantUsername: "ben",
      regulatorUsername: "david",
    });
    assert.equal(configured.manager?.configured, true);
    assert.equal(configured.manager?.merchantUsername, "ben");
    assert.equal(configured.manager?.regulatorUsername, "david");

    let benDashboard = await ben.dashboard();
    assert.equal(benDashboard.canIssuePurchases, true);
    assert.equal((await alice.dashboard()).canIssuePurchases, false);
    assert.equal((await clara.dashboard()).canIssuePurchases, false);
    assert.equal((await david.dashboard()).canIssuePurchases, false);

    benDashboard = await ben.action("/api/actions/issue-purchase", {
      buyerUsername: "alice",
      orderId: "ORD-88421",
    });
    assert.equal(benDashboard.purchases.length, 0);

    let aliceDashboard = await alice.dashboard();
    assert.equal(aliceDashboard.purchases.length, 1);
    assert.equal(aliceDashboard.purchases[0]!.orderId, "ORD-88421");
    assert.equal(aliceDashboard.purchases[0]!.canReview, true);
    assert.equal(aliceDashboard.purchases[0]!.canRequestSupport, true);
    const purchaseId = aliceDashboard.purchases[0]!.purchaseId;

    aliceDashboard = await alice.action("/api/actions/publish-review", {
      purchaseId,
      rating: 2,
      text: "The battery swelled after twelve days of normal use.",
    });
    assert.equal(aliceDashboard.reviews.length, 1);
    assert.equal(aliceDashboard.reviews[0]!.verifiedPurchase, true);
    assert.equal(aliceDashboard.reviews[0]!.openedByYou, true);
    const reviewId = aliceDashboard.reviews[0]!.reviewId;
    const publicReviewJson = JSON.stringify(aliceDashboard.reviews[0]);
    assert.equal(publicReviewJson.includes("alice"), false);
    assert.equal(publicReviewJson.includes("ORD-88421"), false);

    let claraDashboard = await clara.dashboard();
    assert.equal(claraDashboard.reviews.length, 1);
    assert.equal(claraDashboard.reviews[0]!.openedByYou, false);
    assert.deepEqual(claraDashboard.purchases, []);
    assert.deepEqual(claraDashboard.supportInbox, []);
    assert.deepEqual(claraDashboard.assignedCases, []);
    for (const privateValue of ["alice", "ORD-88421", "CASE-001", "REG-001"]) {
      assert.equal(JSON.stringify(claraDashboard.reviews).includes(privateValue), false);
    }

    claraDashboard = await clara.action("/api/actions/open-review", { reviewId });
    assert.equal(claraDashboard.reviews[0]!.openedByYou, true);
    assert.match(claraDashboard.reviews[0]!.text, /battery swelled/);
    assert.deepEqual(claraDashboard.purchases, []);

    aliceDashboard = await alice.action("/api/actions/request-support", {
      purchaseId,
    });
    assert.equal(aliceDashboard.purchases[0]!.support?.caseId, "CASE-001");
    assert.equal(aliceDashboard.counts.publicCommitments, 2);

    benDashboard = await ben.dashboard();
    assert.equal(benDashboard.supportInbox.length, 1);
    assert.equal(benDashboard.supportInbox[0]!.caseId, "CASE-001");
    const supportInboxJson = JSON.stringify(benDashboard.supportInbox);
    assert.equal(supportInboxJson.includes("alice"), false);
    assert.equal(supportInboxJson.includes("ORD-88421"), false);
    assert.equal(supportInboxJson.includes("battery swelled"), false);

    benDashboard = await ben.action("/api/actions/decide-support", {
      caseId: "CASE-001",
      outcome: "rejected",
      reason: "Inspection is required before replacement approval.",
    });
    assert.equal(benDashboard.supportInbox[0]!.outcome, "rejected");
    assert.equal(benDashboard.counts.publicCommitments, 3);

    aliceDashboard = await alice.dashboard();
    assert.equal(aliceDashboard.purchases[0]!.support?.outcome, "rejected");
    assert.equal(aliceDashboard.purchases[0]!.canEscalate, true);

    aliceDashboard = await alice.action("/api/actions/escalate", { purchaseId });
    assert.equal(aliceDashboard.purchases[0]!.regulatoryCase?.caseId, "REG-001");
    assert.equal(aliceDashboard.counts.publicCommitments, 4);

    assert.deepEqual((await ben.dashboard()).assignedCases, []);
    assert.deepEqual((await clara.dashboard()).assignedCases, []);
    let davidDashboard = await david.dashboard();
    assert.equal(davidDashboard.assignedCases.length, 1);
    assert.equal(davidDashboard.assignedCases[0]!.caseId, "REG-001");
    assert.equal(davidDashboard.assignedCases[0]!.verified, false);

    davidDashboard = await david.action("/api/actions/verify-case", {
      caseId: "REG-001",
    });
    assert.equal(davidDashboard.assignedCases[0]!.verified, true);
    assert.deepEqual(davidDashboard.assignedCases[0]!.result, {
      samePurchase: true,
      reviewIntegrity: true,
      supportDecisionIntegrity: true,
    });

    const claraPrivateCaseAttempt = await clara.request<{ code: string }>(
      "/api/actions/verify-case",
      { method: "POST", body: { caseId: "REG-001" } },
    );
    assert.equal(claraPrivateCaseAttempt.status, 404);
    assert.equal(claraPrivateCaseAttempt.payload.code, "CASE_NOT_FOUND");

    const logout = await alice.request<{ ok: boolean }>("/api/logout", {
      method: "POST",
    });
    assert.equal(logout.status, 200);
    assert.equal(logout.payload.ok, true);
    assert.equal((await alice.request("/api/dashboard")).status, 401);
  });
});
