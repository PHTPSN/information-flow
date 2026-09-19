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

  async login(
    username: string,
    password = "correct-horse-123",
  ): Promise<PlatformDashboard> {
    const result = await this.request<PlatformDashboard>("/api/login", {
      method: "POST",
      body: { username, password },
    });
    assert.equal(result.status, 200);
    return result.payload;
  }

  async loginAdministrator(
    username: string,
    password: string,
  ): Promise<PlatformDashboard> {
    const result = await this.request<PlatformDashboard>("/api/login", {
      method: "POST",
      body: { username, password },
    });
    assert.equal(result.status, 200);
    assert.equal(result.payload.account.isAdministrator, true);
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
    assert.ok(
      result.status === 200 || result.status === 201 || result.status === 202,
    );
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

  it("opens with ordinary registration and a separate administrator login", async () => {
    const response = await fetch(origin);
    const html = await response.text();
    const appScript = await (await fetch(`${origin}/app.js`)).text();
    const styles = await (await fetch(`${origin}/styles.css`)).text();

    assert.equal(response.status, 200);
    assert.match(html, /Log in to your account/);
    assert.match(html, /Create your account/);
    assert.match(html, /Administrator login/);
    assert.match(html, /One account for comments and support/);
    assert.doesNotMatch(html, /id="public-reviews"/);
    assert.doesNotMatch(html, /Verified reviews/);
    assert.match(html, /New administrator registration is[\s\S]*?not currently available/);
    assert.doesNotMatch(html, /manager|12345678/i);
    assert.match(html, /name="username"/);
    assert.match(html, /name="password"/);
    assert.match(html, /Display name <small>\(optional\)<\/small>/);
    const displayNameInput = html.match(
      /<input\s+name="displayName"[\s\S]*?\/>/,
    );
    assert.ok(displayNameInput);
    assert.doesNotMatch(displayNameInput[0], /\brequired\b/);
    assert.doesNotMatch(html, /Actor A|Actor B|Actor C|Actor D/);
    assert.doesNotMatch(html, /Current viewpoint|Run all|Scenario control/);
    assert.doesNotMatch(html, /registers as a buyer, merchant, or regulator/i);
    assert.match(html, /Shop by merchant/);
    assert.match(html, /id="merchant-directory"/);
    assert.match(html, /data-tab="shop"/);
    assert.match(html, /data-tab="account"/);
    assert.match(html, /data-tab="activity"/);
    assert.match(html, /id="review-view"/);
    assert.match(html, /← Back to shop/);
    assert.match(html, /Product comments/);
    assert.match(html, /Account &amp; merchant tools/);
    assert.match(appScript, /\/api\/actions\/buy-product/);
    assert.match(appScript, /product\.belongsToAccountOrganization/);
    assert.match(appScript, /\? "Your merchant"/);
    assert.match(
      appScript,
      /product\.availableForPurchase \?\? product\.canPurchase \?\? false/,
    );
    assert.match(appScript, /buyButton\.disabled = !hasPurchasePermission/);
    assert.doesNotMatch(appScript, /Unavailable/);
    assert.match(appScript, /showProductReviews/);
    assert.match(appScript, /Read comments/);
    assert.match(appScript, /Publish comment/);
    assert.match(appScript, /Send for review/);
    assert.match(
      styles,
      /button:disabled[\s\S]*?cursor: not-allowed/,
    );
    assert.doesNotMatch(appScript, /\.disabled\s*=\s*true/);
    assert.doesNotMatch(appScript, /disabledForBusy/);
    const registrationFormHtml = html.slice(
      html.indexOf('id="register-form"'),
      html.indexOf("</form>", html.indexOf('id="register-form"')),
    );
    assert.doesNotMatch(registrationFormHtml, /name=["']role["']/);
    const administratorFormHtml = html.slice(
      html.indexOf('id="administrator-login-form"'),
      html.indexOf(
        "</form>",
        html.indexOf('id="administrator-login-form"'),
      ),
    );
    assert.match(administratorFormHtml, /name="username"/);
    assert.match(administratorFormHtml, /name="password"/);
    assert.doesNotMatch(administratorFormHtml, /\bvalue=/);

    const registerHandler = appScript.slice(
      appScript.indexOf('elements.registerForm.addEventListener("submit"'),
      appScript.indexOf('elements.loginForm.addEventListener("submit"'),
    );
    assert.ok(
      registerHandler.indexOf("formValues(elements.registerForm)") <
        registerHandler.indexOf("setBusy(true)"),
      "registration must read enabled controls before disabling them",
    );

    const loginHandler = appScript.slice(
      appScript.indexOf('elements.loginForm.addEventListener("submit"'),
      appScript.indexOf(
        'elements.administratorLoginForm.addEventListener("submit"',
      ),
    );
    assert.ok(
      loginHandler.indexOf("formValues(elements.loginForm)") <
        loginHandler.indexOf("setBusy(true)"),
      "login must read enabled controls before disabling them",
    );
    const administratorLoginHandler = appScript.slice(
      appScript.indexOf(
        'elements.administratorLoginForm.addEventListener("submit"',
      ),
      appScript.indexOf('elements.logout.addEventListener("click"'),
    );
    assert.match(administratorLoginHandler, /request\("\/api\/login"/);
    assert.match(administratorLoginHandler, /account\.isAdministrator/);
    assert.match(administratorLoginHandler, /request\("\/api\/logout"/);
    assert.ok(
      administratorLoginHandler.indexOf(
        "formValues(elements.administratorLoginForm)",
      ) < administratorLoginHandler.indexOf("setBusy(true)"),
      "administrator login must read enabled controls before disabling them",
    );
  });

  it("registers four ordinary users, logs into each account, and completes the real workflow", async () => {
    const registration = new BrowserSession(origin);
    const anonymousDashboard = await registration.request<{ code: string }>(
      "/api/dashboard",
    );
    assert.equal(anonymousDashboard.status, 401);
    assert.equal(anonymousDashboard.payload.code, "AUTH_REQUIRED");

    const users = [
      { username: "alice" },
      { username: "bob", displayName: "Bob Wu" },
      { username: "clara", displayName: "Clara Lee" },
      { username: "david", displayName: "David Lin" },
    ] as const;
    for (const user of users) {
      const result = await registration.request<{
        account: Record<string, unknown>;
      }>("/api/register", {
        method: "POST",
        body: {
          ...user,
          password: "correct-horse-123",
          role: "administrator",
        },
      });
      assert.equal(result.status, 201);
      assert.deepEqual(Object.keys(result.payload.account).sort(), [
        "createdAt",
        "displayName",
        "userId",
        "username",
      ]);
      assert.equal("role" in result.payload.account, false);
      assert.equal(
        result.payload.account.displayName,
        "displayName" in user ? user.displayName : user.username,
      );
    }

    const wrongPassword = await new BrowserSession(origin).request<{
      code: string;
    }>("/api/login", {
      method: "POST",
      body: { username: "alice", password: "wrong" },
    });
    assert.equal(wrongPassword.status, 401);
    assert.equal(wrongPassword.payload.code, "LOGIN_FAILED");

    const ordinaryAdministratorAttempt = await new BrowserSession(origin).request<{
      code: string;
    }>("/api/administrator/login", {
      method: "POST",
      body: { username: "alice", password: "correct-horse-123" },
    });
    assert.equal(ordinaryAdministratorAttempt.status, 401);
    assert.equal(ordinaryAdministratorAttempt.payload.code, "LOGIN_FAILED");

    const alice = new BrowserSession(origin);
    const bob = new BrowserSession(origin);
    const clara = new BrowserSession(origin);
    const david = new BrowserSession(origin);
    const administrator = new BrowserSession(origin);

    for (const [browser, username] of [
      [alice, "alice"],
      [bob, "bob"],
      [clara, "clara"],
      [david, "david"],
    ] as const) {
      const dashboard = await browser.login(username);
      assert.equal(dashboard.account.username, username);
      assert.equal(dashboard.account.kind, "user");
      assert.deepEqual(dashboard.purchases, []);
      assert.equal(dashboard.canIssuePurchases, false);
      assert.equal(dashboard.account.isAdministrator, false);
    }

    let administratorDashboard = await administrator.loginAdministrator(
      "manager",
      "12345678",
    );
    assert.equal(administratorDashboard.account.isAdministrator, true);
    assert.deepEqual(administratorDashboard.account.specialRoles, []);

    let bobDashboard = await bob.action("/api/organizations", {
      organizationId: "acme-audio",
      name: "Acme Audio",
    });
    assert.deepEqual(bobDashboard.organizations, []);
    assert.equal(bobDashboard.organizationRequests[0]?.status, "pending");
    const organizationRequestId =
      bobDashboard.organizationRequests[0]!.requestId;

    const aliceAdminAttempt = await alice.request<{ code: string }>(
      "/api/administrator/organization-requests/decide",
      {
        method: "POST",
        body: {
          requestId: organizationRequestId,
          decision: "approved",
        },
      },
    );
    assert.equal(aliceAdminAttempt.status, 403);
    assert.equal(aliceAdminAttempt.payload.code, "ADMINISTRATOR_REQUIRED");

    administratorDashboard = await administrator.action(
      "/api/administrator/organization-requests/decide",
      { requestId: organizationRequestId, decision: "approved" },
    );
    assert.deepEqual(
      administratorDashboard.administratorApprovals.organizationRequests,
      [],
    );
    bobDashboard = await bob.dashboard();
    assert.equal(bobDashboard.organizations[0]?.name, "Acme Audio");
    bobDashboard = await bob.action("/api/products", {
      organizationId: "acme-audio",
      productId: "H1",
      name: "H1 Headphones",
    });
    assert.equal(bobDashboard.organizations[0]?.products[0]?.productId, "H1");
    assert.equal(bobDashboard.products[0]?.belongsToAccountOrganization, true);
    assert.equal(bobDashboard.products[0]?.availableForPurchase, false);
    assert.equal(bobDashboard.authorityGrants.length, 2);
    assert.equal(bobDashboard.canIssuePurchases, true);
    const immediatelyAvailableProduct = await alice.dashboard();
    assert.equal(
      immediatelyAvailableProduct.products[0]?.availableForPurchase,
      true,
    );

    const ownerPurchaseGrant = bobDashboard.authorityGrants.find(
      (grant) =>
        grant.productId === "H1" &&
        grant.capability === "issue-purchase-credential" &&
        grant.receivedByYou,
    );
    assert.ok(ownerPurchaseGrant);
    bobDashboard = await bob.action("/api/authority-grants/revoke", {
      grantId: ownerPurchaseGrant.grantId,
    });
    const davidCatalogWithoutActiveIssuer = await david.dashboard();
    assert.equal(
      davidCatalogWithoutActiveIssuer.products[0]?.availableForPurchase,
      true,
    );
    const davidPurchaseWithoutActiveIssuer = await david.action(
      "/api/actions/buy-product",
      { productId: "H1" },
    );
    assert.equal(davidPurchaseWithoutActiveIssuer.purchases.length, 1);

    const prematureGrant = await bob.request<{ code: string }>(
      "/api/authority-grants",
      {
        method: "POST",
        body: {
          productId: "H1",
          granteeUsername: "clara",
          capability: "issue-purchase-credential",
        },
      },
    );
    assert.equal(prematureGrant.status, 403);
    assert.equal(
      prematureGrant.payload.code,
      "ORGANIZATION_MEMBERSHIP_REQUIRED",
    );

    let claraDashboard = await clara.action("/api/membership-requests", {
      organizationId: "acme-audio",
    });
    assert.equal(claraDashboard.membershipRequests[0]?.status, "pending");
    const membershipRequestId =
      claraDashboard.membershipRequests[0]!.requestId;

    const aliceMembershipAttempt = await alice.request<{ code: string }>(
      "/api/membership-requests/decide",
      {
        method: "POST",
        body: {
          requestId: membershipRequestId,
          decision: "approved",
        },
      },
    );
    assert.equal(aliceMembershipAttempt.status, 403);
    assert.equal(
      aliceMembershipAttempt.payload.code,
      "ORGANIZATION_CREATOR_REQUIRED",
    );

    bobDashboard = await bob.action("/api/membership-requests/decide", {
      requestId: membershipRequestId,
      decision: "approved",
    });
    assert.equal(bobDashboard.organizations[0]?.members.length, 2);

    bobDashboard = await bob.action("/api/authority-grants", {
      productId: "H1",
      granteeUsername: "clara",
      capability: "issue-purchase-credential",
    });
    bobDashboard = await bob.action("/api/authority-grants", {
      productId: "H1",
      granteeUsername: "clara",
      capability: "handle-support-cases",
    });
    assert.equal(bobDashboard.authorityGrants.length, 5);
    claraDashboard = await clara.dashboard();
    assert.equal(claraDashboard.products[0]?.belongsToAccountOrganization, true);
    assert.equal(claraDashboard.products[0]?.availableForPurchase, false);

    for (const merchantAccount of [bob, clara]) {
      const ownMerchantPurchase = await merchantAccount.request<{ code: string }>(
        "/api/actions/buy-product",
        { method: "POST", body: { productId: "H1" } },
      );
      assert.equal(ownMerchantPurchase.status, 403);
      assert.equal(
        ownMerchantPurchase.payload.code,
        "MERCHANT_ACCOUNT_CANNOT_BUY",
      );
    }

    let davidDashboard = await david.action("/api/special-role-requests", {
      role: "regulator",
      justification: "Review consumer product safety disclosures",
    });
    assert.equal(davidDashboard.specialRoleRequests[0]?.status, "pending");
    assert.deepEqual(davidDashboard.account.specialRoles, []);
    const regulatorRequestId = davidDashboard.specialRoleRequests[0]!.requestId;

    const claraRoleApprovalAttempt = await clara.request<{ code: string }>(
      "/api/administrator/special-role-requests/decide",
      {
        method: "POST",
        body: {
          requestId: regulatorRequestId,
          decision: "approved",
        },
      },
    );
    assert.equal(claraRoleApprovalAttempt.status, 403);
    assert.equal(claraRoleApprovalAttempt.payload.code, "ADMINISTRATOR_REQUIRED");

    administratorDashboard = await administrator.action(
      "/api/administrator/special-role-requests/decide",
      { requestId: regulatorRequestId, decision: "approved" },
    );
    assert.deepEqual(
      administratorDashboard.administratorApprovals.specialRoleRequests,
      [],
    );
    davidDashboard = await david.dashboard();
    assert.deepEqual(davidDashboard.account.specialRoles, ["regulator"]);

    const unauthorizedProduct = await alice.request<{ code: string }>(
      "/api/products",
      {
        method: "POST",
        body: {
          organizationId: "acme-audio",
          productId: "H2",
          name: "Unauthorized",
        },
      },
    );
    assert.equal(unauthorizedProduct.status, 403);
    assert.equal(unauthorizedProduct.payload.code, "ORGANIZATION_CONTROL_REQUIRED");

    claraDashboard = await clara.dashboard();
    assert.equal(claraDashboard.canIssuePurchases, true);
    assert.equal((await alice.dashboard()).canIssuePurchases, false);
    assert.equal((await bob.dashboard()).canIssuePurchases, true);
    assert.equal((await david.dashboard()).canIssuePurchases, false);
    const aliceCatalog = await alice.dashboard();
    assert.equal(aliceCatalog.products[0]?.belongsToAccountOrganization, false);
    assert.equal(aliceCatalog.products[0]?.availableForPurchase, true);

    let aliceDashboard = await alice.action("/api/actions/buy-product", {
      productId: "H1",
    });
    assert.equal(aliceDashboard.purchases.length, 1);
    assert.match(aliceDashboard.purchases[0]!.orderId, /^ORD-[A-F0-9]{8}$/);
    assert.equal(aliceDashboard.purchases[0]!.canReview, true);
    assert.equal(aliceDashboard.purchases[0]!.canRequestSupport, true);
    const privateOrderId = aliceDashboard.purchases[0]!.orderId;
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
    assert.equal(publicReviewJson.includes(privateOrderId), false);

    bobDashboard = await bob.dashboard();
    assert.equal(bobDashboard.reviews.length, 1);
    assert.equal(bobDashboard.reviews[0]!.openedByYou, false);
    assert.deepEqual(bobDashboard.purchases, []);
    assert.deepEqual(bobDashboard.supportInbox, []);
    assert.deepEqual(bobDashboard.assignedCases, []);
    for (const privateValue of ["alice", privateOrderId, "CASE-001", "REG-001"]) {
      assert.equal(JSON.stringify(bobDashboard.reviews).includes(privateValue), false);
    }

    bobDashboard = await bob.action("/api/actions/open-review", { reviewId });
    assert.equal(bobDashboard.reviews[0]!.openedByYou, true);
    assert.match(bobDashboard.reviews[0]!.text, /battery swelled/);
    assert.deepEqual(bobDashboard.purchases, []);

    const publicReviews = await new BrowserSession(origin).request<{
      reviews: PlatformDashboard["reviews"];
    }>("/api/public/reviews");
    assert.equal(publicReviews.status, 200);
    assert.equal(publicReviews.payload.reviews[0]?.reviewId, reviewId);
    assert.equal(JSON.stringify(publicReviews.payload).includes(privateOrderId), false);

    aliceDashboard = await alice.action("/api/actions/request-support", {
      purchaseId,
    });
    assert.equal(aliceDashboard.purchases[0]!.support?.caseId, "CASE-001");
    assert.equal(aliceDashboard.counts.publicCommitments, 2);

    claraDashboard = await clara.dashboard();
    assert.equal(claraDashboard.supportInbox.length, 1);
    assert.equal(claraDashboard.supportInbox[0]!.caseId, "CASE-001");
    const supportInboxJson = JSON.stringify(claraDashboard.supportInbox);
    assert.equal(supportInboxJson.includes("alice"), false);
    assert.equal(supportInboxJson.includes(privateOrderId), false);
    assert.equal(supportInboxJson.includes("battery swelled"), false);

    claraDashboard = await clara.action("/api/actions/decide-support", {
      caseId: "CASE-001",
      outcome: "rejected",
      reason: "Inspection is required before replacement approval.",
    });
    assert.equal(claraDashboard.supportInbox[0]!.outcome, "rejected");
    assert.equal(claraDashboard.counts.publicCommitments, 3);

    aliceDashboard = await alice.dashboard();
    assert.equal(aliceDashboard.purchases[0]!.support?.outcome, "rejected");
    assert.equal(aliceDashboard.purchases[0]!.canEscalate, true);

    const nonRegulatorDisclosure = await alice.request<{ code: string }>(
      "/api/actions/escalate",
      {
        method: "POST",
        body: {
          purchaseId,
          reviewerUsername: "clara",
          purpose: "Invalid non-regulator recipient",
        },
      },
    );
    assert.equal(nonRegulatorDisclosure.status, 403);
    assert.equal(nonRegulatorDisclosure.payload.code, "SPECIAL_ROLE_REQUIRED");

    aliceDashboard = await alice.action("/api/actions/escalate", {
      purchaseId,
      reviewerUsername: "david",
      purpose: "Investigate the H1 battery safety dispute",
    });
    assert.equal(aliceDashboard.purchases[0]!.regulatoryCase?.caseId, "REG-001");
    assert.equal(aliceDashboard.counts.publicCommitments, 4);

    assert.deepEqual((await clara.dashboard()).assignedCases, []);
    assert.deepEqual((await bob.dashboard()).assignedCases, []);
    davidDashboard = await david.dashboard();
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

    aliceDashboard = await alice.action("/api/actions/buy-product", {
      productId: "H1",
    });
    const purchaseWithoutReview = aliceDashboard.purchases.find(
      (purchase) => purchase.reviewId === null && purchase.support === null,
    );
    assert.ok(purchaseWithoutReview);

    aliceDashboard = await alice.action("/api/actions/request-support", {
      purchaseId: purchaseWithoutReview.purchaseId,
    });
    claraDashboard = await clara.action("/api/actions/decide-support", {
      caseId: "CASE-002",
      outcome: "rejected",
      reason: "The merchant declined the second replacement request.",
    });
    assert.equal(claraDashboard.supportInbox.length, 2);

    aliceDashboard = await alice.dashboard();
    const rejectedPurchaseWithoutReview = aliceDashboard.purchases.find(
      (purchase) => purchase.purchaseId === purchaseWithoutReview.purchaseId,
    );
    assert.ok(rejectedPurchaseWithoutReview);
    assert.equal(rejectedPurchaseWithoutReview.reviewId, null);
    assert.equal(rejectedPurchaseWithoutReview.support?.outcome, "rejected");
    assert.equal(rejectedPurchaseWithoutReview.canEscalate, true);

    aliceDashboard = await alice.action("/api/actions/escalate", {
      purchaseId: purchaseWithoutReview.purchaseId,
      reviewerUsername: "david",
      purpose: "Investigate the rejected replacement request",
    });
    assert.equal(
      aliceDashboard.purchases.find(
        (purchase) => purchase.purchaseId === purchaseWithoutReview.purchaseId,
      )?.regulatoryCase?.caseId,
      "REG-002",
    );

    davidDashboard = await david.action("/api/actions/verify-case", {
      caseId: "REG-002",
    });
    assert.deepEqual(
      davidDashboard.assignedCases.find(({ caseId }) => caseId === "REG-002")
        ?.result,
      {
        samePurchase: true,
        reviewIntegrity: null,
        supportDecisionIntegrity: true,
      },
    );

    const claraPrivateCaseAttempt = await clara.request<{ code: string }>(
      "/api/actions/verify-case",
      { method: "POST", body: { caseId: "REG-001" } },
    );
    assert.equal(claraPrivateCaseAttempt.status, 403);
    assert.equal(claraPrivateCaseAttempt.payload.code, "SPECIAL_ROLE_REQUIRED");

    const logout = await alice.request<{ ok: boolean }>("/api/logout", {
      method: "POST",
    });
    assert.equal(logout.status, 200);
    assert.equal(logout.payload.ok, true);
    assert.equal((await alice.request("/api/dashboard")).status, 401);
  });
});
