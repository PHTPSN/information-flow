import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, describe, it } from "node:test";

import { createInformationFlowDemoServer } from "../src/demo-server.js";
import type { PlatformDashboard } from "../src/platform-demo.js";

interface ApiResult<T> {
  readonly status: number;
  readonly payload: T;
}

class BrowserSession {
  origin = "";
  #cookie: string | null = null;

  async request<T>(
    requestPath: string,
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
    const response = await fetch(`${this.origin}${requestPath}`, requestInit);
    const setCookie = response.headers.get("set-cookie");
    if (setCookie !== null) this.#cookie = setCookie.split(";", 1)[0]!;
    return {
      status: response.status,
      payload: (await response.json()) as T,
    };
  }

  async login(
    username: string,
    password = "correct-horse-123",
  ): Promise<PlatformDashboard> {
    const response = await this.request<PlatformDashboard>("/api/login", {
      method: "POST",
      body: { username, password },
    });
    assert.equal(response.status, 200);
    return response.payload;
  }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

describe("persistent foundation", () => {
  let temporaryDirectory = "";
  let activeServer: Server | null = null;

  after(async () => {
    if (activeServer?.listening) await close(activeServer);
    if (temporaryDirectory !== "") {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  });

  it("survives restart and enforces control, expiration, and revocation", async () => {
    temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "information-flow-foundation-"),
    );
    const databasePath = path.join(temporaryDirectory, "application.sqlite");
    const encryptionKey = randomBytes(32);
    let currentTime = new Date("2026-09-18T00:00:00.000Z");
    const clock = () => new Date(currentTime);
    const serverOptions = {
      databasePath,
      encryptionKey,
      clock,
      sessionTtlMs: 24 * 60 * 60 * 1_000,
    };

    let server = createInformationFlowDemoServer({
      ...serverOptions,
      bootstrapAdministrator: {
        username: "admin",
        displayName: "System Administrator",
        password: "legacy-admin-password",
      },
    });
    activeServer = server;
    let origin = await listen(server);
    const legacyAdministrator = new BrowserSession();
    legacyAdministrator.origin = origin;
    await legacyAdministrator.login(
      "admin",
      "legacy-admin-password",
    );
    await close(server);
    activeServer = null;
    const legacyDatabase = new DatabaseSync(databasePath, { readOnly: true });
    const { user_id: administratorUserId } = legacyDatabase
      .prepare("SELECT user_id FROM system_administrators")
      .get() as { user_id: string };
    legacyDatabase.close();

    server = createInformationFlowDemoServer(serverOptions);
    activeServer = server;
    origin = await listen(server);
    const registration = new BrowserSession();
    registration.origin = origin;
    for (const username of ["controller", "staff", "outsider", "regulator"]) {
      const response = await registration.request<{ account: object }>(
        "/api/register",
        {
          method: "POST",
          body: {
            username,
            password: "correct-horse-123",
            role: "administrator",
          },
        },
      );
      assert.equal(response.status, 201);
    }
    const controller = new BrowserSession();
    const staff = new BrowserSession();
    const outsider = new BrowserSession();
    const regulator = new BrowserSession();
    const administrator = new BrowserSession();
    for (const browser of [
      controller,
      staff,
      outsider,
      regulator,
      administrator,
    ]) {
      browser.origin = origin;
    }
    await controller.login("controller");
    await staff.login("staff");
    await outsider.login("outsider");
    await regulator.login("regulator");
    const administratorDashboard = await administrator.login(
      "manager",
      "12345678",
    );
    assert.equal(administratorDashboard.account.isAdministrator, true);

    let response = await controller.request<PlatformDashboard>(
      "/api/organizations",
      {
        method: "POST",
        body: { organizationId: "acme-audio", name: "Acme Audio" },
      },
    );
    assert.equal(response.status, 202);
    assert.deepEqual(response.payload.organizations, []);
    assert.equal(response.payload.organizationRequests[0]?.status, "pending");
    const organizationRequestId =
      response.payload.organizationRequests[0]!.requestId;

    const unauthorizedOrganizationApproval = await outsider.request<{
      code: string;
    }>("/api/administrator/organization-requests/decide", {
      method: "POST",
      body: {
        requestId: organizationRequestId,
        decision: "approved",
      },
    });
    assert.equal(unauthorizedOrganizationApproval.status, 403);
    assert.equal(
      unauthorizedOrganizationApproval.payload.code,
      "ADMINISTRATOR_REQUIRED",
    );

    const approvedOrganization = await administrator.request<PlatformDashboard>(
      "/api/administrator/organization-requests/decide",
      {
        method: "POST",
        body: {
          requestId: organizationRequestId,
          decision: "approved",
        },
      },
    );
    assert.equal(approvedOrganization.status, 200);
    response = await controller.request<PlatformDashboard>("/api/dashboard");
    assert.equal(response.payload.organizations[0]?.name, "Acme Audio");

    response = await controller.request<PlatformDashboard>("/api/products", {
      method: "POST",
      body: {
        organizationId: "acme-audio",
        productId: "H1",
        name: "H1 Headphones",
      },
    });
    assert.equal(response.status, 201);

    const unauthorizedProduct = await outsider.request<{ code: string }>(
      "/api/products",
      {
        method: "POST",
        body: {
          organizationId: "acme-audio",
          productId: "H2",
          name: "Unauthorized product",
        },
      },
    );
    assert.equal(unauthorizedProduct.status, 403);
    assert.equal(
      unauthorizedProduct.payload.code,
      "ORGANIZATION_CONTROL_REQUIRED",
    );

    const nonMemberGrant = await controller.request<{ code: string }>(
      "/api/authority-grants",
      {
        method: "POST",
        body: {
          productId: "H1",
          granteeUsername: "staff",
          capability: "issue-purchase-credential",
        },
      },
    );
    assert.equal(nonMemberGrant.status, 403);
    assert.equal(
      nonMemberGrant.payload.code,
      "ORGANIZATION_MEMBERSHIP_REQUIRED",
    );

    const membershipRequest = await staff.request<PlatformDashboard>(
      "/api/membership-requests",
      {
        method: "POST",
        body: { organizationId: "acme-audio" },
      },
    );
    assert.equal(membershipRequest.status, 202);
    const membershipRequestId =
      membershipRequest.payload.membershipRequests[0]!.requestId;

    const unauthorizedMembershipApproval = await outsider.request<{
      code: string;
    }>("/api/membership-requests/decide", {
      method: "POST",
      body: {
        requestId: membershipRequestId,
        decision: "approved",
      },
    });
    assert.equal(unauthorizedMembershipApproval.status, 403);
    assert.equal(
      unauthorizedMembershipApproval.payload.code,
      "ORGANIZATION_CREATOR_REQUIRED",
    );

    const approvedMembership = await controller.request<PlatformDashboard>(
      "/api/membership-requests/decide",
      {
        method: "POST",
        body: {
          requestId: membershipRequestId,
          decision: "approved",
        },
      },
    );
    assert.equal(approvedMembership.status, 200);
    assert.equal(approvedMembership.payload.organizations[0]?.members.length, 2);

    const roleApplication = await regulator.request<PlatformDashboard>(
      "/api/special-role-requests",
      {
        method: "POST",
        body: {
          role: "regulator",
          justification: "Review scoped consumer safety disclosures",
        },
      },
    );
    assert.equal(roleApplication.status, 202);
    const roleRequestId = roleApplication.payload.specialRoleRequests[0]!.requestId;
    const unauthorizedRoleApproval = await outsider.request<{ code: string }>(
      "/api/administrator/special-role-requests/decide",
      {
        method: "POST",
        body: { requestId: roleRequestId, decision: "approved" },
      },
    );
    assert.equal(unauthorizedRoleApproval.status, 403);
    assert.equal(
      unauthorizedRoleApproval.payload.code,
      "ADMINISTRATOR_REQUIRED",
    );
    const approvedRole = await administrator.request<PlatformDashboard>(
      "/api/administrator/special-role-requests/decide",
      {
        method: "POST",
        body: { requestId: roleRequestId, decision: "approved" },
      },
    );
    assert.equal(approvedRole.status, 200);

    const issuerExpiration = "2026-09-18T01:00:00.000Z";
    response = await controller.request<PlatformDashboard>(
      "/api/authority-grants",
      {
        method: "POST",
        body: {
          productId: "H1",
          granteeUsername: "staff",
          capability: "issue-purchase-credential",
          expiresAt: issuerExpiration,
        },
      },
    );
    assert.equal(response.status, 201);
    response = await controller.request<PlatformDashboard>(
      "/api/authority-grants",
      {
        method: "POST",
        body: {
          productId: "H1",
          granteeUsername: "staff",
          capability: "handle-support-cases",
        },
      },
    );
    assert.equal(response.status, 201);

    const outsiderDashboard = await outsider.request<PlatformDashboard>(
      "/api/dashboard",
    );
    assert.equal(outsiderDashboard.status, 200);
    assert.deepEqual(outsiderDashboard.payload.organizations, []);
    assert.deepEqual(outsiderDashboard.payload.authorityGrants, []);

    await close(server);
    activeServer = null;
    const preDefaultAuthorityDatabase = new DatabaseSync(databasePath);
    const { user_id: controllerUserId } = preDefaultAuthorityDatabase
      .prepare("SELECT user_id FROM accounts WHERE username = 'controller'")
      .get() as { user_id: string };
    preDefaultAuthorityDatabase
      .prepare(
        `DELETE FROM authority_grants
          WHERE product_id = 'H1' AND grantee_user_id = ?`,
      )
      .run(controllerUserId);
    preDefaultAuthorityDatabase.close();
    server = createInformationFlowDemoServer(serverOptions);
    activeServer = server;
    origin = await listen(server);
    for (const browser of [
      controller,
      staff,
      outsider,
      regulator,
      administrator,
    ]) {
      browser.origin = origin;
    }

    const restoredSession = await controller.request<{
      authenticated: boolean;
      account: { username: string };
    }>("/api/session");
    assert.equal(restoredSession.status, 200);
    assert.equal(restoredSession.payload.authenticated, true);
    assert.equal(restoredSession.payload.account.username, "controller");

    const restoredController = await controller.request<PlatformDashboard>(
      "/api/dashboard",
    );
    assert.equal(restoredController.status, 200);
    assert.equal(restoredController.payload.organizations[0]?.name, "Acme Audio");
    assert.equal(
      restoredController.payload.organizations[0]?.products[0]?.productId,
      "H1",
    );
    assert.equal(restoredController.payload.authorityGrants.length, 4);
    assert.equal(restoredController.payload.canIssuePurchases, true);
    const restoredStaff = await staff.request<PlatformDashboard>(
      "/api/dashboard",
    );
    assert.equal(restoredStaff.payload.memberships[0]?.organizationId, "acme-audio");
    const restoredRegulator = await regulator.request<PlatformDashboard>(
      "/api/dashboard",
    );
    assert.deepEqual(restoredRegulator.payload.account.specialRoles, [
      "regulator",
    ]);

    const activeIssue = await staff.request<PlatformDashboard>(
      "/api/actions/issue-purchase",
      {
        method: "POST",
        body: {
          productId: "H1",
          buyerUsername: "outsider",
          orderId: "ORD-PERSISTED-AUTHORITY",
        },
      },
    );
    assert.equal(activeIssue.status, 200);

    currentTime = new Date("2026-09-18T02:00:00.000Z");
    const expiredIssue = await staff.request<{ code: string }>(
      "/api/actions/issue-purchase",
      {
        method: "POST",
        body: {
          productId: "H1",
          buyerUsername: "controller",
          orderId: "ORD-EXPIRED",
        },
      },
    );
    assert.equal(expiredIssue.status, 403);
    assert.equal(expiredIssue.payload.code, "AUTHORITY_REQUIRED");

    response = await controller.request<PlatformDashboard>(
      "/api/authority-grants",
      {
        method: "POST",
        body: {
          productId: "H1",
          granteeUsername: "staff",
          capability: "issue-purchase-credential",
          expiresAt: "2026-09-19T00:00:00.000Z",
        },
      },
    );
    assert.equal(response.status, 201);
    const replacementGrant = response.payload.authorityGrants.find(
      (grant) =>
        grant.capability === "issue-purchase-credential" &&
        grant.status === "active",
    );
    assert.ok(replacementGrant);

    const unauthorizedRevoke = await outsider.request<{ code: string }>(
      "/api/authority-grants/revoke",
      { method: "POST", body: { grantId: replacementGrant.grantId } },
    );
    assert.equal(unauthorizedRevoke.status, 403);
    assert.equal(
      unauthorizedRevoke.payload.code,
      "ORGANIZATION_CONTROL_REQUIRED",
    );

    const revoked = await controller.request<PlatformDashboard>(
      "/api/authority-grants/revoke",
      { method: "POST", body: { grantId: replacementGrant.grantId } },
    );
    assert.equal(revoked.status, 200);
    assert.equal(
      revoked.payload.authorityGrants.find(
        (grant) => grant.grantId === replacementGrant.grantId,
      )?.status,
      "revoked",
    );

    const revokedIssue = await staff.request<{ code: string }>(
      "/api/actions/issue-purchase",
      {
        method: "POST",
        body: {
          productId: "H1",
          buyerUsername: "controller",
          orderId: "ORD-REVOKED",
        },
      },
    );
    assert.equal(revokedIssue.status, 403);
    assert.equal(revokedIssue.payload.code, "AUTHORITY_REQUIRED");

    await close(server);
    activeServer = null;

    const database = new DatabaseSync(databasePath, { readOnly: true });
    const migrations = database
      .prepare("SELECT name FROM schema_migrations ORDER BY name")
      .all() as Array<{ name: string }>;
    assert.deepEqual(migrations.map(({ name }) => name), [
      "001_wave_2_foundation.sql",
      "002_approval_workflows.sql",
    ]);
    const persistedCounts = database
      .prepare(
        `SELECT
           (SELECT count(*) FROM accounts) AS accounts,
           (SELECT count(*) FROM organizations) AS organizations,
           (SELECT count(*) FROM products) AS products,
           (SELECT count(*) FROM authority_grants) AS grants,
           (SELECT count(*) FROM login_sessions) AS sessions,
           (SELECT count(*) FROM system_administrators) AS administrators,
           (SELECT count(*) FROM organization_creation_requests) AS organization_requests,
           (SELECT count(*) FROM organization_memberships) AS memberships,
           (SELECT count(*) FROM organization_membership_requests) AS membership_requests,
           (SELECT count(*) FROM special_role_requests) AS role_requests,
           (SELECT count(*) FROM account_special_roles) AS special_roles`,
      )
      .get() as {
      accounts: number;
      organizations: number;
      products: number;
      grants: number;
      sessions: number;
      administrators: number;
      organization_requests: number;
      memberships: number;
      membership_requests: number;
      role_requests: number;
      special_roles: number;
    };
    const persistedAdministrators = database
      .prepare(
        `SELECT a.user_id, a.username, a.display_name
           FROM system_administrators administrator
           JOIN accounts a ON a.user_id = administrator.user_id`,
      )
      .all() as Array<{
      user_id: string;
      username: string;
      display_name: string;
    }>;
    database.close();
    assert.deepEqual({ ...persistedCounts }, {
      accounts: 5,
      organizations: 1,
      products: 1,
      grants: 5,
      sessions: 5,
      administrators: 1,
      organization_requests: 1,
      memberships: 2,
      membership_requests: 1,
      role_requests: 1,
      special_roles: 1,
    });
    assert.deepEqual(persistedAdministrators.map((row) => ({ ...row })), [
      {
        user_id: administratorUserId,
        username: "manager",
        display_name: "Manager",
      },
    ]);
    const databaseBytes = await readFile(databasePath);
    assert.equal(databaseBytes.includes(Buffer.from("BEGIN PRIVATE KEY")), false);
    assert.equal(databaseBytes.includes(encryptionKey), false);
  });
});
