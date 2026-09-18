import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ApplicationError } from "./application-error.js";
import {
  DEFAULT_ADMIN_DISPLAY_NAME,
  DEFAULT_ADMIN_PASSWORD,
  DEFAULT_ADMIN_USERNAME,
  InformationFlowPlatform,
  PlatformError,
  type InformationFlowPlatformOptions,
} from "./platform-demo.js";
import { decodeDataEncryptionKey } from "./persistence.js";

const adjacentWebDirectory = fileURLToPath(new URL("../web/", import.meta.url));
const WEB_DIRECTORY = existsSync(adjacentWebDirectory)
  ? adjacentWebDirectory
  : path.resolve(process.cwd(), "web");
const SESSION_COOKIE = "if_session";

const STATIC_FILES = new Map([
  ["/", { file: "index.html", contentType: "text/html; charset=utf-8" }],
  [
    "/styles.css",
    { file: "styles.css", contentType: "text/css; charset=utf-8" },
  ],
  [
    "/app.js",
    { file: "app.js", contentType: "text/javascript; charset=utf-8" },
  ],
]);

function sendJson(
  response: ServerResponse<IncomingMessage>,
  status: number,
  value: unknown,
  headers: Record<string, string> = {},
): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(JSON.stringify(value));
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 32_768) {
      throw new PlatformError(413, "BODY_TOO_LARGE", "Request body is too large");
    }
    chunks.push(bytes);
  }
  if (chunks.length === 0) return {};
  try {
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error("Expected an object");
    }
    return value as Record<string, unknown>;
  } catch {
    throw new PlatformError(400, "INVALID_JSON", "Request body must be valid JSON");
  }
}

function sessionToken(request: IncomingMessage): string | null {
  const cookie = request.headers.cookie;
  if (cookie === undefined) return null;
  for (const part of cookie.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === SESSION_COOKIE) return decodeURIComponent(valueParts.join("="));
  }
  return null;
}

function requireToken(request: IncomingMessage): string {
  const token = sessionToken(request);
  if (token === null) {
    throw new PlatformError(401, "AUTH_REQUIRED", "Please log in to continue");
  }
  return token;
}

function sessionHeader(token: string): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`;
}

function clearSessionHeader(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
}

export function createInformationFlowDemoServer(
  options: InformationFlowPlatformOptions = {},
): Server {
  const platform = new InformationFlowPlatform(options);

  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");

      if (request.method === "GET" && url.pathname === "/api/session") {
        const account = platform.session(sessionToken(request));
        sendJson(response, 200, { authenticated: account !== null, account });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/public/reviews") {
        sendJson(response, 200, { reviews: platform.publicReviews() });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/register") {
        const body = await readJson(request);
        const account = platform.register({
          username: body.username,
          displayName: body.displayName,
          password: body.password,
        });
        sendJson(response, 201, { account });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/login") {
        const body = await readJson(request);
        const token = platform.loginUser({
          username: body.username,
          password: body.password,
        });
        sendJson(response, 200, platform.dashboard(token), {
          "set-cookie": sessionHeader(token),
        });
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/administrator/login"
      ) {
        const body = await readJson(request);
        const token = platform.loginAdministrator({
          username: body.username,
          password: body.password,
        });
        sendJson(response, 200, platform.dashboard(token), {
          "set-cookie": sessionHeader(token),
        });
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/logout") {
        const token = sessionToken(request);
        if (token !== null) platform.logout(token);
        sendJson(response, 200, { ok: true }, {
          "set-cookie": clearSessionHeader(),
        });
        return;
      }

      if (request.method === "GET" && url.pathname === "/api/dashboard") {
        sendJson(response, 200, platform.dashboard(requireToken(request)));
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/organizations") {
        const body = await readJson(request);
        sendJson(
          response,
          202,
          platform.requestOrganization(requireToken(request), {
            organizationId: body.organizationId,
            name: body.name,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/administrator/organization-requests/decide"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          200,
          platform.decideOrganizationRequest(requireToken(request), {
            requestId: body.requestId,
            decision: body.decision,
            note: body.note,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/membership-requests"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          202,
          platform.requestMembership(requireToken(request), {
            organizationId: body.organizationId,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/membership-requests/decide"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          200,
          platform.decideMembershipRequest(requireToken(request), {
            requestId: body.requestId,
            decision: body.decision,
            note: body.note,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/special-role-requests"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          202,
          platform.requestSpecialRole(requireToken(request), {
            role: body.role,
            justification: body.justification,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/administrator/special-role-requests/decide"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          200,
          platform.decideSpecialRoleRequest(requireToken(request), {
            requestId: body.requestId,
            decision: body.decision,
            note: body.note,
          }),
        );
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/products") {
        const body = await readJson(request);
        sendJson(
          response,
          201,
          platform.createProduct(requireToken(request), {
            organizationId: body.organizationId,
            productId: body.productId,
            name: body.name,
          }),
        );
        return;
      }

      if (request.method === "POST" && url.pathname === "/api/authority-grants") {
        const body = await readJson(request);
        sendJson(
          response,
          201,
          platform.grantAuthority(requireToken(request), {
            productId: body.productId,
            granteeUsername: body.granteeUsername,
            capability: body.capability,
            expiresAt: body.expiresAt,
          }),
        );
        return;
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/authority-grants/revoke"
      ) {
        const body = await readJson(request);
        sendJson(
          response,
          200,
          platform.revokeAuthority(requireToken(request), {
            grantId: body.grantId,
          }),
        );
        return;
      }

      const actionRoutes = new Map<
        string,
        (token: string, body: Record<string, unknown>) => unknown
      >([
        [
          "/api/actions/issue-purchase",
          (token, body) =>
            platform.issuePurchase(token, {
              productId: body.productId,
              buyerUsername: body.buyerUsername,
              orderId: body.orderId,
            }),
        ],
        [
          "/api/actions/buy-product",
          (token, body) =>
            platform.buyProduct(token, { productId: body.productId }),
        ],
        [
          "/api/actions/publish-review",
          (token, body) =>
            platform.publishReview(token, {
              purchaseId: body.purchaseId,
              rating: body.rating,
              text: body.text,
            }),
        ],
        [
          "/api/actions/open-review",
          (token, body) =>
            platform.openReview(token, { reviewId: body.reviewId }),
        ],
        [
          "/api/actions/request-support",
          (token, body) =>
            platform.requestSupport(token, { purchaseId: body.purchaseId }),
        ],
        [
          "/api/actions/decide-support",
          (token, body) =>
            platform.decideSupport(token, {
              caseId: body.caseId,
              outcome: body.outcome,
              reason: body.reason,
            }),
        ],
        [
          "/api/actions/escalate",
          (token, body) =>
            platform.escalate(token, {
              purchaseId: body.purchaseId,
              reviewerUsername: body.reviewerUsername,
              purpose: body.purpose,
            }),
        ],
        [
          "/api/actions/verify-case",
          (token, body) =>
            platform.verifyCase(token, { caseId: body.caseId }),
        ],
      ]);
      const action = actionRoutes.get(url.pathname);
      if (request.method === "POST" && action !== undefined) {
        const body = await readJson(request);
        sendJson(response, 200, action(requireToken(request), body));
        return;
      }

      const staticFile = STATIC_FILES.get(url.pathname);
      if (request.method === "GET" && staticFile !== undefined) {
        const contents = await readFile(
          path.join(WEB_DIRECTORY, staticFile.file),
          "utf8",
        );
        response.writeHead(200, {
          "content-type": staticFile.contentType,
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "content-security-policy":
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'",
        });
        response.end(contents);
        return;
      }

      sendJson(response, 404, { error: "Not found", code: "NOT_FOUND" });
    } catch (error) {
      const expected =
        error instanceof PlatformError || error instanceof ApplicationError;
      const status = expected ? error.status : 500;
      const code = expected ? error.code : "REQUEST_FAILED";
      sendJson(response, status, {
        error: expected ? error.message : "Request failed",
        code,
      });
    }
  });
  server.once("close", () => platform.close());
  return server;
}

/** Kept as an import-compatible name for existing local scripts. */
export const createFourActorDemoServer = createInformationFlowDemoServer;

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath === fileURLToPath(import.meta.url)) {
  const parsedPort = Number.parseInt(
    process.env.INFORMATION_FLOW_DEMO_PORT ?? "4173",
    10,
  );
  const port = Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : 4173;
  const dataKey = process.env.INFORMATION_FLOW_DATA_KEY;
  if (dataKey === undefined) {
    throw new Error(
      "Set INFORMATION_FLOW_DATA_KEY to a base64url-encoded 32-byte local secret",
    );
  }
  const databasePath = path.resolve(
    process.env.INFORMATION_FLOW_DATABASE_PATH ??
      path.join("data", "information-flow.sqlite"),
  );
  const server = createInformationFlowDemoServer({
    databasePath,
    encryptionKey: decodeDataEncryptionKey(dataKey),
    bootstrapAdministrator: {
      username:
        process.env.INFORMATION_FLOW_ADMIN_USERNAME ?? DEFAULT_ADMIN_USERNAME,
      displayName:
        process.env.INFORMATION_FLOW_ADMIN_DISPLAY_NAME ??
        DEFAULT_ADMIN_DISPLAY_NAME,
      password:
        process.env.INFORMATION_FLOW_ADMIN_PASSWORD ?? DEFAULT_ADMIN_PASSWORD,
    },
  });
  server.listen(port, "127.0.0.1", () => {
    process.stdout.write(`Information Flow MVP: http://127.0.0.1:${port}\n`);
  });
}
