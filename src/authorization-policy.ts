import { ApplicationError } from "./application-error.js";
import {
  ApplicationStore,
  type AuthorityGrantRecord,
  type GrantCapability,
  type OrganizationRecord,
  type ProductRecord,
  type SpecialRole,
} from "./persistence.js";

export type GrantStatus = "active" | "expired" | "revoked";

export function authorityGrantStatus(
  grant: AuthorityGrantRecord,
  now: string,
): GrantStatus {
  if (grant.revokedAt !== null) return "revoked";
  if (grant.expiresAt !== null && grant.expiresAt <= now) return "expired";
  return "active";
}

export class AuthorizationPolicy {
  constructor(
    private readonly store: ApplicationStore,
    private readonly clock: () => Date,
  ) {}

  requireSystemAdministrator(userId: string): void {
    if (!this.store.isSystemAdministrator(userId)) {
      throw new ApplicationError(
        403,
        "ADMINISTRATOR_REQUIRED",
        "System administrator approval is required",
      );
    }
  }

  requireOrganizationCreator(
    userId: string,
    organizationId: string,
  ): OrganizationRecord {
    const organization = this.store.getOrganization(organizationId);
    if (organization === null) {
      throw new ApplicationError(
        404,
        "ORGANIZATION_NOT_FOUND",
        "Organization not found",
      );
    }
    if (organization.createdByUserId !== userId) {
      throw new ApplicationError(
        403,
        "ORGANIZATION_CREATOR_REQUIRED",
        "Only the organization creator can approve membership",
      );
    }
    return organization;
  }

  requireOrganizationMembership(userId: string, organizationId: string): void {
    if (!this.store.isOrganizationMember(userId, organizationId)) {
      throw new ApplicationError(
        403,
        "ORGANIZATION_MEMBERSHIP_REQUIRED",
        "Approved organization membership is required",
      );
    }
  }

  requireSpecialRole(userId: string, role: SpecialRole): void {
    if (!this.store.hasSpecialRole(userId, role)) {
      throw new ApplicationError(
        403,
        "SPECIAL_ROLE_REQUIRED",
        `Administrator-approved ${role} status is required`,
      );
    }
  }

  requireOrganizationControl(
    userId: string,
    organizationId: string,
  ): OrganizationRecord {
    const organization = this.store.getOrganization(organizationId);
    if (organization === null) {
      throw new ApplicationError(
        404,
        "ORGANIZATION_NOT_FOUND",
        "Organization not found",
      );
    }
    if (!this.store.controlsOrganization(userId, organizationId)) {
      throw new ApplicationError(
        403,
        "ORGANIZATION_CONTROL_REQUIRED",
        "You do not control this organization",
      );
    }
    return organization;
  }

  requireProductControl(userId: string, productId: string): ProductRecord {
    const product = this.store.getProduct(productId);
    if (product === null) {
      throw new ApplicationError(404, "PRODUCT_NOT_FOUND", "Product not found");
    }
    this.requireOrganizationControl(userId, product.organizationId);
    return product;
  }

  requireGrantControl(
    userId: string,
    grantId: string,
  ): AuthorityGrantRecord {
    const grant = this.store.getAuthorityGrant(grantId);
    if (grant === null) {
      throw new ApplicationError(404, "GRANT_NOT_FOUND", "Authority grant not found");
    }
    this.requireOrganizationControl(userId, grant.organizationId);
    return grant;
  }

  requireActiveGrant(
    userId: string,
    capability: GrantCapability,
    productId: string,
  ): AuthorityGrantRecord {
    const grant = this.store.findActiveAuthorityGrant(
      userId,
      capability,
      productId,
      this.clock().toISOString(),
    );
    if (grant === null) {
      throw new ApplicationError(
        403,
        "AUTHORITY_REQUIRED",
        "An active scoped authority grant is required",
      );
    }
    return grant;
  }

  hasActiveGrant(
    userId: string,
    capability: GrantCapability,
    productId: string,
  ): boolean {
    return (
      this.store.findActiveAuthorityGrant(
        userId,
        capability,
        productId,
        this.clock().toISOString(),
      ) !== null
    );
  }
}
