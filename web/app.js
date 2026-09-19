const state = {
  dashboard: null,
  busy: false,
  activeTab: "shop",
};

const elements = {
  authView: document.querySelector("#auth-view"),
  appView: document.querySelector("#app-view"),
  showLogin: document.querySelector("#show-login"),
  showRegister: document.querySelector("#show-register"),
  showAdministratorLogin: document.querySelector("#show-administrator-login"),
  loginForm: document.querySelector("#login-form"),
  registerForm: document.querySelector("#register-form"),
  administratorLoginForm: document.querySelector("#administrator-login-form"),
  registerSuccess: document.querySelector("#register-success"),
  logout: document.querySelector("#logout"),
  workspaceTabs: [...document.querySelectorAll("[data-tab]")],
  shopPanel: document.querySelector("#shop-panel"),
  accountPanel: document.querySelector("#account-panel"),
  activityPanel: document.querySelector("#activity-panel"),
  reviewView: document.querySelector("#review-view"),
  reviewViewTitle: document.querySelector("#review-view-title"),
  reviewViewList: document.querySelector("#review-view-list"),
  backToShop: document.querySelector("#back-to-shop"),
  accountName: document.querySelector("#account-name"),
  accountUsername: document.querySelector("#account-username"),
  welcomeOverline: document.querySelector("#welcome-overline"),
  dashboardTitle: document.querySelector("#dashboard-title"),
  dashboardSubtitle: document.querySelector("#dashboard-subtitle"),
  reviewCount: document.querySelector("#review-count"),
  catalogSection: document.querySelector("#catalog-section"),
  merchantDirectory: document.querySelector("#merchant-directory"),
  foundationSection: document.querySelector("#foundation-section"),
  organizationForm: document.querySelector("#organization-form"),
  membershipForm: document.querySelector("#membership-form"),
  specialRoleForm: document.querySelector("#special-role-form"),
  productForm: document.querySelector("#product-form"),
  grantForm: document.querySelector("#grant-form"),
  organizations: document.querySelector("#organizations"),
  organizationRequests: document.querySelector("#organization-requests"),
  memberships: document.querySelector("#memberships"),
  membershipRequests: document.querySelector("#membership-requests"),
  specialRoleRequests: document.querySelector("#special-role-requests"),
  authorityGrants: document.querySelector("#authority-grants"),
  membershipApprovalsSection: document.querySelector(
    "#membership-approvals-section",
  ),
  membershipApprovals: document.querySelector("#membership-approvals"),
  administratorSection: document.querySelector("#administrator-section"),
  administratorOrganizationApprovals: document.querySelector(
    "#administrator-organization-approvals",
  ),
  administratorRoleApprovals: document.querySelector(
    "#administrator-role-approvals",
  ),
  purchasesSection: document.querySelector("#purchases-section"),
  purchases: document.querySelector("#purchases"),
  salesSection: document.querySelector("#sales-section"),
  purchaseForm: document.querySelector("#purchase-form"),
  supportSection: document.querySelector("#support-section"),
  supportInbox: document.querySelector("#support-inbox"),
  casesSection: document.querySelector("#cases-section"),
  assignedCases: document.querySelector("#assigned-cases"),
  activitySection: document.querySelector("#activity-section"),
  activity: document.querySelector("#activity"),
  toast: document.querySelector("#toast"),
};

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function button(text, action, data = {}) {
  const element = node("button", "button button-secondary", text);
  element.type = "button";
  element.dataset.action = action;
  Object.entries(data).forEach(([key, value]) => {
    element.dataset[key] = value;
  });
  return element;
}

function field(labelText, control) {
  const label = node("label");
  label.append(node("span", "", labelText), control);
  return label;
}

function formValues(form) {
  return Object.fromEntries(new FormData(form).entries());
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    method: options.method ?? "GET",
    headers: options.body ? { "content-type": "application/json" } : undefined,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? "Request failed");
  return payload;
}

function showToast(message, kind = "success") {
  elements.toast.textContent = message;
  elements.toast.dataset.kind = kind;
  elements.toast.hidden = false;
  window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 4200);
}

function setBusy(busy) {
  state.busy = busy;
  document.body.setAttribute("aria-busy", String(busy));
}

function showAuth(mode = "login") {
  state.dashboard = null;
  state.activeTab = "shop";
  elements.authView.hidden = false;
  elements.appView.hidden = true;
  const login = mode === "login";
  const register = mode === "register";
  const administrator = mode === "administrator";
  elements.loginForm.hidden = !login;
  elements.registerForm.hidden = !register;
  elements.administratorLoginForm.hidden = !administrator;
  elements.showLogin.classList.toggle("is-active", login);
  elements.showRegister.classList.toggle("is-active", register);
  elements.showAdministratorLogin.classList.toggle("is-active", administrator);
  elements.showLogin.setAttribute("aria-selected", String(login));
  elements.showRegister.setAttribute("aria-selected", String(register));
  elements.showAdministratorLogin.setAttribute(
    "aria-selected",
    String(administrator),
  );
}

function selectTab(tabName, scroll = true) {
  state.activeTab = tabName;
  const panels = {
    shop: elements.shopPanel,
    account: elements.accountPanel,
    activity: elements.activityPanel,
  };
  Object.entries(panels).forEach(([name, panel]) => {
    panel.hidden = name !== tabName;
  });
  elements.reviewView.hidden = true;
  elements.workspaceTabs.forEach((tab) => {
    const selected = tab.dataset.tab === tabName;
    tab.classList.toggle("is-active", selected);
    tab.setAttribute("aria-selected", String(selected));
  });
  if (scroll) resetPageScroll();
}

function resetPageScroll() {
  document.documentElement.scrollTop = 0;
  document.body.scrollTop = 0;
}

function showProductReviews(productId) {
  const product = state.dashboard.products.find(
    (candidate) => candidate.productId === productId,
  );
  const reviews = state.dashboard.reviews.filter(
    (review) => review.productId === productId,
  );
  elements.shopPanel.hidden = true;
  elements.accountPanel.hidden = true;
  elements.activityPanel.hidden = true;
  elements.reviewViewTitle.textContent = `${product?.name ?? "Product"} comments`;
  renderReviewList(elements.reviewViewList, reviews);
  elements.reviewView.hidden = false;
  resetPageScroll();
}

function option(value, label) {
  const element = document.createElement("option");
  element.value = value;
  element.textContent = label;
  return element;
}

function fillUserSelect(select, users, selected = null) {
  select.replaceChildren(option("", "Select an account"));
  users.forEach((user) => {
    const item = option(user.username, `${user.displayName} (@${user.username})`);
    item.selected = selected === user.username;
    select.append(item);
  });
}

function fillProductSelect(select, products) {
  select.replaceChildren(option("", "Select a product"));
  products.forEach((product) => {
    select.append(
      option(
        product.productId,
        `${product.name} · ${product.organizationName ?? product.organizationId}`,
      ),
    );
  });
}

function appendDecisionButtons(item, approveAction, rejectAction, requestId) {
  const actions = node("div", "card-actions");
  actions.append(
    button("Approve", approveAction, { requestId }),
    button("Reject", rejectAction, { requestId }),
  );
  item.append(actions);
}

function renderCatalog(dashboard) {
  elements.catalogSection.hidden = dashboard.account.isAdministrator;
  elements.merchantDirectory.replaceChildren();
  if (dashboard.account.isAdministrator) return;

  const merchants = new Map();
  dashboard.products.forEach((product) => {
    const merchant = merchants.get(product.organizationId) ?? {
      organizationId: product.organizationId,
      name: product.organizationName,
      products: [],
    };
    merchant.products.push(product);
    merchants.set(product.organizationId, merchant);
  });

  if (merchants.size === 0) {
    elements.merchantDirectory.append(
      node("p", "empty-state", "No merchants have published products yet."),
    );
    return;
  }

  merchants.forEach((merchant) => {
    const directoryItem = node("details", "merchant-card");
    const summary = node("summary", "merchant-summary");
    const identity = node("div");
    identity.append(
      node("span", "merchant-monogram", merchant.name.slice(0, 2).toUpperCase()),
      node("strong", "", merchant.name),
    );
    summary.append(
      identity,
      node(
        "span",
        "merchant-product-count",
        `${merchant.products.length} product${merchant.products.length === 1 ? "" : "s"}`,
      ),
    );
    const products = node("div", "product-grid");
    merchant.products.forEach((product) => {
      const card = node("article", "product-card");
      const visual = node("div", "product-visual");
      visual.append(node("span", "", product.name.slice(0, 1).toUpperCase()));
      const copy = node("div", "product-copy");
      copy.append(
        node("p", "card-kicker", product.productId),
        node("h3", "", product.name),
        node(
          "p",
          "muted",
          `${product.reviewCount} verified comment${product.reviewCount === 1 ? "" : "s"}`,
        ),
      );
      const actions = node("div", "card-actions product-actions");
      const purchaseLabel = product.belongsToAccountOrganization
        ? "Your merchant"
        : "Buy now";
      const hasPurchasePermission =
        product.availableForPurchase ?? product.canPurchase ?? false;
      const buyButton = button(
        purchaseLabel,
        "buy-product",
        { productId: product.productId },
      );
      if (hasPurchasePermission) {
        buyButton.classList.remove("button-secondary");
        buyButton.classList.add("button-primary");
      }
      buyButton.disabled = !hasPurchasePermission;
      actions.append(
        buyButton,
        button("Read comments", "show-product-reviews", {
          productId: product.productId,
        }),
      );
      card.append(visual, copy, actions);
      products.append(card);
    });
    directoryItem.append(summary, products);
    elements.merchantDirectory.append(directoryItem);
  });
}

function renderFoundation(dashboard) {
  elements.foundationSection.hidden = false;
  if (dashboard.account.isAdministrator) elements.foundationSection.open = true;
  const controlledProducts = dashboard.organizations.flatMap((organization) =>
    organization.products.map((product) => ({
      ...product,
      organizationId: organization.organizationId,
      organizationName: organization.name,
      members: organization.members,
    })),
  );
  const grantableAccounts = [
    ...new Map(
      dashboard.organizations
        .flatMap((organization) => organization.members)
        .filter((member) => member.username !== dashboard.account.username)
        .map((member) => [member.userId, member]),
    ).values(),
  ];

  elements.organizationForm.hidden = dashboard.account.isAdministrator;

  elements.membershipForm.hidden =
    dashboard.account.isAdministrator || dashboard.availableOrganizations.length === 0;
  const membershipOrganizationSelect =
    elements.membershipForm.elements.organizationId;
  membershipOrganizationSelect.replaceChildren(
    option("", "Select an organization"),
  );
  dashboard.availableOrganizations.forEach((organization) => {
    membershipOrganizationSelect.append(
      option(organization.organizationId, organization.name),
    );
  });

  const hasPendingRegulatorRequest = dashboard.specialRoleRequests.some(
    (request) => request.role === "regulator" && request.status === "pending",
  );
  elements.specialRoleForm.hidden =
    dashboard.account.isAdministrator ||
    dashboard.account.specialRoles.includes("regulator") ||
    hasPendingRegulatorRequest;

  elements.productForm.hidden = dashboard.organizations.length === 0;
  const organizationSelect = elements.productForm.elements.organizationId;
  organizationSelect.replaceChildren(option("", "Select an organization"));
  dashboard.organizations.forEach((organization) => {
    organizationSelect.append(
      option(organization.organizationId, organization.name),
    );
  });

  elements.grantForm.hidden =
    controlledProducts.length === 0 || grantableAccounts.length === 0;
  const grantProductSelect = elements.grantForm.elements.productId;
  const grantGranteeSelect = elements.grantForm.elements.granteeUsername;
  fillProductSelect(grantProductSelect, controlledProducts);
  const syncGrantRecipients = () => {
    const product = controlledProducts.find(
      (candidate) => candidate.productId === grantProductSelect.value,
    );
    fillUserSelect(
      grantGranteeSelect,
      (product?.members ?? []).filter(
        (member) => member.username !== dashboard.account.username,
      ),
    );
  };
  grantProductSelect.onchange = syncGrantRecipients;
  syncGrantRecipients();

  elements.organizations.replaceChildren();
  if (dashboard.organizations.length === 0) {
    elements.organizations.append(
      node(
        "p",
        "empty-state",
        dashboard.account.isAdministrator
          ? "Administrators approve organizations but do not control them automatically."
          : "Request an organization and wait for administrator approval.",
      ),
    );
  }
  dashboard.organizations.forEach((organization) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", organization.name),
      node("span", "", organization.organizationId),
    );
    item.append(
      identity,
      node(
        "span",
        "row-note",
        `${organization.products.length} product${organization.products.length === 1 ? "" : "s"} · ${organization.members.length} approved member${organization.members.length === 1 ? "" : "s"} · You control this organization`,
      ),
    );
    elements.organizations.append(item);
  });

  elements.organizationRequests.replaceChildren();
  dashboard.organizationRequests.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", `${request.name} · ${request.status}`),
      node("span", "", `Organization request ${request.organizationId}`),
    );
    item.append(identity);
    elements.organizationRequests.append(item);
  });

  elements.memberships.replaceChildren();
  dashboard.memberships.forEach((membership) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", membership.organizationName),
      node("span", "", "Approved organization member"),
    );
    item.append(identity);
    elements.memberships.append(item);
  });

  elements.membershipRequests.replaceChildren();
  dashboard.membershipRequests.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", `${request.organizationName} · ${request.status}`),
      node("span", "", "Membership request"),
    );
    item.append(identity);
    elements.membershipRequests.append(item);
  });

  elements.specialRoleRequests.replaceChildren();
  if (dashboard.account.specialRoles.includes("regulator")) {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", "Regulator"),
      node("span", "", "Approved by the system administrator"),
    );
    item.append(identity);
    elements.specialRoleRequests.append(item);
  }
  dashboard.specialRoleRequests.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", `${request.role} application · ${request.status}`),
      node("span", "", request.justification),
    );
    item.append(identity);
    elements.specialRoleRequests.append(item);
  });

  elements.authorityGrants.replaceChildren();
  dashboard.authorityGrants.forEach((grant) => {
    const item = node("article", "user-row");
    const identity = node("div");
    const action =
      grant.capability === "issue-purchase-credential"
        ? `record ${grant.productName} purchases`
        : `handle ${grant.productName} support cases`;
    identity.append(
      node("strong", "", `${grant.organizationName} · ${grant.status}`),
      node(
        "span",
        "",
        grant.receivedByYou
          ? `${grant.organizationName} authorized you to ${action}`
          : `@${grant.granteeUsername} may ${action}`,
      ),
    );
    item.append(identity);
    if (grant.canRevoke) {
      item.append(
        button("Revoke", "revoke-authority", { grantId: grant.grantId }),
      );
    }
    elements.authorityGrants.append(item);
  });
}

function renderApprovals(dashboard) {
  elements.membershipApprovalsSection.hidden =
    dashboard.pendingMembershipApprovals.length === 0;
  elements.membershipApprovals.replaceChildren();
  dashboard.pendingMembershipApprovals.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", `${request.requesterDisplayName} (@${request.requesterUsername})`),
      node("span", "", `Wants to join ${request.organizationName}`),
    );
    item.append(identity);
    appendDecisionButtons(
      item,
      "approve-membership",
      "reject-membership",
      request.requestId,
    );
    elements.membershipApprovals.append(item);
  });

  elements.administratorSection.hidden = !dashboard.account.isAdministrator;
  elements.administratorOrganizationApprovals.replaceChildren();
  elements.administratorRoleApprovals.replaceChildren();
  if (!dashboard.account.isAdministrator) return;

  const organizationRequests =
    dashboard.administratorApprovals.organizationRequests;
  if (organizationRequests.length === 0) {
    elements.administratorOrganizationApprovals.append(
      node("p", "empty-state", "No pending organization requests."),
    );
  }
  organizationRequests.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", request.name),
      node("span", "", `@${request.requesterUsername} requests ${request.organizationId}`),
    );
    item.append(identity);
    appendDecisionButtons(
      item,
      "approve-organization",
      "reject-organization",
      request.requestId,
    );
    elements.administratorOrganizationApprovals.append(item);
  });

  const roleRequests = dashboard.administratorApprovals.specialRoleRequests;
  if (roleRequests.length === 0) {
    elements.administratorRoleApprovals.append(
      node("p", "empty-state", "No pending special-role applications."),
    );
  }
  roleRequests.forEach((request) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", `${request.requesterDisplayName} requests ${request.role}`),
      node("span", "", request.justification),
    );
    item.append(identity);
    appendDecisionButtons(
      item,
      "approve-special-role",
      "reject-special-role",
      request.requestId,
    );
    elements.administratorRoleApprovals.append(item);
  });
}

function renderPurchases(dashboard) {
  elements.purchasesSection.hidden = dashboard.purchases.length === 0;
  elements.purchases.replaceChildren();
  dashboard.purchases.forEach((purchase) => {
    const card = node("article", "content-card purchase-card");
    const heading = node("div", "card-heading");
    const title = node("div");
    title.append(
      node("p", "card-kicker", `Order ${purchase.orderId}`),
      node("h3", "", purchase.productName),
    );
    heading.append(title, node("span", "badge", "Verified purchase"));
    card.append(heading);

    if (purchase.support) {
      const support = node("div", "status-panel");
      support.append(
        node("strong", "", `Support ${purchase.support.caseId}`),
        node("span", "", purchase.support.outcome),
      );
      if (purchase.support.reason) support.append(node("p", "", purchase.support.reason));
      card.append(support);
    }
    if (purchase.regulatoryCase) {
      card.append(
        node(
          "p",
          "case-line",
          `${purchase.regulatoryCase.caseId} · ${purchase.regulatoryCase.verified ? "evidence checked" : "under review"}`,
        ),
      );
    }

    const actions = node("div", "card-actions");
    if (purchase.canReview) {
      const reviewForm = node("form", "stack-form compact-form");
      reviewForm.dataset.action = "publish-review";
      reviewForm.dataset.purchaseId = purchase.purchaseId;
      const rating = document.createElement("select");
      rating.name = "rating";
      rating.required = true;
      rating.append(option("", "Rating"));
      for (let value = 5; value >= 1; value -= 1) {
        rating.append(option(String(value), `${value} / 5`));
      }
      const text = document.createElement("textarea");
      text.name = "text";
      text.required = true;
      text.rows = 3;
      text.placeholder = "What should other customers know?";
      const submit = node("button", "button button-primary", "Publish comment");
      submit.type = "submit";
      reviewForm.append(field("Write a comment", rating), field("Your comment", text), submit);
      actions.append(reviewForm);
    }
    if (purchase.canRequestSupport) {
      actions.append(
        button("Request a replacement", "request-support", {
          purchaseId: purchase.purchaseId,
        }),
      );
    }
    if (purchase.canEscalate && dashboard.availableRegulators.length > 0) {
      const disclosureForm = node("form", "stack-form compact-form");
      disclosureForm.dataset.action = "escalate";
      disclosureForm.dataset.purchaseId = purchase.purchaseId;
      const reviewer = document.createElement("select");
      reviewer.name = "reviewerUsername";
      reviewer.required = true;
      fillUserSelect(reviewer, dashboard.availableRegulators);
      const purpose = document.createElement("input");
      purpose.name = "purpose";
      purpose.required = true;
      purpose.placeholder = "Purpose for this case-specific disclosure";
      const submit = node(
        "button",
        "button button-primary",
        "Send for review",
      );
      submit.type = "submit";
      disclosureForm.append(
        field("Approved regulator", reviewer),
        field("Purpose", purpose),
        submit,
      );
      actions.append(disclosureForm);
    } else if (purchase.canEscalate) {
      actions.append(
        node(
          "p",
          "empty-state",
          "No administrator-approved regulator is currently available.",
        ),
      );
    }
    card.append(actions);
    elements.purchases.append(card);
  });
}

function renderSales(dashboard) {
  elements.salesSection.hidden = !dashboard.canIssuePurchases;
  if (!dashboard.canIssuePurchases) return;
  fillProductSelect(
    elements.purchaseForm.elements.productId,
    dashboard.issuableProducts,
  );
  fillUserSelect(
    elements.purchaseForm.elements.buyerUsername,
    dashboard.availableBuyers,
  );
}

function renderSupport(dashboard) {
  elements.supportSection.hidden = dashboard.supportInbox.length === 0;
  elements.supportInbox.replaceChildren();
  dashboard.supportInbox.forEach((supportCase) => {
    const card = node("article", "content-card");
    const heading = node("div", "card-heading");
    const title = node("div");
    title.append(
      node("p", "card-kicker", supportCase.caseId),
      node("h3", "", `${supportCase.productName} replacement`),
    );
    heading.append(title, node("span", "badge", supportCase.outcome));
    card.append(
      heading,
      node("p", "muted", `Customer reference ${supportCase.customerReference}…`),
      node(
        "p",
        "fact-line",
        supportCase.purchasedWithinThirtyDays
          ? "Purchased within 30 days"
          : "Outside the replacement window",
      ),
      node(
        "p",
        "fact-line",
        supportCase.replacementAvailable
          ? "Replacement benefit is available"
          : "Replacement benefit has been used",
      ),
    );
    if (supportCase.outcome === "pending") {
      const decisionForm = node("form", "stack-form compact-form");
      decisionForm.dataset.action = "decide-support";
      decisionForm.dataset.caseId = supportCase.caseId;
      const outcome = document.createElement("select");
      outcome.name = "outcome";
      outcome.required = true;
      outcome.append(option("approved", "Approve"), option("rejected", "Reject"));
      const reason = document.createElement("input");
      reason.name = "reason";
      reason.required = true;
      reason.placeholder = "Reason shown to the customer";
      const submit = node("button", "button button-primary", "Save decision");
      submit.type = "submit";
      decisionForm.append(field("Decision", outcome), field("Reason", reason), submit);
      card.append(decisionForm);
    } else if (supportCase.reason) {
      card.append(node("p", "status-copy", supportCase.reason));
    }
    elements.supportInbox.append(card);
  });
}

function renderCases(dashboard) {
  elements.casesSection.hidden = dashboard.assignedCases.length === 0;
  elements.assignedCases.replaceChildren();
  dashboard.assignedCases.forEach((assignedCase) => {
    const card = node("article", "content-card");
    const heading = node("div", "card-heading");
    const title = node("div");
    title.append(
      node("p", "card-kicker", assignedCase.caseId),
      node("h3", "", assignedCase.productName),
    );
    heading.append(
      title,
      node("span", "badge", assignedCase.verified ? "Checked" : "New"),
    );
    card.append(heading, node("p", "muted", assignedCase.purpose));
    if (!assignedCase.verified) {
      card.append(
        button("Verify submitted evidence", "verify-case", {
          caseId: assignedCase.caseId,
        }),
      );
    } else {
      const result = node("div", "status-panel success-panel");
      const evidenceSummary =
        assignedCase.result?.reviewIntegrity === true
          ? "The purchase, comment, and rejected support decision match this case."
          : "The purchase and rejected support decision match this case.";
      result.append(
        node("strong", "", "Evidence checks completed"),
        node("p", "", evidenceSummary),
      );
      card.append(result);
    }
    elements.assignedCases.append(card);
  });
}

function renderReviewList(target, reviews) {
  target.replaceChildren();
  if (reviews.length === 0) {
    target.append(
      node("p", "empty-state", "No customer comments have been published yet."),
    );
    return;
  }
  reviews.forEach((review) => {
    const card = node("article", "review-card");
    const meta = node("div", "review-meta");
    meta.append(
      node("span", "stars", "★".repeat(review.rating) + "☆".repeat(5 - review.rating)),
      node("span", "verified", "Verified purchase"),
    );
    card.append(
      meta,
      node("h3", "", review.productName),
      node("p", "review-copy", review.text),
    );
    target.append(card);
  });
}

function renderActivity(dashboard) {
  elements.activitySection.hidden = false;
  elements.activity.replaceChildren();
  if (dashboard.activity.length === 0) {
    elements.activity.append(node("li", "empty-state", "No activity yet."));
    return;
  }
  dashboard.activity.forEach((entry) => {
    const item = node("li");
    item.append(
      node("strong", "", entry.message),
      node("time", "", new Date(entry.at).toLocaleString()),
    );
    elements.activity.append(item);
  });
}

function renderDashboard(dashboard) {
  state.dashboard = dashboard;
  elements.authView.hidden = true;
  elements.appView.hidden = false;
  elements.accountName.textContent = dashboard.account.displayName;
  const accountCapabilities = [
    dashboard.account.isAdministrator ? "Administrator" : null,
    ...dashboard.account.specialRoles.map(
      (role) => role.charAt(0).toUpperCase() + role.slice(1),
    ),
  ].filter(Boolean);
  elements.accountUsername.textContent = `@${dashboard.account.username}${
    accountCapabilities.length > 0 ? ` · ${accountCapabilities.join(" · ")}` : ""
  }`;
  elements.reviewCount.textContent = String(dashboard.counts.publicReviews);
  elements.welcomeOverline.textContent = dashboard.account.isAdministrator
    ? "System administration"
    : "Your account";
  elements.dashboardTitle.textContent = `Good to see you, ${dashboard.account.displayName.split(" ")[0]}.`;
  elements.dashboardSubtitle.textContent = dashboard.account.isAdministrator
    ? "Review organization and special-role applications."
    : "Browse products by merchant, read verified comments, and manage purchases from one place.";

  elements.catalogSection.hidden = true;
  elements.foundationSection.hidden = true;
  elements.membershipApprovalsSection.hidden = true;
  elements.administratorSection.hidden = true;
  elements.purchasesSection.hidden = true;
  elements.salesSection.hidden = true;
  elements.supportSection.hidden = true;
  elements.casesSection.hidden = true;
  elements.activitySection.hidden = true;

  renderCatalog(dashboard);
  renderFoundation(dashboard);
  renderApprovals(dashboard);
  renderPurchases(dashboard);
  renderSales(dashboard);
  renderSupport(dashboard);
  renderCases(dashboard);
  renderActivity(dashboard);
  if (dashboard.account.isAdministrator && state.activeTab === "shop") {
    state.activeTab = "account";
  }
  selectTab(state.activeTab, false);
  setBusy(false);
}

async function perform(path, body, successMessage) {
  setBusy(true);
  try {
    renderDashboard(await request(path, { method: "POST", body }));
    if (successMessage) showToast(successMessage);
    return true;
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
    return false;
  }
}

elements.showLogin.addEventListener("click", () => showAuth("login"));
elements.showRegister.addEventListener("click", () => showAuth("register"));
elements.showAdministratorLogin.addEventListener("click", () =>
  showAuth("administrator"),
);

elements.registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const values = formValues(elements.registerForm);
  setBusy(true);
  try {
    await request("/api/register", { method: "POST", body: values });
    elements.loginForm.elements.username.value = values.username;
    elements.registerSuccess.textContent = "Account created. You can log in now.";
    elements.registerSuccess.hidden = false;
    showAuth("login");
    showToast("Account created");
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    setBusy(false);
  }
});

elements.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const values = formValues(elements.loginForm);
  setBusy(true);
  try {
    renderDashboard(
      await request("/api/login", {
        method: "POST",
        body: values,
      }),
    );
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
  }
});

elements.administratorLoginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const values = formValues(elements.administratorLoginForm);
  setBusy(true);
  try {
    const dashboard = await request("/api/login", {
      method: "POST",
      body: values,
    });
    if (!dashboard.account.isAdministrator) {
      await request("/api/logout", { method: "POST" });
      throw new Error("Administrator access is required");
    }
    renderDashboard(dashboard);
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
  }
});

elements.logout.addEventListener("click", async () => {
  setBusy(true);
  try {
    await request("/api/logout", { method: "POST" });
    showAuth();
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    setBusy(false);
  }
});

elements.workspaceTabs.forEach((tab) => {
  tab.addEventListener("click", () => selectTab(tab.dataset.tab));
});

elements.backToShop.addEventListener("click", () => selectTab("shop"));

elements.organizationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (await perform(
    "/api/organizations",
    formValues(elements.organizationForm),
    "Organization request submitted for administrator approval",
  )) elements.organizationForm.reset();
});

elements.membershipForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (await perform(
    "/api/membership-requests",
    formValues(elements.membershipForm),
    "Membership request sent to the organization creator",
  )) elements.membershipForm.reset();
});

elements.specialRoleForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (await perform(
    "/api/special-role-requests",
    formValues(elements.specialRoleForm),
    "Regulator application sent to the administrator",
  )) elements.specialRoleForm.reset();
});

elements.productForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (await perform(
    "/api/products",
    formValues(elements.productForm),
    "Product added",
  )) elements.productForm.reset();
});

elements.grantForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const values = formValues(elements.grantForm);
  if (values.expiresAt) {
    values.expiresAt = new Date(values.expiresAt).toISOString();
  }
  if (await perform(
    "/api/authority-grants",
    values,
    "Scoped authority granted",
  )) {
    elements.grantForm.reset();
    elements.grantForm.elements.productId.value = "";
    elements.grantForm.elements.granteeUsername.value = "";
    elements.grantForm.elements.capability.value = "issue-purchase-credential";
    elements.grantForm.elements.expiresAt.value = "";
  }
});

elements.purchaseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (await perform(
    "/api/actions/issue-purchase",
    formValues(elements.purchaseForm),
    "Purchase added to the customer account",
  )) elements.purchaseForm.reset();
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.action === "publish-review") {
    event.preventDefault();
    await perform(
      "/api/actions/publish-review",
      { ...formValues(form), purchaseId: form.dataset.purchaseId },
      "Comment published",
    );
  }
  if (form.dataset.action === "decide-support") {
    event.preventDefault();
    await perform(
      "/api/actions/decide-support",
      { ...formValues(form), caseId: form.dataset.caseId },
      "Decision saved",
    );
  }
  if (form.dataset.action === "escalate") {
    event.preventDefault();
    await perform(
      "/api/actions/escalate",
      { ...formValues(form), purchaseId: form.dataset.purchaseId },
      "Case sent for independent review",
    );
  }
});

document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-action]");
  if (!(target instanceof HTMLButtonElement)) return;
  const { action } = target.dataset;
  if (action === "request-support") {
    await perform(
      "/api/actions/request-support",
      { purchaseId: target.dataset.purchaseId },
      "Replacement request submitted",
    );
  }
  if (action === "buy-product") {
    const completed = await perform(
      "/api/actions/buy-product",
      { productId: target.dataset.productId },
      "Purchase completed — you can now comment on it or request a replacement",
    );
    if (completed) elements.purchasesSection.scrollIntoView({ behavior: "smooth" });
  }
  if (action === "show-product-reviews") {
    showProductReviews(target.dataset.productId);
  }
  if (action === "revoke-authority") {
    await perform(
      "/api/authority-grants/revoke",
      { grantId: target.dataset.grantId },
      "Authority revoked",
    );
  }
  if (action === "verify-case") {
    await perform(
      "/api/actions/verify-case",
      { caseId: target.dataset.caseId },
      "Evidence verified",
    );
  }
  if (action === "approve-organization" || action === "reject-organization") {
    await perform(
      "/api/administrator/organization-requests/decide",
      {
        requestId: target.dataset.requestId,
        decision: action === "approve-organization" ? "approved" : "rejected",
      },
      `Organization request ${action === "approve-organization" ? "approved" : "rejected"}`,
    );
  }
  if (action === "approve-membership" || action === "reject-membership") {
    await perform(
      "/api/membership-requests/decide",
      {
        requestId: target.dataset.requestId,
        decision: action === "approve-membership" ? "approved" : "rejected",
      },
      `Membership request ${action === "approve-membership" ? "approved" : "rejected"}`,
    );
  }
  if (action === "approve-special-role" || action === "reject-special-role") {
    await perform(
      "/api/administrator/special-role-requests/decide",
      {
        requestId: target.dataset.requestId,
        decision: action === "approve-special-role" ? "approved" : "rejected",
      },
      `Special-role application ${action === "approve-special-role" ? "approved" : "rejected"}`,
    );
  }
  if (action === "open-review") {
    await perform(
      "/api/actions/open-review",
      { reviewId: target.dataset.reviewId },
      null,
    );
  }
});

try {
  const session = await request("/api/session");
  if (session.authenticated) {
    renderDashboard(await request("/api/dashboard"));
  } else {
    showAuth();
  }
} catch (error) {
  showAuth();
  showToast(error instanceof Error ? error.message : String(error), "error");
}
