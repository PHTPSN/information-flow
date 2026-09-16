const state = {
  dashboard: null,
  busy: false,
};

const elements = {
  authView: document.querySelector("#auth-view"),
  appView: document.querySelector("#app-view"),
  showLogin: document.querySelector("#show-login"),
  showRegister: document.querySelector("#show-register"),
  loginForm: document.querySelector("#login-form"),
  registerForm: document.querySelector("#register-form"),
  registerSuccess: document.querySelector("#register-success"),
  managerLogin: document.querySelector("#manager-login"),
  logout: document.querySelector("#logout"),
  accountName: document.querySelector("#account-name"),
  accountUsername: document.querySelector("#account-username"),
  welcomeOverline: document.querySelector("#welcome-overline"),
  dashboardTitle: document.querySelector("#dashboard-title"),
  dashboardSubtitle: document.querySelector("#dashboard-subtitle"),
  reviewCount: document.querySelector("#review-count"),
  managerSection: document.querySelector("#manager-section"),
  managerStatus: document.querySelector("#manager-status"),
  configureForm: document.querySelector("#configure-form"),
  registeredUsers: document.querySelector("#registered-users"),
  purchasesSection: document.querySelector("#purchases-section"),
  purchases: document.querySelector("#purchases"),
  salesSection: document.querySelector("#sales-section"),
  purchaseForm: document.querySelector("#purchase-form"),
  supportSection: document.querySelector("#support-section"),
  supportInbox: document.querySelector("#support-inbox"),
  casesSection: document.querySelector("#cases-section"),
  assignedCases: document.querySelector("#assigned-cases"),
  reviews: document.querySelector("#reviews"),
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
  document.querySelectorAll("button, input, select, textarea").forEach((control) => {
    control.disabled = busy;
  });
}

function showAuth(mode = "login") {
  state.dashboard = null;
  elements.authView.hidden = false;
  elements.appView.hidden = true;
  const login = mode === "login";
  elements.loginForm.hidden = !login;
  elements.registerForm.hidden = login;
  elements.showLogin.classList.toggle("is-active", login);
  elements.showRegister.classList.toggle("is-active", !login);
  elements.showLogin.setAttribute("aria-selected", String(login));
  elements.showRegister.setAttribute("aria-selected", String(!login));
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

function renderManager(dashboard) {
  const manager = dashboard.manager;
  elements.managerSection.hidden = false;
  elements.managerStatus.textContent = manager.configured ? "Connected" : "Setup required";
  elements.managerStatus.dataset.status = manager.configured ? "ready" : "waiting";
  elements.configureForm.hidden = manager.configured;

  if (!manager.configured) {
    fillUserSelect(
      elements.configureForm.elements.merchantUsername,
      manager.users,
    );
    fillUserSelect(
      elements.configureForm.elements.regulatorUsername,
      manager.users,
    );
  }

  elements.registeredUsers.replaceChildren();
  if (manager.users.length === 0) {
    elements.registeredUsers.append(
      node("p", "empty-state", "No customer accounts have been created yet."),
    );
    return;
  }
  manager.users.forEach((user) => {
    const item = node("article", "user-row");
    const identity = node("div");
    identity.append(
      node("strong", "", user.displayName),
      node("span", "", `@${user.username}`),
    );
    let access = "Customer account";
    if (manager.merchantUsername === user.username) access = "Acme workspace connected";
    if (manager.regulatorUsername === user.username) access = "Case review assigned";
    item.append(identity, node("span", "row-note", access));
    elements.registeredUsers.append(item);
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
      const submit = node("button", "button button-primary", "Publish review");
      submit.type = "submit";
      reviewForm.append(field("Write a review", rating), field("Your review", text), submit);
      actions.append(reviewForm);
    }
    if (purchase.canRequestSupport) {
      actions.append(
        button("Request a replacement", "request-support", {
          purchaseId: purchase.purchaseId,
        }),
      );
    }
    if (purchase.canEscalate) {
      actions.append(
        button("Send for independent review", "escalate", {
          purchaseId: purchase.purchaseId,
        }),
      );
    }
    card.append(actions);
    elements.purchases.append(card);
  });
}

function renderSales(dashboard) {
  elements.salesSection.hidden = !dashboard.canIssuePurchases;
  if (!dashboard.canIssuePurchases) return;
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
      result.append(
        node("strong", "", "Evidence checks completed"),
        node("p", "", "The purchase, review, and support decision match this case."),
      );
      card.append(result);
    }
    elements.assignedCases.append(card);
  });
}

function renderReviews(dashboard) {
  elements.reviews.replaceChildren();
  if (dashboard.reviews.length === 0) {
    elements.reviews.append(
      node("p", "empty-state", "No customer reviews have been published yet."),
    );
    return;
  }
  dashboard.reviews.forEach((review) => {
    const card = node("article", "review-card");
    const meta = node("div", "review-meta");
    meta.append(
      node("span", "stars", "★".repeat(review.rating) + "☆".repeat(5 - review.rating)),
      node("span", "verified", "Verified purchase"),
    );
    card.append(meta, node("h3", "", review.productName));
    if (dashboard.account.kind === "manager" || review.openedByYou) {
      card.append(node("p", "review-copy", review.text));
    } else {
      card.append(
        node("p", "muted", "Open this review to read what the customer shared."),
        button("Read review", "open-review", { reviewId: review.reviewId }),
      );
    }
    elements.reviews.append(card);
  });
}

function renderActivity(dashboard) {
  elements.activitySection.hidden = dashboard.activity.length === 0;
  elements.activity.replaceChildren();
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
  elements.accountUsername.textContent = `@${dashboard.account.username}`;
  elements.reviewCount.textContent = String(dashboard.counts.publicReviews);
  const manager = dashboard.account.kind === "manager";
  elements.welcomeOverline.textContent = manager ? "Workspace administration" : "Your account";
  elements.dashboardTitle.textContent = manager
    ? "Manager console"
    : `Good to see you, ${dashboard.account.displayName.split(" ")[0]}.`;
  elements.dashboardSubtitle.textContent = manager
    ? "Connect registered accounts to the Acme Audio workspace."
    : dashboard.product
      ? "Your purchases, reviews, requests, and assigned work appear here."
      : "Your account is ready. The workspace manager is still completing setup.";

  elements.managerSection.hidden = true;
  elements.purchasesSection.hidden = true;
  elements.salesSection.hidden = true;
  elements.supportSection.hidden = true;
  elements.casesSection.hidden = true;
  elements.activitySection.hidden = true;

  if (manager) renderManager(dashboard);
  else {
    renderPurchases(dashboard);
    renderSales(dashboard);
    renderSupport(dashboard);
    renderCases(dashboard);
    renderActivity(dashboard);
  }
  renderReviews(dashboard);
  setBusy(false);
}

async function perform(path, body, successMessage) {
  setBusy(true);
  try {
    renderDashboard(await request(path, { method: "POST", body }));
    if (successMessage) showToast(successMessage);
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
  }
}

elements.showLogin.addEventListener("click", () => showAuth("login"));
elements.showRegister.addEventListener("click", () => showAuth("register"));

elements.registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  try {
    const values = formValues(elements.registerForm);
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
  setBusy(true);
  try {
    renderDashboard(
      await request("/api/login", {
        method: "POST",
        body: formValues(elements.loginForm),
      }),
    );
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
  }
});

elements.managerLogin.addEventListener("click", async () => {
  setBusy(true);
  try {
    renderDashboard(
      await request("/api/login/manager", {
        method: "POST",
        body: { password: "123456" },
      }),
    );
  } catch (error) {
    setBusy(false);
    showToast(error instanceof Error ? error.message : String(error), "error");
  }
});

elements.logout.addEventListener("click", async () => {
  setBusy(true);
  try {
    await request("/api/logout", { method: "POST" });
    showAuth("login");
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    setBusy(false);
  }
});

elements.configureForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await perform(
    "/api/manager/configure",
    formValues(elements.configureForm),
    "Workspace connected",
  );
});

elements.purchaseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await perform(
    "/api/actions/issue-purchase",
    formValues(elements.purchaseForm),
    "Purchase added to the customer account",
  );
});

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (form.dataset.action === "publish-review") {
    event.preventDefault();
    await perform(
      "/api/actions/publish-review",
      { ...formValues(form), purchaseId: form.dataset.purchaseId },
      "Review published",
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
  if (action === "escalate") {
    await perform(
      "/api/actions/escalate",
      { purchaseId: target.dataset.purchaseId },
      "Case submitted for independent review",
    );
  }
  if (action === "verify-case") {
    await perform(
      "/api/actions/verify-case",
      { caseId: target.dataset.caseId },
      "Evidence verified",
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
    showAuth("login");
  }
} catch (error) {
  showAuth("login");
  showToast(error instanceof Error ? error.message : String(error), "error");
}
