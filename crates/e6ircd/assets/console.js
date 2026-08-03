(() => {
  "use strict";

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const message = form.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  for (const button of document.querySelectorAll("[data-copy-target]")) {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target) {
        button.textContent = "Copy unavailable";
        return;
      }
      try {
        await navigator.clipboard.writeText(target.textContent);
        button.textContent = "Copied";
      } catch (_) {
        button.textContent = "Select and copy manually";
      }
    });
  }

  for (const form of document.querySelectorAll("[data-network-form]")) {
    const preset = form.querySelector("[data-network-preset]");
    const name = form.querySelector("[data-network-name]");
    const addr = form.querySelector("[data-network-addr]");
    const tls = form.querySelector("[data-network-tls]");
    if (
      !(preset instanceof HTMLSelectElement) ||
      !(name instanceof HTMLInputElement) ||
      !(addr instanceof HTMLInputElement) ||
      !(tls instanceof HTMLInputElement)
    ) {
      continue;
    }

    preset.addEventListener("change", () => {
      const option = preset.selectedOptions[0];
      if (!option || option.value === "custom") return;
      name.value = option.dataset.name || "";
      addr.value = option.dataset.addr || "";
      tls.checked = option.dataset.tls === "true";
    });

    const markCustom = () => {
      if (preset.value !== "custom") preset.value = "custom";
    };
    name.addEventListener("input", markCustom);
    addr.addEventListener("input", markCustom);
    tls.addEventListener("change", markCustom);
  }

  for (const clear of document.querySelectorAll("[data-sasl-clear]")) {
    const form = clear.closest("form");
    const account = form?.querySelector("[data-sasl-account]");
    const password = form?.querySelector("[data-sasl-password]");
    if (
      !(clear instanceof HTMLInputElement) ||
      !(account instanceof HTMLInputElement) ||
      !(password instanceof HTMLInputElement)
    ) {
      continue;
    }
    clear.addEventListener("change", () => {
      if (clear.checked) {
        account.dataset.previousValue = account.value;
        account.value = "";
        password.value = "";
        account.disabled = true;
        password.disabled = true;
      } else {
        account.disabled = false;
        account.value = account.dataset.previousValue || "";
        password.disabled = password.dataset.storageAvailable !== "true";
      }
    });
  }

  const refresh = async (panel) => {
    const status = document.getElementById(panel.dataset.refreshStatus);
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const response = await fetch(panel.dataset.refreshUrl, {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      panel.innerHTML = await response.text();
      if (status) status.textContent = "Live data refreshed.";
    } catch (error) {
      if (status) {
        status.textContent = `Live refresh failed (${error.message}). Use Refresh to retry.`;
        status.classList.add("refresh-error");
      }
    } finally {
      panel.removeAttribute("aria-busy");
    }
  };

  for (const panel of document.querySelectorAll("[data-refresh-url]")) {
    const seconds = Number(panel.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => refresh(panel), seconds * 1000);
    }
  }

  for (const button of document.querySelectorAll("[data-refresh-target]")) {
    button.addEventListener("click", () => {
      const panel = document.querySelector(button.dataset.refreshTarget);
      if (panel) refresh(panel);
    });
  }

  const configurationResult = document.getElementById("configuration-api-result");

  const apiProblem = async (response) => {
    try {
      const problem = await response.json();
      if (typeof problem.detail === "string") return problem.detail;
      if (typeof problem.title === "string") return problem.title;
    } catch (_) {
      // An intermediary may replace a problem response with a non-JSON body.
    }
    return `Request failed with HTTP ${response.status}.`;
  };

  const optionalValue = (value) => {
    const trimmed = value.trim();
    return trimmed || null;
  };

  const splitValues = (value, separator) =>
    value
      .split(separator)
      .map((item) => item.trim())
      .filter(Boolean);

  const networkBody = (form) => {
    const fields = new FormData(form);
    const number = Number(fields.get("buffer_cap"));
    const revision = Number(fields.get("revision"));
    if (!Number.isSafeInteger(number) || number < 1) {
      throw new Error("Buffer capacity must be a positive whole number.");
    }
    if (!Number.isSafeInteger(revision) || revision < 0) {
      throw new Error("The configuration revision is invalid. Reload and try again.");
    }
    return {
      revision,
      name: String(fields.get("name") || "").trim(),
      owner: optionalValue(String(fields.get("owner") || "")),
      kind: String(fields.get("kind") || ""),
      addr: String(fields.get("addr") || "").trim(),
      tls: fields.has("tls"),
      nick: String(fields.get("nick") || "").trim(),
      realname: optionalValue(String(fields.get("realname") || "")),
      autojoin: splitValues(String(fields.get("autojoin") || ""), ","),
      buffer_cap: number,
      sasl_account: optionalValue(String(fields.get("sasl_account") || "")),
      sasl_password: optionalValue(String(fields.get("sasl_password") || "")),
    };
  };

  const setConfigurationResult = (message, success) => {
    if (!configurationResult) return;
    configurationResult.textContent = message;
    configurationResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateConfiguration = async (form, url, method, body) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      const csrf = form.querySelector('input[name="csrf"]')?.value;
      if (!csrf) throw new Error("The session security token is missing. Reload and try again.");
      const response = await fetch(url, {
        method,
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-E6IRC-CSRF": csrf,
        },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(await apiProblem(response));
      window.location.reload();
    } catch (error) {
      setConfigurationResult(error instanceof Error ? error.message : "Configuration request failed.", false);
      if (submit) submit.disabled = false;
    }
  };

  for (const form of document.querySelectorAll("[data-api-network-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      let body;
      try {
        body = networkBody(form);
      } catch (error) {
        setConfigurationResult(error instanceof Error ? error.message : "Invalid network configuration.", false);
        return;
      }
      void mutateConfiguration(form, "/api/v1/admin/configuration/networks", "POST", body);
    });
  }

  for (const form of document.querySelectorAll("[data-api-network-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const revision = Number(fields.get("revision"));
      if (!Number.isSafeInteger(revision) || revision < 0) {
        setConfigurationResult("The configuration revision is invalid. Reload and try again.", false);
        return;
      }
      const name = String(fields.get("name") || "").trim();
      if (!name) {
        setConfigurationResult("The network name is missing. Reload and try again.", false);
        return;
      }
      void mutateConfiguration(
        form,
        `/api/v1/admin/configuration/networks/${encodeURIComponent(name)}`,
        "DELETE",
        { revision, owner: optionalValue(String(fields.get("owner") || "")) },
      );
    });
  }

  for (const form of document.querySelectorAll("[data-api-oper-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const revision = Number(fields.get("revision"));
      const name = String(fields.get("name") || "").trim();
      const password = String(fields.get("password") || "");
      if (!Number.isSafeInteger(revision) || revision < 0 || !name || !password) {
        setConfigurationResult("Enter an operator name and password, then reload if the revision is stale.", false);
        return;
      }
      void mutateConfiguration(
        form,
        "/api/v1/admin/configuration/opers",
        "POST",
        { revision, name, password },
      );
    });
  }

  for (const form of document.querySelectorAll("[data-api-oper-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const revision = Number(fields.get("revision"));
      const name = String(fields.get("name") || "").trim();
      if (!Number.isSafeInteger(revision) || revision < 0 || !name) {
        setConfigurationResult("The operator or configuration revision is missing. Reload and try again.", false);
        return;
      }
      void mutateConfiguration(
        form,
        `/api/v1/admin/configuration/opers/${encodeURIComponent(name)}`,
        "DELETE",
        { revision },
      );
    });
  }

  for (const form of document.querySelectorAll("[data-api-oidc-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const revision = Number(fields.get("revision"));
      const name = String(fields.get("name") || "").trim();
      const issuer_url = String(fields.get("issuer_url") || "").trim();
      const client_id = String(fields.get("client_id") || "").trim();
      const client_secret = String(fields.get("client_secret") || "");
      if (!Number.isSafeInteger(revision) || revision < 0 || !name || !issuer_url || !client_id || !client_secret) {
        setConfigurationResult("Enter every required provider value, then reload if the revision is stale.", false);
        return;
      }
      void mutateConfiguration(
        form,
        "/api/v1/admin/configuration/oidc-providers",
        "POST",
        {
          revision,
          name,
          issuer_url,
          client_id,
          client_secret,
          scopes: splitValues(String(fields.get("scopes") || ""), /[,\s]+/),
          allowed_email_domains: splitValues(String(fields.get("allowed_email_domains") || ""), /[,\s]+/),
          end_session_endpoint: optionalValue(String(fields.get("end_session_endpoint") || "")),
          token_endpoint_auth_method: String(fields.get("token_endpoint_auth_method") || ""),
        },
      );
    });
  }

  for (const form of document.querySelectorAll("[data-api-oidc-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const revision = Number(fields.get("revision"));
      const name = String(fields.get("name") || "").trim();
      if (!Number.isSafeInteger(revision) || revision < 0 || !name) {
        setConfigurationResult("The provider or configuration revision is missing. Reload and try again.", false);
        return;
      }
      void mutateConfiguration(
        form,
        `/api/v1/admin/configuration/oidc-providers/${encodeURIComponent(name)}`,
        "DELETE",
        { revision },
      );
    });
  }
})();
