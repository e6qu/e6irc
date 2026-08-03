(() => {
  "use strict";

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const message = form.dataset.confirm;
    if (message && !window.confirm(message)) {
      event.preventDefault();
      event.stopPropagation();
    }
  }, true);

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

  const textLines = (value) => {
    if (!value) return [];
    const lines = value.split("\n");
    if (value.endsWith("\n")) lines.pop();
    return lines;
  };

  const fieldValue = (fields, name) => String(fields.get(name) || "").trim();

  const positiveInteger = (fields, name, label) => {
    const value = Number(fields.get(name));
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new Error(`${label} must be a positive whole number.`);
    }
    return value;
  };

  const optionalPositiveInteger = (fields, name, label) => {
    const value = fieldValue(fields, name);
    return value ? positiveInteger({ get: () => value }, name, label) : null;
  };

  const parseListeners = (value) =>
    value
      .split("\n")
      .map((line, index) => {
        const fields = line.split("|").map((field) => field.trim());
        if (!fields.some(Boolean)) return null;
        const [addr, mode = "plain", cert_path, key_path] = fields;
        if (!addr) throw new Error(`Listener line ${index + 1} has no address.`);
        if (mode === "plain") return { addr, tls: null, websocket: false };
        if (mode === "websocket") return { addr, tls: null, websocket: true };
        if (mode === "tls" && cert_path && key_path) {
          return { addr, tls: { cert_path, key_path }, websocket: false };
        }
        if (mode === "tls") {
          throw new Error(`TLS listener line ${index + 1} needs certificate and private-key paths.`);
        }
        throw new Error(`Listener line ${index + 1} mode must be plain, tls, or websocket.`);
      })
      .filter(Boolean);

  const configurationPatch = (form) => {
    const fields = new FormData(form);
    const revision = Number(fields.get("revision"));
    if (!Number.isSafeInteger(revision) || revision < 0) {
      throw new Error("The configuration revision is invalid. Reload and try again.");
    }
    const bnc_addr = fields.has("bnc_enabled") ? fieldValue(fields, "bnc_addr") : null;
    if (fields.has("bnc_enabled") && !bnc_addr) {
      throw new Error("BNC listen address must be host:port when the listener is enabled.");
    }
    return {
      revision,
      settings: {
        server_name: fieldValue(fields, "server_name"),
        network_name: fieldValue(fields, "network_name"),
        description: fieldValue(fields, "description"),
        motd: textLines(String(fields.get("motd") || "")),
        nicklen: positiveInteger(fields, "nicklen", "Nickname length"),
        sendq: positiveInteger(fields, "sendq", "Send queue"),
        core_queue: positiveInteger(fields, "core_queue", "Core queue"),
        max_hot_channels: positiveInteger(fields, "max_hot_channels", "Hot channels"),
        listeners: parseListeners(String(fields.get("listeners") || "")),
        registration: {
          before_connect: fields.has("registration_before_connect"),
          require_email: fields.has("registration_require_email"),
        },
        limits: {
          max_connections_per_ip: optionalPositiveInteger(fields, "max_connections_per_ip", "Connections per IP"),
          command_burst: optionalPositiveInteger(fields, "command_burst", "Command burst"),
          trusted_proxies: String(fields.get("trusted_proxies") || "")
            .split("\n")
            .map((entry) => entry.trim())
            .filter(Boolean),
          auth_rate_burst: optionalPositiveInteger(fields, "auth_rate_burst", "Authentication burst"),
          api_rate_burst: optionalPositiveInteger(fields, "api_rate_burst", "Authenticated API burst"),
          administrator_api_rate_burst: optionalPositiveInteger(fields, "administrator_api_rate_burst", "Administrator API burst"),
          registration_burst: optionalPositiveInteger(fields, "registration_burst", "Registration burst"),
        },
        observability: {
          enabled: fields.has("observability_enabled"),
          sample_interval_seconds: positiveInteger(fields, "observability_sample_interval_seconds", "Sample interval"),
          retention_hours: positiveInteger(fields, "observability_retention_hours", "Monitoring retention"),
        },
        storage: {
          history_retention_days: positiveInteger(fields, "storage_history_retention_days", "Message history retention"),
          audit_retention_days: positiveInteger(fields, "storage_audit_retention_days", "Audit retention"),
        },
        bnc_addr,
        public_url: optionalValue(String(fields.get("public_url") || "")),
        secure_cookies: fields.has("secure_cookies"),
        admin_accounts: String(fields.get("admin_accounts") || "")
          .split("\n")
          .map((account) => account.trim())
          .filter(Boolean),
      },
    };
  };

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

  try {
    const message = window.sessionStorage.getItem("e6irc.configuration-result");
    if (message) {
      window.sessionStorage.removeItem("e6irc.configuration-result");
      setConfigurationResult(message, true);
    }
  } catch (_) {
    // A successful reload remains authoritative if the browser denies session storage.
  }

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
      try {
        window.sessionStorage.setItem("e6irc.configuration-result", "Configuration saved.");
      } catch (_) {
        // A successful API response is still authoritative if the browser denies storage.
      }
      window.location.reload();
    } catch (error) {
      setConfigurationResult(error instanceof Error ? error.message : "Configuration request failed.", false);
      if (submit) submit.disabled = false;
    }
  };

  for (const form of document.querySelectorAll("[data-api-configuration-patch]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      let body;
      try {
        body = configurationPatch(form);
      } catch (error) {
        setConfigurationResult(error instanceof Error ? error.message : "Invalid configuration.", false);
        return;
      }
      void mutateConfiguration(form, "/api/v1/admin/configuration", "PATCH", body);
    });
  }

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

  const banResult = document.getElementById("ban-api-result");
  const setBanResult = (message, success) => {
    if (!banResult) return;
    banResult.textContent = message;
    banResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateBan = async (form, url, method, body) => {
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
      setBanResult(error instanceof Error ? error.message : "Server-ban request failed.", false);
      if (submit) submit.disabled = false;
    }
  };

  for (const form of document.querySelectorAll("[data-api-ban-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const kind = fieldValue(fields, "kind");
      const mask = fieldValue(fields, "mask");
      if (!kind || !mask) {
        setBanResult("Choose a policy kind and enter a mask.", false);
        return;
      }
      void mutateBan(form, "/api/v1/admin/bans", "POST", {
        kind,
        mask,
        reason: fieldValue(fields, "reason"),
      });
    });
  }

  for (const form of document.querySelectorAll("[data-api-ban-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const id = Number(new FormData(form).get("id"));
      if (!Number.isSafeInteger(id) || id < 1) {
        setBanResult("The server-ban ID is invalid. Reload and try again.", false);
        return;
      }
      void mutateBan(form, `/api/v1/admin/bans/${id}`, "DELETE", {});
    });
  }

  const sessionResult = document.getElementById("session-api-result");
  const setSessionResult = (message, success) => {
    if (!sessionResult) return;
    sessionResult.textContent = message;
    sessionResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateSession = async (form, url, message) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      const csrf = form.querySelector('input[name="csrf"]')?.value;
      if (!csrf) throw new Error("The session security token is missing. Reload and try again.");
      const response = await fetch(url, {
        method: "DELETE",
        credentials: "same-origin",
        headers: { Accept: "application/json", "X-E6IRC-CSRF": csrf },
      });
      if (!response.ok) throw new Error(await apiProblem(response));
      window.location.reload();
    } catch (error) {
      setSessionResult(error instanceof Error ? error.message : message, false);
      if (submit) submit.disabled = false;
    }
  };

  for (const form of document.querySelectorAll("[data-api-session-revoke]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateSession(form, form.action, "Browser-session request failed.");
    });
  }

  for (const form of document.querySelectorAll("[data-api-session-disconnect]")) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const id = Number(fields.get("id"));
      if (!Number.isSafeInteger(id) || id < 1) {
        setSessionResult("The live-connection ID is invalid. Reload and try again.", false);
        return;
      }
      const reason = fieldValue(fields, "reason");
      const separator = form.action.includes("?") ? "&" : "?";
      const query = reason ? `${separator}reason=${encodeURIComponent(reason)}` : "";
      void mutateSession(form, `${form.action}${query}`, "Disconnect request failed.");
    });
  }
})();
