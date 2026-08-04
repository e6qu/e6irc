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

  for (const button of document.querySelectorAll("[data-refresh-target]")) {
    button.addEventListener("click", () => {
      const panel = document.querySelector(button.dataset.refreshTarget);
      if (!panel) return;
      if (panel.matches("[data-api-admin-monitoring]")) {
        void refreshMonitoring(panel);
      } else if (panel.matches("[data-api-network-operations]")) {
        void refreshNetworkOperations(panel);
      }
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

  const MAX_API_JSON_BYTES = 1024 * 1024;
  const apiJson = async (response) => {
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > MAX_API_JSON_BYTES) {
      throw new Error("The API response is too large. Reload and try again.");
    }
    const text = await response.text();
    if (text.length > MAX_API_JSON_BYTES) {
      throw new Error("The API response is too large. Reload and try again.");
    }
    return text ? JSON.parse(text) : undefined;
  };

  const apiRequest = async (form, url, method, body) => {
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
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(await apiProblem(response));
    return response.status === 204 ? undefined : apiJson(response);
  };

  const apiRead = async (url) => {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error(await apiProblem(response));
    return apiJson(response);
  };

  const element = (name, className, text) => {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };

  const append = (parent, ...children) => {
    for (const child of children) parent.append(child);
    return parent;
  };

  const monitoringEmpty = (message) => element("div", "chart-empty", message);

  const monitoringHealth = (view) => {
    const health = element("div", "health-strip");
    health.setAttribute("aria-label", "Component health");
    const states = [
      [view.core_ready ? "on" : "off", "IRC core", view.core_ready ? "Healthy" : "Stale"],
      [view.database_ready ? "on" : "off", "PostgreSQL", view.database_ready ? "Healthy" : "Unavailable"],
      [view.upstreams_ready ? "on" : view.upstreams_degraded ? "warn" : "off", "Upstreams", `${view.bnc_connected} / ${view.bnc_networks} connected`],
      [view.error_total === 0 ? "on" : "warn", "Errors", `${view.error_total} since start`],
    ];
    for (const [state, label, value] of states) {
      health.append(append(element("div"), element("span", `dot ${state}`), element("span", "", label), element("strong", "", value)));
    }
    return health;
  };

  const monitoringMetrics = (view) => {
    const grid = element("div", "metric-grid");
    const metrics = [
      ["Connections", view.active_connections, `${view.registered_connections} registered · ${view.opened_total} opened`],
      ["Channels", view.channels, "Currently active in core memory"],
      ["Inbound traffic", view.traffic_in, `${view.inbound_rate} over the visible window`],
      ["Outbound traffic", view.traffic_out, `${view.outbound_rate} over the visible window`],
      ["Upstream received", view.upstream_in, `${view.upstream_inbound_rate} over the visible window`],
      ["Upstream sent", view.upstream_out, `${view.upstream_outbound_rate} over the visible window`],
      ["BNC clients", view.bnc_clients, "Authenticated raw IRC and web attachments"],
      ["HTTP requests", view.http_requests, "All routes since process start"],
      ["Database operations", view.database_requests, "Measured IRC, history, and sampler work"],
      ["Rejected connections", view.rejected_total, "Per-IP admission limit", view.rejected_total > 0],
      ["SendQ kills", view.sendq_kills, "Slow clients disconnected", view.sendq_kills > 0],
    ];
    for (const [label, value, detail, alert] of metrics) {
      grid.append(append(element("article", alert ? "metric-card metric-alert" : "metric-card"), element("span", "metric-label", label), element("strong", "", value), element("small", "", detail)));
    }
    return grid;
  };

  const monitoringChart = (title, description, windowLabel, ariaLabel, bars, kind, emptyWhenMissing = false) => {
    const section = element("section", "panel monitoring-chart");
    section.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", title), element("p", "", description)), element("span", "count", windowLabel)));
    if (emptyWhenMissing && bars.length === 0) {
      section.append(monitoringEmpty("Waiting for the first historical sample."));
      return section;
    }
    const chart = element("div", "bar-chart");
    chart.setAttribute("aria-label", ariaLabel);
    for (const bar of bars) {
      const wrapper = element("div", kind === "single" ? "bar-single" : kind === "triplet" ? "bar-triplet" : "bar-pair");
      wrapper.title = bar.title;
      const entries = kind === "traffic"
        ? [["bar-in", bar.inbound_height], ["bar-out", bar.outbound_height]]
        : kind === "connections"
          ? [["bar-irc", bar.irc_height], ["bar-bnc", bar.bnc_height]]
          : kind === "upstreams"
            ? [[bar.status_class, bar.height]]
            : kind === "errors"
              ? [["bar-errors", bar.height]]
              : kind === "triplet"
                ? [["bar-core", bar.core_height], ["bar-database", bar.database_height], ["bar-http", bar.http_height]]
                : kind === "queues"
                  ? [["bar-core", bar.core_height], ["bar-database", bar.database_height]]
                  : [];
      for (const [className, height] of entries) {
        const line = element("i", className);
        line.style.height = `${height}%`;
        wrapper.append(line);
      }
      chart.append(wrapper);
    }
    section.append(chart);
    return section;
  };

  const monitoringTable = (title, description, headings, rows) => {
    const section = element("section", "panel monitoring-chart");
    section.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", title), element("p", "", description))));
    const table = element("div", "latency-table");
    table.append(append(element("div", "latency-head"), ...headings.map((heading) => element("span", "", heading))));
    for (const [label, ...values] of rows) {
      table.append(append(element("div"), element("strong", "", label), ...values.map((value) => element("span", "", value))));
    }
    section.append(table);
    return section;
  };

  const renderMonitoring = (panel, view) => {
    const fragment = document.createDocumentFragment();
    fragment.append(monitoringHealth(view), monitoringMetrics(view));
    const history = element("div", "monitoring-history-grid");
    history.append(
      monitoringChart("IRC traffic", "Bytes per sample · inbound blue, outbound green", view.window_label, "IRC traffic history", view.traffic_bars, "traffic", true),
      monitoringChart("Upstream traffic", "Bytes per sample · received blue, sent green", view.window_label, "BNC upstream traffic history", view.upstream_traffic_bars, "traffic", true),
      monitoringChart("Connections", "Current IRC clients in blue · BNC attachments in violet", view.window_label, "Client connection history", view.connection_bars, "connections"),
      monitoringChart("Upstream availability", "Share of configured networks connected at each sample", view.window_label, "BNC upstream availability history", view.upstream_bars, "upstreams"),
      monitoringChart("New errors", "New fixed-category errors recorded per sample", view.window_label, "New operational errors history", view.error_bars, "errors", true),
      monitoringChart("P95 latency", "Core blue · PostgreSQL amber · HTTP violet", view.window_label, "P95 latency history", view.latency_bars, "triplet"),
      monitoringChart("Queue pressure", "Capacity used · IRC core blue, PostgreSQL amber", view.window_label, "Runtime queue pressure history", view.queue_bars, "queues"),
      monitoringTable("Runtime queues", "Live bounded-queue state and overload-mode transitions", ["Queue", "Pressure", "Mode", "Switches"], view.queues.map((queue) => [queue.label, `${queue.depth} / ${queue.capacity} (${queue.pressure}%)`, queue.mode, queue.mode_switches])),
      monitoringTable("Latency", "Cumulative process histograms", ["Path", "P50", "P95", "P99"], [["IRC core", view.core_p50, view.core_p95, view.core_p99], ["PostgreSQL", view.database_p50, view.database_p95, view.database_p99], ["HTTP", view.http_p50, view.http_p95, view.http_p99]])
    );
    fragment.append(history);
    const ledger = element("section", "panel");
    ledger.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", "Error ledger"), element("p", "", "Fixed categories only; request data and secrets never become metric labels.")), element("span", "count", `${view.error_total} total`)));
    if (view.errors.length === 0) {
      ledger.append(append(element("div", "all-clear"), element("span", "dot on"), document.createTextNode("No operational errors recorded since process start.")));
    } else {
      const errors = element("div", "error-grid");
      for (const error of view.errors) errors.append(append(element("div"), element("strong", "", error.kind), element("span", "", error.count), element("small", "", error.last_seen)));
      ledger.append(errors);
    }
    fragment.append(ledger);
    const foot = element("div", "monitoring-foot");
    const json = element("a", "", "JSON");
    json.href = `/api/v1/admin/monitoring?minutes=${encodeURIComponent(view.window_minutes)}`;
    const prometheus = element("a", "", "Prometheus");
    prometheus.href = "/api/v1/admin/metrics";
    foot.append(element("span", "", `${view.history_samples} stored samples · ${view.window_label}`), element("span", "", `Updated ${view.sampled_age}`), json, prometheus);
    fragment.append(foot);
    panel.replaceChildren(fragment);
  };

  const refreshMonitoring = async (panel) => {
    const status = document.getElementById(panel.dataset.refreshStatus);
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const minutes = Number(panel.dataset.minutes);
      if (!Number.isSafeInteger(minutes) || minutes < 1) throw new Error("The monitoring window is invalid. Reload and try again.");
      const view = await apiRead(`/api/v1/admin/monitoring?minutes=${encodeURIComponent(minutes)}`);
      renderMonitoring(panel, view);
      if (status) status.textContent = "Live data refreshed.";
    } catch (error) {
      panel.replaceChildren(monitoringEmpty(`Live monitoring failed (${error.message}). Use Refresh to retry.`));
      if (status) {
        status.textContent = `Live refresh failed (${error.message}). Use Refresh to retry.`;
        status.classList.add("refresh-error");
      }
    } finally {
      panel.removeAttribute("aria-busy");
    }
  };

  for (const panel of document.querySelectorAll("[data-api-admin-monitoring]")) {
    void refreshMonitoring(panel);
    const seconds = Number(panel.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => void refreshMonitoring(panel), seconds * 1000);
    }
  }

  const networkOperationsHealth = (view) => {
    const health = element("div", "health-strip");
    health.setAttribute("aria-label", "Network health");
    const states = [
      [view.connected ? "on" : "off", "Lifecycle", view.state],
      [view.errors === 0 ? "on" : "warn", "Errors", view.errors],
      [view.attached_clients > 0 ? "on" : "off", "Attached clients", view.attached_clients],
      [view.stored_lines > 0 ? "on" : "off", "Stored backlog", `${view.stored_lines} ${view.stored_lines === 1 ? "line" : "lines"}`],
    ];
    for (const [state, label, value] of states) {
      health.append(append(element("div"), element("span", `dot ${state}`), element("span", "", label), element("strong", "", value)));
    }
    return health;
  };

  const networkOperationsMetrics = (view) => {
    const grid = element("div", "metric-grid");
    const metrics = [
      ["Received from upstream", view.traffic_in, `${view.lines_in} upstream ${view.lines_in === 1 ? "line" : "lines"}`],
      ["Sent to upstream", view.traffic_out, `${view.lines_out} upstream ${view.lines_out === 1 ? "line" : "lines"}`],
      ["Connect latency", view.connect_latency, `${view.connection_attempts} ${view.connection_attempts === 1 ? "attempt" : "attempts"} since start`],
      ["Memory buffer", view.memory_buffer, "Current lines / capacity"],
    ];
    for (const [label, value, detail] of metrics) {
      grid.append(append(element("article", "metric-card"), element("span", "metric-label", label), element("strong", "", value), element("small", "", detail)));
    }
    return grid;
  };

  const renderNetworkOperations = (panel, view) => {
    const fragment = document.createDocumentFragment();
    fragment.append(networkOperationsHealth(view), networkOperationsMetrics(view));
    const timeline = element("section", "panel");
    timeline.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", "Connection timeline"), element("p", "", "Runtime-only timestamps reset when this network is restarted or reconfigured.")), element("span", "count", view.state_changed)));
    const summary = element("div", "network-summary");
    const details = [["Connected since", view.connected_since], ["Next reconnect attempt", view.next_retry], ["Last received", view.last_input], ["Last sent", view.last_output], ["Last error", view.last_error], ["Last error reason", view.last_error_reason], ["Oldest stored line", view.stored_oldest], ["Newest stored line", view.stored_newest]];
    for (const [label, value] of details) summary.append(append(element("div"), element("span", "", label), element("strong", "", value)));
    timeline.append(summary);
    if (view.recent_failures.length > 0) {
      const failures = element("div", "network-summary");
      const list = element("ul", "failure-history");
      for (const failure of view.recent_failures) list.append(element("li", "", failure));
      failures.append(append(element("div"), element("span", "", "Recent failures"), list));
      timeline.append(failures);
    }
    fragment.append(timeline);
    const backlog = element("section", "panel");
    backlog.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", "Recent detached backlog"), element("p", "", "The newest 100 persisted upstream lines, shown oldest first. Client attachment replays the same stored stream.")), element("span", "count", `${view.stored_lines} stored`)));
    if (view.recent_lines.length === 0) {
      backlog.append(element("p", "empty", "No upstream lines have been stored for this network."));
    } else {
      const lines = element("div", "backlog");
      lines.setAttribute("role", "log");
      lines.setAttribute("aria-label", "Recent raw IRC backlog");
      for (const line of view.recent_lines) lines.append(element("code", "", line));
      backlog.append(lines);
    }
    fragment.append(backlog);
    panel.replaceChildren(fragment);
  };

  const refreshNetworkOperations = async (panel) => {
    const status = document.getElementById(panel.dataset.refreshStatus);
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const name = panel.dataset.networkName;
      if (!name) throw new Error("The network name is missing. Reload and try again.");
      const view = await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}/operations`);
      renderNetworkOperations(panel, view);
      if (status) status.textContent = "Live data refreshed.";
    } catch (error) {
      panel.replaceChildren(monitoringEmpty(`Live network operations failed (${error.message}). Use Refresh to retry.`));
      if (status) {
        status.textContent = `Live refresh failed (${error.message}). Use Refresh to retry.`;
        status.classList.add("refresh-error");
      }
    } finally {
      panel.removeAttribute("aria-busy");
    }
  };

  for (const panel of document.querySelectorAll("[data-api-network-operations]")) {
    void refreshNetworkOperations(panel);
    const seconds = Number(panel.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => void refreshNetworkOperations(panel), seconds * 1000);
    }
  }

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

  const mutateConfiguration = async (form, url, method, body, success = "Configuration saved.") => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      await apiRequest(form, url, method, body);
      try {
        window.sessionStorage.setItem("e6irc.configuration-result", success);
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
      void mutateConfiguration(
        form,
        "/api/v1/admin/configuration/networks",
        "POST",
        body,
        `added server network ${body.name}`,
      );
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
        `removed server network ${name}`,
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
        `added IRC operator ${name}`,
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
        `removed IRC operator ${name}`,
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
        `added OpenID Connect provider ${name}`,
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
        `removed OpenID Connect provider ${name}`,
      );
    });
  }

  const configurationValue = (form, name, value) => {
    const field = form.elements.namedItem(name);
    if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) field.value = value ?? "";
  };

  const configurationChecked = (form, name, checked) => {
    const field = form.elements.namedItem(name);
    if (field instanceof HTMLInputElement) field.checked = Boolean(checked);
  };

  const configurationListeners = (listeners) => listeners.map((listener) => {
    if (listener.tls) return `${listener.addr} | tls | ${listener.tls.cert_path} | ${listener.tls.key_path}`;
    return `${listener.addr} | ${listener.websocket ? "websocket" : "plain"}`;
  }).join("\n");

  const configurationHidden = (name, value) => {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = String(value ?? "");
    return input;
  };

  const configurationDeleteForm = (kind, name, revision, csrf, owner) => {
    const form = document.createElement("form");
    form.method = "post";
    form.dataset.apiConfigurationDelete = kind;
    form.append(configurationHidden("csrf", csrf), configurationHidden("revision", revision), configurationHidden("name", name));
    if (owner !== undefined) form.append(configurationHidden("owner", owner));
    const button = element("button", "danger", "Remove");
    button.type = "submit";
    form.append(button);
    return form;
  };

  const configurationCredentialWarning = (settings, text) => {
    if (!settings.credentials_from_bootstrap) return null;
    const warning = element("div", "banner-info");
    warning.append(append(element("div"), element("strong", "", text)));
    return warning;
  };

  const renderConfigurationList = (target, content, empty) => {
    target.replaceChildren();
    if (content.length === 0) {
      target.append(element("p", "empty", empty));
      return;
    }
    const list = element("div", content[0].tagName === "ARTICLE" ? "provider-list" : "compact-list");
    list.append(...content);
    target.append(list);
  };

  const bindConfigurationDeletes = () => {
    for (const form of document.querySelectorAll("[data-api-configuration-delete]")) {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        const fields = new FormData(form);
        const revision = Number(fields.get("revision"));
        const name = String(fields.get("name") || "").trim();
        if (!Number.isSafeInteger(revision) || revision < 0 || !name) {
          setConfigurationResult("The configuration revision or item name is missing. Reload and try again.", false);
          return;
        }
        const kind = form.dataset.apiConfigurationDelete;
        const route = kind === "network" ? "networks" : kind === "oper" ? "opers" : "oidc-providers";
        const body = kind === "network" ? { revision, owner: optionalValue(String(fields.get("owner") || "")) } : { revision };
        void mutateConfiguration(form, `/api/v1/admin/configuration/${route}/${encodeURIComponent(name)}`, "DELETE", body, `removed ${kind === "oidc" ? "OpenID Connect provider" : kind === "oper" ? "IRC operator" : "server network"} ${name}`);
      });
    }
  };

  const renderConfiguration = (root, view) => {
    const settings = view.settings;
    const runtime = view.runtime;
    if (!settings || !runtime || !Number.isSafeInteger(view.revision)) throw new Error("The configuration response is incomplete.");
    const form = root.querySelector("[data-api-configuration-patch]");
    if (!(form instanceof HTMLFormElement)) throw new Error("The configuration form is missing.");
    const revision = String(view.revision);
    root.querySelector("[data-configuration-revision]").textContent = `Revision ${revision}`;
    const provenance = root.querySelector("[data-configuration-provenance]");
    provenance.replaceChildren(append(element("span", "", "Last changed by "), element("strong", "", view.updated_by)), element("span", "", view.updated_at));
    const bootstrap = root.querySelector("[data-configuration-bootstrap]");
    const httpBind = runtime.http_bind || "dedicated WebSocket listener only";
    const release = runtime.release_revision || "not set";
    const keys = runtime.master_key_count || 0;
    bootstrap.replaceChildren(
      append(element("div"), element("span", "", "PostgreSQL"), append(element("strong"), element("span", "dot on"), document.createTextNode("Connected"))),
      append(element("div"), element("span", "", "HTTP bind"), append(element("strong"), element("code", "", httpBind))),
      append(element("div"), element("span", "", "Master keyring"), append(element("strong"), element("span", runtime.has_master_key ? "dot on" : "dot off"), document.createTextNode(runtime.has_master_key ? `${keys} key${keys === 1 ? "" : "s"}` : "Not configured"))),
      append(element("div"), element("span", "", "Release revision"), append(element("strong"), element("code", "", release))),
      element("p", "", "These bootstrap values must exist before the console can start. Their effective state is shown here; more than one key means a credential rotation window is active. Operational configuration below is UI-managed."),
    );
    for (const hidden of root.querySelectorAll('input[name="revision"]')) hidden.value = revision;
    configurationValue(form, "server_name", settings.server_name);
    configurationValue(form, "network_name", settings.network_name);
    configurationValue(form, "description", settings.description);
    configurationValue(form, "motd", (settings.motd || []).join("\n"));
    configurationValue(form, "storage_history_retention_days", settings.storage.history_retention_days);
    configurationValue(form, "storage_audit_retention_days", settings.storage.audit_retention_days);
    configurationChecked(form, "bnc_enabled", settings.bnc_addr !== null);
    configurationValue(form, "bnc_addr", settings.bnc_addr);
    configurationValue(form, "listeners", configurationListeners(settings.listeners || []));
    configurationValue(form, "public_url", settings.public_url);
    configurationChecked(form, "secure_cookies", settings.secure_cookies);
    configurationValue(form, "admin_accounts", (settings.admin_accounts || []).join("\n"));
    for (const name of ["nicklen", "sendq", "core_queue", "max_hot_channels"]) configurationValue(form, name, settings[name]);
    for (const name of ["max_connections_per_ip", "command_burst", "auth_rate_burst", "api_rate_burst", "administrator_api_rate_burst", "registration_burst"]) configurationValue(form, name, settings.limits[name]);
    configurationValue(form, "trusted_proxies", (settings.limits.trusted_proxies || []).join("\n"));
    configurationChecked(form, "observability_enabled", settings.observability.enabled);
    configurationValue(form, "observability_sample_interval_seconds", settings.observability.sample_interval_seconds);
    configurationValue(form, "observability_retention_hours", settings.observability.retention_hours);
    configurationChecked(form, "registration_before_connect", settings.registration.before_connect);
    configurationChecked(form, "registration_require_email", settings.registration.require_email);
    const bncStatus = root.querySelector("[data-configuration-bnc-status]");
    bncStatus.replaceChildren(element("span", runtime.bound_bnc_addr ? "dot on" : "dot off"), document.createTextNode(runtime.bound_bnc_addr ? "Accepting clients on " : "Attach listener is disabled"));
    if (runtime.bound_bnc_addr) bncStatus.append(element("code", "", runtime.bound_bnc_addr));

    const csrf = root.dataset.csrf || "";
    const networks = (settings.networks || []).map((network) => {
      const article = document.createElement("article");
      article.append(append(element("div"), element("strong", "", network.name), element("span", "tag", network.kind)), element("code", "", network.addr), element("span", "meta", `Available to ${network.owner || "all accounts"}`), configurationDeleteForm("network", network.name, revision, csrf, network.owner || ""));
      return article;
    });
    const networkTarget = root.querySelector("[data-configuration-networks]");
    renderConfigurationList(networkTarget, networks, "No server-level networks configured.");
    const networkWarning = configurationCredentialWarning(settings, "Credential-bearing networks still come from bootstrap configuration. Configure the master key and restart once to enable UI changes.");
    if (networkWarning) networkTarget.prepend(networkWarning);
    const kinds = root.querySelector("[data-configuration-network-kinds]");
    kinds.replaceChildren(...(runtime.network_drivers || []).map((kind) => element("option", "", kind.toUpperCase())));
    for (const option of kinds.options) option.value = option.textContent.toLowerCase();

    const opers = (settings.opers || []).map((oper) => append(element("div"), element("code", "", oper.name), configurationDeleteForm("oper", oper.name, revision, csrf)));
    const operTarget = root.querySelector("[data-configuration-opers]");
    renderConfigurationList(operTarget, opers, "No IRC operators configured.");
    const operWarning = configurationCredentialWarning(settings, "Credentials still come from bootstrap configuration. Configure the deployment master key and restart once; e6irc will seal and import them before UI editing is enabled.");
    if (operWarning) operTarget.prepend(operWarning);
    const providers = (settings.oidc_providers || []).map((provider) => {
      const article = document.createElement("article");
      const domains = provider.allowed_email_domains?.length ? provider.allowed_email_domains.join(", ") : "any verified provider identity";
      article.append(append(element("div"), element("strong", "", provider.name), element("span", "tag", provider.token_endpoint_auth_method)), element("code", "", provider.issuer_url), element("span", "meta", `Client ${provider.client_id} · scopes ${(provider.scopes || []).join(" ")}`), element("span", "meta", `Allowed email domains: ${domains}`), configurationDeleteForm("oidc", provider.name, revision, csrf));
      return article;
    });
    const providerTarget = root.querySelector("[data-configuration-oidc-providers]");
    renderConfigurationList(providerTarget, providers, "No identity providers configured.");
    const providerWarning = configurationCredentialWarning(settings, "Credentials still come from bootstrap configuration. Configure the deployment master key and restart once; e6irc will seal and import them before UI editing is enabled.");
    if (providerWarning) providerTarget.prepend(providerWarning);
    bindConfigurationDeletes();
  };

  const configurationRoot = document.querySelector("[data-api-configuration-read]");
  if (configurationRoot instanceof HTMLElement) {
    void apiRead("/api/v1/admin/configuration")
      .then((view) => renderConfiguration(configurationRoot, view))
      .catch((error) => setConfigurationResult(`Configuration failed to load (${error instanceof Error ? error.message : "unknown error"}). Reload to retry.`, false));
  }

  const banResult = document.getElementById("ban-api-result");
  const adminBanRows = document.querySelector("[data-api-admin-ban-list]");
  if (adminBanRows instanceof HTMLElement) {
    void apiRead(`/api/v1/admin/bans${window.location.search}`)
      .then((result) => { const bans = Array.isArray(result.bans) ? result.bans : []; adminBanRows.replaceChildren(); const count = document.getElementById("admin-ban-count"); if (count) count.textContent = String(bans.length); const pager = document.getElementById("admin-ban-pager"); if (pager) { pager.replaceChildren(); if (result.next_before_id) { const link = document.createElement("a"); const query = new URLSearchParams(window.location.search); query.set("before_id", String(result.next_before_id)); link.href = `/console/bans?${query}`; link.textContent = "Older rules"; pager.append(link); } } if (!bans.length) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "empty"; cell.textContent = "No server bans match this view."; row.append(cell); adminBanRows.append(row); return; } for (const ban of bans) { const row = document.createElement("tr"); [ban.id, ban.kind, ban.mask, ban.reason, ban.set_by, ban.created_at].forEach((value) => { const cell = document.createElement("td"); cell.textContent = String(value || ""); row.append(cell); }); const actions = document.createElement("td"); const form = document.createElement("form"); form.method = "post"; form.action = `/api/v1/admin/bans/${ban.id}`; form.dataset.apiBanDelete = ""; form.dataset.confirm = `Remove ${ban.kind} ${ban.mask}?`; const csrf = document.createElement("input"); csrf.type = "hidden"; csrf.name = "csrf"; csrf.value = adminBanRows.dataset.csrf || ""; const id = document.createElement("input"); id.type = "hidden"; id.name = "id"; id.value = String(ban.id); const button = document.createElement("button"); button.type = "submit"; button.className = "danger"; button.textContent = "Remove"; form.append(csrf, id, button); actions.append(form); row.append(actions); adminBanRows.append(row); } })
      .catch((error) => { adminBanRows.textContent = error instanceof Error ? error.message : "Server-ban directory failed to load."; });
  }
  const setBanResult = (message, success) => {
    if (!banResult) return;
    banResult.textContent = message;
    banResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateBan = async (form, url, method, body) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      await apiRequest(form, url, method, body);
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

  // The ban directory is populated after its API read completes, so delete
  // forms must be delegated instead of bound only to the server-rendered DOM.
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-api-ban-delete]")) return;
    event.preventDefault();
    const id = Number(new FormData(form).get("id"));
    if (!Number.isSafeInteger(id) || id < 1) {
      setBanResult("The server-ban ID is invalid. Reload and try again.", false);
      return;
    }
    void mutateBan(form, `/api/v1/admin/bans/${id}`, "DELETE", {});
  });

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
      await apiRequest(form, url, "DELETE");
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

  const accountResult = document.getElementById("account-api-result");
  const accountSecret = document.getElementById("account-api-secret");
  const setAccountResult = (message, success) => {
    if (!accountResult) return;
    accountResult.textContent = message;
    accountResult.className = success ? "banner-success" : "banner-error";
  };

  const showAccountSecret = (kind, value) => {
    if (!accountSecret) return;
    accountSecret.replaceChildren();
    const section = document.createElement("section");
    section.className = "secret-reveal";
    const copy = document.createElement("button");
    const code = document.createElement("code");
    code.id = "issued-secret";
    code.textContent = value;
    copy.type = "button";
    copy.textContent = "Copy";
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(value);
        copy.textContent = "Copied";
      } catch (_) {
        copy.textContent = "Select and copy manually";
      }
    });
    const heading = document.createElement("h2");
    heading.textContent = kind;
    const valueBox = document.createElement("div");
    valueBox.className = "secret-value";
    valueBox.append(code, copy);
    section.append(heading, valueBox);
    accountSecret.append(section);
  };

  const mutateAccount = async (form, method, body, failure) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      const result = await apiRequest(form, form.action, method, body);
      return result === undefined ? true : result;
    } catch (error) {
      setAccountResult(error instanceof Error ? error.message : failure, false);
      if (submit) submit.disabled = false;
      return undefined;
    }
  };

  const reloadAccount = () => window.location.reload();

  for (const form of document.querySelectorAll("[data-api-account-profile]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const email = fieldValue(new FormData(form), "contact_email");
      void mutateAccount(form, "PATCH", { contact_email: email || null }, "Profile update failed.")
        .then((result) => { if (result !== false) reloadAccount(); });
    });
  }

  const accountContactEmail = document.querySelector("[data-api-account-contact-email]");
  if (accountContactEmail instanceof HTMLInputElement) {
    void apiRead("/api/v1/me/profile")
      .then((profile) => { accountContactEmail.value = typeof profile.contact_email === "string" ? profile.contact_email : ""; })
      .catch((error) => setAccountResult(
        error instanceof Error ? error.message : "Contact email failed to load.",
        false,
      ));
  }

  for (const form of document.querySelectorAll("[data-api-account-password]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const current = fieldValue(fields, "current_password");
      const next = fieldValue(fields, "new_password");
      if (next !== fieldValue(fields, "confirm_password")) {
        setAccountResult("The new password and confirmation do not match.", false);
        return;
      }
      void mutateAccount(form, "PUT", { current_password: current || null, new_password: next }, "Password update failed.")
        .then((result) => {
          if (result !== false) setAccountResult(current ? "Local password changed." : "Local password added.", true);
        });
    });
  }

  for (const form of document.querySelectorAll("[data-api-account-app-password]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const label = fieldValue(new FormData(form), "label");
      if (!label) {
        setAccountResult("Enter an app-password label.", false);
        return;
      }
      void mutateAccount(form, "POST", { label }, "App-password creation failed.")
        .then((result) => {
          if (!result || typeof result !== "object") return;
          showAccountSecret("App password", result.app_password);
          setAccountResult("App password created. Copy it now; it cannot be shown again.", true);
        });
    });
  }

  for (const form of document.querySelectorAll("[data-api-account-token]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const scopes = ["read", "write", "administrator", "irc"]
        .filter((scope) => fields.has(`scope_${scope}`));
      if (!scopes.length) {
        setAccountResult("Choose at least one token scope.", false);
        return;
      }
      void mutateAccount(form, "POST", {
        label: fieldValue(fields, "label"),
        scopes,
        expires_in_days: Number(fields.get("expires_in_days")),
      }, "Token creation failed.").then((result) => {
        if (!result || typeof result !== "object") return;
        showAccountSecret("Personal access token", result.token);
        setAccountResult("Personal access token created. Copy it now; it cannot be shown again.", true);
      });
    });
  }

  const accountTokenRows = document.querySelector("[data-api-account-token-list]");
  if (accountTokenRows instanceof HTMLElement) {
    void apiRead("/api/v1/me/tokens")
      .then((result) => {
        const tokens = Array.isArray(result.tokens) ? result.tokens : [];
        accountTokenRows.replaceChildren();
        const count = document.getElementById("account-token-count");
        if (count) count.textContent = String(tokens.length);
        if (!tokens.length) {
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.colSpan = 5;
          cell.className = "empty";
          cell.textContent = "No personal access tokens.";
          row.append(cell);
          accountTokenRows.append(row);
          return;
        }
        for (const token of tokens) {
          const row = document.createElement("tr");
          const scopes = Array.isArray(token.scopes) ? token.scopes.join(", ") : "";
          [token.label, scopes, token.created_at, token.expires_at].forEach((value) => {
            const cell = document.createElement("td");
            cell.textContent = String(value || "");
            row.append(cell);
          });
          const actions = document.createElement("td");
          const form = document.createElement("form");
          form.className = "cell-form";
          form.method = "post";
          form.action = `/api/v1/me/tokens/${token.id}`;
          form.dataset.apiAccountDelete = "";
          form.dataset.confirm = "Revoke this personal access token?";
          const csrf = document.createElement("input");
          csrf.type = "hidden";
          csrf.name = "csrf";
          csrf.value = accountTokenRows.dataset.csrf || "";
          const button = document.createElement("button");
          button.className = "danger";
          button.type = "submit";
          button.textContent = "Revoke";
          form.append(csrf, button);
          actions.append(form);
          row.append(actions);
          accountTokenRows.append(row);
        }
      })
      .catch((error) => {
        accountTokenRows.textContent = error instanceof Error
          ? error.message
          : "Personal access tokens failed to load.";
      });
  }

  for (const form of document.querySelectorAll("[data-api-account-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateAccount(form, "DELETE", undefined, "Account access change failed.")
        .then((result) => { if (result !== false) reloadAccount(); });
    });
  }

  for (const form of document.querySelectorAll("[data-api-account-delete-self]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const confirmation = fieldValue(new FormData(form), "confirmation");
      void mutateAccount(form, "DELETE", { confirmation }, "Account deletion failed.")
        .then((result) => { if (result !== false) window.location.assign("/auth/signed-out"); });
    });
  }

  const accountSecurityActivityRows = document.querySelector("[data-api-account-security-activity-list]");
  if (accountSecurityActivityRows instanceof HTMLElement) {
    void apiRead("/api/v1/me/security-activity?limit=50")
      .then((result) => {
        const activity = Array.isArray(result.activity) ? result.activity : [];
        accountSecurityActivityRows.replaceChildren();
        const count = document.getElementById("account-security-activity-count");
        if (count) count.textContent = String(activity.length);
        if (!activity.length) {
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.colSpan = 5;
          cell.className = "empty";
          cell.textContent = "No retained security activity.";
          row.append(cell);
          accountSecurityActivityRows.append(row);
          return;
        }
        for (const event of activity) {
          const row = document.createElement("tr");
          [event.at, event.action, event.actor, event.target, event.detail]
            .forEach((value, index) => {
              const cell = document.createElement("td");
              cell.textContent = String(value || "");
              if (index === 1) cell.className = "tag";
              row.append(cell);
            });
          accountSecurityActivityRows.append(row);
        }
      })
      .catch((error) => {
        accountSecurityActivityRows.textContent = error instanceof Error
          ? error.message
          : "Security activity failed to load.";
      });
  }

  const accountReadMarkers = document.querySelector("[data-api-account-read-marker-list]");
  if (accountReadMarkers instanceof HTMLElement) {
    void apiRead("/api/v1/me/read-markers")
      .then((result) => {
        const markers = Array.isArray(result.markers) ? result.markers : [];
        accountReadMarkers.replaceChildren();
        const count = document.getElementById("account-read-marker-count");
        if (count) count.textContent = String(markers.length);
        if (!markers.length) {
          const empty = document.createElement("p");
          empty.className = "empty";
          empty.textContent = "No read markers have been stored yet.";
          accountReadMarkers.append(empty);
          return;
        }
        for (const marker of markers) {
          const entry = document.createElement("div");
          const target = document.createElement("code");
          target.textContent = String(marker.target || "");
          const timestamp = document.createElement("span");
          timestamp.textContent = String(marker.timestamp || "");
          entry.append(target, timestamp);
          accountReadMarkers.append(entry);
        }
      })
      .catch((error) => {
        accountReadMarkers.textContent = error instanceof Error
          ? error.message
          : "Read markers failed to load.";
      });
  }

  const adminAccountResult = document.getElementById("admin-account-api-result");
  const adminAccountSecret = document.getElementById("admin-account-api-secret");
  const setAdminAccountResult = (message, success) => {
    if (!adminAccountResult) return;
    adminAccountResult.textContent = message;
    adminAccountResult.className = success ? "banner-success" : "banner-error";
  };
  const mutateAdminAccount = async (form, method, body, failure) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      return (await apiRequest(form, form.action, method, body)) ?? {};
    } catch (error) {
      setAdminAccountResult(error instanceof Error ? error.message : failure, false);
      if (submit) submit.disabled = false;
      return undefined;
    }
  };
  const showInvitationSecret = (value) => {
    if (!adminAccountSecret) return;
    adminAccountSecret.replaceChildren();
    const section = document.createElement("section");
    section.className = "secret-reveal";
    const title = document.createElement("h2");
    title.textContent = "Account invitation link";
    const code = document.createElement("code");
    code.id = "issued-invitation";
    code.textContent = value;
    const copy = document.createElement("button");
    copy.type = "button";
    copy.textContent = "Copy";
    copy.addEventListener("click", async () => { try { await navigator.clipboard.writeText(value); copy.textContent = "Copied"; } catch (_) { copy.textContent = "Select and copy manually"; } });
    section.append(title, code, copy);
    adminAccountSecret.append(section);
  };
  for (const form of document.querySelectorAll("[data-api-admin-account-create]")) form.addEventListener("submit", (event) => { event.preventDefault(); const fields = new FormData(form); void mutateAdminAccount(form, "POST", { account: fieldValue(fields, "account"), password: String(fields.get("password") || ""), contact_email: optionalValue(String(fields.get("contact_email") || "")), administrator: fields.has("administrator") }, "Account creation failed.").then((result) => { if (result) window.location.reload(); }); });
  for (const form of document.querySelectorAll("[data-api-admin-invitation-create]")) form.addEventListener("submit", (event) => { event.preventDefault(); const fields = new FormData(form); void mutateAdminAccount(form, "POST", { account: fieldValue(fields, "account"), contact_email: optionalValue(String(fields.get("contact_email") || "")), expires_in_days: Number(fields.get("expires_in_days")), administrator: fields.has("administrator") }, "Invitation creation failed.").then((result) => { if (!result) return; showInvitationSecret(result.invitation_url); setAdminAccountResult("Invitation issued. Copy the link now; it cannot be shown again.", true); }); });
  document.addEventListener("submit", (event) => { const form = event.target; if (!(form instanceof HTMLFormElement)) return; if (form.matches("[data-api-admin-invitation-delete]")) { event.preventDefault(); void mutateAdminAccount(form, "DELETE", undefined, "Invitation revocation failed.").then((result) => { if (result) window.location.reload(); }); } else if (form.matches("[data-api-admin-account-state]")) { event.preventDefault(); const fields = new FormData(form); const key = form.dataset.apiAdminAccountState === "suspension" ? "suspended" : "administrator"; void mutateAdminAccount(form, "PATCH", { [key]: fieldValue(fields, key) === "true" }, "Account state change failed.").then((result) => { if (result) window.location.reload(); }); } else if (form.matches("[data-api-admin-account-delete]")) { event.preventDefault(); void mutateAdminAccount(form, "DELETE", { confirmation: fieldValue(new FormData(form), "confirmation") }, "Account deletion failed.").then((result) => { if (result) window.location.reload(); }); } });

  const adminNetworkResult = document.getElementById("admin-network-api-result");
  const adminNetworkRows = document.querySelector("[data-api-admin-network-list]");
  const renderAdminNetworks = (networks) => {
    if (!(adminNetworkRows instanceof HTMLElement)) return;
    adminNetworkRows.replaceChildren();
    const count = document.getElementById("admin-network-count");
    if (count) count.textContent = String(networks.length);
    if (!networks.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 9;
      cell.className = "empty";
      cell.textContent = "No networks configured by any account.";
      row.append(cell);
      adminNetworkRows.append(row);
      return;
    }
    for (const network of networks) {
      const row = document.createElement("tr");
      const runtime = network.runtime || {};
      const cells = [runtime.state || (network.enabled ? "not running" : "disabled"), network.owner, network.name, network.kind, network.addr, runtime.attached_clients || 0, runtime.errors || 0, runtime.last_error?.summary || "—"];
      cells.forEach((value, index) => { const cell = document.createElement("td"); cell.textContent = String(value); if (index === 0) { const dot = document.createElement("span"); dot.className = `dot ${network.connected ? "on" : "off"}`; cell.prepend(dot); } if (index === 4 && network.tls) { const tls = document.createElement("span"); tls.className = "tag"; tls.textContent = "TLS"; cell.append(" ", tls); } row.append(cell); });
      const actions = document.createElement("td");
      actions.className = "row-actions";
      const form = document.createElement("form");
      form.method = "post";
      form.action = `/api/v1/admin/networks/${encodeURIComponent(network.owner)}/${encodeURIComponent(network.name)}`;
      form.dataset.apiAdminNetworkToggle = "";
      const csrf = document.createElement("input"); csrf.type = "hidden"; csrf.name = "csrf"; csrf.value = adminNetworkRows.dataset.csrf || "";
      const enabled = document.createElement("input"); enabled.type = "hidden"; enabled.name = "enabled"; enabled.value = network.enabled ? "false" : "true";
      const button = document.createElement("button"); button.type = "submit"; button.textContent = network.enabled ? "Disable" : "Enable";
      form.append(csrf, enabled, button); actions.append(form); row.append(actions); adminNetworkRows.append(row);
    }
  };
  if (adminNetworkRows instanceof HTMLElement) {
    void apiRead("/api/v1/admin/networks")
      .then((result) => renderAdminNetworks(Array.isArray(result.networks) ? result.networks : []))
      .catch((error) => { adminNetworkRows.textContent = error instanceof Error ? error.message : "Network list failed to load."; });
  }
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.matches("[data-api-admin-network-toggle]")) return;
    event.preventDefault();
    const enabled = fieldValue(new FormData(form), "enabled");
    if (enabled !== "true" && enabled !== "false") {
      if (adminNetworkResult) {
        adminNetworkResult.textContent = "The requested network state is invalid. Reload and try again.";
        adminNetworkResult.className = "banner-error";
      }
      return;
    }
    void apiRequest(form, form.action, "PATCH", { enabled: enabled === "true" })
      .then(() => window.location.reload())
      .catch((error) => {
        if (!adminNetworkResult) return;
        adminNetworkResult.textContent = error instanceof Error ? error.message : "Network lifecycle change failed.";
        adminNetworkResult.className = "banner-error";
      });
  });

  const ownerNetworkResult = document.getElementById("network-api-result");
  const setOwnerNetworkResult = (message, success) => {
    if (!ownerNetworkResult) return;
    ownerNetworkResult.textContent = message;
    ownerNetworkResult.className = success ? "banner-success" : "banner-error";
  };

  const ownerNetworkRows = document.querySelector("[data-api-owner-network-list]");
  const ownerNetworkCount = document.getElementById("owner-network-count");
  const ownerNetworkRefreshStatus = ownerNetworkRows instanceof HTMLElement
    ? document.getElementById(ownerNetworkRows.dataset.refreshStatus)
    : null;
  const networkCell = (value) => {
    const cell = document.createElement("td");
    cell.textContent = String(value);
    return cell;
  };
  const renderOwnerNetworks = (networks) => {
    if (!(ownerNetworkRows instanceof HTMLElement)) return;
    const body = document.createElement("tbody");
    if (ownerNetworkCount) ownerNetworkCount.textContent = String(networks.length);
    if (!networks.length) {
      const row = document.createElement("tr");
      const cell = networkCell("No networks yet. Add one above.");
      cell.colSpan = 7;
      cell.className = "empty";
      row.append(cell);
      body.append(row);
    }
    for (const network of networks) {
      if (!network || typeof network.name !== "string" || typeof network.kind !== "string") {
        throw new Error("The network list response is invalid. Reload and try again.");
      }
      const runtime = network.runtime && typeof network.runtime === "object" ? network.runtime : null;
      const enabled = network.enabled === true;
      const connected = network.connected === true;
      const state = !enabled
        ? "disabled"
        : typeof runtime?.state === "string" ? runtime.state.replaceAll("_", " ") : "not running";
      const row = document.createElement("tr");
      const status = document.createElement("td");
      const dot = document.createElement("span");
      dot.className = `dot ${connected ? "on" : "off"}`;
      status.append(dot, document.createTextNode(state));
      const name = document.createElement("a");
      name.className = "rowlink";
      name.href = `/console/networks/${encodeURIComponent(network.name)}`;
      name.textContent = network.name;
      const nameCell = document.createElement("td");
      nameCell.append(name);
      const kind = networkCell(network.kind);
      const upstream = document.createElement("td");
      const address = document.createElement("code");
      address.textContent = typeof network.addr === "string" ? network.addr : "";
      upstream.append(address);
      if (network.tls === true) {
        const tls = document.createElement("span");
        tls.className = "tag";
        tls.textContent = "TLS";
        upstream.append(document.createTextNode(" "), tls);
      }
      const clients = networkCell(Number.isSafeInteger(runtime?.attached_clients) ? runtime.attached_clients : 0);
      const errors = networkCell(Number.isSafeInteger(runtime?.errors) ? runtime.errors : 0);
      const actions = document.createElement("td");
      actions.className = "row-actions";
      const inspect = document.createElement("a");
      inspect.className = "rowlink";
      inspect.href = name.href;
      inspect.textContent = "Inspect";
      const toggle = document.createElement("form");
      toggle.method = "post";
      toggle.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`;
      toggle.dataset.apiOwnerNetworkToggle = "";
      const csrf = document.createElement("input");
      csrf.type = "hidden";
      csrf.name = "csrf";
      csrf.value = ownerNetworkRows.dataset.csrf || "";
      const nextEnabled = document.createElement("input");
      nextEnabled.type = "hidden";
      nextEnabled.name = "enabled";
      nextEnabled.value = enabled ? "false" : "true";
      const toggleButton = document.createElement("button");
      toggleButton.type = "submit";
      toggleButton.textContent = enabled ? "Disable" : "Enable";
      toggle.append(csrf, nextEnabled, toggleButton);
      const remove = document.createElement("form");
      remove.method = "post";
      remove.action = toggle.action;
      remove.dataset.apiOwnerNetworkDelete = "";
      remove.dataset.confirm = `Remove network ${network.name}? This also stops its live connection.`;
      const removeCsrf = csrf.cloneNode();
      const removeButton = document.createElement("button");
      removeButton.className = "danger";
      removeButton.type = "submit";
      removeButton.textContent = "Remove";
      remove.append(removeCsrf, removeButton);
      actions.append(inspect, toggle, remove);
      row.append(status, nameCell, kind, upstream, clients, errors, actions);
      body.append(row);
    }
    const table = ownerNetworkRows.querySelector("table");
    const previous = table?.querySelector("tbody");
    if (!(table instanceof HTMLTableElement) || !(previous instanceof HTMLTableSectionElement)) {
      throw new Error("The network list is unavailable. Reload and try again.");
    }
    table.replaceChild(body, previous);
  };
  const renderOwnerNetworkFailure = (message) => {
    if (!(ownerNetworkRows instanceof HTMLElement)) return;
    const table = ownerNetworkRows.querySelector("table");
    const previous = table?.querySelector("tbody");
    if (!(table instanceof HTMLTableElement) || !(previous instanceof HTMLTableSectionElement)) return;
    if (ownerNetworkCount) ownerNetworkCount.textContent = "—";
    const body = document.createElement("tbody");
    const row = document.createElement("tr");
    const cell = networkCell(message);
    cell.colSpan = 7;
    cell.className = "empty";
    row.append(cell);
    body.append(row);
    table.replaceChild(body, previous);
  };
  const refreshOwnerNetworks = async () => {
    if (!(ownerNetworkRows instanceof HTMLElement)) return;
    ownerNetworkRows.setAttribute("aria-busy", "true");
    if (ownerNetworkRefreshStatus) {
      ownerNetworkRefreshStatus.textContent = "Refreshing…";
      ownerNetworkRefreshStatus.classList.remove("refresh-error");
    }
    try {
      const result = await apiRead("/api/v1/me/networks");
      renderOwnerNetworks(Array.isArray(result.networks) ? result.networks : []);
      if (ownerNetworkRefreshStatus) ownerNetworkRefreshStatus.textContent = "Live data refreshed.";
    } catch (error) {
      const message = error instanceof Error ? error.message : "Network list failed to load.";
      renderOwnerNetworkFailure(message);
      if (ownerNetworkRefreshStatus) {
        ownerNetworkRefreshStatus.textContent = `Live refresh failed (${message}). Use Reload to retry.`;
        ownerNetworkRefreshStatus.classList.add("refresh-error");
      }
    } finally {
      ownerNetworkRows.removeAttribute("aria-busy");
    }
  };
  if (ownerNetworkRows instanceof HTMLElement) {
    void refreshOwnerNetworks();
    const seconds = Number(ownerNetworkRows.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => { void refreshOwnerNetworks(); }, seconds * 1000);
    }
  }

  const mutateOwnerNetwork = async (form, url, method, body, reload = true) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      const result = await apiRequest(form, url, method, body);
      if (reload) {
        window.location.reload();
      } else {
        const nick = result?.confirmed_nick;
        const timings = [result?.dns_ms, result?.connect_ms, result?.registration_ms];
        if (
          typeof nick !== "string" || !nick
          || !Number.isSafeInteger(result?.resolved_addresses) || result.resolved_addresses < 1
          || timings.some((value) => !Number.isSafeInteger(value) || value < 0)
        ) {
          throw new Error("The connection check returned an invalid response. Reload and try again.");
        }
        setOwnerNetworkResult(
          `Registered as ${nick}. Resolved ${result.resolved_addresses} address${result.resolved_addresses === 1 ? "" : "es"}; DNS ${result.dns_ms}ms, connection ${result.connect_ms}ms, registration ${result.registration_ms}ms. No network was created.`,
          true,
        );
      }
    } catch (error) {
      setOwnerNetworkResult(error instanceof Error ? error.message : "Network request failed.", false);
      if (submit) submit.disabled = false;
    }
  };

  const ownerNetworkConnection = (fields) => ({
    addr: fieldValue(fields, "addr"),
    tls: fields.has("tls"),
    nick: fieldValue(fields, "nick"),
    realname: optionalValue(String(fields.get("realname") || "")),
    autojoin: splitValues(String(fields.get("autojoin") || ""), ","),
    sasl_account: optionalValue(String(fields.get("sasl_account") || "")),
    sasl_password: optionalValue(String(fields.get("sasl_password") || "")),
  });

  for (const form of document.querySelectorAll("[data-api-owner-network-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const name = fieldValue(fields, "name");
      const connection = ownerNetworkConnection(fields);
      if (!name || !connection.addr || !connection.nick) {
        setOwnerNetworkResult("Enter a network ID, server, and nickname.", false);
        return;
      }
      const preflight = event.submitter instanceof HTMLElement
        && event.submitter.matches("[data-api-network-preflight]");
      if (preflight) {
        const { addr, tls, nick, realname, sasl_account, sasl_password } = connection;
        void mutateOwnerNetwork(form, "/api/v1/me/networks/preflight", "POST", {
          addr, tls, nick, realname, sasl_account, sasl_password,
        }, false);
        return;
      }
      void mutateOwnerNetwork(form, form.action, "POST", { kind: "irc", name, ...connection });
    });
  }

  for (const form of document.querySelectorAll("[data-api-owner-bridge-create]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const name = fieldValue(fields, "name");
      const kind = fieldValue(fields, "kind");
      const password = String(fields.get("sasl_password") || "");
      if (!name || !kind || !password) {
        setOwnerNetworkResult("Enter every required bridge value.", false);
        return;
      }
      void mutateOwnerNetwork(form, form.action, "POST", {
        kind, name, addr: fieldValue(fields, "addr"), tls: true,
        nick: fieldValue(fields, "nick"), realname: null,
        autojoin: splitValues(String(fields.get("autojoin") || ""), ","),
        sasl_account: optionalValue(String(fields.get("sasl_account") || "")),
        sasl_password: password,
      });
    });
  }

  const ownerNetworkUpdate = (form, bridge) => {
    const fields = new FormData(form);
    const password = String(fields.get("sasl_password") || "");
    const account = optionalValue(String(fields.get("sasl_account") || ""));
    const credentials = fields.has("clear_sasl")
      ? { action: "remove" }
      : (account || password)
        ? { action: "set", account, password: password || null }
        : { action: "keep" };
    const body = {
      addr: fieldValue(fields, "addr"), tls: bridge || fields.has("tls"),
      nick: fieldValue(fields, "nick"),
      realname: bridge ? null : optionalValue(String(fields.get("realname") || "")),
      autojoin: splitValues(String(fields.get("autojoin") || ""), ","), credentials,
    };
    if (!body.addr || (!bridge && !body.nick)) {
      throw new Error("Enter the required network connection values.");
    }
    return body;
  };

  for (const form of document.querySelectorAll("[data-api-owner-network-update], [data-api-owner-bridge-update]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      try {
        void mutateOwnerNetwork(form, form.action, "PUT", ownerNetworkUpdate(form, form.hasAttribute("data-api-owner-bridge-update")));
      } catch (error) {
        setOwnerNetworkResult(error instanceof Error ? error.message : "Invalid network configuration.", false);
      }
    });
  }

  // The network-list fragment is replaced during live refreshes, so lifecycle
  // controls are delegated rather than bound only to the original rows.
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.matches("[data-api-owner-network-toggle]")) {
      event.preventDefault();
      const enabled = fieldValue(new FormData(form), "enabled");
      if (enabled !== "true" && enabled !== "false") {
        setOwnerNetworkResult("The requested network state is invalid. Reload and try again.", false);
        return;
      }
      void mutateOwnerNetwork(form, form.action, "PATCH", { enabled: enabled === "true" });
    } else if (form.matches("[data-api-owner-network-delete]")) {
      event.preventDefault();
      void mutateOwnerNetwork(form, form.action, "DELETE");
    }
  });

  const channelResult = document.getElementById("channel-api-result");
  const adminChannelRows = document.querySelector("[data-api-admin-channel-list]");
  if (adminChannelRows instanceof HTMLElement) {
    void apiRead(`/api/v1/admin/channels${window.location.search}`)
      .then((result) => {
        const channels = Array.isArray(result.channels) ? result.channels : [];
        const pager = document.getElementById("admin-channel-pager");
        if (pager) { pager.replaceChildren(); if (result.next_before_id) { const link = document.createElement("a"); const query = new URLSearchParams(window.location.search); query.set("before_id", String(result.next_before_id)); link.href = `/console/admin/channels?${query}`; link.textContent = "Older registrations"; pager.append(link); } }
        adminChannelRows.replaceChildren();
        const count = document.getElementById("admin-channel-count"); if (count) count.textContent = String(channels.length);
        if (!channels.length) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "empty"; cell.textContent = "No registered channels match this view."; row.append(cell); adminChannelRows.append(row); return; }
        for (const channel of channels) { const row = document.createElement("tr"); const policy = channel.policy || {}; const values = [channel.id, channel.name, channel.founder, channel.created_at, `KEEP ${policy.keeptopic ? "on" : "off"}${policy.topic_retained ? "; topic retained" : ""}${policy.mlock ? `; MLOCK ${policy.mlock}` : ""}`, `${policy.access_entries || 0} grants`]; values.forEach((value) => { const cell = document.createElement("td"); cell.textContent = String(value); row.append(cell); }); const actions = document.createElement("td"); const form = document.createElement("form"); form.method = "post"; form.action = `/api/v1/admin/channels/${encodeURIComponent(channel.name)}`; form.dataset.apiAdminChannelDrop = ""; form.dataset.confirm = `Unregister ${channel.name} and delete its retained policy?`; const csrf = document.createElement("input"); csrf.type = "hidden"; csrf.name = "csrf"; csrf.value = adminChannelRows.dataset.csrf || ""; const button = document.createElement("button"); button.type = "submit"; button.className = "danger"; button.textContent = "Unregister"; form.append(csrf, button); actions.append(form); row.append(actions); adminChannelRows.append(row); }
      })
      .catch((error) => { adminChannelRows.textContent = error instanceof Error ? error.message : "Channel directory failed to load."; });
  }

  const adminAuditRows = document.querySelector("[data-api-admin-audit-list]");
  if (adminAuditRows instanceof HTMLElement) {
    void apiRead(`/api/v1/admin/audit${window.location.search}`)
      .then((result) => {
        const entries = Array.isArray(result.audit) ? result.audit : [];
        adminAuditRows.replaceChildren();
        const count = document.getElementById("admin-audit-count");
        if (count) count.textContent = String(entries.length);
        const pager = document.getElementById("admin-audit-pager");
        if (pager) {
          pager.replaceChildren();
          const status = document.createElement("span");
          status.className = "meta";
          status.textContent = new URLSearchParams(window.location.search).has("before_id")
            ? "Showing an older page."
            : "Showing the newest matching actions.";
          pager.append(status);
          if (result.next_before_id) {
            const link = document.createElement("a");
            const query = new URLSearchParams(window.location.search);
            query.set("before_id", String(result.next_before_id));
            link.href = `/console/audit?${query}`;
            link.textContent = "Older actions";
            pager.append(link);
          }
        }
        if (!entries.length) {
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.colSpan = 6;
          cell.className = "empty";
          cell.textContent = "No audited actions match this view.";
          row.append(cell);
          adminAuditRows.append(row);
          return;
        }
        for (const entry of entries) {
          const row = document.createElement("tr");
          [entry.id, entry.at, entry.actor, entry.action, entry.target, entry.detail]
            .forEach((value, index) => {
              const cell = document.createElement("td");
              cell.textContent = String(value || "");
              if (index === 0 || index === 1) cell.className = "meta";
              if (index === 4) cell.className = "audit-target";
              if (index === 5) cell.className = "audit-detail";
              row.append(cell);
            });
          adminAuditRows.append(row);
        }
      })
      .catch((error) => {
        adminAuditRows.textContent = error instanceof Error
          ? error.message
          : "Audit history failed to load.";
      });
  }

  const setChannelResult = (message, success) => {
    if (!channelResult) return;
    channelResult.textContent = message;
    channelResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateChannel = async (form, url, method, body) => {
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      await apiRequest(form, url, method, body);
      window.location.reload();
    } catch (error) {
      setChannelResult(error instanceof Error ? error.message : "Channel request failed.", false);
      if (submit) submit.disabled = false;
    }
  };

  for (const form of document.querySelectorAll("[data-api-channel-register]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const name = fieldValue(new FormData(form), "channel");
      if (!name) {
        setChannelResult("Enter the channel to register.", false);
        return;
      }
      void mutateChannel(form, form.action, "POST", { name });
    });
  }

  for (const form of document.querySelectorAll("[data-api-channel-patch]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      let body;
      switch (form.dataset.apiChannelPatch) {
        case "topic": {
          const topic = fieldValue(fields, "topic");
          body = { action: "set_topic", topic: topic || null };
          break;
        }
        case "keeptopic":
          body = { action: "set_keeptopic", enabled: fieldValue(fields, "enabled") === "on" };
          break;
        case "mlock": {
          const mlock = fieldValue(fields, "mlock");
          body = { action: "set_mlock", mlock: mlock || null };
          break;
        }
        case "founder": {
          const account = fieldValue(fields, "account");
          if (!account) {
            setChannelResult("Enter the new founder account.", false);
            return;
          }
          body = { action: "transfer_founder", account };
          break;
        }
        default:
          setChannelResult("The channel operation is invalid. Reload and try again.", false);
          return;
      }
      void mutateChannel(form, form.action, "PATCH", body);
    });
  }

  for (const form of document.querySelectorAll("[data-api-channel-access]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const account = fieldValue(fields, "account");
      const flags = [fields.has("auto_op") && "o", fields.has("auto_voice") && "v"]
        .filter(Boolean).join("");
      if (!account || !flags) {
        setChannelResult("Enter an account and select at least one access grant.", false);
        return;
      }
      void mutateChannel(form, `${form.action}/${encodeURIComponent(account)}`, "PUT", { flags });
    });
  }

  for (const form of document.querySelectorAll("[data-api-channel-access-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateChannel(form, form.action, "DELETE");
    });
  }

  for (const form of document.querySelectorAll("[data-api-channel-drop]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateChannel(form, form.action, "DELETE");
    });
  }

  for (const form of document.querySelectorAll("[data-api-admin-channel-drop]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateChannel(form, form.action, "DELETE");
    });
  }
})();
