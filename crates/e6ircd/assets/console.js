import { apiContractLoader, getOperationJson } from "/console-contract.js";
import { loadSettings, saveSettings } from "/console-settings.js";

(() => {
  "use strict";

  const consoleTheme = document.querySelector("[data-console-theme]");
  const consoleThemeResult = document.querySelector("[data-console-theme-result]");
  const confirmationDialog = document.querySelector("[data-console-confirm]");
  const confirmationMessage = document.querySelector("[data-console-confirm-message]");
  const confirmationAction = document.querySelector("[data-console-confirm-action]");
  const panelRefreshers = new WeakMap();
  const formSubmissionTriggers = new WeakMap();
  const activeFormSubmissions = new WeakSet();
  let pendingConfirmation = null;
  let pendingConfirmationSubmitter = null;
  let confirmationTrigger = null;
  const showConsoleThemeResult = (message) => {
    if (consoleThemeResult) consoleThemeResult.textContent = message;
  };
  const applyConsoleTheme = (theme) => {
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
  };
  const preserveFormEdits = (form) => {
    const mark = (event) => {
      const field = event.target;
      if (field instanceof HTMLInputElement || field instanceof HTMLSelectElement || field instanceof HTMLTextAreaElement) {
        field.dataset.apiEdited = "true";
      }
    };
    form.addEventListener("input", mark);
    form.addEventListener("change", mark);
  };
  const hydrateTextInput = (form, name, value) => {
    const field = form.elements.namedItem(name);
    if (field instanceof HTMLInputElement && field.dataset.apiEdited !== "true") field.value = value;
  };
  const hydrateCheckbox = (form, name, checked) => {
    const field = form.elements.namedItem(name);
    if (field instanceof HTMLInputElement && field.dataset.apiEdited !== "true") field.checked = checked;
  };
  if (consoleTheme instanceof HTMLSelectElement) {
    const loaded = loadSettings(() => localStorage);
    if (loaded.warning) showConsoleThemeResult(loaded.warning);
    consoleTheme.value = loaded.settings.theme;
    applyConsoleTheme(loaded.settings.theme);
    consoleTheme.addEventListener("change", () => {
      const nextTheme = consoleTheme.value;
      applyConsoleTheme(nextTheme);
      const warning = saveSettings(() => localStorage, { ...loaded.settings, theme: nextTheme });
      showConsoleThemeResult(warning || "Theme preference saved for chat and console.");
    });
  }

  const activeConsoleDestination = document.querySelector('nav[aria-label="Console"] [aria-current="page"]');
  if (
    activeConsoleDestination instanceof HTMLElement
    && window.matchMedia("(max-width: 40rem)").matches
  ) {
    activeConsoleDestination.scrollIntoView({ block: "nearest", inline: "center" });
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const message = form.dataset.confirm;
    const submitter = event.submitter instanceof HTMLElement ? event.submitter : null;
    if (!message || form.dataset.confirmed === "true") {
      delete form.dataset.confirmed;
      formSubmissionTriggers.set(form, submitter);
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (
      confirmationDialog instanceof HTMLDialogElement
      && confirmationMessage instanceof HTMLElement
    ) {
      pendingConfirmation = form;
      pendingConfirmationSubmitter = submitter;
      confirmationTrigger = submitter
        ?? (document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null);
      confirmationMessage.textContent = message;
      confirmationDialog.returnValue = "cancel";
      if (confirmationAction instanceof HTMLButtonElement) {
        const actionLabel = submitter instanceof HTMLInputElement
          ? submitter.value.trim()
          : submitter?.textContent?.trim();
        confirmationAction.textContent = actionLabel || "Continue";
        confirmationAction.className = submitter?.classList.contains("danger") ? "danger" : "primary";
      }
      confirmationDialog.showModal();
      return;
    }
    if (window.confirm(message)) {
      form.dataset.confirmed = "true";
      queueMicrotask(() => form.requestSubmit(submitter?.isConnected ? submitter : undefined));
    }
  }, true);

  if (confirmationDialog instanceof HTMLDialogElement) {
    confirmationDialog.addEventListener("close", () => {
      const form = pendingConfirmation;
      const submitter = pendingConfirmationSubmitter;
      const trigger = confirmationTrigger;
      pendingConfirmation = null;
      pendingConfirmationSubmitter = null;
      confirmationTrigger = null;
      if (!form || confirmationDialog.returnValue !== "confirm") {
        trigger?.focus();
        return;
      }
      form.dataset.confirmed = "true";
      form.requestSubmit(submitter?.isConnected ? submitter : undefined);
    });
  }

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
      const refresh = panelRefreshers.get(panel);
      if (refresh) void refresh(true);
    });
  }

  const configurationResult = document.getElementById("configuration-api-result");

  const apiOperation = (method, url) => {
    const parsed = new URL(url, window.location.origin);
    if (parsed.origin !== window.location.origin || parsed.hash !== "" || !parsed.pathname.startsWith("/api/v1/")) {
      throw new Error("The API request URL is invalid. Reload and try again.");
    }
    return Object.freeze({ method, url: `${parsed.pathname}${parsed.search}` });
  };

  const apiMutation = apiOperation;

  const consoleApiContract = apiContractLoader(fetch);

  const apiRequest = async (form, operation, body) => {
    const csrf = form.querySelector('input[name="csrf"]')?.value;
    if (!csrf) throw new Error("The session security token is missing. Reload and try again.");
    const contract = await consoleApiContract();
    return getOperationJson(fetch, contract, operation.method, operation.url, {
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-E6IRC-CSRF": csrf,
      },
      json: body,
    });
  };

  const runFormSubmission = async (form, operation, explicitTrigger) => {
    if (activeFormSubmissions.has(form)) return undefined;
    activeFormSubmissions.add(form);

    const submittedBy = explicitTrigger ?? formSubmissionTriggers.get(form);
    formSubmissionTriggers.delete(form);
    const submitControls = Array.from(form.querySelectorAll('button[type="submit"], input[type="submit"], input[type="image"]'));
    if (submittedBy instanceof HTMLButtonElement && !submitControls.includes(submittedBy)) {
      submitControls.push(submittedBy);
    }
    const disabledStates = submitControls.map((control) => control.disabled);
    const previousBusy = form.getAttribute("aria-busy");
    const trigger = submittedBy instanceof HTMLButtonElement
      ? submittedBy
      : submitControls.find((control) => control instanceof HTMLButtonElement);
    const previousTriggerLabel = trigger?.getAttribute("aria-label") ?? null;

    form.setAttribute("aria-busy", "true");
    for (const control of submitControls) control.disabled = true;
    if (trigger instanceof HTMLButtonElement) {
      const label = trigger.getAttribute("aria-label") || trigger.textContent?.trim() || "Action";
      trigger.dataset.submitting = "true";
      trigger.setAttribute("aria-label", `${label} — in progress`);
    }

    try {
      return await operation();
    } finally {
      activeFormSubmissions.delete(form);
      if (previousBusy === null) form.removeAttribute("aria-busy");
      else form.setAttribute("aria-busy", previousBusy);
      submitControls.forEach((control, index) => { control.disabled = disabledStates[index]; });
      if (trigger instanceof HTMLButtonElement) {
        delete trigger.dataset.submitting;
        if (previousTriggerLabel === null) trigger.removeAttribute("aria-label");
        else trigger.setAttribute("aria-label", previousTriggerLabel);
      }
    }
  };

  const apiRead = async (url) => {
    const operation = apiOperation("GET", url);
    return getOperationJson(fetch, await consoleApiContract(), operation.method, operation.url, {
      cache: "no-store",
      credentials: "same-origin",
    });
  };

  const apiCollection = (value, field) => value[field];

  const serializeRefresh = (refresh, reportQueued) => {
    let running = false;
    let queued = false;
    return async (announceQueue = false) => {
      if (running) {
        queued = true;
        if (announceQueue) reportQueued();
        return;
      }
      running = true;
      try {
        do {
          queued = false;
          await refresh();
        } while (queued);
      } finally {
        running = false;
      }
    };
  };

  const refreshAfterMutation = async (refresh) => {
    if (!refresh) throw new Error("The updated view is unavailable. Return to the directory and try again.");
    if (await refresh() === false) {
      throw new Error("The change was saved, but the updated data could not be loaded.");
    }
  };

  const element = (name, className, text) => {
    const node = document.createElement(name);
    if (className) node.className = className;
    if (name === "th" && text === undefined) text = "Actions";
    if (text !== undefined) node.textContent = String(text);
    return node;
  };

  const append = (parent, ...children) => {
    for (const child of children) parent.append(child);
    return parent;
  };
  const scrollRegion = (label, child) => {
    const region = element("div", "scroll");
    region.tabIndex = 0;
    region.setAttribute("role", "region");
    region.setAttribute("aria-label", label);
    region.append(child);
    return region;
  };
  const logRegion = (label) => {
    const region = element("div", "backlog");
    region.tabIndex = 0;
    region.setAttribute("role", "log");
    region.setAttribute("aria-label", label);
    return region;
  };

  const retryButton = (retry) => {
    const button = element("button", "secondary-link", "Retry");
    button.type = "button";
    button.addEventListener("click", retry);
    return button;
  };

  const tableLoadFailure = (body, columns, error, retry) => {
    body.replaceChildren();
    const row = document.createElement("tr");
    const cell = element("td", "empty");
    cell.colSpan = columns;
    const status = element("span");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const message = error instanceof Error ? error.message : "The directory failed to load.";
    status.textContent = `${message} `;
    cell.append(status, retryButton(retry));
    row.append(cell);
    body.append(row);
  };

  const listLoadFailure = (host, error, retry) => {
    host.replaceChildren();
    const status = element("p", "empty");
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.textContent = error instanceof Error ? error.message : "The section failed to load.";
    host.append(status, retryButton(retry));
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

  const monitoringWindowLabel = (minutes) => {
    const label = ({ 60: "1 hour", 360: "6 hours", 1440: "24 hours", 10080: "7 days" })[minutes];
    if (label === undefined) throw new Error("The monitoring window is invalid.");
    return label;
  };
  const monitoringAge = (now, then) => {
    const seconds = Math.max(0, Math.floor((now - then) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };
  const monitoringLatency = (micros) => micros >= 1000000 ? `${(micros / 1000000).toFixed(2)} s` : micros >= 1000 ? `${(micros / 1000).toFixed(1)} ms` : `${micros} µs`;
  const monitoringHeight = (value, peak) => value === 0 ? 0 : Math.max(1, Math.floor(value * 100 / Math.max(1, peak)));
  const monitoringQueue = (queue, name) => {
    if (!Number.isSafeInteger(queue.capacity) || queue.capacity < 1) throw new Error(`Telemetry queue ${name} has an invalid capacity.`);
    return queue;
  };
  const monitoringDatabaseQueue = (sample) => {
    if (sample.queues.db === undefined) throw new Error("Telemetry is missing the database queue.");
    return monitoringQueue(sample.queues.db, "db");
  };
  const monitoringCoreQueues = (sample) => {
    const queues = Object.entries(sample.queues).filter(([name]) => name.startsWith("core-"));
    if (queues.length === 0) throw new Error("Telemetry is missing IRC core queues.");
    return queues.map(([name, queue]) => monitoringQueue(queue, name));
  };
  const monitoringLastSeen = (sample, kind) => {
    const timestamp = sample.error_last_seen_ms[kind];
    if (!Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error(`Telemetry is missing the last-seen time for ${kind}.`);
    return timestamp;
  };
  const monitoringDeltaBars = (samples, inbound, outbound, inboundLabel, outboundLabel, now) => {
    const values = samples.slice(1).map((sample, index) => ({ inbound: Math.max(0, inbound(sample) - inbound(samples[index])), outbound: Math.max(0, outbound(sample) - outbound(samples[index])), at: sample.sampled_at_ms }));
    const peak = Math.max(1, ...values.flatMap((value) => [value.inbound, value.outbound]));
    return values.map((value) => ({ inbound_height: monitoringHeight(value.inbound, peak), outbound_height: monitoringHeight(value.outbound, peak), title: `${formatBytes(value.inbound)} ${inboundLabel} · ${formatBytes(value.outbound)} ${outboundLabel} · ${monitoringAge(now, value.at)}` }));
  };
  const monitoringView = ({ current, history }, minutes) => {
    const samples = [...history.filter((sample) => sample.sampled_at_ms !== current.sampled_at_ms), current];
    const first = samples[0];
    const elapsed = Math.max(1, Math.floor((current.sampled_at_ms - first.sampled_at_ms) / 1000));
    const errorTotal = Object.values(current.errors).reduce((sum, count) => sum + count, 0);
    const connectionPeak = Math.max(1, ...samples.map((sample) => Math.max(sample.active_connections, sample.bnc_client_connections)));
    const latencyPeak = Math.max(1, ...samples.map((sample) => Math.max(sample.core_latency.p95_us, sample.database_latency.p95_us, sample.http_latency.p95_us)));
    const queuePressure = (queue) => Math.floor(queue.depth * 100 / queue.capacity);
    const corePressure = (sample) => Math.max(...monitoringCoreQueues(sample).map(queuePressure));
    const errorBars = samples.slice(1).map((sample, index) => ({ count: Math.max(0, Object.values(sample.errors).reduce((sum, count) => sum + count, 0) - Object.values(samples[index].errors).reduce((sum, count) => sum + count, 0)), at: sample.sampled_at_ms }));
    const errorPeak = Math.max(1, ...errorBars.map((bar) => bar.count));
    return {
      core_ready: current.core_heartbeat_age_ms <= 45000, database_ready: true,
      active_connections: current.active_connections, registered_connections: current.registered_connections, channels: current.channels, opened_total: current.connections_opened_total, rejected_total: current.connections_rejected_total,
      traffic_in: formatBytes(current.irc_bytes_in_total), traffic_out: formatBytes(current.irc_bytes_out_total), upstream_in: formatBytes(current.bnc_bytes_in_total), upstream_out: formatBytes(current.bnc_bytes_out_total),
      inbound_rate: `${formatBytes(Math.max(0, current.irc_bytes_in_total - first.irc_bytes_in_total) / elapsed)}/s`, outbound_rate: `${formatBytes(Math.max(0, current.irc_bytes_out_total - first.irc_bytes_out_total) / elapsed)}/s`, upstream_inbound_rate: `${formatBytes(Math.max(0, current.bnc_bytes_in_total - first.bnc_bytes_in_total) / elapsed)}/s`, upstream_outbound_rate: `${formatBytes(Math.max(0, current.bnc_bytes_out_total - first.bnc_bytes_out_total) / elapsed)}/s`,
      http_requests: current.http_requests_total, database_requests: current.database_requests_total, bnc_connected: current.bnc_connected, bnc_networks: current.bnc_networks, upstreams_ready: current.bnc_networks > 0 && current.bnc_connected === current.bnc_networks, upstreams_degraded: current.bnc_connected > 0 && current.bnc_connected < current.bnc_networks, bnc_clients: current.bnc_client_connections, error_total: errorTotal, sendq_kills: current.sendq_kills_total,
      core_p50: monitoringLatency(current.core_latency.p50_us), core_p95: monitoringLatency(current.core_latency.p95_us), core_p99: monitoringLatency(current.core_latency.p99_us), database_p50: monitoringLatency(current.database_latency.p50_us), database_p95: monitoringLatency(current.database_latency.p95_us), database_p99: monitoringLatency(current.database_latency.p99_us), http_p50: monitoringLatency(current.http_latency.p50_us), http_p95: monitoringLatency(current.http_latency.p95_us), http_p99: monitoringLatency(current.http_latency.p99_us),
      traffic_bars: monitoringDeltaBars(samples, (sample) => sample.irc_bytes_in_total, (sample) => sample.irc_bytes_out_total, "inbound", "outbound", current.sampled_at_ms), upstream_traffic_bars: monitoringDeltaBars(samples, (sample) => sample.bnc_bytes_in_total, (sample) => sample.bnc_bytes_out_total, "received", "sent", current.sampled_at_ms),
      connection_bars: samples.filter((sample) => sample.schema_version === current.schema_version).map((sample) => ({ irc_height: monitoringHeight(sample.active_connections, connectionPeak), bnc_height: monitoringHeight(sample.bnc_client_connections, connectionPeak), title: `${sample.active_connections} IRC · ${sample.bnc_client_connections} BNC · ${monitoringAge(current.sampled_at_ms, sample.sampled_at_ms)}` })),
      upstream_bars: samples.map((sample) => ({ height: sample.bnc_networks === 0 ? 0 : Math.floor(sample.bnc_connected * 100 / sample.bnc_networks), status_class: sample.bnc_networks === 0 || sample.bnc_connected === 0 ? "bar-off" : sample.bnc_connected === sample.bnc_networks ? "bar-ok" : "bar-warn", title: `${sample.bnc_connected} of ${sample.bnc_networks} connected · ${monitoringAge(current.sampled_at_ms, sample.sampled_at_ms)}` })),
      error_bars: errorBars.map((bar) => ({ height: monitoringHeight(bar.count, errorPeak), title: `${bar.count} new errors · ${monitoringAge(current.sampled_at_ms, bar.at)}` })), latency_bars: samples.map((sample) => ({ core_height: monitoringHeight(sample.core_latency.p95_us, latencyPeak), database_height: monitoringHeight(sample.database_latency.p95_us, latencyPeak), http_height: monitoringHeight(sample.http_latency.p95_us, latencyPeak), title: `Core ${monitoringLatency(sample.core_latency.p95_us)} · PostgreSQL ${monitoringLatency(sample.database_latency.p95_us)} · HTTP ${monitoringLatency(sample.http_latency.p95_us)} · ${monitoringAge(current.sampled_at_ms, sample.sampled_at_ms)}` })), queue_bars: samples.map((sample) => {
        const core = corePressure(sample);
        const database = queuePressure(monitoringDatabaseQueue(sample));
        return { core_height: core, database_height: database, title: `Core ${core}% · PostgreSQL ${database}% · ${monitoringAge(current.sampled_at_ms, sample.sampled_at_ms)}` };
      }),
      queues: Object.entries(current.queues).map(([name, queue]) => {
        const checked = monitoringQueue(queue, name);
        if (name === "db") return { label: "Database worker", depth: checked.depth, capacity: checked.capacity, pressure: queuePressure(checked), mode: checked.mode.toUpperCase(), mode_switches: checked.mode_switches };
        if (!name.startsWith("core-")) throw new Error(`Telemetry has an unknown queue ${name}.`);
        return { label: `IRC core shard ${name.slice(5)}`, depth: checked.depth, capacity: checked.capacity, pressure: queuePressure(checked), mode: checked.mode.toUpperCase(), mode_switches: checked.mode_switches };
      }), errors: Object.entries(current.errors).filter(([, count]) => count > 0).map(([kind, count]) => ({ kind: kind.replaceAll("_", " "), count, last_seen: monitoringAge(current.sampled_at_ms, monitoringLastSeen(current, kind)) })),
      sampled_age: monitoringAge(current.sampled_at_ms, current.sampled_at_ms), history_samples: samples.length - 1, window_label: monitoringWindowLabel(minutes), window_minutes: minutes,
    };
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
    json.href = `/api/v1/admin/observability?minutes=${encodeURIComponent(view.window_minutes)}`;
    const prometheus = element("a", "", "Prometheus");
    prometheus.href = "/api/v1/admin/metrics";
    foot.append(element("span", "", `${view.history_samples} stored samples · ${view.window_label}`), element("span", "", `Updated ${view.sampled_age}`), json, prometheus);
    fragment.append(foot);
    panel.replaceChildren(fragment);
  };

  const refreshMonitoringNow = async (panel) => {
    const status = document.getElementById(panel.dataset.refreshStatus);
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const minutes = Number(panel.dataset.minutes);
      if (!Number.isSafeInteger(minutes) || minutes < 1) throw new Error("The monitoring window is invalid. Reload and try again.");
      const view = monitoringView(await apiRead(`/api/v1/admin/observability?minutes=${encodeURIComponent(minutes)}`), minutes);
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
    const refresh = serializeRefresh(
      () => refreshMonitoringNow(panel),
      () => {
        const status = document.getElementById(panel.dataset.refreshStatus);
        if (status) status.textContent = "Refresh queued.";
      },
    );
    panelRefreshers.set(panel, refresh);
    void refresh();
    const seconds = Number(panel.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => void refresh(), seconds * 1000);
    }
  }

  const operationTime = (value, absent) => value === null ? absent : new Date(value).toLocaleString();

  const networkOperationsHealth = (view) => {
    const health = element("div", "health-strip");
    health.setAttribute("aria-label", "Network health");
    const runtime = view.runtime;
    const state = !view.enabled ? "disabled" : runtime === null ? "not running" : runtime.state.replaceAll("_", " ");
    const states = [
      [runtime !== null && runtime.state === "connected" ? "on" : "off", "Lifecycle", state],
      [runtime === null ? "off" : runtime.errors === 0 ? "on" : "warn", "Errors", runtime === null ? "Unavailable" : runtime.errors],
      [runtime !== null && runtime.attached_clients > 0 ? "on" : "off", "Attached clients", runtime === null ? "Unavailable" : runtime.attached_clients],
      [view.storage.lines > 0 ? "on" : "off", "Stored backlog", `${view.storage.lines} ${view.storage.lines === 1 ? "line" : "lines"}`],
    ];
    for (const [state, label, value] of states) {
      health.append(append(element("div"), element("span", `dot ${state}`), element("span", "", label), element("strong", "", value)));
    }
    return health;
  };

  const networkOperationsMetrics = (runtime) => {
    const grid = element("div", "metric-grid");
    if (runtime === null) {
      grid.append(append(element("article", "metric-card"), element("span", "metric-label", "Live metrics"), element("strong", "", "Unavailable"), element("small", "", "The network has no running driver.")));
      return grid;
    }
    const metrics = [
      ["Received from upstream", formatBytes(runtime.traffic.bytes_in), `${runtime.traffic.lines_in} upstream ${runtime.traffic.lines_in === 1 ? "line" : "lines"}`],
      ["Sent to upstream", formatBytes(runtime.traffic.bytes_out), `${runtime.traffic.lines_out} upstream ${runtime.traffic.lines_out === 1 ? "line" : "lines"}`],
      ["Connect latency", runtime.connect_latency_ms === null ? "Not measured" : `${runtime.connect_latency_ms} ms`, `${runtime.connection_attempts} ${runtime.connection_attempts === 1 ? "attempt" : "attempts"} since start`],
      ["Memory buffer", `${runtime.buffer.lines} / ${runtime.buffer.capacity}`, "Current lines / capacity"],
    ];
    for (const [label, value, detail] of metrics) {
      grid.append(append(element("article", "metric-card"), element("span", "metric-label", label), element("strong", "", value), element("small", "", detail)));
    }
    return grid;
  };

  const renderNetworkOperations = (panel, view) => {
    const fragment = document.createDocumentFragment();
    const runtime = view.runtime;
    fragment.append(networkOperationsHealth(view), networkOperationsMetrics(runtime));
    const timeline = element("section", "panel");
    const stateChanged = runtime === null ? "Unavailable" : operationTime(runtime.state_changed_at, "Unavailable");
    timeline.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", "Connection timeline"), element("p", "", "Runtime-only timestamps reset when this network is restarted or reconfigured.")), element("span", "count", stateChanged)));
    const summary = element("div", "network-summary");
    const details = runtime === null
      ? [["Live runtime", view.enabled ? "Not running" : "Disabled"]]
      : [
        ["Connected since", operationTime(runtime.connected_at, "Never")],
        ["Next reconnect attempt", operationTime(runtime.next_retry_at, "Not scheduled")],
        ["Last received", operationTime(runtime.last_input_at, "Never")],
        ["Last sent", operationTime(runtime.last_output_at, "Never")],
        ["Last error", operationTime(runtime.last_error_at, "Never")],
        ["Last error reason", runtime.last_error === null ? "No classified runtime failure." : `${runtime.last_error.code}: ${runtime.last_error.summary}${runtime.last_error.diagnostic ? ` Upstream: ${runtime.last_error.diagnostic}` : ""}`],
      ];
    details.push(["Oldest stored line", operationTime(view.storage.oldest_at, "Never")], ["Newest stored line", operationTime(view.storage.newest_at, "Never")]);
    for (const [label, value] of details) summary.append(append(element("div"), element("span", "", label), element("strong", "", value)));
    timeline.append(summary);
    if (runtime !== null && runtime.recent_failures.length > 0) {
      const failures = element("div", "network-summary");
      const list = element("ul", "failure-history");
      for (const failure of runtime.recent_failures) list.append(element("li", "", `${operationTime(failure.at, "Unknown time")} — ${failure.code}: ${failure.summary}`));
      failures.append(append(element("div"), element("span", "", "Recent failures"), list));
      timeline.append(failures);
    }
    fragment.append(timeline);
    const backlog = element("section", "panel");
    backlog.append(append(element("div", "panel-head"), append(element("div"), element("h2", "", "IRC transcript"), element("p", "", "The newest 100 persisted upstream IRC lines, shown oldest first—including NickServ replies, server numerics, and connection diagnostics.")), element("span", "count", `${view.storage.lines} stored`)));
    if (view.recent_lines.length === 0) {
      backlog.append(element("p", "empty", "No IRC output has been stored for this network."));
    } else {
      const lines = logRegion("Recent raw IRC backlog");
      for (const line of view.recent_lines) lines.append(element("code", "", line));
      backlog.append(lines);
    }
    fragment.append(backlog);
    panel.replaceChildren(fragment);
  };

  const refreshNetworkOperationsNow = async (panel) => {
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
    const refresh = serializeRefresh(
      () => refreshNetworkOperationsNow(panel),
      () => {
        const status = document.getElementById(panel.dataset.refreshStatus);
        if (status) status.textContent = "Refresh queued.";
      },
    );
    panelRefreshers.set(panel, refresh);
    void refresh();
    const seconds = Number(panel.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => void refresh(), seconds * 1000);
    }
  }

  const renderNetworkLog = (panel, lines) => {
    const log = logRegion("Component log");
    if (lines.length === 0) {
      log.append(element("p", "empty", "No component lines have been stored yet."));
    } else {
      for (const line of lines) log.append(element("code", "", line));
    }
    panel.replaceChildren(log);
  };

  const refreshNetworkLogNow = async (root) => {
    const panel = root.querySelector("#network-log-panel");
    const status = document.getElementById(root.dataset.refreshStatus);
    if (!(panel instanceof HTMLElement)) return;
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const name = root.dataset.networkName;
      if (!name) throw new Error("This component has no resource ID. Return to networks and try again.");
      const network = await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}`);
      const title = root.querySelector("[data-network-log-title]");
      if (title) title.textContent = `${network.name} log`;
      const detail = root.querySelector("[data-network-log-detail]");
      if (detail instanceof HTMLAnchorElement) detail.href = `/console/networks/${encodeURIComponent(network.name)}`;
      const result = await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}/buffer?limit=1000`);
      renderNetworkLog(panel, apiCollection(result, "lines", "component log"));
      if (status) status.textContent = "Live log refreshed.";
    } catch (error) {
      panel.replaceChildren(monitoringEmpty(`Component log failed (${error.message}). Use Refresh to retry.`));
      if (status) {
        status.textContent = `Live log refresh failed (${error.message}). Use Refresh to retry.`;
        status.classList.add("refresh-error");
      }
    } finally {
      panel.removeAttribute("aria-busy");
    }
  };

  for (const root of document.querySelectorAll("[data-api-network-log]")) {
    const refresh = serializeRefresh(
      () => refreshNetworkLogNow(root),
      () => {
        const status = document.getElementById(root.dataset.refreshStatus);
        if (status) status.textContent = "Refresh queued.";
      },
    );
    panelRefreshers.set(root, refresh);
    void refresh();
    const seconds = Number(root.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) window.setInterval(() => void refresh(), seconds * 1000);
  }

  const renderServerLog = (panel, entries) => {
    const log = logRegion("Live server logs");
    if (entries.length === 0) {
      log.append(element("p", "empty", "No operational events have been recorded yet."));
    } else {
      for (const entry of entries) {
        const at = new Date(entry.at_ms).toISOString();
        log.append(element("code", "", `${at} — ${entry.component} — ${entry.severity}: ${entry.message}`));
      }
    }
    panel.replaceChildren(log);
  };

  const refreshServerLogNow = async (root) => {
    const panel = root.querySelector("#server-log-panel");
    const status = document.getElementById(root.dataset.refreshStatus);
    if (!(panel instanceof HTMLElement)) return;
    panel.setAttribute("aria-busy", "true");
    if (status) {
      status.textContent = "Refreshing…";
      status.classList.remove("refresh-error");
    }
    try {
      const result = await apiRead("/api/v1/admin/logs");
      renderServerLog(panel, apiCollection(result, "entries", "live logs"));
      if (status) status.textContent = "Live logs refreshed.";
    } catch (error) {
      panel.replaceChildren(monitoringEmpty(`Live logs failed (${error.message}). Use Refresh to retry.`));
      if (status) {
        status.textContent = `Live log refresh failed (${error.message}). Use Refresh to retry.`;
        status.classList.add("refresh-error");
      }
    } finally {
      panel.removeAttribute("aria-busy");
    }
  };

  for (const root of document.querySelectorAll("[data-api-server-log]")) {
    const refresh = serializeRefresh(
      () => refreshServerLogNow(root),
      () => {
        const status = document.getElementById(root.dataset.refreshStatus);
        if (status) status.textContent = "Refresh queued.";
      },
    );
    panelRefreshers.set(root, refresh);
    void refresh();
    const seconds = Number(root.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) window.setInterval(() => void refresh(), seconds * 1000);
  }

  const overviewSection = (target, title, href, headings, rows) => {
    target.replaceChildren();
    const head = element("div", "panel-head list-head");
    head.append(element("h2", "", `${title} `), Object.assign(element("a", "secondary-link", `Explore ${title.toLowerCase()}`), { href }));
    target.append(head);
    if (!rows.length) { target.append(element("p", "empty", `No ${title.toLowerCase()}.`)); return; }
    const table = element("table");
    const thead = document.createElement("thead"); const header = document.createElement("tr");
    for (const label of headings) header.append(element("th", "", label));
    thead.append(header); table.append(thead);
    const body = document.createElement("tbody");
    for (const row of rows) { const tr = document.createElement("tr"); for (const value of row) tr.append(element("td", "", value)); body.append(tr); }
    table.append(body); target.append(scrollRegion(`${title} table`, table));
  };

  const formatBytes = (value) => {
    const bytes = value; const units = ["B", "KiB", "MiB", "GiB"];
    let amount = bytes; let unit = 0; while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1; }
    return `${amount >= 10 || unit === 0 ? Math.round(amount) : amount.toFixed(1)} ${units[unit]}`;
  };

  const overviewRoot = document.querySelector("[data-api-admin-overview]");
  if (overviewRoot instanceof HTMLElement) {
    const refreshOverview = async () => {
      try {
        const [stats, accounts, channels, bans, audit] = await Promise.all([apiRead("/api/v1/admin/stats"), apiRead("/api/v1/admin/accounts?limit=10"), apiRead("/api/v1/admin/channels?limit=10"), apiRead("/api/v1/admin/bans?limit=10"), apiRead("/api/v1/admin/audit?limit=10")]);
        overviewRoot.querySelector("#overview").textContent = stats.server;
        overviewRoot.querySelector("[data-overview-lede]").textContent = `Network ${stats.network} · e6ircd ${stats.version}`;
        const metrics = [["Live IRC connections", stats.live.connections, "Current core sessions"], ["Connected upstreams", `${stats.live.connected_upstreams} / ${stats.live.upstreams}`, "Always-on networks"], ["Traffic since start", formatBytes(stats.live.traffic), "IRC and BNC, both directions"], ["Operational errors", stats.live.errors, "Since process start"]];
        overviewRoot.querySelector("[data-overview-metrics]").replaceChildren(...metrics.map(([label, value, detail]) => append(element("div", "metric-card"), element("span", "metric-label", label), element("strong", "", value), element("small", "", detail))));
        overviewRoot.querySelector("[data-overview-counts]").replaceChildren(...[[stats.accounts, "Accounts"], [stats.registered_channels, "Registered channels"], [stats.server_bans, "Server bans"]].map(([value, label]) => append(element("div", "card"), element("div", "n", value), element("div", "l", label))));
        overviewSection(overviewRoot.querySelector("[data-overview-accounts]"), "Newest accounts", "/console/accounts", ["Name"], apiCollection(accounts, "accounts", "account directory").map((entry) => [entry.name]));
        overviewSection(overviewRoot.querySelector("[data-overview-channels]"), "Newest registered channels", "/console/admin/channels", ["Channel", "Founder", "Registered (UTC)"], apiCollection(channels, "channels", "channel directory").map((entry) => [entry.name, entry.founder, entry.created_at]));
        overviewSection(overviewRoot.querySelector("[data-overview-bans]"), "Newest server bans", "/console/bans", ["Kind", "Mask", "Reason", "Set by", "Created (UTC)"], apiCollection(bans, "bans", "server-ban directory").map((entry) => [entry.kind, entry.mask, entry.reason, entry.set_by, entry.created_at]));
        overviewSection(overviewRoot.querySelector("[data-overview-audit]"), "Recent audited actions", "/console/audit", ["When (UTC)", "Actor", "Action", "Target", "Detail"], apiCollection(audit, "audit", "audit directory").map((entry) => [entry.at, entry.actor, entry.action, entry.target, entry.detail]));
      } catch (error) {
        const result = document.getElementById("overview-api-result");
        if (!(result instanceof HTMLElement)) return;
        result.replaceChildren(element("span", "", error instanceof Error ? error.message : "Overview failed to load."), retryButton(() => void refreshOverview()));
        result.className = "banner-error";
      }
    };
    void refreshOverview();
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
        core_workers: positiveInteger(fields, "core_workers", "Core workers"),
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
          api_rate_burst: positiveInteger(fields, "api_rate_burst", "Authenticated API burst"),
          administrator_api_rate_burst: positiveInteger(fields, "administrator_api_rate_burst", "Administrator API burst"),
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

  const syncNetworkForm = (form) => {
    const driver = form.elements.namedItem("kind");
    if (!(driver instanceof HTMLSelectElement)) throw new Error("Network form has no driver selector.");
    const kind = driver.value;
    const requirements = {
      irc: { required: ["addr", "nick", "realname"], visible: ["addr", "nick", "realname", "sasl_account", "sasl_password"] },
      local: { required: ["nick", "realname"], visible: ["addr", "nick", "realname"] },
      matrix: { required: ["nick", "sasl_password"], visible: ["addr", "nick", "sasl_password"] },
      discord: { required: ["sasl_password"], visible: ["addr", "sasl_password"] },
      slack: { required: ["sasl_account", "sasl_password"], visible: ["addr", "sasl_account", "sasl_password"] },
    }[kind];
    if (!requirements) throw new Error(`Unsupported network driver: ${kind}`);
    for (const name of ["addr", "nick", "realname", "sasl_account", "sasl_password"]) {
      const input = form.elements.namedItem(name);
      if (!(input instanceof HTMLInputElement)) throw new Error(`Network form has no ${name} input.`);
      const active = requirements.visible.includes(name);
      input.disabled = !active;
      input.required = requirements.required.includes(name);
      const label = input.closest("label");
      if (!label) throw new Error(`Network form ${name} input has no label.`);
      label.hidden = !active;
    }
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
    const optional = (name) => {
      const value = String(fields.get(name) || "").trim();
      return value ? { [name]: value } : {};
    };
    const required = (name, label) => {
      const value = String(fields.get(name) || "").trim();
      if (!value) throw new Error(`${label} is required.`);
      return value;
    };
    const kind = required("kind", "Driver");
    const common = {
      revision,
      name: required("name", "Network name"),
      kind,
      tls: fields.has("tls"),
      autojoin: splitValues(String(fields.get("autojoin") || ""), ","),
      buffer_cap: number,
      ...optional("owner"),
    };
    const addr = String(fields.get("addr") || "").trim();
    switch (kind) {
      case "irc": {
        const saslAccount = optional("sasl_account");
        const saslPassword = optional("sasl_password");
        if (Boolean(saslAccount.sasl_account) !== Boolean(saslPassword.sasl_password)) {
          throw new Error("IRC SASL account and password must be provided together.");
        }
        return {
          ...common,
          addr: required("addr", "Address"),
          nick: required("nick", "Nickname / user"),
          realname: required("realname", "Real name"),
          ...saslAccount,
          ...saslPassword,
        };
      }
      case "local":
        return {
          ...common,
          addr,
          nick: required("nick", "Nickname / user"),
          realname: required("realname", "Real name"),
        };
      case "matrix":
        return {
          ...common,
          addr,
          nick: required("nick", "Nickname / user"),
          sasl_password: required("sasl_password", "Login password"),
        };
      case "discord":
        return {
          ...common,
          addr,
          sasl_password: required("sasl_password", "Bot token"),
        };
      case "slack":
        return {
          ...common,
          addr,
          sasl_account: required("sasl_account", "Bot token"),
          sasl_password: required("sasl_password", "App-level token"),
        };
      default:
        throw new Error(`Unsupported network driver: ${kind}.`);
    }
  };

  const setConfigurationResult = (message, success) => {
    if (!configurationResult) return;
    configurationResult.textContent = message;
    configurationResult.className = success ? "banner-success" : "banner-error";
  };

  let refreshConfiguration;

  const mutateConfiguration = (form, url, method, body, success = "Configuration saved.") =>
    runFormSubmission(form, async () => {
      try {
        await apiRequest(form, apiMutation(method, url), body);
        await refreshAfterMutation(refreshConfiguration);
        setConfigurationResult(success, true);
      } catch (error) {
        setConfigurationResult(error instanceof Error ? error.message : "Configuration request failed.", false);
      }
    });

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
    form.addEventListener("change", () => syncNetworkForm(form));
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
          account_claim: String(fields.get("account_claim") || ""),
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
    configurationValue(form, "motd", apiCollection(settings, "motd", "configuration").join("\n"));
    configurationValue(form, "storage_history_retention_days", settings.storage.history_retention_days);
    configurationValue(form, "storage_audit_retention_days", settings.storage.audit_retention_days);
    configurationChecked(form, "bnc_enabled", settings.bnc_addr !== null);
    configurationValue(form, "bnc_addr", settings.bnc_addr);
    configurationValue(form, "listeners", configurationListeners(apiCollection(settings, "listeners", "configuration")));
    configurationValue(form, "public_url", settings.public_url);
    configurationChecked(form, "secure_cookies", settings.secure_cookies);
    configurationValue(form, "admin_accounts", apiCollection(settings, "admin_accounts", "configuration").join("\n"));
    for (const name of ["nicklen", "sendq", "core_queue", "core_workers", "max_hot_channels"]) configurationValue(form, name, settings[name]);
    for (const name of ["max_connections_per_ip", "command_burst", "auth_rate_burst", "api_rate_burst", "administrator_api_rate_burst", "registration_burst"]) configurationValue(form, name, settings.limits[name]);
    configurationValue(form, "trusted_proxies", apiCollection(settings.limits, "trusted_proxies", "configuration").join("\n"));
    configurationChecked(form, "observability_enabled", settings.observability.enabled);
    configurationValue(form, "observability_sample_interval_seconds", settings.observability.sample_interval_seconds);
    configurationValue(form, "observability_retention_hours", settings.observability.retention_hours);
    configurationChecked(form, "registration_before_connect", settings.registration.before_connect);
    configurationChecked(form, "registration_require_email", settings.registration.require_email);
    const bncStatus = root.querySelector("[data-configuration-bnc-status]");
    bncStatus.replaceChildren(element("span", runtime.bound_bnc_addr ? "dot on" : "dot off"), document.createTextNode(runtime.bound_bnc_addr ? "Accepting clients on " : "Attach listener is disabled"));
    if (runtime.bound_bnc_addr) bncStatus.append(element("code", "", runtime.bound_bnc_addr));

    const csrf = root.dataset.csrf || "";
    const networks = apiCollection(settings, "networks", "configuration").map((network) => {
      const article = document.createElement("article");
      article.append(append(element("div"), element("strong", "", network.name), element("span", "tag", network.kind)), element("code", "", network.addr), element("span", "meta", `Available to ${network.owner || "all accounts"}`), configurationDeleteForm("network", network.name, revision, csrf, network.owner || ""));
      return article;
    });
    const networkTarget = root.querySelector("[data-configuration-networks]");
    renderConfigurationList(networkTarget, networks, "No server-level networks configured.");
    const networkWarning = configurationCredentialWarning(settings, "Credential-bearing networks still come from bootstrap configuration. Configure the master key and restart once to enable UI changes.");
    if (networkWarning) networkTarget.prepend(networkWarning);
    const kinds = root.querySelector("[data-configuration-network-kinds]");
    kinds.replaceChildren(...apiCollection(runtime, "network_drivers", "configuration runtime").map((kind) => element("option", "", kind.toUpperCase())));
    for (const option of kinds.options) option.value = option.textContent.toLowerCase();
    for (const networkForm of root.querySelectorAll("[data-api-network-create]")) syncNetworkForm(networkForm);

    const opers = apiCollection(settings, "opers", "configuration").map((oper) => append(element("div"), element("code", "", oper.name), configurationDeleteForm("oper", oper.name, revision, csrf)));
    const operTarget = root.querySelector("[data-configuration-opers]");
    renderConfigurationList(operTarget, opers, "No IRC operators configured.");
    const operWarning = configurationCredentialWarning(settings, "Credentials still come from bootstrap configuration. Configure the deployment master key and restart once; e6irc will seal and import them before UI editing is enabled.");
    if (operWarning) operTarget.prepend(operWarning);
    const providers = apiCollection(settings, "oidc_providers", "configuration").map((provider) => {
      const article = document.createElement("article");
      const domains = apiCollection(provider, "allowed_email_domains", "identity-provider");
      const scopes = apiCollection(provider, "scopes", "identity-provider");
      article.append(append(element("div"), element("strong", "", provider.name), element("span", "tag", provider.token_endpoint_auth_method)), element("code", "", provider.issuer_url), element("span", "meta", `Client ${provider.client_id} · account claim ${provider.account_claim} · scopes ${scopes.join(" ")}`), element("span", "meta", `Allowed email domains: ${domains.length ? domains.join(", ") : "any verified provider identity"}`), configurationDeleteForm("oidc", provider.name, revision, csrf));
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
    refreshConfiguration = async () => {
      try {
        renderConfiguration(configurationRoot, await apiRead("/api/v1/admin/configuration"));
      } catch (error) {
        const result = document.getElementById("configuration-api-result");
        if (!(result instanceof HTMLElement)) return false;
        result.replaceChildren(element("span", "", error instanceof Error ? error.message : "Configuration failed to load."), retryButton(() => void refreshConfiguration()));
        result.className = "banner-error";
        return false;
      }
      return true;
    };
    void refreshConfiguration();
  }

  const banResult = document.getElementById("ban-api-result");
  const adminBanRows = document.querySelector("[data-api-admin-ban-list]");
  let refreshBanDirectory;
  if (adminBanRows instanceof HTMLElement) {
    refreshBanDirectory = async () => {
      try {
        const result = await apiRead(`/api/v1/admin/bans${window.location.search}`);
        const bans = apiCollection(result, "bans", "server-ban directory");
        adminBanRows.replaceChildren();
        const count = document.getElementById("admin-ban-count");
        if (count) count.textContent = String(bans.length);
        const pager = document.getElementById("admin-ban-pager");
        if (pager) {
          pager.replaceChildren();
          if (result.next_before_id) {
            const link = document.createElement("a");
            const query = new URLSearchParams(window.location.search);
            query.set("before_id", String(result.next_before_id));
            link.href = `/console/bans?${query}`;
            link.textContent = "Older rules";
            pager.append(link);
          }
        }
        if (!bans.length) {
          const row = document.createElement("tr");
          const cell = document.createElement("td");
          cell.colSpan = 7;
          cell.className = "empty";
          cell.textContent = "No server bans match this view.";
          row.append(cell);
          adminBanRows.append(row);
          return true;
        }
        for (const ban of bans) {
          const row = document.createElement("tr");
          [ban.id, ban.kind, ban.mask, ban.reason, ban.set_by, ban.created_at].forEach((value) => {
            const cell = document.createElement("td");
            cell.textContent = String(value || "");
            row.append(cell);
          });
          const actions = document.createElement("td");
          const form = document.createElement("form");
          form.method = "post";
          form.action = `/api/v1/admin/bans/${ban.id}`;
          form.dataset.apiBanDelete = "";
          form.dataset.confirm = `Remove ${ban.kind} ${ban.mask}?`;
          const csrf = document.createElement("input");
          csrf.type = "hidden";
          csrf.name = "csrf";
          csrf.value = adminBanRows.dataset.csrf || "";
          const id = document.createElement("input");
          id.type = "hidden";
          id.name = "id";
          id.value = String(ban.id);
          const button = document.createElement("button");
          button.type = "submit";
          button.className = "danger";
          button.textContent = "Remove";
          form.append(csrf, id, button);
          actions.append(form);
          row.append(actions);
          adminBanRows.append(row);
        }
      } catch (error) {
        tableLoadFailure(adminBanRows, 7, error, () => void refreshBanDirectory());
        return false;
      }
      return true;
    };
    void refreshBanDirectory();
  }
  const setBanResult = (message, success) => {
    if (!banResult) return;
    banResult.textContent = message;
    banResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateBan = (form, url, method, body) => runFormSubmission(form, async () => {
    try {
      await apiRequest(form, apiMutation(method, url), body);
      await refreshAfterMutation(refreshBanDirectory);
      setBanResult("Updated.", true);
    } catch (error) {
      setBanResult(error instanceof Error ? error.message : "Server-ban request failed.", false);
    }
  });

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
    void mutateBan(form, `/api/v1/admin/bans/${id}`, "DELETE");
  });

  const sessionResult = document.getElementById("session-api-result");
  const setSessionResult = (message, success) => {
    if (!sessionResult) return;
    sessionResult.textContent = message;
    sessionResult.className = success ? "banner-success" : "banner-error";
  };

  const mutateSession = (form, url, message, refresh) => runFormSubmission(form, async () => {
    try {
      await apiRequest(form, apiMutation("DELETE", url));
      await refresh();
    } catch (error) {
      setSessionResult(error instanceof Error ? error.message : message, false);
    }
  });

  const sessionPage = document.querySelector("[data-api-session-page]");
  if (sessionPage instanceof HTMLElement) {
    const own = sessionPage.dataset.own === "true";
    const csrf = sessionPage.dataset.csrf;
    const browserSessions = sessionPage.querySelector("[data-api-browser-sessions]");
    const connections = sessionPage.querySelector("[data-api-live-connections]");
    const filters = sessionPage.querySelector("[data-api-connection-filter]");
    const clear = sessionPage.querySelector("[data-api-session-clear]");
    const pagePath = own ? "/console/my-sessions" : "/console/sessions";
    const apiPath = own ? "/api/v1/me/connections" : "/api/v1/admin/connections";

    const csrfInput = () => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = "csrf";
      input.value = csrf || "";
      return input;
    };
    const formButton = (label, className) => {
      const button = element("button", className, label);
      button.type = "submit";
      return button;
    };
    const sessionMethod = (row) => row.method === "oidc"
      ? `OpenID Connect · ${row.provider || "unknown provider"}`
      : "Local password";
    const currentQuery = () => new URLSearchParams(window.location.search);
    const connectionQuery = () => {
      const source = currentQuery();
      const query = new URLSearchParams();
      for (const key of own
        ? ["nick", "transport", "oper", "limit", "before_id"]
        : ["nick", "account", "transport", "oper", "limit", "before_id"]) {
        const value = source.get(key);
        if (value) query.set(key, value);
      }
      if (!query.has("limit")) query.set("limit", "50");
      return query;
    };
    const refresh = async () => {
      const query = connectionQuery();
      const suffix = query.toString();
      const connectionData = await apiRead(`${apiPath}?${suffix}`);
      renderConnections(connectionData, query);
      if (own) renderBrowserSessions(await apiRead("/api/v1/me/sessions"));
    };
    const refreshAfterMutation = async () => {
      await refresh();
      setSessionResult("Updated.", true);
    };
    const renderBrowserSessions = (data) => {
      if (!(browserSessions instanceof HTMLElement)) return;
      browserSessions.replaceChildren();
      const rows = apiCollection(data, "sessions", "browser-session directory");
      const heading = append(element("div", "panel-head"), append(
        element("div"),
        element("h2", "", "Browser sessions"),
        element("p", "", "Durable web logins for this account. Tokens remain hash-only and are never displayed."),
      ), element("span", "count", rows.length));
      if (rows.length > 1) {
        const revokeOthers = document.createElement("form");
        revokeOthers.dataset.confirm = "Sign out every other browser session?";
        revokeOthers.append(csrfInput(), formButton("Sign out others", "danger"));
        revokeOthers.addEventListener("submit", (event) => {
          event.preventDefault();
          void mutateSession(revokeOthers, "/api/v1/me/sessions?except=current", "Browser-session request failed.", refreshAfterMutation);
        });
        heading.append(revokeOthers);
      }
      browserSessions.append(heading);
      if (rows.length === 0) {
        browserSessions.append(element("p", "empty", "No active browser sessions."));
        return;
      }
      const body = document.createElement("tbody");
      for (const row of rows) {
        const action = element("td");
        if (row.current) {
          action.append(element("span", "tag", "Current session"));
        } else {
          const revoke = document.createElement("form");
          revoke.className = "cell-form";
          revoke.dataset.confirm = "Sign out this browser session?";
          revoke.append(csrfInput(), formButton("Sign out", "danger"));
          revoke.addEventListener("submit", (event) => {
            event.preventDefault();
            void mutateSession(revoke, `/api/v1/me/sessions/${encodeURIComponent(row.id)}`, "Browser-session request failed.", refreshAfterMutation);
          });
          action.append(revoke);
        }
        const created = element("time", "", row.created_at || "—");
        created.dateTime = row.created_at || "";
        const expires = element("time", "", row.expires_at || "—");
        expires.dateTime = row.expires_at || "";
        body.append(append(element("tr"), element("td", "session-agent", row.user_agent || "Unknown browser"), element("td", "", sessionMethod(row)), element("td", "", created), element("td", "", expires), action));
      }
      const table = append(document.createElement("table"), append(document.createElement("thead"), append(document.createElement("tr"), element("th", "", "Browser"), element("th", "", "Sign-in method"), element("th", "", "Created"), element("th", "", "Expires"), element("th", "", "Actions"))), body);
      browserSessions.append(scrollRegion("Browser sessions", table));
    };
    const renderConnections = (data, query) => {
      if (!(connections instanceof HTMLElement)) return;
      connections.replaceChildren();
      const rows = apiCollection(data, "connections", "live-connection directory");
      const heading = append(element("div", "panel-head"), append(
        element("div"),
        element("h2", "", own ? "Your live IRC connections" : "Live IRC connections"),
        element("p", "", "Newest connection IDs first. Each disconnect targets the immutable ID shown in this row."),
      ), element("span", "count", rows.length));
      connections.append(heading);
      if (rows.length === 0) {
        connections.append(element("p", "empty", query.has("nick") || query.has("account") || query.has("transport") || query.has("oper") ? "No live connection matches these exact filters." : "No connected IRC clients."));
      } else {
        const body = document.createElement("tbody");
        for (const row of rows) {
          const client = append(element("td"), append(element("strong"), element("code", "", row.nick)), row.oper ? element("span", "tag", "oper") : document.createTextNode(""), append(element("div", "meta"), element("code", "", `${row.user}@${row.host}`)));
          const account = row.account ? element("code", "", row.account) : element("span", "meta", "—");
          const connected = element("time", "", row.connected_at || "—");
          connected.dateTime = row.connected_at || "";
          const disconnect = document.createElement("form");
          disconnect.className = "cell-form";
          disconnect.dataset.confirm = `Disconnect connection ${row.id} (${row.nick})?`;
          const reason = document.createElement("input");
          reason.name = "reason";
          reason.maxLength = 300;
          reason.placeholder = "reason";
          disconnect.append(csrfInput(), reason, formButton("Disconnect", "danger"));
          disconnect.addEventListener("submit", (event) => {
            event.preventDefault();
            const value = reason.value.trim();
            const suffix = value ? `?reason=${encodeURIComponent(value)}` : "";
            void mutateSession(disconnect, `${apiPath}/${encodeURIComponent(row.id)}${suffix}`, "Disconnect request failed.", refreshAfterMutation);
          });
          body.append(append(element("tr"), element("td", "meta", row.id), client, append(element("td"), element("span", "tag", row.transport)), element("td", "", account), append(element("td"), connected, element("div", "meta", `${row.idle_seconds} seconds idle`)), element("td", "", row.channels.length ? element("code", "", row.channels.join(", ")) : element("span", "meta", "—")), append(element("td"), disconnect)));
        }
        const table = append(document.createElement("table"), append(document.createElement("thead"), append(document.createElement("tr"), element("th", "", "ID"), element("th", "", "Client"), element("th", "", "Transport"), element("th", "", "Account"), element("th", "", "Connected / idle"), element("th", "", "Channels"), element("th", "", "Actions"))), body);
        connections.append(scrollRegion("Live connections", table));
      }
      const pager = element("div", "pager");
      pager.append(element("span", "meta", query.has("before_id") ? "Showing an older page." : "Showing the newest matching connections."));
      if (typeof data.next_before_id === "string") {
        const next = new URLSearchParams(query);
        next.set("before_id", data.next_before_id);
        const older = document.createElement("a");
        older.href = `${pagePath}?${next}`;
        older.textContent = "Older connections";
        pager.append(older);
      }
      connections.append(pager);
    };
    if (filters instanceof HTMLFormElement) {
      const query = currentQuery();
      for (const input of filters.elements) {
        if ((input instanceof HTMLInputElement || input instanceof HTMLSelectElement) && input.name) input.value = query.get(input.name) || (input.name === "limit" ? "50" : "");
      }
    }
    if (clear instanceof HTMLAnchorElement) clear.href = pagePath;
    void refresh().catch((error) => {
      setSessionResult(error instanceof Error ? error.message : "Session data could not be loaded.", false);
    });
  }

  const accountResult = document.getElementById("account-api-result");
  const accountSecret = document.getElementById("account-api-secret");
  const setAccountResult = (message, success) => {
    if (!accountResult) return;
    accountResult.textContent = message;
    accountResult.className = success ? "banner-success" : "banner-error";
  };
  const accountLoadFailure = (error, retry) => {
    if (!accountResult) return;
    accountResult.replaceChildren(
      element("span", "", error instanceof Error ? error.message : "Account data failed to load."),
      retryButton(retry),
    );
    accountResult.className = "banner-error";
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

  const mutateAccount = (form, method, body, failure) => runFormSubmission(form, async () => {
    try {
      const result = await apiRequest(form, apiMutation(method, form.action), body);
      return result === undefined ? true : result;
    } catch (error) {
      setAccountResult(error instanceof Error ? error.message : failure, false);
      return undefined;
    }
  });

  let refreshAccountAccess;
  let refreshContactEmail;
  let refreshTokens;
  let profileReadRevision = 0;

  const accountRoot = document.querySelector("[data-api-account-read]");
  if (accountRoot instanceof HTMLElement) {
    const passwordPanel = accountRoot.querySelector("[data-api-account-password-panel]");
    const credentialRows = accountRoot.querySelector("[data-api-account-credential-list]");
    const identityList = accountRoot.querySelector("[data-api-account-identity-list]");
    const linkProviders = accountRoot.querySelector("[data-api-account-link-providers]");
    const csrf = accountRoot.dataset.csrf || "";
    const bindDelete = (form) => form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateAccount(form, "DELETE", undefined, "Account access change failed.")
        .then(async (result) => {
          if (result === undefined) return;
          try {
            await refreshAfterMutation(refreshAccountAccess);
            setAccountResult("Updated.", true);
          } catch (error) {
            setAccountResult(error instanceof Error ? error.message : "Account data failed to load.", false);
          }
        });
    });
    const renderPassword = (hasLocalPassword) => {
      if (!(passwordPanel instanceof HTMLElement)) return;
      const title = hasLocalPassword ? "Primary password" : "Add a local password";
      const description = hasLocalPassword
        ? "Used for local web sign-in, IRC identification, and authorizing new app passwords."
        : "This account currently signs in through OpenID Connect. Add a password to enable local web and IRC credential sign-in too.";
      const form = element("form", "field-grid");
      form.method = "post";
      form.action = "/api/v1/me/password";
      form.dataset.apiAccountPassword = "";
      const token = element("input"); token.type = "hidden"; token.name = "csrf"; token.value = csrf;
      form.append(token);
      const passwordField = (label, name, autocomplete) => {
        const field = element("label", "field");
        const input = element("input");
        input.type = "password"; input.name = name; input.maxLength = 512; input.autocomplete = autocomplete; input.required = true;
        append(field, element("span", "", label), input);
        return field;
      };
      if (hasLocalPassword) form.append(passwordField("Current password", "current_password", "current-password"));
      form.append(passwordField("New password", "new_password", "new-password"), passwordField("Confirm new password", "confirm_password", "new-password"));
      const actions = element("div", "field field-wide");
      append(actions, element("button", "primary", hasLocalPassword ? "Change password" : "Add password"));
      actions.querySelector("button").type = "submit";
      form.append(actions);
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        const fields = new FormData(form);
        const current = fieldValue(fields, "current_password");
        const next = fieldValue(fields, "new_password");
        if (next !== fieldValue(fields, "confirm_password")) {
          setAccountResult("The new password and confirmation do not match.", false);
          return;
        }
        const body = { new_password: next };
        if (current) body.current_password = current;
        void mutateAccount(form, "PUT", body, "Password update failed.")
          .then((result) => {
            if (result === undefined) return;
            setAccountResult(current ? "Local password changed." : "Local password added.", true);
            void apiRead("/api/v1/me/credentials").then((updated) => {
              const credentials = apiCollection(updated, "credentials", "credential directory");
              renderPassword(credentials.some((credential) => credential.kind === "local_password"));
              renderCredentials(credentials);
            }).catch(() => void refreshAccountAccess());
          });
      });
      passwordPanel.replaceChildren(append(element("div", "panel-head"), append(element("div"), element("h2", "", title), element("p", "", description)), element("span", "tag", "Argon2id")), form);
    };
    const renderCredentials = (credentials) => {
      if (!(credentialRows instanceof HTMLElement)) return;
      credentialRows.replaceChildren();
      const count = accountRoot.querySelector("[data-api-account-credential-count]");
      if (count) count.textContent = String(credentials.length);
      if (!credentials.length) {
        const cell = element("td", "empty", "No account credentials."); cell.colSpan = 5;
        credentialRows.append(append(element("tr"), cell));
        return;
      }
      for (const credential of credentials) {
        const row = element("tr");
        const label = credential.label || (credential.kind === "local_password" ? "Primary password" : "");
        append(row, append(element("td"), element("span", "tag", credential.kind)), element("td", "", label), element("td", "", credential.created_at), element("td", "", credential.last_used_at || "Never"));
        const actions = element("td");
        if (credential.kind === "app_password") {
          const form = element("form", "cell-form"); form.method = "post"; form.action = `/api/v1/me/credentials/${encodeURIComponent(credential.id)}`; form.dataset.confirm = "Revoke this app password?";
          const token = element("input"); token.type = "hidden"; token.name = "csrf"; token.value = csrf;
          const button = element("button", "danger", "Revoke"); button.type = "submit";
          form.append(token, button); bindDelete(form); actions.append(form);
        } else actions.append(element("span", "meta", "Primary"));
        row.append(actions); credentialRows.append(row);
      }
    };
    const renderIdentities = (result, hasLocalPassword) => {
      if (!(identityList instanceof HTMLElement) || !(linkProviders instanceof HTMLElement)) return;
      const identities = apiCollection(result, "identities", "identity directory");
      const providers = apiCollection(result, "link_providers", "identity-provider directory");
      const count = accountRoot.querySelector("[data-api-account-identity-count]");
      if (count) count.textContent = String(identities.length);
      linkProviders.replaceChildren();
      if (providers.length) {
        const actions = element("div", "provider-actions");
        for (const provider of providers) {
          const link = element("a", "button-link secondary-link", `Link ${provider}`);
          link.href = `/api/v1/auth/oidc/${encodeURIComponent(provider)}/link`;
          actions.append(link);
        }
        linkProviders.append(actions);
      } else linkProviders.append(element("p", "section-note", "No login providers are currently configured."));
      identityList.replaceChildren();
      if (!identities.length) {
        identityList.append(element("p", "empty", hasLocalPassword ? "No linked single sign-on identities. Local password sign-in remains available." : "No login method is configured for this account."));
        return;
      }
      for (const identity of identities) {
        const card = element("article");
        const copy = element("div"); append(copy, element("strong", "", identity.issuer), element("code", "", identity.subject), element("small", "", `Linked ${identity.created_at}`));
        card.append(copy);
        if (identities.length > 1 || hasLocalPassword) {
          const form = element("form"); form.method = "post"; form.action = `/api/v1/me/identities/${encodeURIComponent(identity.id)}`; form.dataset.confirm = "Unlink this identity and revoke its browser sessions?";
          const token = element("input"); token.type = "hidden"; token.name = "csrf"; token.value = csrf;
          const button = element("button", "danger", "Unlink"); button.type = "submit";
          form.append(token, button); bindDelete(form); card.append(form);
        } else card.append(element("span", "tag", "Last login method"));
        identityList.append(card);
      }
    };
    refreshAccountAccess = async () => {
      try {
        const [credentialResult, identityResult] = await Promise.all([
          apiRead("/api/v1/me/credentials"),
          apiRead("/api/v1/me/identities"),
        ]);
        const credentials = apiCollection(credentialResult, "credentials", "credential directory");
        const hasLocalPassword = credentials.some((credential) => credential.kind === "local_password");
        renderPassword(hasLocalPassword); renderCredentials(credentials); renderIdentities(identityResult, hasLocalPassword);
      } catch (error) {
        if (passwordPanel instanceof HTMLElement) listLoadFailure(passwordPanel, error, () => void refreshAccountAccess());
        if (credentialRows instanceof HTMLElement) tableLoadFailure(credentialRows, 5, error, () => void refreshAccountAccess());
        if (identityList instanceof HTMLElement) listLoadFailure(identityList, error, () => void refreshAccountAccess());
        if (linkProviders instanceof HTMLElement) linkProviders.replaceChildren();
        return false;
      }
      return true;
    };
    void refreshAccountAccess();
  }

  for (const form of document.querySelectorAll("[data-api-account-profile]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      profileReadRevision += 1;
      const email = fieldValue(new FormData(form), "contact_email");
      void mutateAccount(form, "PATCH", { contact_email: email || null }, "Profile update failed.")
        .then(async (result) => {
          if (result === undefined) return;
          try {
            await refreshAfterMutation(refreshContactEmail);
            setAccountResult("Profile updated.", true);
          } catch (error) {
            setAccountResult(error instanceof Error ? error.message : "Profile data failed to load.", false);
          }
        });
    });
  }

  const accountContactEmail = document.querySelector("[data-api-account-contact-email]");
  if (accountContactEmail instanceof HTMLInputElement) {
    const form = accountContactEmail.form;
    if (form instanceof HTMLFormElement) preserveFormEdits(form);
    refreshContactEmail = async () => {
      const revision = ++profileReadRevision;
      try {
        const profile = await apiRead("/api/v1/me/profile");
        if (revision !== profileReadRevision) return true;
        if (accountContactEmail.dataset.apiEdited !== "true") {
          accountContactEmail.value = profile.contact_email ?? "";
        }
      } catch (error) {
        if (revision !== profileReadRevision) return true;
        accountLoadFailure(error, () => void refreshContactEmail());
        return false;
      }
      return true;
    };
    void refreshContactEmail();
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
          if (result !== undefined) setAccountResult(current ? "Local password changed." : "Local password added.", true);
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
          if (result === undefined) return;
          showAccountSecret("App password", result.app_password);
          setAccountResult("App password created. Copy it now; it cannot be shown again.", true);
          void refreshAccountAccess?.();
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
        if (result === undefined) return;
        showAccountSecret("Personal access token", result.token);
        setAccountResult("Personal access token created. Copy it now; it cannot be shown again.", true);
        void refreshTokens?.();
      });
    });
  }

  const accountTokenRows = document.querySelector("[data-api-account-token-list]");
  if (accountTokenRows instanceof HTMLElement) {
    refreshTokens = async () => {
      try {
        const result = await apiRead("/api/v1/me/tokens");
        const tokens = apiCollection(result, "tokens", "token directory");
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
          return true;
        }
        for (const token of tokens) {
          const row = document.createElement("tr");
          const scopes = token.scopes.join(", ");
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
      } catch (error) {
        tableLoadFailure(accountTokenRows, 5, error, () => void refreshTokens());
        return false;
      }
      return true;
    };
    void refreshTokens();
  }

  for (const form of document.querySelectorAll("[data-api-account-delete]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void mutateAccount(form, "DELETE", undefined, "Account access change failed.")
        .then(async (result) => {
          if (result === undefined) return;
          try {
            await refreshAfterMutation(refreshTokens);
            setAccountResult("Token revoked.", true);
          } catch (error) {
            setAccountResult(error instanceof Error ? error.message : "Token directory failed to load.", false);
          }
        });
    });
  }

  for (const form of document.querySelectorAll("[data-api-account-delete-self]")) {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const confirmation = fieldValue(new FormData(form), "confirmation");
      void mutateAccount(form, "DELETE", { confirmation }, "Account deletion failed.")
        .then((result) => { if (result !== undefined) window.location.assign("/auth/signed-out"); });
    });
  }

  const accountSecurityActivityRows = document.querySelector("[data-api-account-security-activity-list]");
  if (accountSecurityActivityRows instanceof HTMLElement) {
    const refreshSecurityActivity = async () => {
      try {
        const result = await apiRead("/api/v1/me/security-activity?limit=50");
        const activity = apiCollection(result, "activity", "security-activity directory");
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
      } catch (error) {
        tableLoadFailure(accountSecurityActivityRows, 5, error, () => void refreshSecurityActivity());
      }
    };
    void refreshSecurityActivity();
  }

  const accountReadMarkers = document.querySelector("[data-api-account-read-marker-list]");
  if (accountReadMarkers instanceof HTMLElement) {
    const refreshReadMarkers = async () => {
      try {
        const result = await apiRead("/api/v1/me/read-markers");
        const markers = apiCollection(result, "markers", "read-marker directory");
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
      } catch (error) {
        listLoadFailure(accountReadMarkers, error, () => void refreshReadMarkers());
      }
    };
    void refreshReadMarkers();
  }

  const adminAccountResult = document.getElementById("admin-account-api-result");
  const adminAccountSecret = document.getElementById("admin-account-api-secret");
  let refreshAdminAccounts;
  const setAdminAccountResult = (message, success) => {
    if (!adminAccountResult) return;
    adminAccountResult.textContent = message;
    adminAccountResult.className = success ? "banner-success" : "banner-error";
  };
  const mutateAdminAccount = (form, method, body, failure) => runFormSubmission(form, async () => {
    try {
      return await apiRequest(form, apiMutation(method, form.action), body);
    } catch (error) {
      setAdminAccountResult(error instanceof Error ? error.message : failure, false);
      return undefined;
    }
  });
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
  const refreshAdminAccountDirectory = async (result, success) => {
    if (result === undefined) return;
    try {
      await refreshAfterMutation(refreshAdminAccounts);
      setAdminAccountResult(success, true);
    } catch (error) {
      setAdminAccountResult(error instanceof Error ? error.message : "Account directory failed to load.", false);
    }
  };
  for (const form of document.querySelectorAll("[data-api-admin-account-create]")) form.addEventListener("submit", (event) => { event.preventDefault(); const fields = new FormData(form); void mutateAdminAccount(form, "POST", { account: fieldValue(fields, "account"), password: String(fields.get("password") || ""), contact_email: optionalValue(String(fields.get("contact_email") || "")), administrator: fields.has("administrator") }, "Account creation failed.").then((result) => refreshAdminAccountDirectory(result, "Account created.")); });
  for (const form of document.querySelectorAll("[data-api-admin-invitation-create]")) form.addEventListener("submit", (event) => { event.preventDefault(); const fields = new FormData(form); void mutateAdminAccount(form, "POST", { account: fieldValue(fields, "account"), contact_email: optionalValue(String(fields.get("contact_email") || "")), expires_in_days: Number(fields.get("expires_in_days")), administrator: fields.has("administrator") }, "Invitation creation failed.").then(async (result) => { if (!result) return; showInvitationSecret(result.invitation_url); try { await refreshAfterMutation(refreshAdminAccounts); setAdminAccountResult("Invitation issued. Copy the link now; it cannot be shown again.", true); } catch (error) { setAdminAccountResult(error instanceof Error ? error.message : "Invitation directory failed to load.", false); } }); });
  document.addEventListener("submit", (event) => { const form = event.target; if (!(form instanceof HTMLFormElement)) return; if (form.matches("[data-api-admin-invitation-delete]")) { event.preventDefault(); void mutateAdminAccount(form, "DELETE", undefined, "Invitation revocation failed.").then((result) => refreshAdminAccountDirectory(result, "Invitation revoked.")); } else if (form.matches("[data-api-admin-account-state]")) { event.preventDefault(); const fields = new FormData(form); const key = form.dataset.apiAdminAccountState === "suspension" ? "suspended" : "administrator"; void mutateAdminAccount(form, "PATCH", { [key]: fieldValue(fields, key) === "true" }, "Account state change failed.").then((result) => refreshAdminAccountDirectory(result, "Account state updated.")); } else if (form.matches("[data-api-admin-account-delete]")) { event.preventDefault(); void mutateAdminAccount(form, "DELETE", { confirmation: fieldValue(new FormData(form), "confirmation") }, "Account deletion failed.").then((result) => refreshAdminAccountDirectory(result, "Account deleted.")); } });

  const adminAccountsPage = document.querySelector("[data-api-admin-accounts-page]");
  if (adminAccountsPage instanceof HTMLElement) {
    const csrf = adminAccountsPage.dataset.csrf || "";
    const invitationHost = adminAccountsPage.querySelector("[data-api-admin-invitations]");
    const accountHost = adminAccountsPage.querySelector("[data-api-admin-accounts]");
    const filters = adminAccountsPage.querySelector("[data-api-admin-accounts-filter]");
    const capability = () => { const input = document.createElement("input"); input.type = "hidden"; input.name = "csrf"; input.value = csrf; return input; };
    const button = (text, className) => { const node = element("button", className, text); node.type = "submit"; return node; };
    const query = () => { const params = new URLSearchParams(window.location.search); if (!params.get("limit")) params.set("limit", "50"); return params; };
    const pager = (text, cursor, parameter) => { const wrapper = element("div", "pager"); wrapper.append(element("span", "meta", cursor ? "Showing an older page." : "Showing the newest page.")); if (cursor) { const link = element("a", "", text); const params = query(); params.set(parameter, String(cursor)); link.href = `/console/accounts?${params}`; wrapper.append(link); } return wrapper; };
    const renderInvitations = (data) => {
      if (!(invitationHost instanceof HTMLElement)) return; invitationHost.replaceChildren(); const rows = apiCollection(data, "invitations", "invitation directory");
      if (!rows.length) invitationHost.append(element("p", "empty", "No pending invitations.")); else { const table = document.createElement("table"); table.append(element("caption", "sr-only", "Pending account invitations")); const head = document.createElement("thead"); head.append(append(element("tr"), element("th", "", "Account"), element("th", "", "Contact"), element("th", "", "Authority"), element("th", "", "Issued by"), element("th", "", "Expires (UTC)"), element("th", "", "Actions"))); const body = document.createElement("tbody"); for (const invitation of rows) { const revoke = document.createElement("form"); revoke.className = "cell-form"; revoke.dataset.apiAdminInvitationDelete = ""; revoke.dataset.confirm = `Revoke the invitation for ${invitation.account}?`; revoke.action = `/api/v1/admin/invitations/${encodeURIComponent(invitation.id)}`; revoke.append(capability(), button("Revoke", "danger")); const expires = element("time", "", invitation.expires_at); expires.dateTime = invitation.expires_at; body.append(append(element("tr"), append(element("td"), append(element("strong"), element("code", "", invitation.account))), element("td", "", invitation.contact_email || "Not supplied"), element("td", "", invitation.administrator ? "administrator" : "member"), append(element("td"), element("code", "", invitation.created_by)), append(element("td"), expires), append(element("td"), revoke))); } table.append(head, body); invitationHost.append(scrollRegion("Pending account invitations", table)); } invitationHost.append(pager("Older invitations", data.next_before_id, "invitation_before_id"));
    };
    const renderAccounts = (data) => {
      if (!(accountHost instanceof HTMLElement)) return; accountHost.replaceChildren(); const rows = apiCollection(data, "accounts", "account directory");
      const section = append(element("div", "panel-head"), append(element("div"), element("h2", "", "Accounts"), element("p", "", "Only active browser sessions and unexpired personal access tokens are counted.")), element("span", "count", rows.length)); accountHost.append(section);
      if (!rows.length) accountHost.append(element("p", "empty", "No account matches this exact name.")); else { const table = document.createElement("table"); table.append(element("caption", "sr-only", "Account directory")); const head = document.createElement("thead"); head.append(append(element("tr"), element("th", "", "ID"), element("th", "", "Account"), element("th", "", "Created (UTC)"), element("th", "", "Login methods"), element("th", "", "Status"), element("th", "", "Active access"), element("th", "", "Resources"), element("th"))); const body = document.createElement("tbody"); for (const account of rows) { const auth = account.authentication; const resources = account.resources; const sources = account.administrator_sources; const actions = element("td"); if (account.current) actions.append(element("span", "meta", "Current account")); else { for (const [key, value, label, confirmation] of [["suspension", !account.suspended, account.suspended ? "Reactivate" : "Suspend", account.suspended ? `Reactivate ${account.name} and restart its enabled networks?` : `Suspend ${account.name}, revoke its sessions and tokens, disconnect its clients, and stop its networks?`], ["administrator", !sources.durable, sources.durable ? "Revoke durable admin" : "Grant durable admin", sources.durable ? `Remove durable administrator authority from ${account.name}?` : `Grant durable administrator authority to ${account.name}?`]]) { const form = document.createElement("form"); form.className = "cell-form"; form.dataset.apiAdminAccountState = key; form.dataset.confirm = confirmation; form.action = `/api/v1/admin/accounts/${encodeURIComponent(account.id)}`; const state = document.createElement("input"); state.type = "hidden"; state.name = key === "suspension" ? "suspended" : "administrator"; state.value = String(value); form.append(capability(), state, button(label, value ? "" : "danger")); actions.append(form); } const deletion = document.createElement("form"); deletion.className = "cell-form account-delete-form"; deletion.dataset.apiAdminAccountDelete = ""; deletion.dataset.confirm = `Permanently delete ${account.name}, revoke every credential and session, erase its private history, stop its networks, and retire the account name? This cannot be undone.`; deletion.action = `/api/v1/admin/accounts/${encodeURIComponent(account.id)}`; const confirmation = document.createElement("input"); confirmation.name = "confirmation"; confirmation.autocomplete = "off"; confirmation.required = true; const deletionLabel = append(element("label", "field"), element("span", "", `Type ${account.name} to delete`), confirmation); deletion.append(capability(), deletionLabel, button("Delete permanently", "danger")); actions.append(deletion); } const created = element("time", "", account.created_at); created.dateTime = account.created_at; const loginMethods = `${auth.local_password ? "local password · " : ""}${auth.oidc_identities} OIDC · ${auth.app_passwords} app passwords`; const status = `${account.suspended ? "suspended" : "active"}${account.administrator ? " · administrator" : ""}${sources.durable ? " · durable grant" : ""}${sources.configuration ? " · configuration grant" : ""}`; body.append(append(element("tr"), element("td", "meta", account.id), append(element("td"), append(element("strong"), element("code", "", account.name))), append(element("td", "meta"), created), element("td", "", loginMethods), element("td", "", status), element("td", "", `${auth.browser_sessions} browsers · ${auth.api_tokens} API tokens`), element("td", "", `${resources.networks} networks · ${resources.founded_channels} channels`), actions)); } table.append(head, body); accountHost.append(scrollRegion("Account directory", table)); } accountHost.append(pager("Older accounts", data.next_before_id, "before_id")); accountHost.append(element("p", "section-note", "An account that founded registered channels cannot be deleted. Transfer or drop those channels first. Deleted account names remain permanently retired so old credentials and identity links can never resolve to a different person."));
    };
    refreshAdminAccounts = async () => { const params = query(); const invitations = new URLSearchParams(); invitations.set("limit", params.get("limit") || "50"); if (params.get("invitation_before_id")) invitations.set("before_id", params.get("invitation_before_id")); const [accounts, invitationData] = await Promise.all([apiRead(`/api/v1/admin/accounts?${params}`), apiRead(`/api/v1/admin/invitations?${invitations}`)]); renderAccounts(accounts); renderInvitations(invitationData); };
    if (filters instanceof HTMLFormElement) for (const input of filters.elements) if ((input instanceof HTMLInputElement || input instanceof HTMLSelectElement) && input.name) input.value = new URLSearchParams(window.location.search).get(input.name) || (input.name === "limit" ? "50" : "");
    void refreshAdminAccounts().catch((error) => setAdminAccountResult(error instanceof Error ? error.message : "Account directory failed to load.", false));
  }

  const adminNetworkResult = document.getElementById("admin-network-api-result");
  const adminNetworkRows = document.querySelector("[data-api-admin-network-list]");
  let refreshAdminNetworks;
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
      const runtime = network.runtime;
      const cells = [runtime === null ? (network.enabled ? "not running" : "disabled") : runtime.state, network.owner, network.name, network.kind, network.shared === true ? "Managed configuration" : network.addr, runtime === null ? 0 : runtime.attached_clients, runtime === null ? 0 : runtime.errors, runtime?.last_error?.summary ?? "—"];
      cells.forEach((value, index) => { const cell = document.createElement("td"); cell.textContent = String(value); if (index === 0) { const dot = document.createElement("span"); dot.className = `dot ${network.connected ? "on" : "off"}`; cell.prepend(dot); } if (index === 4 && network.tls) { const tls = document.createElement("span"); tls.className = "tag"; tls.textContent = "TLS"; cell.append(" ", tls); } row.append(cell); });
      const actions = document.createElement("td");
      actions.className = "row-actions";
      if (network.shared === true) actions.textContent = "Managed configuration";
      else {
        const form = document.createElement("form");
        form.method = "post";
        form.action = `/api/v1/admin/networks/${encodeURIComponent(network.owner)}/${encodeURIComponent(network.name)}`;
        form.dataset.apiAdminNetworkToggle = "";
        const csrf = document.createElement("input"); csrf.type = "hidden"; csrf.name = "csrf"; csrf.value = adminNetworkRows.dataset.csrf || "";
        const enabled = document.createElement("input"); enabled.type = "hidden"; enabled.name = "enabled"; enabled.value = network.enabled ? "false" : "true";
        const button = document.createElement("button"); button.type = "submit"; button.textContent = network.enabled ? "Disable" : "Enable";
        form.append(csrf, enabled, button); actions.append(form);
      }
      row.append(actions); adminNetworkRows.append(row);
    }
  };
  if (adminNetworkRows instanceof HTMLElement) {
    refreshAdminNetworks = async () => {
      try {
        const result = await apiRead("/api/v1/admin/networks");
        renderAdminNetworks(apiCollection(result, "networks", "network directory"));
      } catch (error) {
        tableLoadFailure(adminNetworkRows, 9, error, () => void refreshAdminNetworks());
        return false;
      }
      return true;
    };
    void refreshAdminNetworks();
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
    void runFormSubmission(form, async () => {
      try {
        await apiRequest(form, apiMutation("PATCH", form.action), { enabled: enabled === "true" });
        await refreshAfterMutation(refreshAdminNetworks);
        if (!adminNetworkResult) return;
        adminNetworkResult.textContent = "Network state updated.";
        adminNetworkResult.className = "banner-success";
      } catch (error) {
        if (!adminNetworkResult) return;
        adminNetworkResult.textContent = error instanceof Error ? error.message : "Network lifecycle change failed.";
        adminNetworkResult.className = "banner-error";
      }
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
      const runtime = network.runtime;
      const enabled = network.enabled;
      const connected = network.connected;
      const state = !enabled
        ? "disabled"
        : runtime === null ? "not running" : runtime.state.replaceAll("_", " ");
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
      address.textContent = network.shared === true ? "" : network.addr;
      upstream.append(address);
      if (network.tls === true) {
        const tls = document.createElement("span");
        tls.className = "tag";
        tls.textContent = "TLS";
        upstream.append(document.createTextNode(" "), tls);
      }
      const clients = networkCell(runtime === null ? 0 : runtime.attached_clients);
      const errors = networkCell(runtime === null ? 0 : runtime.errors);
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
  const renderOwnerNetworkFailure = (error, retry) => {
    if (!(ownerNetworkRows instanceof HTMLElement)) return;
    const table = ownerNetworkRows.querySelector("table");
    const previous = table?.querySelector("tbody");
    if (!(table instanceof HTMLTableElement) || !(previous instanceof HTMLTableSectionElement)) return;
    if (ownerNetworkCount) ownerNetworkCount.textContent = "—";
    tableLoadFailure(previous, 7, error, retry);
  };
  let refreshOwnerNetworks;
  const refreshOwnerNetworksNow = async () => {
    if (!(ownerNetworkRows instanceof HTMLElement)) return;
    ownerNetworkRows.setAttribute("aria-busy", "true");
    if (ownerNetworkRefreshStatus) {
      ownerNetworkRefreshStatus.textContent = "Refreshing…";
      ownerNetworkRefreshStatus.classList.remove("refresh-error");
    }
    try {
      const result = await apiRead("/api/v1/me/networks");
      renderOwnerNetworks(apiCollection(result, "networks", "network directory"));
      if (ownerNetworkRefreshStatus) ownerNetworkRefreshStatus.textContent = "Live data refreshed.";
      return true;
    } catch (error) {
      renderOwnerNetworkFailure(error, () => { if (refreshOwnerNetworks) void refreshOwnerNetworks(true); });
      if (ownerNetworkRefreshStatus) {
        ownerNetworkRefreshStatus.textContent = "Live refresh failed. Retry is available in the network list.";
        ownerNetworkRefreshStatus.classList.add("refresh-error");
      }
      return false;
    } finally {
      ownerNetworkRows.removeAttribute("aria-busy");
    }
  };
  if (ownerNetworkRows instanceof HTMLElement) {
    refreshOwnerNetworks = serializeRefresh(
      refreshOwnerNetworksNow,
      () => {
        if (ownerNetworkRefreshStatus) ownerNetworkRefreshStatus.textContent = "Refresh queued.";
      },
    );
    void refreshOwnerNetworks();
    const seconds = Number(ownerNetworkRows.dataset.refreshSeconds);
    if (Number.isFinite(seconds) && seconds >= 5) {
      window.setInterval(() => { void refreshOwnerNetworks(); }, seconds * 1000);
    }
  }

  let refreshOwnerNetworkEditor;
  let refreshOwnerBridgeEditor;
  let refreshOwnerNetworkDetail;
  let refreshIntegrations;
  const ownerNetworkPreflight = Symbol("owner-network-preflight");
  const ownerNetworkRefresher = (form) => {
    if (form.closest("[data-api-owner-network-editor]")) return refreshOwnerNetworkEditor;
    if (form.closest("[data-api-owner-bridge-editor]")) return refreshOwnerBridgeEditor;
    if (form.closest("[data-api-owner-network-detail]")) return refreshOwnerNetworkDetail;
    if (form.closest("[data-api-integrations]")) return refreshIntegrations;
    return refreshOwnerNetworks;
  };

  const mutateOwnerNetwork = (
    form,
    url,
    method,
    body,
    mode,
    trigger = form.querySelector('button[type="submit"]'),
  ) => runFormSubmission(form, async () => {
    try {
      const result = await apiRequest(form, apiMutation(method, url), body);
      if (mode === ownerNetworkPreflight) {
        setOwnerNetworkResult(
          `Registered as ${result.confirmed_nick}. Joined ${result.joined_channels.length} configured channel${result.joined_channels.length === 1 ? "" : "s"}. Resolved ${result.resolved_addresses} address${result.resolved_addresses === 1 ? "" : "es"}; DNS ${result.dns_ms}ms, connection ${result.connect_ms}ms, registration ${result.registration_ms}ms. No network was created.`,
          true,
        );
      } else {
        await refreshAfterMutation(ownerNetworkRefresher(form));
        setOwnerNetworkResult("Updated.", true);
      }
      return result;
    } catch (error) {
      setOwnerNetworkResult(error instanceof Error ? error.message : "Network request failed.", false);
      return undefined;
    }
  }, trigger);

  const ownerNetworkConnection = (fields) => ({
    addr: fieldValue(fields, "addr"),
    tls: fields.has("tls"),
    nick: fieldValue(fields, "nick"),
    realname: fieldValue(fields, "realname"),
    autojoin: splitValues(String(fields.get("autojoin") || ""), ","),
    sasl_account: optionalValue(String(fields.get("sasl_account") || "")),
    sasl_password: optionalValue(String(fields.get("sasl_password") || "")),
  });

  for (const form of document.querySelectorAll("[data-api-owner-network-create]")) {
    const preflightButton = form.querySelector("[data-api-network-preflight]");
    const addButton = form.querySelector('[type="submit"]');
    let qualifiedConnection = null;
    const connectionFingerprint = () => JSON.stringify(ownerNetworkConnection(new FormData(form)));
    if (addButton instanceof HTMLButtonElement) addButton.disabled = true;
    form.addEventListener("input", (event) => {
      if (event.target instanceof HTMLInputElement && event.target.name === "name") return;
      qualifiedConnection = null;
      if (addButton instanceof HTMLButtonElement) addButton.disabled = true;
    });
    if (preflightButton) {
      preflightButton.addEventListener("click", () => {
        const fields = new FormData(form);
        const connection = ownerNetworkConnection(fields);
        if (!connection.addr || !connection.nick || !connection.realname) {
          setOwnerNetworkResult("Enter a server, nickname, and real name.", false);
          return;
        }
        const { addr, tls, nick, realname, autojoin, sasl_account, sasl_password } = connection;
        const fingerprint = connectionFingerprint();
        void mutateOwnerNetwork(form, "/api/v1/me/networks/preflight", "POST", {
          addr, tls, nick, realname, autojoin, sasl_account, sasl_password,
        }, ownerNetworkPreflight, preflightButton).then((result) => {
          if (!result || connectionFingerprint() !== fingerprint) return;
          qualifiedConnection = fingerprint;
          if (addButton instanceof HTMLButtonElement) addButton.disabled = false;
        });
      });
    }
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(form);
      const name = fieldValue(fields, "name");
      const connection = ownerNetworkConnection(fields);
      if (!name || !connection.addr || !connection.nick || !connection.realname) {
        setOwnerNetworkResult("Enter a network ID, server, nickname, and real name.", false);
        return;
      }
      if (qualifiedConnection !== connectionFingerprint()) {
        setOwnerNetworkResult("Test this exact connection before adding it.", false);
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
      const base = { kind, name, addr: fieldValue(fields, "addr"), tls: true, autojoin: splitValues(String(fields.get("autojoin") || ""), ","), sasl_password: password };
      const body = kind === "matrix"
        ? { ...base, nick: fieldValue(fields, "nick") }
        : kind === "slack"
          ? { ...base, sasl_account: fieldValue(fields, "sasl_account") }
          : base;
      void mutateOwnerNetwork(form, form.action, "POST", body);
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
      realname: bridge ? null : fieldValue(fields, "realname"),
      autojoin: splitValues(String(fields.get("autojoin") || ""), ","), credentials,
    };
    if (!bridge && (!body.addr || !body.nick || !body.realname)) {
      throw new Error("Enter the server, nickname, and real name.");
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

  const integrations = document.querySelector("[data-api-integrations]");
  if (integrations instanceof HTMLElement) {
    const account = integrations.dataset.account || "";
    const csrf = integrations.dataset.csrf || "";
    const render = (networks) => {
      for (const kind of ["matrix", "discord", "slack"]) {
        const target = integrations.querySelector(`[data-integration-list="${kind}"]`);
        const count = integrations.querySelector(`[data-integration-count="${kind}"]`);
        if (!(target instanceof HTMLElement)) continue;
        const entries = networks.filter((network) => network.kind === kind);
        if (count) count.textContent = String(entries.length);
        target.replaceChildren();
        if (!entries.length) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = `No ${kind} bridges configured.`; target.append(empty); continue; }
        const table = document.createElement("table"); table.innerHTML = "<thead><tr><th>Status</th><th>Network</th><th>Owner</th><th>Actions</th></tr></thead>";
        const body = document.createElement("tbody");
        for (const network of entries) {
          const row = document.createElement("tr"); const runtime = network.runtime;
          const status = document.createElement("td"); const dot = document.createElement("span"); dot.className = `dot ${network.connected ? "on" : "off"}`; status.append(dot, String(runtime === null ? (network.enabled ? "not running" : "disabled") : runtime.state));
          const name = document.createElement("td"); const code = document.createElement("code"); code.textContent = network.name; name.append(code);
          const owner = document.createElement("td"); const ownerCode = document.createElement("code"); ownerCode.textContent = network.owner; owner.append(ownerCode);
          const actions = document.createElement("td"); actions.className = "row-actions";
          if (network.owner === account && network.shared !== true) {
            for (const [label, href] of [["Inspect", `/console/networks/${encodeURIComponent(network.name)}`], ["Edit", `/console/integrations/${encodeURIComponent(network.name)}/edit`]]) { const link = document.createElement("a"); link.className = "rowlink"; link.href = href; link.textContent = label; actions.append(link); }
            const toggle = document.createElement("form"); toggle.method = "post"; toggle.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`; toggle.dataset.apiOwnerNetworkToggle = ""; const token = document.createElement("input"); token.type = "hidden"; token.name = "csrf"; token.value = csrf; const enabled = document.createElement("input"); enabled.type = "hidden"; enabled.name = "enabled"; enabled.value = network.enabled ? "false" : "true"; const button = document.createElement("button"); button.type = "submit"; button.textContent = network.enabled ? "Disable" : "Enable"; toggle.append(token, enabled, button); actions.append(toggle);
            const remove = document.createElement("form"); remove.method = "post"; remove.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`; remove.dataset.apiOwnerNetworkDelete = ""; remove.dataset.confirm = `Remove bridge ${network.name}? Its stored backlog will also be deleted.`; const removeToken = document.createElement("input"); removeToken.type = "hidden"; removeToken.name = "csrf"; removeToken.value = csrf; const removeButton = document.createElement("button"); removeButton.type = "submit"; removeButton.className = "danger"; removeButton.textContent = "Remove"; remove.append(removeToken, removeButton); actions.append(remove);
          } else actions.textContent = `Managed by ${network.owner}`;
          row.append(status, name, owner, actions); body.append(row);
        }
        table.append(body); target.append(table);
      }
    };
    refreshIntegrations = async () => {
      try {
        const result = await apiRead("/api/v1/admin/networks");
        render(apiCollection(result, "networks", "integration directory"));
      } catch (error) {
        integrations.querySelectorAll("[data-integration-list]").forEach((target) => {
          if (target instanceof HTMLElement) listLoadFailure(target, error, () => void refreshIntegrations());
        });
        return false;
      }
      return true;
    };
    void refreshIntegrations();
  }

  const ownerNetworkEditor = document.querySelector("[data-api-owner-network-editor]");
  if (ownerNetworkEditor instanceof HTMLElement) {
    const name = ownerNetworkEditor.dataset.networkName || "";
    const form = ownerNetworkEditor.querySelector("[data-api-owner-network-update]");
    const showFailure = (error, retry) => {
      if (!(ownerNetworkResult instanceof HTMLElement)) return;
      ownerNetworkResult.replaceChildren(element("span", "", error instanceof Error ? error.message : "Network configuration failed to load."), retryButton(retry));
      ownerNetworkResult.className = "banner-error";
    };
    if (form instanceof HTMLFormElement) preserveFormEdits(form);
    const render = (network) => {
      if (network.kind !== "irc") { window.location.replace("/console/networks"); return; }
      if (ownerNetworkResult instanceof HTMLElement) { ownerNetworkResult.replaceChildren(); ownerNetworkResult.className = ""; }
      hydrateTextInput(form, "addr", network.addr); hydrateTextInput(form, "nick", network.nick); hydrateTextInput(form, "realname", network.realname ?? ""); hydrateTextInput(form, "autojoin", network.autojoin.join(", ")); hydrateTextInput(form, "sasl_account", network.sasl_account ?? "");
      hydrateCheckbox(form, "tls", network.tls);
      form.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`;
      const title = ownerNetworkEditor.querySelector("[data-network-editor-title]"); if (title) title.textContent = `Edit ${network.name}`;
      form.hidden = false;
    };
    refreshOwnerNetworkEditor = async () => {
      try {
        render(await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}`));
      } catch (error) {
        showFailure(error, () => void refreshOwnerNetworkEditor());
        return false;
      }
      return true;
    };
    if (!name || !(form instanceof HTMLFormElement)) setOwnerNetworkResult("This network editor has no resource ID. Return to the network directory and try again.", false); else void refreshOwnerNetworkEditor();
  }

  const ownerBridgeEditor = document.querySelector("[data-api-owner-bridge-editor]");
  if (ownerBridgeEditor instanceof HTMLElement) {
    const name = ownerBridgeEditor.dataset.networkName || "";
    const form = ownerBridgeEditor.querySelector("[data-api-owner-bridge-update]");
    if (!name || !(form instanceof HTMLFormElement)) setOwnerNetworkResult("This bridge editor has no resource ID. Return to integrations and try again.", false); else {
      preserveFormEdits(form);
      const render = (network) => {
        if (!["matrix", "discord", "slack"].includes(network.kind)) { window.location.replace("/console/integrations"); return; }
        hydrateTextInput(form, "addr", network.addr); hydrateTextInput(form, "nick", network.nick); hydrateTextInput(form, "autojoin", network.autojoin.join(", "));
        const nick = ownerBridgeEditor.querySelector("[data-bridge-nick]"); if (nick instanceof HTMLElement) nick.hidden = !network.nick;
        const account = ownerBridgeEditor.querySelector("[data-bridge-account]"); if (account instanceof HTMLElement) account.hidden = network.kind !== "slack";
        const accountStatus = ownerBridgeEditor.querySelector("[data-bridge-account-status]"); if (accountStatus) accountStatus.textContent = network.has_sasl_account === true ? "A token is stored. Leave blank to keep it." : "No token is stored; enter one before saving.";
        const kind = ownerBridgeEditor.querySelector("[data-bridge-kind]"); if (kind) kind.textContent = `${network.kind} bridge`;
        const title = ownerBridgeEditor.querySelector("[data-bridge-editor-title]"); if (title) title.textContent = `Edit ${network.name}`;
        const credential = ownerBridgeEditor.querySelector("[data-bridge-credential]"); if (credential) credential.textContent = network.has_sasl_password === true ? "A credential is stored. Leave blank to keep it." : "No credential is stored; enter one before saving.";
        form.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`; form.hidden = false;
      };
      refreshOwnerBridgeEditor = async () => {
        try {
          render(await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}`));
        } catch (error) {
          setOwnerNetworkResult(error instanceof Error ? error.message : "Bridge configuration failed to load.", false);
          return false;
        }
        return true;
      };
      void refreshOwnerBridgeEditor();
    }
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

  const ownerNetworkDetail = document.querySelector("[data-api-owner-network-detail]");
  if (ownerNetworkDetail instanceof HTMLElement) {
    const name = ownerNetworkDetail.dataset.networkName || "";
    let currentNetwork = null;
    const setField = (field, value) => { const node = ownerNetworkDetail.querySelector(`[data-network-field="${field}"]`); if (node) node.textContent = value; };
    const detailResult = document.getElementById("network-api-result");
    const showFailure = (error, retry) => {
      if (!(detailResult instanceof HTMLElement)) return;
      detailResult.replaceChildren(element("span", "", error instanceof Error ? error.message : "Network details failed to load."), retryButton(retry));
      detailResult.className = "banner-error";
    };
    const render = (network) => {
      currentNetwork = network;
      if (detailResult instanceof HTMLElement) { detailResult.replaceChildren(); detailResult.className = ""; }
      const title = ownerNetworkDetail.querySelector("[data-network-title]"); if (title) title.textContent = network.name;
      const kind = ownerNetworkDetail.querySelector("[data-network-kind]"); if (kind) kind.textContent = `${network.kind} network`;
      const provider = network.addr || "Provider API";
      setField("kind", network.kind); setField("addr", provider); setField("transport", network.tls ? "TLS" : network.addr ? "Plaintext" : "Provider-managed"); setField("nick", network.nick || "Provider account"); setField("realname", network.realname || "Not set"); setField("autojoin", network.autojoin.length ? network.autojoin.join(", ") : "None"); setField("account-credential", network.has_sasl_account ? "Stored" : "Not set"); setField("secret-credential", network.has_sasl_password ? "Stored encrypted" : "Not set"); setField("enabled", network.enabled ? "Enabled" : "Disabled");
      const summary = ownerNetworkDetail.querySelector("[data-network-summary]"); if (summary instanceof HTMLElement) summary.hidden = false;
      const actions = ownerNetworkDetail.querySelector("[data-network-actions]"); if (actions instanceof HTMLElement) actions.hidden = false;
      const destructive = ownerNetworkDetail.querySelector("[data-network-destructive]"); if (destructive instanceof HTMLElement) destructive.hidden = false;
      const toggle = ownerNetworkDetail.querySelector("[data-network-toggle]"); if (toggle) toggle.textContent = network.enabled ? "Disable" : "Enable";
      const enabled = ownerNetworkDetail.querySelector("[data-network-enabled]"); if (enabled instanceof HTMLInputElement) enabled.value = String(!network.enabled);
      const toggleForm = ownerNetworkDetail.querySelector("[data-api-owner-network-toggle]"); if (toggleForm instanceof HTMLFormElement) toggleForm.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`;
      const deleteForm = ownerNetworkDetail.querySelector("[data-api-owner-network-delete]"); if (deleteForm instanceof HTMLFormElement) { deleteForm.action = `/api/v1/me/networks/${encodeURIComponent(network.name)}`; deleteForm.dataset.confirm = `Remove network ${network.name}? Its live connection and stored backlog will be deleted.`; }
      const edit = ownerNetworkDetail.querySelector("[data-network-edit]"); if (edit instanceof HTMLAnchorElement) { if (network.kind === "irc") { edit.href = `/console/networks/${encodeURIComponent(network.name)}/edit`; edit.hidden = false; } else if (ownerNetworkDetail.dataset.isAdmin === "true") { edit.href = `/console/integrations/${encodeURIComponent(network.name)}/edit`; edit.textContent = "Edit integration"; edit.hidden = false; } }
      const logs = ownerNetworkDetail.querySelector("[data-network-logs]"); if (logs instanceof HTMLAnchorElement) logs.href = `/console/networks/${encodeURIComponent(network.name)}/logs`;
      const accountSetup = ownerNetworkDetail.querySelector("[data-network-account-setup]");
      if (accountSetup instanceof HTMLElement) {
        accountSetup.hidden = network.kind !== "irc";
        const chat = accountSetup.querySelector("[data-network-chat]");
        if (chat instanceof HTMLAnchorElement) chat.href = `/?network=${encodeURIComponent(network.name)}`;
        const account = accountSetup.querySelector('[name="sasl_account"]');
        if (account instanceof HTMLInputElement && !account.value) account.value = network.sasl_account || network.nick;
        const warning = accountSetup.querySelector("[data-network-registration-warning]");
        if (warning instanceof HTMLElement) warning.hidden = !network.addr.toLowerCase().includes("libera.chat");
      }
    };
    refreshOwnerNetworkDetail = async () => {
      try {
        render(await apiRead(`/api/v1/me/networks/${encodeURIComponent(name)}`));
      } catch (error) {
        showFailure(error, () => void refreshOwnerNetworkDetail());
        return false;
      }
      return true;
    };
    const refreshTranscript = async () => {
      const panel = ownerNetworkDetail.querySelector("[data-api-network-operations]");
      const refresh = panel instanceof HTMLElement ? panelRefreshers.get(panel) : null;
      if (refresh) await refresh(true);
    };
    const accountCommand = (form, body, success) => runFormSubmission(form, async () => {
      try {
        await apiRequest(form, apiMutation("POST", `/api/v1/me/networks/${encodeURIComponent(name)}/account-registration`), body);
        await refreshTranscript();
        setOwnerNetworkResult(success, true);
      } catch (error) {
        setOwnerNetworkResult(error instanceof Error ? error.message : "NickServ command failed.", false);
      }
    });
    const register = ownerNetworkDetail.querySelector("[data-api-network-account-register]");
    if (register instanceof HTMLFormElement) register.addEventListener("submit", (event) => {
      event.preventDefault();
      const fields = new FormData(register);
      const email = fieldValue(fields, "email");
      const password = fieldValue(fields, "password");
      if (!email || !password) { setOwnerNetworkResult("Enter an email address and NickServ password.", false); return; }
      const savedPassword = ownerNetworkDetail.querySelector('[data-api-network-account-save] [name="sasl_password"]');
      if (savedPassword instanceof HTMLInputElement) savedPassword.value = password;
      void accountCommand(register, { action: "register", email, password }, "NickServ REGISTER queued. Read the IRC transcript for the network's response, then check your email.");
    });
    const verify = ownerNetworkDetail.querySelector("[data-api-network-account-verify]");
    if (verify instanceof HTMLFormElement) verify.addEventListener("submit", (event) => {
      event.preventDefault();
      const code = fieldValue(new FormData(verify), "code");
      if (!code) { setOwnerNetworkResult("Enter the verification code from the email.", false); return; }
      void accountCommand(verify, { action: "verify", code }, "NickServ VERIFY REGISTER queued. Confirm the result in the IRC transcript before saving SASL credentials.");
    });
    const save = ownerNetworkDetail.querySelector("[data-api-network-account-save]");
    if (save instanceof HTMLFormElement) save.addEventListener("submit", (event) => {
      event.preventDefault();
      if (currentNetwork === null) { setOwnerNetworkResult("Network details are not loaded. Refresh and try again.", false); return; }
      const fields = new FormData(save);
      const account = fieldValue(fields, "sasl_account");
      const password = fieldValue(fields, "sasl_password");
      if (!account || !password) { setOwnerNetworkResult("Enter the verified NickServ account and password.", false); return; }
      const body = {
        addr: currentNetwork.addr,
        tls: currentNetwork.tls,
        nick: currentNetwork.nick,
        realname: currentNetwork.realname,
        autojoin: currentNetwork.autojoin,
        credentials: { action: "set", account, password },
      };
      const url = `/api/v1/me/networks/${encodeURIComponent(name)}`;
      void runFormSubmission(save, async () => {
        try {
          await apiRequest(save, apiMutation("PUT", url), body);
          if (!currentNetwork.enabled) {
            await apiRequest(save, apiMutation("PATCH", url), { enabled: true });
          }
          const registrationPassword = ownerNetworkDetail.querySelector('[data-api-network-account-register] [name="password"]');
          if (registrationPassword instanceof HTMLInputElement) registrationPassword.value = "";
          const savedPassword = save.querySelector('[name="sasl_password"]');
          if (savedPassword instanceof HTMLInputElement) savedPassword.value = "";
          await refreshOwnerNetworkDetail();
          setOwnerNetworkResult("SASL credentials saved. The network is reconnecting with the verified account.", true);
        } catch (error) {
          setOwnerNetworkResult(error instanceof Error ? error.message : "SASL credential update failed.", false);
        }
      });
    });
    if (!name) showFailure(new Error("This network page has no resource ID. Return to the network directory and try again."), () => void refreshOwnerNetworkDetail()); else void refreshOwnerNetworkDetail();
  }

  const channelResult = document.getElementById("channel-api-result");
  const adminChannelRows = document.querySelector("[data-api-admin-channel-list]");
  let refreshAdminChannelDirectory;
  if (adminChannelRows instanceof HTMLElement) {
    refreshAdminChannelDirectory = async () => {
      try {
        const result = await apiRead(`/api/v1/admin/channels${window.location.search}`);
        const channels = apiCollection(result, "channels", "channel directory");
        const pager = document.getElementById("admin-channel-pager");
        if (pager) { pager.replaceChildren(); if (result.next_before_id) { const link = document.createElement("a"); const query = new URLSearchParams(window.location.search); query.set("before_id", String(result.next_before_id)); link.href = `/console/admin/channels?${query}`; link.textContent = "Older registrations"; pager.append(link); } }
        adminChannelRows.replaceChildren();
        const count = document.getElementById("admin-channel-count"); if (count) count.textContent = String(channels.length);
        if (!channels.length) { const row = document.createElement("tr"); const cell = document.createElement("td"); cell.colSpan = 7; cell.className = "empty"; cell.textContent = "No registered channels match this view."; row.append(cell); adminChannelRows.append(row); return true; }
        for (const channel of channels) { const row = document.createElement("tr"); const policy = channel.policy; const values = [channel.id, channel.name, channel.founder, channel.created_at, `KEEP ${policy.keeptopic ? "on" : "off"}${policy.topic_retained ? "; topic retained" : ""}${policy.mlock ? `; MLOCK ${policy.mlock}` : ""}`, `${policy.access_entries} grants`]; values.forEach((value) => { const cell = document.createElement("td"); cell.textContent = String(value); row.append(cell); }); const actions = document.createElement("td"); const form = document.createElement("form"); form.method = "post"; form.action = `/api/v1/admin/channels/${encodeURIComponent(channel.name)}`; form.dataset.apiAdminChannelDrop = ""; form.dataset.confirm = `Unregister ${channel.name} and delete its retained policy?`; const csrf = document.createElement("input"); csrf.type = "hidden"; csrf.name = "csrf"; csrf.value = adminChannelRows.dataset.csrf || ""; const button = document.createElement("button"); button.type = "submit"; button.className = "danger"; button.textContent = "Unregister"; form.append(csrf, button); actions.append(form); row.append(actions); adminChannelRows.append(row); }
      } catch (error) {
        tableLoadFailure(adminChannelRows, 7, error, () => void refreshAdminChannelDirectory());
        return false;
      }
      return true;
    };
    void refreshAdminChannelDirectory();
  }

  const adminAuditRows = document.querySelector("[data-api-admin-audit-list]");
  if (adminAuditRows instanceof HTMLElement) {
    const refreshAuditDirectory = async () => {
      try {
        const result = await apiRead(`/api/v1/admin/audit${window.location.search}`);
        const entries = apiCollection(result, "audit", "audit directory");
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
      } catch (error) {
        tableLoadFailure(adminAuditRows, 6, error, () => void refreshAuditDirectory());
      }
    };
    void refreshAuditDirectory();
  }

  const setChannelResult = (message, success) => {
    if (!channelResult) return;
    channelResult.textContent = message;
    channelResult.className = success ? "banner-success" : "banner-error";
  };

  let refreshOwnedChannels;
  const channelRefresher = () => ownedChannelList instanceof HTMLElement
    ? refreshOwnedChannels
    : refreshAdminChannelDirectory;
  const mutateChannel = (form, url, method, body) => runFormSubmission(form, async () => {
    try {
      await apiRequest(form, apiMutation(method, url), body);
      await refreshAfterMutation(channelRefresher());
      setChannelResult("Updated.", true);
    } catch (error) {
      setChannelResult(error instanceof Error ? error.message : "Channel request failed.", false);
    }
  });

  const ownedChannelList = document.querySelector("[data-api-owned-channel-list]");
  if (ownedChannelList instanceof HTMLElement) {
    const csrf = ownedChannelList.dataset.csrf || "";
    const input = (name, value = "") => { const node = element("input"); node.name = name; node.value = value; return node; };
    const form = (url, label, body) => {
      const node = element("form", "inline-control"); node.method = "post"; node.action = url;
      const token = input("csrf", csrf); token.type = "hidden"; node.append(token);
      body(node);
      node.addEventListener("submit", (event) => { event.preventDefault(); });
      return node;
    };
    const submit = (node, text, run, confirm) => {
      const button = element("button", text === "Unregister" ? "danger" : "primary", text); button.type = "submit";
      if (confirm) node.dataset.confirm = confirm;
      node.append(button);
      node.addEventListener("submit", (event) => { event.preventDefault(); void run(node); });
    };
    const renderOwnedChannels = (result) => {
      const channels = apiCollection(result, "channels", "channel directory");
      ownedChannelList.replaceChildren();
      const count = document.getElementById("owned-channel-count"); if (count) count.textContent = `${channels.length} owned`;
      if (!channels.length) { ownedChannelList.append(append(element("section", "panel"), element("h2", "", "No channels registered to this account"), element("p", "empty", "Channels registered above appear here after storage confirms ownership."))); return; }
      for (const channel of channels) {
        const url = `/api/v1/me/channels/${encodeURIComponent(channel.name)}`;
        const card = element("article", "panel channel-control");
        const access = apiCollection(channel, "access", "channel access");
        card.append(append(element("div", "panel-head"), append(element("div"), element("p", "eyebrow", "Registered channel"), element("h2", "", channel.name), element("p", "", `Founder ${channel.founder} · ${access.length} access grants`)), element("span", channel.keeptopic ? "live-pill" : "revision", channel.keeptopic ? "Topic retained" : "Topic retention off")));
        const topic = form(url, "topic", (node) => { const field = element("label", "field"); const area = element("textarea"); area.name = "topic"; area.rows = 3; area.maxLength = 390; area.value = channel.topic || ""; append(field, element("span", "", "Retained topic"), area); node.append(field); }); submit(topic, "Save topic", (node) => mutateChannel(node, url, "PATCH", { action: "set_topic", topic: fieldValue(new FormData(node), "topic") || null }));
        const lock = form(url, "mlock", (node) => { const field = element("label", "field"); append(field, element("span", "", "Mode lock"), input("mlock", channel.mlock || "")); node.append(field); }); submit(lock, "Save mode lock", (node) => mutateChannel(node, url, "PATCH", { action: "set_mlock", mlock: fieldValue(new FormData(node), "mlock") || null }));
        const keep = form(url, "keep", (node) => { const select = element("select"); select.name = "enabled"; for (const [value, text] of [["on", "Retention on"], ["off", "Retention off"]]) { const option = element("option", "", text); option.value = value; option.selected = channel.keeptopic === (value === "on"); select.append(option); } node.append(select); }); submit(keep, "Apply retention", (node) => mutateChannel(node, url, "PATCH", { action: "set_keeptopic", enabled: fieldValue(new FormData(node), "enabled") === "on" }));
        const controls = element("div", "channel-control-grid"); controls.append(topic, lock, keep); card.append(controls);
        const grants = element("section", "control-block access-control"); grants.append(element("h3", "", "Channel access"));
        for (const grant of access) { const row = element("div", "compact-list"); row.append(element("code", "", grant.account), element("span", "tag", `+${grant.flags}`)); const remove = form(`${url}/access/${encodeURIComponent(grant.account)}`, "remove", () => {}); submit(remove, "Remove", (node) => mutateChannel(node, node.action, "DELETE"), `Remove ${grant.account} from ${channel.name} access?`); row.append(remove); grants.append(row); }
        const add = form(`${url}/access`, "access", (node) => { node.append(input("account")); for (const [name, text] of [["auto_op", "Auto-op"], ["auto_voice", "Auto-voice"]]) { const label = element("label", "check"); const box = input(name); box.type = "checkbox"; append(label, box, element("span", "", text)); node.append(label); } }); submit(add, "Save access", (node) => { const fields = new FormData(node); const account = fieldValue(fields, "account"); const flags = [fields.has("auto_op") && "o", fields.has("auto_voice") && "v"].filter(Boolean).join(""); if (!account || !flags) { setChannelResult("Enter an account and select at least one access grant.", false); return Promise.resolve(); } return mutateChannel(node, `${node.action}/${encodeURIComponent(account)}`, "PUT", { flags }); }); grants.append(add); card.append(grants);
        const transfer = form(url, "transfer", (node) => { node.append(input("account")); }); submit(transfer, "Transfer ownership", (node) => { const account = fieldValue(new FormData(node), "account"); if (!account) { setChannelResult("Enter the new founder account.", false); return Promise.resolve(); } return mutateChannel(node, url, "PATCH", { action: "transfer_founder", account }); }, `Transfer ${channel.name} to this account? You will lose founder control.`); card.append(transfer);
        const drop = form(url, "drop", () => {}); submit(drop, "Unregister", (node) => mutateChannel(node, url, "DELETE"), `Unregister ${channel.name} and delete its retained policy?`); card.append(drop); ownedChannelList.append(card);
      }
    };
    refreshOwnedChannels = async () => {
      renderOwnedChannels(await apiRead("/api/v1/me/channels"));
    };
    void refreshOwnedChannels().catch((error) => { ownedChannelList.textContent = error instanceof Error ? error.message : "Registered channels failed to load."; });
  }

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

  // Every password field gets a reveal control, added here rather than in ten
  // templates so a field added later is covered without anyone remembering to.
  //
  // A credential typed into this console is frequently pasted -- an upstream
  // NickServ password, a bridge token -- and a masked field gives no way to
  // check it before submitting. The failure that follows is a rejected
  // authentication that reads as "wrong credentials" rather than "you typed it
  // wrong", which is a long way to travel for a transposed character.
  //
  // This only ever reveals what is in the field right now. No stored secret is
  // fetched: the API does not return one, and nothing here asks it to.
  for (const field of document.querySelectorAll('input[type="password"]')) {
    if (field.dataset.noReveal !== undefined) continue;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "reveal";
    button.textContent = "Show";
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", "Show password");
    button.addEventListener("click", () => {
      const shown = field.type === "text";
      field.type = shown ? "password" : "text";
      button.textContent = shown ? "Show" : "Hide";
      button.setAttribute("aria-pressed", String(!shown));
      button.setAttribute("aria-label", shown ? "Show password" : "Hide password");
      field.focus();
    });
    // Wrapped so the control sits with the input rather than after the label's
    // hint text, which would put it in a different place on every form.
    const wrap = document.createElement("span");
    wrap.className = "secret-input";
    field.parentNode.insertBefore(wrap, field);
    wrap.append(field, button);
  }
})();
