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
})();
