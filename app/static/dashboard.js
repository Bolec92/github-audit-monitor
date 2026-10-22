(() => {
  "use strict";

  const box = document.getElementById("snapshot-status");
  if (!box) return;

  const state = document.getElementById("snapshot-status-state");
  const progress = document.getElementById("snapshot-status-progress");
  const error = document.getElementById("snapshot-status-error");
  const button = document.getElementById("run-snapshot-button");
  const statusUrl = box.dataset.statusUrl;
  const githubConfigured = button ? button.dataset.githubConfigured === "1" : false;
  let wasRunning = box.dataset.running === "1";
  let reloadScheduled = false;

  function render(run) {
    const running = Boolean(run && run.running);
    state.textContent = running ? "snapshot w toku" : "idle";
    state.classList.toggle("warn", running);
    state.classList.toggle("good", !running);
    progress.textContent = (run && run.progress) || "Idle";

    const lastError = (run && run.last_error) || "";
    error.textContent = lastError;
    error.hidden = !lastError;

    if (button) button.disabled = running || !githubConfigured;
    box.dataset.running = running ? "1" : "0";
    return running;
  }

  async function poll() {
    try {
      const response = await fetch(statusUrl, {
        method: "GET",
        headers: {"Accept": "application/json"},
        cache: "no-store",
        credentials: "same-origin"
      });
      if (!response.ok) return;

      const payload = await response.json();
      const running = render(payload.run || {});

      if (wasRunning && !running && !reloadScheduled) {
        reloadScheduled = true;
        window.setTimeout(() => window.location.reload(), 700);
      }
      wasRunning = running;
    } catch (_) {
      // Keep the last known state; the next poll will retry automatically.
    }
  }

  window.setInterval(poll, 1500);
  poll();
})();
