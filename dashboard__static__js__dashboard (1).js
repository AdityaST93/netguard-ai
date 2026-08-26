/* NetGuard AI — dashboard client
   Vanilla JS, no build step: fetches from the Flask API and renders
   the overview + alert log pages. */

const API = {
  health: () => fetch("/api/health").then(r => r.json()),
  stats: () => fetch("/api/stats").then(r => r.json()),
  alerts: (limit = 100) => fetch(`/api/alerts?limit=${limit}`).then(r => r.json()),
  blocked: () => fetch("/api/blocked").then(r => r.json()),
  simulate: (limit = 200) =>
    fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ limit }),
    }).then(r => r.json()),
  block: (ip) =>
    fetch("/api/block", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, reason: "manual block" }),
    }).then(r => r.json()),
  unblock: (ip) =>
    fetch("/api/unblock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    }).then(r => r.json()),
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function fmtTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour12: false });
  } catch {
    return iso;
  }
}

function badge(severity) {
  return `<span class="badge badge-${severity}">${severity}</span>`;
}

async function refreshModelStatus() {
  const chip = document.getElementById("model-status");
  const text = document.getElementById("model-status-text");
  try {
    const h = await API.health();
    if (h.model_ready) {
      chip.classList.add("ready");
      chip.classList.remove("error");
      text.textContent = "model ready";
    } else {
      chip.classList.add("error");
      text.textContent = "model not trained";
    }
  } catch {
    chip.classList.add("error");
    text.textContent = "backend unreachable";
  }
}

function renderStats(stats) {
  const totalEl = document.getElementById("stat-total");
  const threatsEl = document.getElementById("stat-threats");
  const blockedEl = document.getElementById("stat-blocked");
  const modelEl = document.getElementById("stat-model");
  if (totalEl) totalEl.textContent = stats.total_events ?? 0;
  if (threatsEl) threatsEl.textContent = stats.total_threats ?? 0;
  if (blockedEl) blockedEl.textContent = stats.blocked_ip_count ?? 0;
  if (modelEl) modelEl.textContent = stats.model_ready ? "trained" : "untrained";

  const chartEl = document.getElementById("threat-bar-chart");
  if (chartEl) {
    const entries = Object.entries(stats.by_type || {}).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
      chartEl.innerHTML = `<p class="muted">No threats detected yet — run a simulation.</p>`;
    } else {
      const max = Math.max(...entries.map(([, v]) => v));
      chartEl.innerHTML = entries
        .map(([label, count]) => `
          <div class="bar-row">
            <span class="bar-label">${label.replace("_", " ")}</span>
            <div class="bar-track"><div class="bar-fill" style="width:${(count / max) * 100}%"></div></div>
            <span class="bar-count">${count}</span>
          </div>`)
        .join("");
    }
  }
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alerts-tbody");
  const countEl = document.getElementById("alert-feed-count");
  if (!tbody) return;
  if (countEl) countEl.textContent = `${alerts.length} alerts`;

  if (alerts.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No alerts yet — run a simulation to see NetGuard in action.</td></tr>`;
    return;
  }

  const sorted = [...alerts].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );

  tbody.innerHTML = sorted
    .slice(0, 15)
    .map(
      (a) => `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td>${a.src_ip}</td>
        <td>${a.threat_type}</td>
        <td>${(a.confidence * 100).toFixed(1)}%</td>
        <td>${badge(a.severity)}</td>
      </tr>`
    )
    .join("");
}

function renderFullAlertsTable(alerts) {
  const tbody = document.getElementById("full-alerts-tbody");
  if (!tbody) return;
  if (alerts.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No alerts recorded yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = alerts
    .map((a) => {
      const scores = Object.entries(a.detail || {})
        .map(([k, v]) => `${k}:${(v * 100).toFixed(0)}%`)
        .join(" · ");
      return `
      <tr>
        <td>${fmtTime(a.timestamp)}</td>
        <td>${a.src_ip}</td>
        <td>${a.threat_type}</td>
        <td>${(a.confidence * 100).toFixed(1)}%</td>
        <td>${badge(a.severity)}</td>
        <td class="muted">${scores}</td>
      </tr>`;
    })
    .join("");
}

function renderBlockedTable(blocked) {
  const tbody = document.getElementById("blocked-tbody");
  const countEl = document.getElementById("blocked-count");
  if (!tbody) return;
  if (countEl) countEl.textContent = `${blocked.length} blocked`;

  if (blocked.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="4">No blocked IPs.</td></tr>`;
    return;
  }
  tbody.innerHTML = blocked
    .map(
      (b) => `
      <tr>
        <td>${b.ip}</td>
        <td class="muted">${b.reason || "—"}</td>
        <td>${fmtTime(b.blocked_at)}</td>
        <td><button class="link-btn" data-unblock="${b.ip}">unblock</button></td>
      </tr>`
    )
    .join("");

  tbody.querySelectorAll("[data-unblock]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await API.unblock(btn.getAttribute("data-unblock"));
      await refreshAll();
    });
  });
}

function spawnRadarBlip() {
  const group = document.getElementById("radar-blips");
  if (!group) return;
  const angle = Math.random() * Math.PI * 2;
  const radius = 30 + Math.random() * 75;
  const x = 120 + Math.cos(angle) * radius;
  const y = 120 + Math.sin(angle) * radius;
  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("cx", x);
  circle.setAttribute("cy", y);
  circle.setAttribute("r", 3.5);
  circle.setAttribute("class", "radar-blip");
  circle.style.opacity = "1";
  circle.style.transition = "opacity 1.8s ease";
  group.appendChild(circle);
  requestAnimationFrame(() => {
    circle.style.opacity = "0";
  });
  setTimeout(() => circle.remove(), 2000);
}

async function refreshAll() {
  try {
    const [stats, alerts, blocked] = await Promise.all([API.stats(), API.alerts(100), API.blocked()]);
    renderStats(stats);
    renderAlertsTable(alerts);
    renderFullAlertsTable(alerts);
    renderBlockedTable(blocked);
  } catch (e) {
    console.error("NetGuard refresh failed", e);
  }
}

function initDashboardPage() {
  const btn = document.getElementById("simulate-btn");
  const hint = document.getElementById("simulate-hint");
  btn?.addEventListener("click", async () => {
    btn.disabled = true;
    const originalText = btn.textContent;
    btn.textContent = "Simulating…";
    try {
      const result = await API.simulate(200);
      if (result.error) {
        hint.textContent = result.error;
      } else {
        hint.textContent = `Processed ${result.processed} flows · ${result.threats_detected} threats flagged`;
        for (let i = 0; i < Math.min(result.threats_detected, 12); i++) {
          setTimeout(spawnRadarBlip, i * 150);
        }
      }
      await refreshAll();
    } catch (e) {
      hint.textContent = "Simulation failed — is the backend running?";
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  });

  document.getElementById("manual-block-btn")?.addEventListener("click", async () => {
    const input = document.getElementById("manual-ip");
    const ip = input.value.trim();
    if (!ip) return;
    await API.block(ip);
    input.value = "";
    await refreshAll();
  });
}

function initAlertsPage() {
  document.getElementById("refresh-alerts-btn")?.addEventListener("click", refreshAll);
}

document.addEventListener("DOMContentLoaded", () => {
  refreshModelStatus();
  refreshAll();
  if (window.NETGUARD_PAGE === "dashboard") initDashboardPage();
  if (window.NETGUARD_PAGE === "alerts") initAlertsPage();
  setInterval(refreshModelStatus, 15000);
});
