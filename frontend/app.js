const API_BASE = "http://127.0.0.1:8000";

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("API error");
  return res.json();
}

function setStatusCard(status) {
  const statusText = document.getElementById("status-text");
  const lastDetection = document.getElementById("last-detection");
  const totalEvents = document.getElementById("total-events");
  const suspiciousCount = document.getElementById("suspicious-count");
  const statusCard = document.getElementById("status-card");

  statusText.textContent = status.status;
  lastDetection.textContent = status.last_detection_time || "-";
  totalEvents.textContent = status.total_events_24h;
  suspiciousCount.textContent = status.suspicious_processes_count;

  statusCard.classList.remove("safe", "suspicious", "danger");
  if (status.status === "safe") statusCard.classList.add("safe");
  else if (status.status === "suspicious") statusCard.classList.add("suspicious");
  else statusCard.classList.add("danger");
}

function renderEvents(events) {
  const tbody = document.querySelector("#events-table tbody");
  tbody.innerHTML = "";
  events.forEach(ev => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${new Date(ev.timestamp).toLocaleTimeString()}</td>
      <td>${ev.process_name}</td>
      <td>${ev.pid}</td>
      <td>${ev.operation}</td>
      <td>${ev.path}</td>
      <td>${ev.risk_score.toFixed(2)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSuspicious(processes) {
  const tbody = document.querySelector("#suspicious-table tbody");
  tbody.innerHTML = "";
  processes.forEach(p => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${p.process_name}</td>
      <td>${p.pid}</td>
      <td>${p.files_touched}</td>
      <td>${p.risk_score.toFixed(2)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function refresh() {
  try {
    const [status, events, procs] = await Promise.all([
      fetchJSON(`${API_BASE}/api/status`),
      fetchJSON(`${API_BASE}/api/events?limit=50`),
      fetchJSON(`${API_BASE}/api/suspicious-processes`)
    ]);
    setStatusCard(status);
    renderEvents(events);
    renderSuspicious(procs);
  } catch (e) {
    console.error(e);
  }
}

setInterval(refresh, 3000);
refresh();