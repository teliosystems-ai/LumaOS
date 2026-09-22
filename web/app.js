(() => {
  "use strict";

  const API = Object.freeze({
    health: "/api/health",
    status: "/api/status",
    models: "/api/models/status",
    grants: "/api/grants",
    enroll: "/api/grants/enroll",
    workflows: "/api/workflows",
    artifacts: "/api/artifacts",
    receipts: "/api/receipts",
  });

  const TERMINAL_STATES = new Set(["completed", "failed", "cancelled"]);
  const VALID_ROUTES = new Set(["overview", "workflow", "workflows", "artifacts", "activity", "access"]);

  const state = {
    health: null,
    serviceStatus: null,
    model: null,
    grants: [],
    workflows: [],
    artifacts: [],
    receipts: [],
    selectedWorkflowId: null,
    selectedArtifactId: null,
    manualDraft: null,
    pollingTimer: null,
    refreshInFlight: false,
  };

  const el = (id) => document.getElementById(id);
  const query = (selector, root = document) => root.querySelector(selector);
  const queryAll = (selector, root = document) => [...root.querySelectorAll(selector)];

  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function collection(payload) {
    if (Array.isArray(payload)) return payload;
    for (const key of ["items", "results", "data", "workflows", "grants", "artifacts", "receipts"]) {
      if (Array.isArray(payload?.[key])) return payload[key];
    }
    return [];
  }

  function entityId(item) {
    return String(item?.id ?? item?.workflow_id ?? item?.artifact_id ?? item?.grant_id ?? item?.receipt_id ?? "");
  }

  function normalizedStatus(item, fallback = "unknown") {
    const raw = String(item?.state ?? item?.status ?? item?.outcome ?? fallback).trim().toLowerCase();
    const aliases = {
      validated: "ready",
      created: "ready",
      succeeded: "completed",
      success: "completed",
      waiting_user: "needs_input",
    };
    return aliases[raw] ?? raw;
  }

  function statusLabel(status) {
    const labels = {
      ready: "Ready",
      created: "Ready",
      queued: "Queued",
      running: "Running",
      completed: "Completed",
      success: "Completed",
      succeeded: "Completed",
      committed: "Committed",
      failed: "Needs attention",
      error: "Needs attention",
      denied: "Denied",
      cancelled: "Cancelled",
      pending: "Pending",
      needs_input: "Needs input",
      unknown: "Unknown",
    };
    return labels[status] || status.replaceAll("_", " ");
  }

  function statusBadge(status) {
    const clean = normalizedStatus({ status });
    const className = ["success", "succeeded", "committed"].includes(clean) ? "completed" : clean;
    return `<span class="status-badge status-${escapeHtml(className)}">${escapeHtml(statusLabel(clean))}</span>`;
  }

  function formatDate(value, includeTime = true) {
    if (!value) return "Not recorded";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    const options = includeTime
      ? { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }
      : { year: "numeric", month: "short", day: "numeric" };
    return new Intl.DateTimeFormat(undefined, options).format(date);
  }

  function relativeTime(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    if (Math.abs(seconds) < 60) return relative.format(seconds, "second");
    const minutes = Math.round(seconds / 60);
    if (Math.abs(minutes) < 60) return relative.format(minutes, "minute");
    const hours = Math.round(minutes / 60);
    if (Math.abs(hours) < 24) return relative.format(hours, "hour");
    return relative.format(Math.round(hours / 24), "day");
  }

  function formatBytes(value) {
    const bytes = Number(value);
    if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
    if (bytes < 1024) return `${bytes} B`;
    const units = ["KB", "MB", "GB"];
    let size = bytes / 1024;
    let unit = units[0];
    for (let index = 1; index < units.length && size >= 1024; index += 1) {
      size /= 1024;
      unit = units[index];
    }
    return `${size >= 10 ? size.toFixed(0) : size.toFixed(1)} ${unit}`;
  }

  function problemMessage(payload, status) {
    if (typeof payload === "string" && payload.trim()) return payload.trim();
    const message = payload?.message ?? payload?.detail ?? payload?.error?.message ?? payload?.error;
    if (typeof message === "string" && message.trim()) return message.trim();
    return `The local service returned HTTP ${status}.`;
  }

  async function api(path, options = {}) {
    const request = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(options.headers || {}) },
      signal: options.signal,
    };
    if (options.body !== undefined) {
      request.headers["Content-Type"] = "application/json";
      request.body = JSON.stringify(options.body);
    }
    let response;
    try {
      response = await fetch(path, request);
    } catch (error) {
      throw new Error("The local Luma service is not reachable.", { cause: error });
    }
    const text = await response.text();
    let payload = null;
    if (text) {
      try { payload = JSON.parse(text); }
      catch { payload = text; }
    }
    if (!response.ok) {
      const error = new Error(problemMessage(payload, response.status));
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload ?? {};
  }

  function toast(title, message = "", type = "success") {
    const region = el("toast-region");
    const item = document.createElement("div");
    item.className = `toast${type === "error" ? " is-error" : ""}`;
    item.setAttribute("role", type === "error" ? "alert" : "status");
    item.innerHTML = `
      <span class="toast-icon" aria-hidden="true">${type === "error" ? "!" : "✓"}</span>
      <div><strong>${escapeHtml(title)}</strong>${message ? `<span>${escapeHtml(message)}</span>` : ""}</div>
      <button type="button" aria-label="Dismiss notification">×</button>`;
    region.append(item);
    const dismiss = () => {
      item.classList.add("is-leaving");
      window.setTimeout(() => item.remove(), 200);
    };
    query("button", item).addEventListener("click", dismiss);
    window.setTimeout(dismiss, type === "error" ? 8000 : 5000);
  }

  function routeTo(route, options = {}) {
    const next = VALID_ROUTES.has(route) ? route : "overview";
    queryAll(".view").forEach((view) => {
      const active = view.dataset.view === next;
      view.hidden = !active;
      view.classList.toggle("is-active", active);
    });
    queryAll(".nav-item").forEach((link) => {
      const active = link.dataset.route === next;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    if (!options.keepHash && window.location.hash !== `#${next}`) history.replaceState(null, "", `#${next}`);
    el("primary-nav").classList.remove("is-open");
    el("mobile-nav-button").setAttribute("aria-expanded", "false");
    if (options.focus !== false) {
      const heading = query("h1", query(`[data-view="${next}"]`));
      heading?.setAttribute("tabindex", "-1");
      heading?.focus({ preventScroll: true });
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function setConnection(online, label) {
    const pill = el("connection-pill");
    pill.classList.toggle("is-online", online);
    pill.classList.toggle("is-offline", !online);
    el("connection-label").textContent = label;
  }

  async function loadResource(key, path) {
    try {
      const payload = await api(path);
      if (["grants", "workflows", "artifacts", "receipts"].includes(key)) state[key] = collection(payload);
      else state[key] = payload;
      return { ok: true, payload };
    } catch (error) {
      if (["grants", "workflows", "artifacts", "receipts"].includes(key) && !state[key].length) state[key] = [];
      return { ok: false, error };
    }
  }

  async function refreshAll({ announce = false } = {}) {
    if (state.refreshInFlight) return;
    state.refreshInFlight = true;
    queryAll("[data-refresh]").forEach((button) => button.classList.add("is-spinning"));
    // Health establishes the HttpOnly local-session cookie. Protected requests
    // wait for it instead of racing the bootstrap response.
    const health = await loadResource("health", API.health);
    if (health.ok) {
      await Promise.all([
        loadResource("serviceStatus", API.status),
        loadResource("model", API.models),
        loadResource("grants", API.grants),
        loadResource("workflows", API.workflows),
        loadResource("artifacts", API.artifacts),
        loadResource("receipts", API.receipts),
      ]);
    }
    state.refreshInFlight = false;
    queryAll("[data-refresh]").forEach((button) => button.classList.remove("is-spinning"));
    setConnection(health.ok, health.ok ? `Local service ${state.health?.version || "online"}` : "Local service unavailable");
    renderAll();
    ensurePolling();
    if (announce) toast(health.ok ? "Workspace refreshed" : "Service unavailable", health.ok ? "Latest local state loaded." : health.error?.message, health.ok ? "success" : "error");
  }

  function renderAll() {
    renderOverview();
    renderEnrollmentHint();
    renderWorkflowList();
    renderWorkflowDetail();
    renderArtifactList();
    renderArtifactDetail();
    renderReceipts();
    renderGrants();
  }

  function renderOverview() {
    const available = Boolean(state.model?.available ?? state.model?.configured ?? false);
    const modelName = state.model?.model ?? state.model?.name ?? state.model?.model_id ?? "No model reported";
    const runtime = state.model?.runtime ?? state.model?.provider ?? "Local runtime";
    const active = state.workflows.filter((item) => ["running", "queued"].includes(normalizedStatus(item))).length;
    el("model-summary").textContent = available ? String(modelName) : "Unavailable";
    el("model-detail").textContent = available ? String(runtime) : "Manual controls remain available";
    el("grant-summary").textContent = String(state.grants.filter((grant) => !grant.revoked_at).length);
    el("active-summary").textContent = String(active);
    el("active-detail").textContent = active ? `${active} currently executing` : "No workflow executing";
    el("artifact-summary").textContent = String(state.artifacts.length);
    setCounter("workflow-count", state.workflows.length);
    setCounter("artifact-count", state.artifacts.length);

    const details = [
      ["Runtime", runtime],
      ["Model", available ? modelName : "Not available"],
      ["Execution", state.model?.execution ?? "Local only"],
    ];
    el("model-details").innerHTML = details.map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");

    const recent = [...state.workflows]
      .sort((a, b) => new Date(b.updated_at ?? b.created_at ?? 0) - new Date(a.updated_at ?? a.created_at ?? 0))
      .slice(0, 4);
    el("recent-workflows").innerHTML = recent.length
      ? recent.map((workflow) => {
          const id = entityId(workflow);
          const title = workflow.name || fileName(workflowSource(workflow)) || "Invoice report";
          return `<button class="stack-item" type="button" data-open-workflow="${escapeHtml(id)}">
            <span class="stack-item-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7L8 5Z"/></svg></span>
            <span class="stack-item-copy"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(statusLabel(normalizedStatus(workflow)))} · ${escapeHtml(relativeTime(workflow.updated_at ?? workflow.created_at))}</span></span>
            ${statusBadge(normalizedStatus(workflow))}
          </button>`;
        }).join("")
      : emptyInline("No workflows yet. Create one from an enrolled CSV file.", "workflow", "Create workflow");
  }

  function setCounter(id, count) {
    const counter = el(id);
    counter.textContent = String(count);
    counter.hidden = count === 0;
  }

  function fileName(path) {
    if (!path) return "";
    return String(path).split(/[\\/]/).filter(Boolean).pop() || String(path);
  }

  function workflowSource(workflow) {
    if (workflow?.source_path) return workflow.source_path;
    const files = workflow?.request?.files;
    if (Array.isArray(files) && files.length) return files.join(", ");
    return workflow?.request?.inline_source?.name ?? "";
  }

  function emptyInline(message, route, action) {
    return `<div class="empty-state compact"><div class="empty-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v5h4"/></svg></div><h2>Nothing here yet</h2><p>${escapeHtml(message)}</p>${route ? `<a class="button button-secondary" href="#${escapeHtml(route)}" data-route="${escapeHtml(route)}">${escapeHtml(action)}</a>` : ""}</div>`;
  }

  function renderEnrollmentHint() {
    const active = state.grants.filter((grant) => !grant.revoked_at);
    el("enrollment-hint").innerHTML = active.length
      ? `<strong>${active.length} folder${active.length === 1 ? "" : "s"} enrolled:</strong> ${active.slice(0, 3).map((grant) => `<code>${escapeHtml(grant.root_path ?? grant.root ?? grant.path ?? "Unknown path")}</code>`).join(" ")}`
      : `No active folder is enrolled. <a href="#access" data-route="access">Enroll one before creating a workflow.</a>`;
  }

  function filteredWorkflows() {
    const queryValue = el("workflow-search").value.trim().toLowerCase();
    const filter = el("workflow-filter").value;
    return state.workflows.filter((workflow) => {
      const status = normalizedStatus(workflow);
      const matchesStatus = filter === "all" || status === filter;
      const haystack = `${workflow.name ?? ""} ${workflowSource(workflow)} ${workflow.kind ?? workflow.type ?? ""} ${entityId(workflow)}`.toLowerCase();
      return matchesStatus && (!queryValue || haystack.includes(queryValue));
    });
  }

  function renderWorkflowList() {
    const list = filteredWorkflows();
    el("workflow-list").innerHTML = list.length
      ? list.map((workflow) => {
          const id = entityId(workflow);
          const selected = id === state.selectedWorkflowId;
          return `<button type="button" class="list-row${selected ? " is-selected" : ""}" data-select-workflow="${escapeHtml(id)}" aria-pressed="${selected}">
            <span class="list-row-copy"><strong>${escapeHtml(workflow.name || fileName(workflowSource(workflow)) || "Invoice report")}</strong><span>${escapeHtml(workflow.kind ?? workflow.type ?? "invoice_report.v1")} · ${escapeHtml(formatDate(workflow.created_at))}</span></span>
            ${statusBadge(normalizedStatus(workflow))}
          </button>`;
        }).join("")
      : emptyInline(state.workflows.length ? "No workflow matches this filter." : "Create a workflow from an enrolled invoice CSV.", state.workflows.length ? null : "workflow", "Create workflow");
  }

  function selectedWorkflow() {
    return state.workflows.find((item) => entityId(item) === state.selectedWorkflowId) || null;
  }

  function renderWorkflowDetail() {
    const container = el("workflow-detail");
    const workflow = selectedWorkflow();
    if (!workflow) {
      container.innerHTML = `<div class="empty-state compact"><div class="empty-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7L8 5Z"/></svg></div><h2>Select a workflow</h2><p>Its source, execution steps, and controls will appear here.</p></div>`;
      return;
    }
    const status = normalizedStatus(workflow);
    const canRun = status === "ready" || status === "created";
    const steps = Array.isArray(workflow.steps) ? workflow.steps : [];
    const error = workflow.error?.message ?? workflow.error ?? workflow.failure_reason;
    container.innerHTML = `
      <div class="detail-header">
        <div><h2>${escapeHtml(workflow.name || fileName(workflowSource(workflow)) || "Invoice report")}</h2><p>ID ${escapeHtml(entityId(workflow))}</p></div>
        <div class="detail-actions">${statusBadge(status)}${canRun ? `<button class="button button-primary" type="button" data-run-workflow="${escapeHtml(entityId(workflow))}">Run</button>` : ""}</div>
      </div>
      <div class="workflow-meta">
        <div><span>Kind</span><strong>${escapeHtml(workflow.kind ?? workflow.type ?? "invoice_report.v1")}</strong></div>
        <div><span>Created</span><strong>${escapeHtml(formatDate(workflow.created_at))}</strong></div>
        <div><span>Artifacts</span><strong>${escapeHtml(String((workflow.result?.artifacts ?? workflow.artifact_ids ?? workflow.artifacts ?? []).length))}</strong></div>
      </div>
      <h3 class="section-title">Enrolled source</h3>
      <div class="source-path"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h7l2 2h9v11H3V7Z"/></svg><code>${escapeHtml(workflowSource(workflow) || "Not reported")}</code></div>
      <h3 class="section-title">Execution steps</h3>
      <div class="step-list">${renderSteps(steps, status)}</div>
      ${error ? `<div class="error-box"><strong>Execution did not complete.</strong><br>${escapeHtml(typeof error === "string" ? error : JSON.stringify(error))}</div>` : ""}`;
  }

  function renderSteps(steps, workflowStatus) {
    const values = steps.length ? steps : [
      { name: "Validate enrolled source", state: workflowStatus === "ready" ? "pending" : workflowStatus },
      { name: "Read and parse CSV", state: "pending" },
      { name: "Commit invoice report", state: "pending" },
    ];
    return values.map((step) => {
      const status = normalizedStatus(step, "pending");
      const className = ["completed", "success", "succeeded"].includes(status) ? "is-complete" : status === "running" ? "is-running" : "";
      return `<div class="run-step ${className}">
        <span class="step-indicator"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"/></svg></span>
        <span><strong>${escapeHtml(step.name || step.label || readableStepName(step.step_id) || "Workflow step")}</strong><small>${escapeHtml(statusLabel(status))}${step.message ? ` · ${escapeHtml(step.message)}` : ""}</small></span>
        <time>${escapeHtml(step.completed_at ? formatDate(step.completed_at) : "")}</time>
      </div>`;
    }).join("");
  }

  function readableStepName(stepId) {
    if (!stepId) return "";
    const labels = {
      read_sources: "Read enrolled sources",
      extract_rows: "Validate invoice rows",
      aggregate: "Calculate monthly totals",
      publish_csv: "Commit summary CSV",
      publish_report: "Commit invoice report",
    };
    return labels[stepId] ?? String(stepId).replaceAll("_", " ");
  }

  async function selectWorkflow(id, navigate = false) {
    state.selectedWorkflowId = id;
    renderWorkflowList();
    renderWorkflowDetail();
    if (navigate) routeTo("workflows");
    try {
      const detail = await api(`${API.workflows}/${encodeURIComponent(id)}`);
      const index = state.workflows.findIndex((item) => entityId(item) === id);
      if (index >= 0) state.workflows[index] = detail;
      else state.workflows.unshift(detail);
      renderOverview();
      renderWorkflowList();
      renderWorkflowDetail();
      ensurePolling();
    } catch (error) {
      toast("Could not load workflow", error.message, "error");
    }
  }

  async function runWorkflow(id) {
    const button = query(`[data-run-workflow="${CSS.escape(id)}"]`);
    if (button) { button.disabled = true; button.textContent = "Starting…"; }
    const index = state.workflows.findIndex((item) => entityId(item) === id);
    if (index >= 0) state.workflows[index] = { ...state.workflows[index], state: "running" };
    renderWorkflowList();
    renderWorkflowDetail();
    try {
      const result = await api(`${API.workflows}/${encodeURIComponent(id)}/run`, { method: "POST", body: {} });
      if (result && typeof result === "object") {
        const current = state.workflows.findIndex((item) => entityId(item) === id);
        if (current >= 0) state.workflows[current] = { ...state.workflows[current], ...result };
      }
      toast("Workflow started", "Execution progress is shown in this panel.");
      await refreshSelectedWorkflow();
      await Promise.all([loadResource("artifacts", API.artifacts), loadResource("receipts", API.receipts)]);
      renderAll();
      ensurePolling();
    } catch (error) {
      toast("Workflow could not run", error.message, "error");
      await refreshSelectedWorkflow();
    }
  }

  async function refreshSelectedWorkflow() {
    if (!state.selectedWorkflowId) return;
    try {
      const detail = await api(`${API.workflows}/${encodeURIComponent(state.selectedWorkflowId)}`);
      const index = state.workflows.findIndex((item) => entityId(item) === state.selectedWorkflowId);
      if (index >= 0) state.workflows[index] = detail;
      else state.workflows.unshift(detail);
      renderOverview();
      renderWorkflowList();
      renderWorkflowDetail();
    } catch {
      // The full refresh and visible connection state handle repeated failures.
    }
  }

  function ensurePolling() {
    const workflow = selectedWorkflow();
    const shouldPoll = workflow && normalizedStatus(workflow) === "running";
    if (!shouldPoll && state.pollingTimer) {
      window.clearInterval(state.pollingTimer);
      state.pollingTimer = null;
    }
    if (shouldPoll && !state.pollingTimer) {
      state.pollingTimer = window.setInterval(async () => {
        await refreshSelectedWorkflow();
        const selected = selectedWorkflow();
        if (!selected || TERMINAL_STATES.has(normalizedStatus(selected))) {
          window.clearInterval(state.pollingTimer);
          state.pollingTimer = null;
          await Promise.all([loadResource("artifacts", API.artifacts), loadResource("receipts", API.receipts)]);
          renderAll();
        }
      }, 1500);
    }
  }

  function renderArtifactList() {
    const list = [...state.artifacts].sort((a, b) => new Date(b.updated_at ?? b.created_at ?? 0) - new Date(a.updated_at ?? a.created_at ?? 0));
    el("artifact-list").innerHTML = list.length
      ? list.map((artifact) => {
          const id = entityId(artifact);
          const selected = id === state.selectedArtifactId;
          const version = artifact.current_version ?? artifact.version ?? 1;
          return `<button type="button" class="list-row${selected ? " is-selected" : ""}" data-select-artifact="${escapeHtml(id)}" aria-pressed="${selected}">
            <span class="list-row-copy"><strong>${escapeHtml(artifact.filename ?? artifact.name ?? "Untitled artifact")}</strong><span>Version ${escapeHtml(version)} · ${escapeHtml(formatBytes(artifact.size_bytes ?? artifact.size))}</span></span>
            <span class="artifact-type">${escapeHtml(shortMediaType(artifact.media_type))}</span>
          </button>`;
        }).join("")
      : emptyInline("Completed workflows commit durable artifacts here.", "workflow", "Create workflow");
  }

  function shortMediaType(value) {
    if (!value) return "FILE";
    if (String(value).includes("json")) return "JSON";
    if (String(value).includes("csv")) return "CSV";
    if (String(value).includes("text")) return "TEXT";
    return String(value).split("/").pop().split(";")[0].toUpperCase().slice(0, 8);
  }

  function selectedArtifact() {
    return state.artifacts.find((item) => entityId(item) === state.selectedArtifactId) || null;
  }

  function artifactVersions(artifact) {
    if (Array.isArray(artifact?.versions) && artifact.versions.length) return artifact.versions;
    const version = Number(artifact?.current_version ?? artifact?.version ?? 1);
    return [{ ...artifact, version }];
  }

  function renderArtifactDetail(selectedVersion = null) {
    const container = el("artifact-detail");
    const artifact = selectedArtifact();
    if (!artifact) {
      container.innerHTML = `<div class="empty-state compact"><div class="empty-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v5h4"/></svg></div><h2>Select an artifact</h2><p>Metadata, available content, and version history will appear here.</p></div>`;
      return;
    }
    const versions = artifactVersions(artifact);
    const currentNumber = Number(selectedVersion ?? artifact.current_version ?? artifact.version ?? versions.at(-1)?.version ?? 1);
    const current = versions.find((version) => Number(version.version) === currentNumber) ?? artifact;
    const rawContent = current._content ?? current.content ?? current.text ?? current.data ?? artifact._content ?? artifact.content ?? artifact.text;
    const content = rawContent === undefined
      ? "Loading artifact content…"
      : typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent, null, 2);
    const artifactId = entityId(artifact);
    container.innerHTML = `
      <div class="artifact-header">
        <div><h2>${escapeHtml(artifact.filename ?? artifact.name ?? "Untitled artifact")}</h2><p>${escapeHtml(artifact.media_type ?? "Unknown media type")} · ${escapeHtml(formatDate(current.created_at ?? artifact.updated_at ?? artifact.created_at))}</p></div>
        <div class="artifact-header-actions"><a class="button button-secondary" href="${API.artifacts}/${encodeURIComponent(artifactId)}/content?version=${encodeURIComponent(currentNumber)}" download>Download</a><label class="version-select">Version<select id="artifact-version-select">${versions.map((version) => `<option value="${escapeHtml(version.version)}"${Number(version.version) === currentNumber ? " selected" : ""}>Version ${escapeHtml(version.version)}</option>`).join("")}</select></label></div>
      </div>
      <pre class="artifact-content">${escapeHtml(content)}</pre>
      <div class="version-history" aria-label="Version history">${versions.map((version) => `<span class="version-chip${Number(version.version) === currentNumber ? " is-current" : ""}">v${escapeHtml(version.version)} · ${escapeHtml(formatDate(version.created_at ?? artifact.created_at, false))}</span>`).join("")}</div>`;
  }

  async function selectArtifact(id) {
    state.selectedArtifactId = id;
    renderArtifactList();
    renderArtifactDetail();
    const artifact = selectedArtifact();
    if (!artifact) return;
    try {
      const detail = await api(`${API.artifacts}/${encodeURIComponent(id)}`);
      Object.assign(artifact, detail);
      await loadArtifactVersion(artifact.current_version ?? artifact.version ?? 1);
      renderArtifactDetail();
    } catch (error) {
      artifact._content = `Content could not be loaded.\n\n${error.message}`;
      renderArtifactDetail();
      toast("Artifact preview unavailable", error.message, "error");
    }
  }

  async function loadArtifactVersion(version) {
    const artifact = selectedArtifact();
    if (!artifact) return;
    const versions = artifactVersions(artifact);
    const selected = versions.find((item) => Number(item.version) === Number(version));
    if (selected?._content !== undefined) {
      renderArtifactDetail(version);
      return;
    }
    try {
      const content = await api(`${API.artifacts}/${encodeURIComponent(entityId(artifact))}/content?version=${encodeURIComponent(version)}`);
      if (selected) selected._content = typeof content === "string" ? content : JSON.stringify(content, null, 2);
      else artifact._content = typeof content === "string" ? content : JSON.stringify(content, null, 2);
      renderArtifactDetail(version);
    } catch (error) {
      if (selected) selected._content = `Content could not be loaded.\n\n${error.message}`;
      renderArtifactDetail(version);
      toast("Artifact preview unavailable", error.message, "error");
    }
  }

  function renderReceipts() {
    const list = [...state.receipts].sort((a, b) => new Date(b.created_at ?? 0) - new Date(a.created_at ?? 0));
    el("receipt-list").innerHTML = list.length
      ? list.map((receipt) => {
          const operation = receipt.operation ?? receipt.effect_type ?? receipt.type ?? "Effect recorded";
          const outcome = normalizedStatus(receipt);
          const target = receipt.target ?? receipt.resource ?? receipt.workflow_id ?? "Local service";
          return `<div class="activity-row">
            <div class="activity-copy"><strong>${escapeHtml(operation.replaceAll(".", " · "))}</strong><span>${escapeHtml(target)} · receipt ${escapeHtml(entityId(receipt).slice(0, 12) || "recorded")}</span></div>
            ${statusBadge(outcome)}
            <time datetime="${escapeHtml(receipt.created_at ?? "")}">${escapeHtml(formatDate(receipt.created_at))}</time>
          </div>`;
        }).join("")
      : emptyInline("No effect receipt has been recorded. Creating a workflow alone does not produce one.", null, null);
  }

  function renderGrants() {
    const list = state.grants.filter((grant) => !grant.revoked_at);
    el("grant-list").innerHTML = list.length
      ? list.map((grant) => {
          const path = grant.root_path ?? grant.root ?? grant.path ?? "Unknown path";
          const permissions = Array.isArray(grant.permissions) ? grant.permissions : [grant.scope ?? "read"];
          return `<div class="grant-row">
            <span class="grant-icon-small"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h7l2 2h9v11H3V7Z"/></svg></span>
            <span class="grant-copy"><strong>${escapeHtml(grant.display_name || fileName(path) || "Enrolled folder")}</strong><span title="${escapeHtml(path)}">${escapeHtml(path)}</span></span>
            <span class="scope-chips">${permissions.map((permission) => `<span class="scope-chip">${escapeHtml(permission)}</span>`).join("")}</span>
            <button class="button button-secondary" type="button" data-revoke-grant="${escapeHtml(entityId(grant))}">Revoke</button>
          </div>`;
        }).join("")
      : emptyInline("Enroll a folder to authorize invoice CSV access.", null, null);
  }

  function isAbsolutePath(value) {
    return value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value) || value.startsWith("\\\\");
  }

  async function submitWorkflow(event) {
    event.preventDefault();
    const pathInput = el("source-input");
    const errorElement = el("source-error");
    const sourcePath = pathInput.value.trim();
    pathInput.removeAttribute("aria-invalid");
    errorElement.textContent = "";
    let error = "";
    if (!sourcePath) error = "Enter the path to an invoice CSV file.";
    else if (!isAbsolutePath(sourcePath)) error = "Use an absolute path inside an enrolled folder.";
    else if (!sourcePath.toLowerCase().endsWith(".csv")) error = "The first MVP accepts CSV files only.";
    if (error) {
      pathInput.setAttribute("aria-invalid", "true");
      errorElement.textContent = error;
      pathInput.focus();
      return;
    }
    const button = el("create-workflow-button");
    const original = button.innerHTML;
    button.disabled = true;
    button.textContent = "Creating…";
    const idempotencyKey = crypto.randomUUID ? crypto.randomUUID() : `web-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    try {
      const workflow = await api(API.workflows, {
        method: "POST",
        body: { kind: "invoice_report.v1", source_path: sourcePath, idempotency_key: idempotencyKey },
      });
      state.workflows.unshift(workflow);
      state.selectedWorkflowId = entityId(workflow);
      pathInput.value = "";
      renderAll();
      routeTo("workflows");
      toast("Workflow is ready", "Review it, then choose Run to begin execution.");
    } catch (requestError) {
      toast("Workflow was not created", requestError.message, "error");
    } finally {
      button.disabled = false;
      button.innerHTML = original;
    }
  }

  async function submitGrant(event) {
    event.preventDefault();
    const input = el("folder-path");
    const errorElement = el("folder-error");
    const path = input.value.trim();
    const permissions = queryAll('input[name="permissions"]:checked', event.currentTarget).map((field) => field.value);
    input.removeAttribute("aria-invalid");
    errorElement.textContent = "";
    if (!path || !isAbsolutePath(path)) {
      input.setAttribute("aria-invalid", "true");
      errorElement.textContent = "Enter an absolute folder path.";
      input.focus();
      return;
    }
    if (!permissions.length) {
      errorElement.textContent = "Select at least one permission.";
      return;
    }
    const button = el("enroll-button");
    button.disabled = true;
    button.textContent = "Enrolling…";
    try {
      const grant = await api(API.enroll, { method: "POST", body: { path, permissions } });
      const id = entityId(grant);
      const index = state.grants.findIndex((item) => entityId(item) === id);
      if (index >= 0) state.grants[index] = grant;
      else state.grants.unshift(grant);
      input.value = "";
      renderAll();
      toast("Folder enrolled", "The local service can now use files covered by this grant.");
    } catch (requestError) {
      toast("Folder was not enrolled", requestError.message, "error");
    } finally {
      button.disabled = false;
      button.textContent = "Enroll folder";
    }
  }

  async function revokeGrant(grantId, button) {
    if (!grantId) return;
    button.disabled = true;
    try {
      await api(`${API.grants}/${encodeURIComponent(grantId)}/revoke`, {
        method: "POST",
        body: {},
      });
      await Promise.all([loadResource("grants", API.grants), loadResource("receipts", API.receipts)]);
      renderAll();
      toast("Folder access revoked", "New reads through this grant are now blocked.");
    } catch (requestError) {
      button.disabled = false;
      toast("Folder access was not revoked", requestError.message, "error");
    }
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const character = text[index];
      if (quoted) {
        if (character === '"' && text[index + 1] === '"') { field += '"'; index += 1; }
        else if (character === '"') quoted = false;
        else field += character;
      } else if (character === '"') quoted = true;
      else if (character === ",") { row.push(field.trim()); field = ""; }
      else if (character === "\n") { row.push(field.trim()); if (row.some(Boolean)) rows.push(row); row = []; field = ""; }
      else if (character !== "\r") field += character;
    }
    row.push(field.trim());
    if (row.some(Boolean)) rows.push(row);
    return rows.slice(0, 201);
  }

  function prepareManualDraft() {
    const source = el("manual-source").value.trim();
    if (!source) {
      toast("Nothing to prepare", "Paste invoice text or CSV rows first.", "error");
      el("manual-source").focus();
      return;
    }
    const looksLikeCsv = source.includes(",") && source.includes("\n");
    if (looksLikeCsv) {
      const parsed = parseCsv(source);
      const width = Math.max(...parsed.map((row) => row.length), 1);
      const headers = parsed[0].map((value, index) => value || `Column ${index + 1}`);
      while (headers.length < width) headers.push(`Column ${headers.length + 1}`);
      const rows = parsed.slice(1);
      state.manualDraft = { type: "csv", headers, rows };
      el("manual-result").innerHTML = `
        <div class="manual-summary"><div><span>Rows detected</span><strong>${rows.length}</strong></div><div><span>Columns detected</span><strong>${headers.length}</strong></div></div>
        <div class="manual-table-wrap"><table class="manual-table"><thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${headers.map((_, index) => `<td contenteditable="true">${escapeHtml(row[index] ?? "")}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
    } else {
      const lines = source.split(/\n+/).map((line) => line.trim()).filter(Boolean).slice(0, 100);
      const rows = lines.map((line, index) => {
        const split = line.match(/^([^:]{1,50}):\s*(.+)$/);
        return split ? [split[1], split[2]] : [`Line ${index + 1}`, line];
      });
      state.manualDraft = { type: "text", headers: ["Field", "Observed text"], rows };
      el("manual-result").innerHTML = `
        <div class="manual-summary"><div><span>Lines detected</span><strong>${rows.length}</strong></div><div><span>Parser</span><strong>Key/value draft</strong></div></div>
        <div class="manual-table-wrap"><table class="manual-table"><thead><tr><th>Field</th><th>Observed text</th></tr></thead><tbody>${rows.map((row) => `<tr><td contenteditable="true">${escapeHtml(row[0])}</td><td contenteditable="true">${escapeHtml(row[1])}</td></tr>`).join("")}</tbody></table></div>`;
    }
    el("copy-manual-button").disabled = false;
  }

  async function copyManualDraft() {
    const table = query(".manual-table", el("manual-result"));
    if (!table) return;
    const lines = queryAll("tr", table).map((row) => queryAll("th, td", row).map((cell) => cell.textContent.trim()).join("\t"));
    try {
      await navigator.clipboard.writeText(lines.join("\n"));
      toast("Draft copied", "The browser-only draft is on your clipboard.");
    } catch {
      toast("Could not copy automatically", "Select the table content and copy it manually.", "error");
    }
  }

  function exportReceipts() {
    if (!state.receipts.length) {
      toast("No receipts to export", "Run a workflow effect first.", "error");
      return;
    }
    const blob = new Blob([JSON.stringify(state.receipts, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `luma-receipts-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast("Receipt export prepared", "The JSON file was created from the currently loaded records.");
  }

  function bindEvents() {
    document.addEventListener("click", (event) => {
      const routeLink = event.target.closest("[data-route]");
      if (routeLink) {
        event.preventDefault();
        routeTo(routeLink.dataset.route);
        return;
      }
      const workflowLink = event.target.closest("[data-open-workflow], [data-select-workflow]");
      if (workflowLink) {
        selectWorkflow(workflowLink.dataset.openWorkflow ?? workflowLink.dataset.selectWorkflow, Boolean(workflowLink.dataset.openWorkflow));
        return;
      }
      const runButton = event.target.closest("[data-run-workflow]");
      if (runButton) { runWorkflow(runButton.dataset.runWorkflow); return; }
      const artifactButton = event.target.closest("[data-select-artifact]");
      if (artifactButton) {
        selectArtifact(artifactButton.dataset.selectArtifact);
        return;
      }
      const revokeButton = event.target.closest("[data-revoke-grant]");
      if (revokeButton) revokeGrant(revokeButton.dataset.revokeGrant, revokeButton);
    });

    window.addEventListener("hashchange", () => routeTo(window.location.hash.slice(1), { keepHash: true, focus: false }));
    el("mobile-nav-button").addEventListener("click", () => {
      const sidebar = el("primary-nav");
      const open = !sidebar.classList.contains("is-open");
      sidebar.classList.toggle("is-open", open);
      el("mobile-nav-button").setAttribute("aria-expanded", String(open));
    });
    queryAll("[data-refresh]").forEach((button) => button.addEventListener("click", () => refreshAll({ announce: true })));
    el("workflow-form").addEventListener("submit", submitWorkflow);
    el("grant-form").addEventListener("submit", submitGrant);
    el("workflow-search").addEventListener("input", renderWorkflowList);
    el("workflow-filter").addEventListener("change", renderWorkflowList);
    el("artifact-detail").addEventListener("change", (event) => {
      if (event.target.id === "artifact-version-select") loadArtifactVersion(event.target.value);
    });
    el("manual-preview-button").addEventListener("click", () => {
      el("manual-dialog").showModal();
      window.setTimeout(() => el("manual-source").focus(), 40);
    });
    el("prepare-manual-button").addEventListener("click", prepareManualDraft);
    el("copy-manual-button").addEventListener("click", copyManualDraft);
    el("export-receipts-button").addEventListener("click", exportReceipts);
    el("manual-dialog").addEventListener("click", (event) => {
      if (event.target === el("manual-dialog")) el("manual-dialog").close();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden && state.pollingTimer) { window.clearInterval(state.pollingTimer); state.pollingTimer = null; }
      else if (!document.hidden) { refreshSelectedWorkflow(); ensurePolling(); }
    });
  }

  async function init() {
    bindEvents();
    routeTo(window.location.hash.slice(1), { keepHash: true, focus: false });
    await refreshAll();
  }

  init();
})();
