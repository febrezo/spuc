const state = {
  locale: localStorage.getItem("spuc-web-locale") || "en",
  theme: localStorage.getItem("spuc-web-theme") || "dark",
  translations: {},
  bootstrap: null,
  principal: null,
  route: "home",
  overview: null,
  rules: {
    page: 1,
    pageSize: 25,
    total: 0,
    entries: [],
    allEntries: [],
    selected: new Set(),
    lastSelectionIndex: -1,
    typeFilters: new Set(["siem", "ids", "content"]),
    observableFilter: "",
    tlpFilter: "ALL",
    papFilter: "ALL",
    sort: "confidence_desc",
    visibleColumns: new Set(["name", "confidence", "tlp", "pap", "rule", "observables", "indicates", "outputs", "emulation"]),
    bulkEditOpen: false,
    lastExportSelectedCsv: "",
    advancedFilters: [],
    workspaceMode: "welcome",
  },
  rulesImport: {
    active: false,
    phase: "idle",
    percent: 0,
    done: 0,
    total: 0,
    ok: 0,
    failed: 0,
  },
  abilities: { entries: [] },
  stixObjects: [],
  stixObjectsView: {
    workspaceMode: "welcome",
  },
  adversaries: {
    page: 1,
    pageSize: 20,
    total: 0,
    entries: [],
    allEntries: [],
    selected: new Set(),
    lastSelectionIndex: -1,
    bulkEditOpen: false,
    platformOptions: [],
    workspaceMode: "welcome",
    sort: "confidence_desc",
    visibleColumns: new Set(["name", "confidence", "tlp", "pap", "steps", "platforms", "exporters"]),
  },
  adversaryCompose: {
    search: "",
    platform: "",
    utility: "",
    destination: "",
    minConfidence: 0,
    selectedOrder: [],
    executor: "manifest",
    mode: "create",
    editingId: null,
    originalSignature: "",
    compatibleExports: [],
  },
  learning: { guides: [], challenges: [], search: "", pathFilter: "", onlyPending: false },
  adminUsers: [],
  compatibility: [],
  rulesFilterTimer: null,
  adversariesFilterTimer: null,
  ruleLab: {
    verifyTimer: null,
    compatibilityTimer: null,
    autocomplete: [],
    activeSuggestion: 0,
    verifyRequestId: 0,
    compatibilityRequestId: 0,
    syntaxOk: null,
    compatFilter: "",
  },
  learningEditor: {
    autocomplete: [],
    activeSuggestion: 0,
    verifyTimer: null,
    requestId: 0,
  },
  selectedChallenge: null,
  completedChallenges: new Set(),
  detailDetectionExport: null,
};

const STIX_TOKENS = [
  "process:name",
  "process:command_line",
  "process:pid",
  "process:cwd",
  "file:name",
  "file:size",
  "directory:path",
  "windows-registry-key:key",
  "windows-registry-key:values[*].name",
  "windows-registry-key:values[*].data",
  "network-traffic:dst_ref.value",
  "network-traffic:dst_port",
  "domain-name:value",
  "ipv4-addr:value",
  "url:value",
  "=",
  "!=",
  "LIKE",
  "MATCHES",
  "ISSUBSET",
  "ISSUPERSET",
  "AND",
  "OR",
  "NOT",
  "FOLLOWEDBY",
  "REPEATS",
  "WITHIN",
  "SECONDS",
  "START",
  "STOP",
];

const STIX_OBSERVABLE_FIELDS = {
  process: ["name", "command_line", "pid", "cwd"],
  file: ["name", "mime_type", "size", "hashes.MD5", "hashes.SHA-1", "hashes.SHA-256"],
  directory: ["path"],
  "windows-registry-key": [
    "key",
    "number_of_subkeys",
    "values[*].name",
    "values[*].data",
    "values[*].data_type",
  ],
  "network-traffic": ["src_ref.value", "src_ref.type", "src_port", "dst_ref.value", "dst_ref.type", "dst_port", "protocols"],
  "domain-name": ["value"],
  "ipv4-addr": ["value"],
  artifact: ["payload_bin"],
  url: ["value"],
};

const STIX_OBSERVABLES = Object.keys(STIX_OBSERVABLE_FIELDS);

const COMPATIBILITY_GROUPS = [
  { name: "SIEM", targets: ["sigma", "eql", "kql"] },
  { name: "IDS", targets: ["snort", "suricata"] },
  { name: "Content", targets: ["yara"] },
];
let RULE_OUTPUT_TARGETS = ["kql", "sigma", "eql", "snort", "suricata", "yara"];
const RULE_EMULATION_TARGETS = ["spuc-agent", "bash", "powershell", "atomic-red-team", "mitre-caldera"];
const RULE_COLUMN_KEYS = ["name", "confidence", "tlp", "pap", "rule", "observables", "indicates", "outputs", "emulation"];
const ADVERSARY_COLUMN_KEYS = ["name", "confidence", "tlp", "pap", "steps", "platforms", "exporters"];

const ROUTE_META = {
  home: { title: "route.home.title", subtitle: "route.home.subtitle" },
  dashboard: { title: "route.dashboard.title", subtitle: "route.dashboard.subtitle" },
  rules: { title: "route.rules.title", subtitle: "route.rules.subtitle" },
  "rules-catalog": { title: "route.rules.title", subtitle: "route.rules.subtitle" },
  "rules-create": { title: "route.rulelab.title", subtitle: "route.rulelab.subtitle" },
  "rules-import": { title: "route.rules.title", subtitle: "route.rules.subtitle" },
  rulelab: { title: "route.rulelab.title", subtitle: "route.rulelab.subtitle" },
  adversaries: { title: "route.adversaries.title", subtitle: "route.adversaries.subtitle" },
  "adversaries-catalog": { title: "route.adversaries.title", subtitle: "route.adversaries.subtitle" },
  "adversaries-create": { title: "route.adversaries.title", subtitle: "route.adversaries.subtitle" },
  "stix-objects": { title: "route.stix_objects.title", subtitle: "route.stix_objects.subtitle" },
  "stix-objects-catalog": { title: "route.stix_objects.title", subtitle: "route.stix_objects.subtitle" },
  learning: { title: "route.learning.title", subtitle: "route.learning.subtitle" },
  admin: { title: "route.admin.title", subtitle: "route.admin.subtitle" },
};

const LEARNING_GUIDE_LOCALIZATION = {
  es: {
    "intro-stix": {
      title: "Fundamentos de STIX Patterns",
      summary: "Modela comportamiento observable con entidades y operadores claros antes de traducir reglas.",
    },
    "rule-quality": {
      title: "Escribe reglas de detección precisas",
      summary: "Empieza con observables acotados y operadores explícitos para reducir conversiones no soportadas.",
    },
    "lab-flow": {
      title: "Usa el laboratorio de reglas",
      summary: "Valida sintaxis primero y después revisa compatibilidad y salida por destino lado a lado.",
    },
    compatibility: {
      title: "Interpreta estados de compatibilidad",
      summary: "Verde significa mapeo exacto, ámbar indica deriva semántica y rojo conversión no soportada.",
    },
    "adversary-build": {
      title: "Construye escenarios adversarios",
      summary: "Compón adversarios con capacidades validadas y exporta artefactos para el ejecutor elegido.",
    },
  },
};

const LEARNING_CHALLENGE_LOCALIZATION = {
  es: {
    core001: {
      title: "Bases de observables",
      goal: "Escribe un patrón que filtre por línea de comandos del proceso y use LIKE o MATCHES.",
      hint: "Usa process:command_line y una condición de texto como LIKE '%powershell%'.",
    },
    core002: {
      title: "Composición de operadores",
      goal: "Escribe un patrón con dos condiciones de proceso combinadas con AND.",
      hint: "Combina process:name y process:command_line con AND.",
    },
    core003: {
      title: "Coincidencia exacta básica",
      goal: "Detecta powershell.exe por nombre exacto de proceso.",
      hint: "Usa process:name con '=' y el valor 'powershell.exe'.",
    },
    core004: {
      title: "Negación simple",
      goal: "Excluye cmd.exe usando != sobre process:name.",
      hint: "Usa process:name != 'cmd.exe'.",
    },
    core005: {
      title: "Composición con OR",
      goal: "Combina mshta.exe y rundll32.exe usando OR.",
      hint: "Usa OR entre dos condiciones process:name.",
    },
    ops001: {
      title: "Triple AND",
      goal: "Escribe una observación con tres condiciones unidas por AND.",
      hint: "Usa process:name, process:command_line y process:pid conjuntamente.",
    },
    ops002: {
      title: "LIKE + MATCHES",
      goal: "Usa LIKE y MATCHES contra process:command_line.",
      hint: "Una condición con LIKE y otra con MATCHES.",
    },
    ops003: {
      title: "Precedencia booleana",
      goal: "Mezcla AND/OR con paréntesis para evitar ambigüedad.",
      hint: "Agrupa la rama OR con paréntesis y luego añade otra condición con AND.",
    },
    time001: {
      title: "Práctica de calificadores",
      goal: "Escribe un patrón con REPEATS ... TIMES WITHIN ... SECONDS.",
      hint: "Parte de un observable y añade calificadores REPEATS y WITHIN.",
    },
    time002: {
      title: "Ventana FOLLOWEDBY",
      goal: "Usa FOLLOWEDBY con WITHIN para una secuencia corta.",
      hint: "Crea dos observaciones de proceso y conéctalas con FOLLOWEDBY.",
    },
    time003: {
      title: "Repetición de red",
      goal: "Usa REPEATS ... TIMES WITHIN con un puerto de destino de red.",
      hint: "Empieza con network-traffic:dst_port y luego añade repetición temporal.",
    },
    time004: {
      title: "Ventana START / STOP",
      goal: "Restringe un patrón de proceso con timestamps START y STOP.",
      hint: "Añade START t'...' STOP t'...' después de la observación.",
    },
    net001: {
      title: "Tupla de red completa",
      goal: "Usa IP origen, IP destino, puerto destino y protocolo en un único patrón.",
      hint: "Combina src_ref.value, dst_ref.value, dst_port y protocols con AND.",
    },
    net002: {
      title: "CIDR ISSUBSET",
      goal: "Escribe ISSUBSET para rango IPv4 de origen con src_ref.type explícito.",
      hint: "Usa src_ref.type = 'ipv4-addr' y src_ref.value ISSUBSET '<cidr>'.",
    },
    file001: {
      title: "Tríada de archivo",
      goal: "Combina hash SHA-256, umbral de tamaño y nombre ejecutable.",
      hint: "Usa file:hashes.SHA-256, file:size y file:name LIKE '%.exe'.",
    },
  },
};

function t(key) {
  return state.translations?.[state.locale]?.[key] ?? state.translations?.en?.[key] ?? key;
}

function tf(key, vars = {}) {
  let text = t(key);
  Object.entries(vars).forEach(([name, value]) => {
    text = text.replaceAll(`{${name}}`, String(value));
  });
  return text;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderMarkdownInline(line) {
  return line
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
}

function renderMarkdown(text) {
  const source = String(text || "").trim();
  if (!source) {
    return `<p class="muted">${escapeHtml(t("markdown.preview.empty"))}</p>`;
  }
  const lines = escapeHtml(source).split(/\r?\n/);
  const out = [];
  let inCode = false;
  let inList = false;

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.startsWith("```")) {
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
      out.push(inCode ? "</code></pre>" : "<pre><code>");
      inCode = !inCode;
      continue;
    }
    if (inCode) {
      out.push(`${line}\n`);
      continue;
    }
    if (/^[-*]\s+/.test(line)) {
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      out.push(`<li>${renderMarkdownInline(line.replace(/^[-*]\s+/, ""))}</li>`);
      continue;
    }
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
    if (!line.trim()) {
      continue;
    }
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const level = heading[1].length;
      out.push(`<h${level}>${renderMarkdownInline(heading[2])}</h${level}>`);
    } else {
      out.push(`<p>${renderMarkdownInline(line)}</p>`);
    }
  }
  if (inList) out.push("</ul>");
  if (inCode) out.push("</code></pre>");
  return out.join("");
}

function setMarkdownEditorMode(editorId, mode) {
  const textarea = document.getElementById(editorId);
  const preview = document.getElementById(`${editorId}-preview`);
  if (!(textarea instanceof HTMLTextAreaElement) || !preview) return;
  const normalizedMode = mode === "preview" ? "preview" : "edit";
  const tabs = document.querySelectorAll(`[data-action="markdown-tab"][data-editor="${editorId}"]`);
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === normalizedMode));
  const previewMode = normalizedMode === "preview";
  textarea.classList.toggle("hidden", previewMode);
  preview.classList.toggle("hidden", !previewMode);
  if (previewMode) {
    preview.innerHTML = renderMarkdown(textarea.value);
  }
}

function refreshMarkdownEditorPreview(editorId) {
  const textarea = document.getElementById(editorId);
  const preview = document.getElementById(`${editorId}-preview`);
  if (!(textarea instanceof HTMLTextAreaElement) || !preview) return;
  preview.innerHTML = renderMarkdown(textarea.value);
}

function setTheme(theme) {
  state.theme = theme === "light" ? "light" : "dark";
  localStorage.setItem("spuc-web-theme", state.theme);
  document.body.classList.toggle("theme-light", state.theme === "light");
}

function applyTranslations() {
  document.documentElement.lang = state.locale;
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.placeholder = t(node.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((node) => {
    const label = t(node.dataset.i18nTitle);
    node.title = label;
    node.setAttribute("aria-label", label);
  });
  ["rulelab-description", "adversary-description"].forEach((editorId) => {
    refreshMarkdownEditorPreview(editorId);
  });
  const titleEditBtn = document.getElementById("adversary-title-edit");
  if (titleEditBtn) {
    titleEditBtn.title = t("adversaries.edit.title_action");
    titleEditBtn.setAttribute("aria-label", t("adversaries.edit.title_action"));
  }
  const exportInlineBtn = document.getElementById("adversary-export-inline-button");
  if (exportInlineBtn) {
    exportInlineBtn.title = t("adversaries.detail.export");
    exportInlineBtn.setAttribute("aria-label", t("adversaries.detail.export"));
  }
  renderRulesColumnPicker();
  renderAdversariesColumnPicker();
  renderStixObjectsTable();
  renderIndicatesObjectOptions();
  updateRulesBulkState();
  updateAdversariesBulkState();
  syncAdversaryModalTitle();
  refreshRouteMeta();
}

function refreshRouteMeta() {
  const meta = ROUTE_META[state.route] || ROUTE_META.dashboard;
  document.getElementById("route-title").textContent = t(meta.title);
  document.getElementById("route-subtitle").textContent = t(meta.subtitle);
}

function showToast(message, asKey = true) {
  const toast = document.getElementById("toast");
  toast.hidden = false;
  toast.textContent = asKey ? t(message) : message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
  }, 2800);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (_error) {
      payload = text;
    }
  }
  if (!response.ok) {
    const error = new Error(payload?.error || payload?.code || response.statusText || "request_failed");
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function badgeClass(statusOrSeverity) {
  const value = String(statusOrSeverity || "").toLowerCase();
  if (value.includes("exact") || value === "success") return "success";
  if (value.includes("lossy") || value.includes("dependent") || value === "warning") return "warning";
  return "error";
}

function statusBadge(label, statusOrSeverity) {
  const cls = badgeClass(statusOrSeverity);
  return `<span class="badge ${cls}">${escapeHtml(label)}</span>`;
}

function normalizeTlpValue(value) {
  const upper = String(value || "").trim().toUpperCase();
  const mapping = {
    "TLP:CLEAR": "TLP:CLEAR",
    "TLP:GREEN": "TLP:GREEN",
    "TLP:AMBER": "TLP:AMBER",
    "TLP:AMBER+STRICT": "TLP:AMBER+STRICT",
    "TLP:RED": "TLP:RED",
    CLEAR: "TLP:CLEAR",
    GREEN: "TLP:GREEN",
    AMBER: "TLP:AMBER",
    "AMBER+STRICT": "TLP:AMBER+STRICT",
    RED: "TLP:RED",
  };
  return mapping[upper] || "TLP:GREEN";
}

function normalizePapValue(value) {
  const upper = String(value || "").trim().toUpperCase();
  const mapping = {
    "PAP:CLEAR": "PAP:CLEAR",
    "PAP:GREEN": "PAP:GREEN",
    "PAP:AMBER": "PAP:AMBER",
    "PAP:RED": "PAP:RED",
    CLEAR: "PAP:CLEAR",
    GREEN: "PAP:GREEN",
    AMBER: "PAP:AMBER",
    RED: "PAP:RED",
  };
  return mapping[upper] || "PAP:GREEN";
}

function levelClassFromValue(value) {
  const upper = String(value || "").toUpperCase();
  if (upper === "ALL" || upper === "KEEP") return "level-clear";
  if (upper.includes("CLEAR")) return "level-clear";
  if (upper.includes("AMBER+STRICT")) return "level-amber-strict";
  if (upper.includes("AMBER")) return "level-amber";
  if (upper.includes("RED")) return "level-red";
  return "level-green";
}

function trafficOrder(value, kind = "tlp") {
  const normalized = kind === "pap" ? normalizePapValue(value) : normalizeTlpValue(value);
  const order = kind === "pap"
    ? ["PAP:CLEAR", "PAP:GREEN", "PAP:AMBER", "PAP:RED"]
    : ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];
  const index = order.indexOf(normalized);
  return index === -1 ? order.length : index;
}

function trafficBadge(value, kind = "tlp") {
  const normalized = kind === "pap" ? normalizePapValue(value) : normalizeTlpValue(value);
  const short = normalized.split(":")[1] || normalized;
  return `<span class="badge ${kind.toLowerCase()} ${levelClassFromValue(normalized)}">${escapeHtml(normalized)}</span>`;
}

function toQuery(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    search.set(key, String(value));
  });
  const raw = search.toString();
  return raw ? `?${raw}` : "";
}

function renderDetailActions(rightHtml = "") {
  return `
    <div class="detail-actions-left">
      <button class="btn btn-danger" data-action="detail-cancel">${escapeHtml(t("common.cancel"))}</button>
    </div>
    <div class="detail-actions-right">${rightHtml || ""}</div>
  `;
}

function setDetailModalMode(mode = "default", targetLabel = "", conversionStatus = "") {
  const tabs = document.getElementById("detail-tabs");
  const raw = document.getElementById("detail-raw");
  const badge = document.getElementById("detail-target-badge");
  const conversionBadge = document.getElementById("detail-conversion-status");
  const hideRawTabs = mode === "emulation";
  if (tabs) {
    tabs.classList.toggle("hidden", hideRawTabs);
  }
  if (raw) {
    raw.classList.toggle("hidden", hideRawTabs);
  }
  if (badge) {
    badge.classList.remove("badge-detection", "badge-emulation");
    if (targetLabel) {
      badge.textContent = targetLabel;
      if (mode === "detection") badge.classList.add("badge-detection");
      if (mode === "emulation") badge.classList.add("badge-emulation");
      badge.classList.remove("hidden");
    } else {
      badge.textContent = "";
      badge.classList.add("hidden");
    }
  }
  if (conversionBadge) {
    conversionBadge.classList.remove("success", "warning", "error");
    const normalized = String(conversionStatus || "").trim();
    if (normalized) {
      conversionBadge.textContent = `${t("common.status")}: ${statusLabel(normalized)}`;
      conversionBadge.classList.add(statusClass(normalized));
      conversionBadge.classList.remove("hidden");
    } else {
      conversionBadge.textContent = "";
      conversionBadge.classList.add("hidden");
    }
  }
}

function targetLabel(target, family = "emulation") {
  const normalized = String(target || "").toLowerCase();
  if (family === "detection") {
    if (normalized.startsWith("sigma-to-")) {
      return normalized.toUpperCase();
    }
    return String(target || "").toUpperCase();
  }
  const mapping = {
    "spuc-agent": "SPUC",
    bash: "Bash",
    powershell: "PowerShell",
    "atomic-red-team": "Atomic Red Team",
    "mitre-caldera": "MITRE CALDERA",
  };
  return mapping[normalized] || String(target || "");
}

function detailBadgeText(mode, target) {
  const value = targetLabel(target, mode);
  if (!value) return "";
  if (mode === "detection") {
    return tf("detail.badge.detection", { target: value });
  }
  if (mode === "emulation") {
    return tf("detail.badge.emulation", { target: value });
  }
  return value;
}

function inlineHelpTip(text) {
  return `
    <span class="help-tip detail-help-tip" tabindex="0" aria-label="Info">
      <span class="help-tip-icon">?</span>
      <span class="help-tip-content">${escapeHtml(text)}</span>
    </span>
  `;
}

function availableRuleEmulationTargets(entry) {
  if (!entry?.ability_id) return [];
  return RULE_EMULATION_TARGETS.filter((target) => statusBucket(entry.emulation_statuses?.[target] || "unsupported") !== "unsupported");
}

function openDetail(title, payload, extra = "") {
  const raw = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  state.detailDetectionExport = null;
  document.getElementById("detail-title").textContent = title;
  setDetailModalMode("default");
  document.getElementById("detail-view").innerHTML = `
    <section class="detail-section">
      <h4>${escapeHtml(t("common.details"))}</h4>
      <pre class="detail-code">${escapeHtml(raw || "")}</pre>
    </section>
  `;
  document.getElementById("detail-raw").textContent = raw || "";
  document.getElementById("detail-actions").innerHTML = renderDetailActions(extra);
  setDetailTab("view");
  document.getElementById("detail-dialog").showModal();
}

function openRuleDetail(entry) {
  state.detailDetectionExport = null;
  const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
    ? entry.indicates_list
    : (entry.indicates ? [entry.indicates] : []);
  const indicatesSection = indicatesList.length
    ? `
      <section class="detail-section">
        <h4>${escapeHtml(t("rules.indicates.existing"))}</h4>
        <div class="indicates-existing-list">
          ${indicatesList
            .map((relation) => `
              <div class="indicates-pill" title="${escapeHtml(relation.stix_id)}">
                <strong>${escapeHtml(relation.object_name || relation.stix_id)}</strong>
                <small>${escapeHtml(relation.stix_id)}</small>
              </div>
            `)
            .join("")}
        </div>
      </section>
    `
    : "";
  const view = `
    <section class="detail-section">
      <h4>${escapeHtml(t("rules.col.name"))}</h4>
      <div class="detail-grid">
        <div class="detail-kv"><span class="label">${escapeHtml(t("common.id"))}</span><code>${escapeHtml(entry.id || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("rules.col.confidence"))}</span><code>${escapeHtml(String(entry.confidence ?? "-"))}</code></div>
        <div class="detail-kv"><span class="label">TLP</span>${trafficBadge(entry.tlp, "tlp")}</div>
        <div class="detail-kv"><span class="label">PAP</span>${trafficBadge(entry.pap, "pap")}</div>
      </div>
    </section>
    <section class="detail-section">
      <div class="detail-code-wrap">
        <div class="detail-code-head">
          <h4>${escapeHtml(t("rules.col.rule"))}</h4>
          ${copyButtonFor(entry.rule || "", t("common.copy"))}
        </div>
        <pre class="detail-code">${escapeHtml(entry.rule || "")}</pre>
      </div>
    </section>
    ${indicatesSection}
  `;
  const targets = availableRuleEmulationTargets(entry);
  const emulationActions = targets.length
    ? `
      <div class="detail-copy-emulation">
        <select id="detail-emulation-target">
          ${targets
            .map((target) => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`)
            .join("")}
        </select>
        <button
          class="btn btn-primary"
          data-action="rule-copy-emulation"
          data-id="${escapeHtml(entry.id)}"
          data-ability="${escapeHtml(entry.ability_id || "")}"
        >
          ${escapeHtml(t("detail.copy_emulation"))}
        </button>
      </div>
    `
    : "";
  document.getElementById("detail-title").textContent = entry.name || t("rules.col.rule");
  setDetailModalMode("default");
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = JSON.stringify(entry, null, 2);
  document.getElementById("detail-actions").innerHTML = renderDetailActions(emulationActions);
  setDetailTab("view");
  document.getElementById("detail-dialog").showModal();
}

function renderIndicatesExistingList(relations) {
  const root = document.getElementById("indicates-existing");
  const list = document.getElementById("indicates-existing-list");
  if (!root || !list) return;
  const safeRelations = Array.isArray(relations) ? relations : [];
  if (!safeRelations.length) {
    root.classList.add("hidden");
    list.innerHTML = "";
    return;
  }
  root.classList.remove("hidden");
  list.innerHTML = safeRelations
    .map((relation) => `
      <button
        type="button"
        class="indicates-pill indicates-pill-action"
        data-action="indicates-fill"
        data-stix-id="${escapeHtml(relation.stix_id || "")}"
        data-object-name="${escapeHtml(relation.object_name || "")}"
        title="${escapeHtml(relation.stix_id || "")}"
      >
        <strong>${escapeHtml(relation.object_name || relation.stix_id || "-")}</strong>
        <small>${escapeHtml(relation.stix_id || "-")}</small>
      </button>
    `)
    .join("");
}

function setDetailTab(tab) {
  const view = document.getElementById("detail-view");
  const raw = document.getElementById("detail-raw");
  const viewBtn = document.getElementById("detail-tab-view");
  const jsonBtn = document.getElementById("detail-tab-json");
  const isJson = tab === "json";
  view.classList.toggle("hidden", isJson);
  raw.classList.toggle("hidden", !isJson);
  viewBtn.classList.toggle("active", !isJson);
  jsonBtn.classList.toggle("active", isJson);
}

function copyButtonFor(text, label = "") {
  if (!text) return "";
  return `<button class="btn btn-ghost" data-action="detail-copy" data-copy="${encodeURIComponent(text)}">${escapeHtml(label || t("common.copy"))}</button>`;
}

function detectionHintSteps(target) {
  const normalized = String(target || "").toLowerCase().replaceAll("-", "_");
  const fallback = String(target || "").toLowerCase().startsWith("sigma-to-") ? "sigma" : null;
  const steps = [];
  for (let idx = 1; idx <= 4; idx += 1) {
    const key = `detail.detection.hint.${normalized}.${idx}`;
    const text = t(key);
    if (text === key) {
      if (fallback) {
        const fallbackKey = `detail.detection.hint.${fallback}.${idx}`;
        const fallbackText = t(fallbackKey);
        if (fallbackText !== fallbackKey) {
          steps.push(fallbackText);
          continue;
        }
      }
      break;
    }
    steps.push(text);
  }
  if (steps.length === 0) {
    return `<ol class="hint-steps"><li>${escapeHtml(t("detail.detection.hint.default"))}</li></ol>`;
  }
  return `<ol class="hint-steps">${steps.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
}

function detectionUtilityLinks(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "sigma" || normalized.startsWith("sigma-to-")) {
    return [
      { label: "Sigma", url: "https://sigmahq.io/" },
      { label: "Sigma", url: "https://github.com/SigmaHQ/sigma-cli" },
    ];
  }
  if (normalized === "kql") {
    return [{ label: "KQL Documentation", url: "https://learn.microsoft.com/kusto/query/" }];
  }
  if (normalized === "eql") {
    return [{ label: "Elastic EQL", url: "https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html" }];
  }
  if (normalized === "snort") {
    return [{ label: "Snort", url: "https://www.snort.org/" }];
  }
  if (normalized === "suricata") {
    return [{ label: "Suricata", url: "https://suricata.io/" }];
  }
  if (normalized === "yara") {
    return [{ label: "YARA", url: "https://virustotal.github.io/yara/" }];
  }
  return [];
}

function detectionExecutionCommand(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "sigma") {
    return "sigma convert -t splunk -r <rule.yml>";
  }
  if (normalized.startsWith("sigma-to-")) {
    const backend = normalized.replace("sigma-to-", "");
    return `sigma convert -t ${backend} -r <rule.yml>`;
  }
  if (normalized === "snort") {
    return "snort -A console -q -c /etc/snort/snort.conf -R <rule.rules> -r <traffic.pcap>";
  }
  if (normalized === "suricata") {
    return "suricata -S <rule.rules> -r <traffic.pcap> -k none";
  }
  if (normalized === "yara") {
    return "yara <rule.yar> <sample_or_directory>";
  }
  return "";
}

function renderDetectionDetonationGuide(target) {
  const links = detectionUtilityLinks(target);
  const command = detectionExecutionCommand(target);
  const steps = detectionHintSteps(target);
  const linksHtml = links.length
    ? `<ul class="hint-steps">${links.map((item) => `<li><a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">${escapeHtml(item.label)}</a></li>`).join("")}</ul>`
    : `<div class="muted">${escapeHtml(t("detail.detection.no_links"))}</div>`;
  const commandHtml = command
    ? `<pre class="detail-code">${escapeHtml(command)}</pre>`
    : `<div class="muted">${escapeHtml(t("detail.detection.no_command"))}</div>`;
  return `
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.detection.detonation"))}</h4>
      ${steps}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.detection.command"))}</h4>
      ${commandHtml}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.detection.utility_links"))}</h4>
      ${linksHtml}
    </section>
  `;
}

function openConversionDetail(title, stixRule, detail) {
  const target = String(detail?.target || "").toLowerCase();
  const displayTarget = targetLabel(target, "detection");
  const output = detail?.output || "";
  state.detailDetectionExport = {
    title,
    target,
    output,
  };
  const view = `
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.conversion.summary"))}</h4>
      <div class="detail-grid">
        <div class="detail-kv">
          <span class="label label-with-help">
            ${escapeHtml(t("detail.conversion.confidence"))}
            ${inlineHelpTip(t("detail.tooltip.conversion_confidence"))}
          </span>
          <code>${escapeHtml(String(detail?.conversion_confidence ?? "-"))}</code>
        </div>
        <div class="detail-kv">
          <span class="label label-with-help">
            ${escapeHtml(t("detail.rule.confidence"))}
            ${inlineHelpTip(t("detail.tooltip.rule_confidence"))}
          </span>
          <code>${escapeHtml(String(detail?.rule_confidence ?? "-"))}</code>
        </div>
      </div>
      <div class="muted">${escapeHtml(detail?.summary || t("detail.no_summary"))}</div>
      ${detail?.cause ? `<div class="muted"><strong>${escapeHtml(t("detail.cause"))}:</strong> ${escapeHtml(detail.cause)}</div>` : ""}
    </section>
    <section class="detail-section">
      <div class="detail-code-wrap">
        <div class="detail-code-head">
          <h4>${escapeHtml(t("detail.stix_rule"))}</h4>
          ${copyButtonFor(stixRule, t("detail.copy_rule"))}
        </div>
        <pre class="detail-code">${escapeHtml(stixRule || "")}</pre>
      </div>
    </section>
    <section class="detail-section">
      <div class="detail-code-wrap">
        <div class="detail-code-head">
          <h4>${escapeHtml(tf("detail.output_target", { target: displayTarget }))}</h4>
        </div>
        <pre class="detail-code">${escapeHtml(output || t("detail.no_output_for_target"))}</pre>
      </div>
    </section>
    ${renderDetectionDetonationGuide(target)}
  `;
  const rightActions = [];
  if (output && String(output).trim()) {
    rightActions.push(
      `<button class="btn btn-ghost" data-action="detail-copy" data-copy="${escapeHtml(encodeURIComponent(output))}">${escapeHtml(t("detail.copy_output"))}</button>`,
    );
    rightActions.push(
      `<button class="btn btn-success" data-action="detail-export-detection">${escapeHtml(tf("detail.export_rule", { target: displayTarget }))}</button>`,
    );
  }
  document.getElementById("detail-title").textContent = title;
  setDetailModalMode("detection", detailBadgeText("detection", target), detail?.runtime_status || "unsupported");
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = JSON.stringify(detail, null, 2);
  document.getElementById("detail-actions").innerHTML = renderDetailActions(rightActions.join(""));
  setDetailTab("view");
  document.getElementById("detail-dialog").showModal();
}

function emulationUtilityLinks(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "spuc-agent") {
    return [{ label: "SPUC Releases", url: "https://github.com/febrezo/spuc/releases" }];
  }
  if (normalized === "bash") {
    return [{ label: "GNU Bash", url: "https://www.gnu.org/software/bash/" }];
  }
  if (normalized === "powershell") {
    return [{ label: "PowerShell Releases", url: "https://github.com/PowerShell/PowerShell/releases" }];
  }
  if (normalized === "atomic-red-team") {
    return [{ label: "Atomic Red Team", url: "https://github.com/redcanaryco/atomic-red-team" }];
  }
  if (normalized === "mitre-caldera") {
    return [{ label: "MITRE CALDERA", url: "https://github.com/mitre/caldera" }];
  }
  return [];
}

function emulationExecutionCommand(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "spuc-agent") {
    return "spuc-agent validate --file <payload.json> && spuc-agent run --file <payload.json>";
  }
  if (normalized === "bash") {
    return "chmod +x <payload.sh> && ./<payload.sh>";
  }
  if (normalized === "powershell") {
    return "powershell -ExecutionPolicy Bypass -File .\\payload.ps1";
  }
  if (normalized === "atomic-red-team") {
    return "Invoke-AtomicTest <technique_id> -PathToAtomicsFolder <path>";
  }
  if (normalized === "mitre-caldera") {
    return "curl -X POST <caldera_url>/api/rest -H \"KEY:<api_key>\" -d @<ability.json>";
  }
  return "";
}

function renderEmulationDetonationGuide(target) {
  const links = emulationUtilityLinks(target);
  const command = emulationExecutionCommand(target);
  const steps = ruleExportHintSteps(target);
  const linksHtml = links.length
    ? `<ul class="hint-steps">${links.map((item) => `<li><a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">${escapeHtml(item.label)}</a></li>`).join("")}</ul>`
    : `<div class="muted">${escapeHtml(t("detail.emulation.no_links"))}</div>`;
  const commandHtml = command
    ? `<pre class="detail-code">${escapeHtml(command)}</pre>`
    : `<div class="muted">${escapeHtml(t("detail.emulation.no_command"))}</div>`;
  return `
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.detonation"))}</h4>
      ${steps}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.command"))}</h4>
      ${commandHtml}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.utility_links"))}</h4>
      ${linksHtml}
    </section>
  `;
}

function openEmulationDetail(title, stixRule, payload) {
  state.detailDetectionExport = null;
  const selectedTarget = String(payload?.selected_target || "").toLowerCase();
  const availableTargets = Array.isArray(payload?.available_targets) && payload.available_targets.length
    ? [...new Set(payload.available_targets.map((target) => String(target || "").toLowerCase()).filter(Boolean))]
    : (selectedTarget ? [selectedTarget] : []);
  const initialTarget = availableTargets.includes(selectedTarget) ? selectedTarget : (availableTargets[0] || selectedTarget);
  const actions = Array.isArray(payload?.actions) ? payload.actions : [];
  const actionsHtml = actions.length
    ? actions
      .map(
        (action, index) => `
          <section class="detail-section">
            <h4>${escapeHtml(tf("detail.action_n", { n: index + 1 }))}: ${escapeHtml(action.action_type || t("common.na"))}</h4>
            <div class="detail-grid">
              <div class="detail-kv"><span class="label">${escapeHtml(t("detail.observable"))}</span><code>${escapeHtml(action.observable || "-")}</code></div>
              <div class="detail-kv"><span class="label">${escapeHtml(t("detail.operator"))}</span><code>${escapeHtml(action.operator || "-")}</code></div>
              <div class="detail-kv"><span class="label">${escapeHtml(t("detail.value"))}</span><code>${escapeHtml(action.value || "-")}</code></div>
            </div>
            <pre class="detail-code">${escapeHtml(action.safe_instructions || t("detail.no_instructions"))}</pre>
          </section>
        `,
      )
      .join("")
    : `<section class="detail-section"><div class="muted">${escapeHtml(t("detail.no_actions"))}</div></section>`;

  const view = `
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.summary"))}</h4>
      <div class="detail-grid">
        <div class="detail-kv"><span class="label">${escapeHtml(t("common.status"))}</span>${statusBadge(payload?.status || "unsupported", payload?.status || "error")}</div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.ability"))}</span><code>${escapeHtml(payload?.ability_name || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.ability_id"))}</span><code>${escapeHtml(payload?.ability_id || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.level"))}</span><code>${escapeHtml(payload?.emulation_level || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.platforms"))}</span><code>${escapeHtml((payload?.platforms || []).join(", ") || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.classification"))}</span><code>${escapeHtml(payload?.classification || "-")}</code></div>
      </div>
      ${payload?.note ? `<div class="muted">${escapeHtml(payload.note)}</div>` : ""}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.available_exports"))}</h4>
      <div class="chip-list">
        ${availableTargets.map((target) => `<span class="rule-observable-tag">${escapeHtml(targetLabel(target, "emulation"))}</span>`).join("") || `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
      </div>
    </section>
    <section class="detail-section">
      <div class="detail-code-wrap">
        <div class="detail-code-head">
          <h4>${escapeHtml(t("detail.stix_rule"))}</h4>
          ${copyButtonFor(stixRule, t("detail.copy_rule"))}
        </div>
        <pre class="detail-code">${escapeHtml(stixRule || "")}</pre>
      </div>
    </section>
    ${actionsHtml}
    ${initialTarget ? `<section id="emulation-detonation-guide">${renderEmulationDetonationGuide(initialTarget)}</section>` : ""}
  `;
  document.getElementById("detail-title").textContent = title;
  setDetailModalMode("emulation", detailBadgeText("emulation", initialTarget || selectedTarget));
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = "";
  document.getElementById("detail-actions").innerHTML = renderDetailActions(
    payload?.ability_id && initialTarget
      ? `<button class="btn btn-success" data-action="emulation-export-download" data-ability="${escapeHtml(payload.ability_id)}" data-target="${escapeHtml(initialTarget)}">${escapeHtml(t("detail.emulation.download_payload"))}</button>`
      : "",
  );
  document.getElementById("detail-dialog").showModal();
}

function renderTable(tableId, headers, rows) {
  const table = document.getElementById(tableId);
  table.innerHTML = `
    <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
    <tbody>${rows.join("")}</tbody>
  `;
}

function sortIndicator(current, asc, desc) {
  if (current === asc) return "↑";
  if (current === desc) return "↓";
  return "↕";
}

function sortableHeader(label, action, column, currentSort, asc, desc) {
  const indicator = sortIndicator(currentSort, asc, desc);
  return `
    <th class="th-sortable">
      <button class="th-sort-btn" data-action="${action}" data-column="${column}">
        <span>${escapeHtml(label)}</span>
        <span class="sort-indicator">${indicator}</span>
      </button>
    </th>
  `;
}

function renderPager(rootId, currentPage, pageSize, total, actionPrefix) {
  const root = document.getElementById(rootId);
  const maxPage = Math.max(1, Math.ceil(total / pageSize));
  root.innerHTML = `
    <button class="btn btn-ghost" data-action="${actionPrefix}-page" data-page="${Math.max(1, currentPage - 1)}" ${currentPage <= 1 ? "disabled" : ""}>${escapeHtml(t("common.prev"))}</button>
    <span>${currentPage}/${maxPage}</span>
    <button class="btn btn-ghost" data-action="${actionPrefix}-page" data-page="${Math.min(maxPage, currentPage + 1)}" ${currentPage >= maxPage ? "disabled" : ""}>${escapeHtml(t("common.next"))}</button>
  `;
}

function renderBarChart(rootId, entries, palette) {
  const root = document.getElementById(rootId);
  if (!entries || entries.length === 0) {
    root.innerHTML = `<div class="muted">${escapeHtml(t("common.no_data"))}</div>`;
    return;
  }
  const max = Math.max(...entries.map((entry) => entry.count), 1);
  root.innerHTML = entries
    .map((entry, idx) => {
      const width = Math.max(3, Math.round((entry.count / max) * 100));
      const color = palette[idx % palette.length];
      return `
        <div class="bar-row">
          <span>${escapeHtml(entry.name)}</span>
          <div class="bar-track"><span class="bar-fill" style="width:${width}%; background:${color}"></span></div>
          <strong>${entry.count}</strong>
        </div>
      `;
    })
    .join("");
}

function renderCoverageChart(rootId, entries, palette) {
  const root = document.getElementById(rootId);
  if (!entries || entries.length === 0) {
    root.innerHTML = `<div class="muted">${escapeHtml(t("common.no_data"))}</div>`;
    return;
  }
  const max = Math.max(...entries.map((entry) => Number(entry.percent || 0)), 1);
  root.innerHTML = entries
    .map((entry, idx) => {
      const percent = Number(entry.percent || 0);
      const width = Math.max(3, Math.round((percent / max) * 100));
      const color = palette[idx % palette.length];
      return `
        <div class="bar-row">
          <span>${escapeHtml(entry.name)}</span>
          <div class="bar-track"><span class="bar-fill" style="width:${width}%; background:${color}"></span></div>
          <strong>${escapeHtml(percent.toFixed(1))}%</strong>
        </div>
      `;
    })
    .join("");
}

function statusBucket(status) {
  const lower = String(status || "").toLowerCase();
  if (lower.includes("exact")) return "exact";
  if (lower.includes("lossy") || lower.includes("dependent") || lower.includes("partial")) return "lossy";
  return "unsupported";
}

function statusClass(status) {
  const bucket = statusBucket(status);
  if (bucket === "exact") return "success";
  if (bucket === "lossy") return "warning";
  return "error";
}

function renderStatusChip(label, status, action, payload = {}) {
  return `<button class="status-chip ${statusClass(status)}" data-action="${action}" ${Object.entries(payload)
    .map(([key, value]) => `data-${key}="${escapeHtml(String(value))}"`)
    .join(" ")}>${escapeHtml(label)}</button>`;
}

function renderCompatibilityStack(groups) {
  const root = document.getElementById("compatibility-stack");
  if (!root) return;
  if (!groups || groups.length === 0) {
    root.innerHTML = "";
    return;
  }

  root.innerHTML = groups
    .map((group) => {
      const total = group.exact + group.lossy + group.unsupported;
      const exact = total ? Math.round((group.exact / total) * 100) : 0;
      const lossy = total ? Math.round((group.lossy / total) * 100) : 0;
      const unsupported = Math.max(0, 100 - exact - lossy);
      return `
        <div class="stack-row">
          <strong>${escapeHtml(group.name)}</strong>
          <div class="stack-track">
            <span class="stack-segment exact" style="width:${exact}%"></span>
            <span class="stack-segment lossy" style="width:${lossy}%"></span>
            <span class="stack-segment unsupported" style="width:${unsupported}%"></span>
          </div>
          <span>${group.exact}/${group.lossy}/${group.unsupported}</span>
        </div>
      `;
    })
    .join("");
}

function highlightStix(raw) {
  const escaped = escapeHtml(raw);
  return escaped
    .replace(/(\[|\])/g, '<span class="token bracket">$1</span>')
    .replace(/\b(AND|OR|NOT|FOLLOWEDBY|REPEATS|WITHIN|SECONDS|START|STOP)\b/g, '<span class="token logic">$1</span>')
    .replace(/\b(MATCHES|LIKE|ISSUBSET|ISSUPERSET|IN|!=|=)\b/g, '<span class="token operator">$1</span>')
    .replace(/([A-Za-z0-9_-]+:[A-Za-z0-9_\.\*\[\]]+)/g, '<span class="token observable">$1</span>')
    .replace(/('[^']*')/g, '<span class="token string">$1</span>');
}

function populateFooter() {
  const app = state.bootstrap.app;
  document.getElementById("footer-copyright").textContent = `© ${app.year}`;
  document.getElementById("footer-version").textContent = `v${app.version}`;
  const projectLink = document.getElementById("footer-project-link");
  projectLink.href = app.project_url;
  if (app.project_name && !projectLink.dataset.i18n) {
    projectLink.textContent = app.project_name;
  }
  const licenseLink = document.getElementById("footer-license-link");
  licenseLink.href = app.license_url;
  licenseLink.textContent = app.license_name || t("login.license");
}

function setupLoginProviders() {
  const providers = state.bootstrap.auth.providers || [];
  const buttons = document.querySelectorAll("[data-provider]");
  buttons.forEach((button) => {
    const provider = providers.find((item) => item.id === button.dataset.provider);
    button.disabled = !provider?.enabled;
    if (provider?.enabled) {
      button.title = t("login.oauth_enabled");
    } else if (provider?.configured && !provider?.authorized) {
      button.title = t("login.oauth_not_authorized");
    } else if (!provider?.configured) {
      button.title = t("login.oauth_not_configured");
    } else {
      button.title = t("login.oauth_disabled");
    }
  });
}

function applyNavSelection(route) {
  const rootRoute = route === "rulelab"
    ? "rules"
    : route.startsWith("rules-")
    ? "rules"
    : route.startsWith("adversaries-")
      ? "adversaries"
      : route.startsWith("stix-objects")
        ? "stix-objects"
      : route;
  document.querySelectorAll(".nav-item").forEach((item) => {
    const itemRoute = item.dataset.route || "";
    const active = itemRoute === route || itemRoute === rootRoute;
    item.classList.toggle("active", active);
  });
}

function setRoute(route) {
  if (!ROUTE_META[route]) route = "home";
  if (route === "admin" && (state.bootstrap?.auth?.no_login || state.principal?.role !== "admin")) {
    route = "home";
  }
  state.route = route;
  const panelRoute = route === "rules-create"
    ? "rulelab"
    : route.startsWith("rules-")
    ? "rules"
    : route.startsWith("adversaries-")
      ? "adversaries"
      : route.startsWith("stix-objects")
        ? "stix-objects"
      : route;
  applyNavSelection(route);
  document.querySelectorAll(".panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `panel-${panelRoute}`);
  });
  refreshRouteMeta();

  if (route === "dashboard") renderDashboard();
  if (panelRoute === "rules") {
    if (route === "rules") {
      state.rules.workspaceMode = "welcome";
    } else if (route === "rules-import") {
      state.rules.workspaceMode = "file";
    } else {
      state.rules.workspaceMode = "explore";
    }
    renderRulesWorkspace();
    loadRules();
    if (route === "rules-import") {
      setTimeout(() => document.getElementById("rules-new-file")?.focus(), 0);
    }
  }
  if (panelRoute === "rulelab") {
    setMarkdownEditorMode("rulelab-description", "preview");
    refreshMarkdownEditorPreview("rulelab-description");
    renderRuleLabPreview();
    setTimeout(() => document.getElementById("rulelab-input")?.focus(), 0);
  }
  if (panelRoute === "adversaries") {
    if (route === "adversaries") {
      state.adversaries.workspaceMode = "welcome";
    } else {
      state.adversaries.workspaceMode = "catalog";
    }
    renderAdversaryWorkspace();
    loadAdversaries();
    if (route === "adversaries-create") {
      setTimeout(() => openAdversaryDialog(), 0);
    }
  }
  if (panelRoute === "stix-objects") {
    if (route === "stix-objects") {
      state.stixObjectsView.workspaceMode = "welcome";
    } else {
      state.stixObjectsView.workspaceMode = "catalog";
    }
    renderStixObjectsWorkspace();
    loadStixObjects();
  }
  if (route === "learning") loadLearning();
  if (route === "admin") loadAdminUsers();

  if (window.innerWidth <= 900) {
    document.body.classList.remove("sidebar-open");
    document.getElementById("sidebar-backdrop").classList.add("hidden");
  }
}

function normalizeDetectionTargets(values) {
  const normalized = Array.isArray(values)
    ? [...new Set(values.map((item) => String(item || "").toLowerCase()).filter(Boolean))]
    : [];
  if (normalized.length > 0) return normalized;
  return ["kql", "sigma", "eql", "snort", "suricata", "yara"];
}

async function bootstrap() {
  state.bootstrap = await api("/api/bootstrap");
  state.principal = state.bootstrap.auth.principal || null;
  RULE_OUTPUT_TARGETS = normalizeDetectionTargets(state.bootstrap?.translation?.available_targets);

  populateFooter();
  setupLoginProviders();
  document.getElementById("locale-select").value = state.locale;
  document.getElementById("logout-button").classList.toggle("hidden", !state.bootstrap.auth.show_logout);

  const adminNavSection = document.getElementById("admin-nav-section");
  if (state.bootstrap.auth.no_login || !state.principal || state.principal.role !== "admin") {
    document.querySelector('[data-route="admin"]')?.classList.add("hidden");
    adminNavSection?.classList.add("hidden");
  } else {
    document.querySelector('[data-route="admin"]')?.classList.remove("hidden");
    adminNavSection?.classList.remove("hidden");
  }

  const noLoginActive = state.bootstrap.auth.no_login;
  document.getElementById("identity-pill").textContent = noLoginActive
    ? t("common.local_user")
    : (state.principal
      ? `${state.principal.username} · ${state.principal.role}`
      : t("common.not_authenticated"));
  if (noLoginActive || state.bootstrap.auth.authenticated) {
    enterApplication();
  } else {
    showLogin();
  }
}

function showLogin() {
  document.getElementById("login-view").classList.remove("hidden");
  document.getElementById("app-view").classList.add("hidden");
}

function enterApplication() {
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-view").classList.remove("hidden");
  const remembered = localStorage.getItem("spuc-web-last-route") || "home";
  setRoute(remembered);
  loadSharedData();
}

async function loadSharedData() {
  await Promise.all([loadOverview(), loadRules(), loadAbilities(), loadAdversaries(), loadStixObjects()]);
  await loadLearning();
  if (state.principal?.role === "admin" && !state.bootstrap?.auth?.no_login) {
    await loadAdminUsers();
  }
  renderDashboard();
  renderAdversaryAbilitySelector();
}

async function loadOverview() {
  state.overview = await api("/api/overview");
}

function renderDashboard() {
  if (!state.overview) return;

  const welcomeDismissed = localStorage.getItem("spuc-web-welcome-dismissed") === "1";
  const welcome = document.getElementById("welcome-card");
  if (welcomeDismissed) {
    welcome.classList.add("hidden");
  } else {
    welcome.classList.remove("hidden");
    welcome.innerHTML = `
      <h2>${escapeHtml(t("welcome.title"))}</h2>
      <p class="muted">${escapeHtml(t("welcome.subtitle"))}</p>
      <div class="welcome-stack">
        <button class="welcome-action welcome-action-row" data-action="welcome-nav" data-route="rules-catalog"><span class="welcome-icon" aria-hidden="true">📚</span><span class="welcome-copy"><strong>${escapeHtml(t("welcome.rules.title"))}</strong><span class="muted">${escapeHtml(t("welcome.rules.desc"))}</span></span></button>
        <button class="welcome-action welcome-action-row" data-action="welcome-nav" data-route="rulelab"><span class="welcome-icon" aria-hidden="true">🧪</span><span class="welcome-copy"><strong>${escapeHtml(t("welcome.lab.title"))}</strong><span class="muted">${escapeHtml(t("welcome.lab.desc"))}</span></span></button>
        <button class="welcome-action welcome-action-row" data-action="welcome-nav" data-route="adversaries-catalog"><span class="welcome-icon" aria-hidden="true">🛰️</span><span class="welcome-copy"><strong>${escapeHtml(t("welcome.adv.title"))}</strong><span class="muted">${escapeHtml(t("welcome.adv.desc"))}</span></span></button>
        <button class="welcome-action welcome-action-row" data-action="welcome-nav" data-route="learning"><span class="welcome-icon" aria-hidden="true">📘</span><span class="welcome-copy"><strong>${escapeHtml(t("welcome.learn.title"))}</strong><span class="muted">${escapeHtml(t("welcome.learn.desc"))}</span></span></button>
      </div>
      <button class="btn btn-ghost" data-action="welcome-dismiss">${escapeHtml(t("welcome.dismiss"))}</button>
    `;
  }

  const kpis = state.overview.kpis;
  document.getElementById("kpi-grid").innerHTML = [
    [t("kpi.rules"), kpis.rules_total],
    [t("kpi.adversaries"), kpis.adversaries_total],
    [t("kpi.abilities"), kpis.abilities_total],
    [t("kpi.destinations"), kpis.supported_destinations],
    [t("kpi.engines"), kpis.engines_available],
  ]
    .map(
      ([label, value]) => `
      <article class="kpi-card glass">
        <span class="muted">${escapeHtml(label)}</span>
        <strong>${escapeHtml(String(value))}</strong>
      </article>
    `,
    )
    .join("");

  renderBarChart("status-chart", state.overview.statuses, ["#39c47a", "#e3b341", "#ef6461"]);
  renderBarChart("platform-chart", state.overview.top_platforms, ["#4d8dff", "#3fd5e0", "#8a78ff"]);
  renderBarChart("target-chart", state.overview.top_targets, ["#4d8dff", "#3fd5e0", "#8a78ff"]);
  renderCoverageChart("emulation-coverage-chart", state.overview.emulation_coverage, ["#4d8dff", "#3fd5e0", "#8a78ff", "#39c47a", "#e3b341"]);
  renderBarChart("observable-chart", state.overview.top_observables, ["#8a78ff", "#4d8dff", "#3fd5e0", "#39c47a"]);
}

function detectRuleTypes(entry) {
  const types = [];
  const statuses = entry.target_statuses || {};
  const has = (keys) => keys.some((key) => (statuses[key] || "unsupported") !== "unsupported");
  const hasSiem = Object.entries(statuses).some(([target, status]) => {
    const normalized = String(target || "").toLowerCase();
    return (normalized === "kql"
      || normalized === "sigma"
      || normalized === "eql"
      || normalized.startsWith("sigma-to-"))
      && statusBucket(status) !== "unsupported";
  });
  if (hasSiem) types.push("siem");
  if (has(["snort", "suricata"])) types.push("ids");
  if (has(["yara"])) types.push("content");
  return types;
}

function stixObjectTypeFromId(stixId) {
  const value = String(stixId || "").trim();
  const marker = value.indexOf("--");
  if (marker <= 0) return "";
  return value.slice(0, marker).toLowerCase();
}

function stixObjectTypeLabel(stixId) {
  const objectType = stixObjectTypeFromId(stixId);
  if (!objectType) return t("rules.indicates.object_unknown");
  return objectType.replaceAll("-", " ");
}

function renderIndicatesObjectOptions() {
  const select = document.getElementById("indicates-object-select");
  if (!(select instanceof HTMLSelectElement)) return;
  const current = select.value || "";
  const options = state.stixObjects || [];
  select.innerHTML = `
    <option value="">${escapeHtml(t("rules.indicates.catalog_placeholder"))}</option>
    ${options
      .map((entry) => `<option value="${escapeHtml(entry.stix_id)}">${escapeHtml(`${entry.name} · ${entry.stix_type}`)}</option>`)
      .join("")}
  `;
  if (options.some((entry) => entry.stix_id === current)) {
    select.value = current;
  }
}

function renderStixObjectsTable() {
  const table = document.getElementById("stix-objects-table");
  const meta = document.getElementById("stix-objects-meta");
  if (!table || !meta) return;
  const entries = Array.isArray(state.stixObjects) ? state.stixObjects : [];
  meta.textContent = `${entries.length} ${t("common.entries")}`;
  if (!entries.length) {
    table.innerHTML = `
      <thead>
        <tr>
          <th>${escapeHtml(t("rules.stix_objects.col.id"))}</th>
          <th>${escapeHtml(t("rules.stix_objects.col.type"))}</th>
          <th>${escapeHtml(t("rules.stix_objects.col.name"))}</th>
        </tr>
      </thead>
      <tbody>
        <tr class="table-empty-row"><td colspan="3">${escapeHtml(t("common.no_data"))}</td></tr>
      </tbody>
    `;
    return;
  }
  const rows = entries
    .map((entry) => `
      <tr>
        <td><code>${escapeHtml(entry.stix_id || "-")}</code></td>
        <td>${escapeHtml(entry.stix_type || "-")}</td>
        <td>${escapeHtml(entry.name || "-")}</td>
      </tr>
    `)
    .join("");
  table.innerHTML = `
    <thead>
      <tr>
        <th>${escapeHtml(t("rules.stix_objects.col.id"))}</th>
        <th>${escapeHtml(t("rules.stix_objects.col.type"))}</th>
        <th>${escapeHtml(t("rules.stix_objects.col.name"))}</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  `;
}

async function loadStixObjects() {
  const response = await api("/api/stix-objects");
  state.stixObjects = response.entries || [];
  renderStixObjectsTable();
  renderIndicatesObjectOptions();
}

function targetStatusReliability(status) {
  const bucket = statusBucket(status);
  if (bucket === "exact") return 95;
  if (bucket === "lossy") return 65;
  return 0;
}

function passesRulesAdvancedFilter(entry, filter) {
  const value = String(filter.value || "").trim();
  if (!value && filter.field !== "emulable") return true;
  if (filter.field === "emulable") {
    const platform = value.toLowerCase();
    return (entry.platforms || []).some((item) => String(item).toLowerCase().includes(platform));
  }
  if (filter.field === "output_target") {
    const target = value.toLowerCase();
    return (entry.target_statuses?.[target] || "unsupported") !== "unsupported";
  }
  if (filter.field === "output_reliability") {
    const [targetRaw, thresholdRaw] = value.split(":");
    const target = String(targetRaw || "").toLowerCase();
    const threshold = Number(thresholdRaw || "70");
    const reliability = targetStatusReliability(entry.target_statuses?.[target] || "unsupported");
    return reliability >= threshold;
  }
  if (filter.field === "confidence") {
    const threshold = Number(value || "0");
    const current = Number(entry.confidence || 0);
    if (filter.op === "lt") return current < threshold;
    if (filter.op === "eq") return current === threshold;
    return current > threshold;
  }
  if (filter.field === "name") {
    return String(entry.name || "").toLowerCase().includes(value.toLowerCase());
  }
  if (filter.field === "completion") {
    return ruleStatusFromEntry(entry) === value.toLowerCase();
  }
  return true;
}

function applyRulesClientFilters(entries) {
  const nameQuery = String(document.getElementById("rules-search")?.value || "").trim().toLowerCase();
  const minConfidence = Number(document.getElementById("rules-min-confidence")?.value || "0");
  const selectedObservable = String(document.getElementById("rules-filter-observable")?.value || state.rules.observableFilter || "")
    .trim()
    .toLowerCase();
  const activeFilters = state.rules.advancedFilters || [];

  let filtered = entries.filter((entry) => {
    if (nameQuery && !String(entry.name || "").toLowerCase().includes(nameQuery)) return false;
    if (Number(entry.confidence || 0) < minConfidence) return false;

    const detectedTypes = detectRuleTypes(entry);
    if (state.rules.typeFilters.size === 0) return false;
    const typeMatch = detectedTypes.some((type) => state.rules.typeFilters.has(type));
    if (!typeMatch) return false;

    const tlp = normalizeTlpValue(entry.tlp);
    const pap = normalizePapValue(entry.pap);
    if (state.rules.tlpFilter !== "ALL" && tlp !== state.rules.tlpFilter) return false;
    if (state.rules.papFilter !== "ALL" && pap !== state.rules.papFilter) return false;
    if (selectedObservable) {
      const observables = Array.isArray(entry.observables) ? entry.observables : [];
      const hasObservable = observables.some((value) => String(value || "").toLowerCase() === selectedObservable);
      if (!hasObservable) return false;
    }

    if (!activeFilters.length) return true;
    let aggregate = true;
    for (let i = 0; i < activeFilters.length; i += 1) {
      const filter = activeFilters[i];
      const pass = passesRulesAdvancedFilter(entry, filter);
      if (i === 0) {
        aggregate = pass;
      } else if (filter.logic === "or") {
        aggregate = aggregate || pass;
      } else {
        aggregate = aggregate && pass;
      }
    }
    return aggregate;
  });

  const sort = state.rules.sort || "confidence_desc";
  if (sort === "confidence_asc") filtered.sort((a, b) => Number(a.confidence || 0) - Number(b.confidence || 0));
  else if (sort === "name_asc") filtered.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  else if (sort === "name_desc") filtered.sort((a, b) => String(b.name || "").localeCompare(String(a.name || "")));
  else if (sort === "tlp_asc") filtered.sort((a, b) => trafficOrder(a.tlp, "tlp") - trafficOrder(b.tlp, "tlp"));
  else if (sort === "tlp_desc") filtered.sort((a, b) => trafficOrder(b.tlp, "tlp") - trafficOrder(a.tlp, "tlp"));
  else if (sort === "pap_asc") filtered.sort((a, b) => trafficOrder(a.pap, "pap") - trafficOrder(b.pap, "pap"));
  else if (sort === "pap_desc") filtered.sort((a, b) => trafficOrder(b.pap, "pap") - trafficOrder(a.pap, "pap"));
  else filtered.sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));

  return filtered;
}

function renderRulesNameDatalist(entries) {
  const options = [...new Set(entries.map((entry) => String(entry.name || "").trim()).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b))
    .map((name) => `<option value="${escapeHtml(name)}"></option>`)
    .join("");
  const datalist = document.getElementById("rules-name-options");
  if (datalist) datalist.innerHTML = options;
}

function renderRulesObservableFilterOptions(entries) {
  const select = document.getElementById("rules-filter-observable");
  if (!(select instanceof HTMLSelectElement)) return;
  const values = [...new Set(
    (entries || [])
      .flatMap((entry) => Array.isArray(entry.observables) ? entry.observables : [])
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean),
  )].sort((a, b) => a.localeCompare(b));
  const current = state.rules.observableFilter || select.value || "";
  select.innerHTML = `
    <option value="">${escapeHtml(t("common.all"))}</option>
    ${values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("")}
  `;
  select.value = values.includes(current) ? current : "";
  state.rules.observableFilter = select.value;
}

function rulesColumnLabel(columnKey) {
  switch (columnKey) {
    case "name": return t("rules.col.name");
    case "confidence": return t("rules.col.confidence");
    case "tlp": return "TLP";
    case "pap": return "PAP";
    case "rule": return t("rules.col.rule");
    case "observables": return t("rules.col.observables");
    case "indicates": return t("rules.col.indicates");
    case "outputs": return t("rules.col.outputs");
    case "emulation": return t("rules.col.emulation");
    default: return columnKey;
  }
}

function adversaryColumnLabel(columnKey) {
  switch (columnKey) {
    case "name": return t("adversaries.col.name");
    case "confidence": return t("adversaries.col.confidence");
    case "tlp": return "TLP";
    case "pap": return "PAP";
    case "steps": return t("adversaries.col.steps");
    case "platforms": return t("adversaries.col.platforms");
    case "exporters": return t("adversaries.col.exporters");
    default: return columnKey;
  }
}

function renderRulesColumnPicker() {
  const menu = document.getElementById("rules-columns-menu");
  if (!menu) return;
  menu.innerHTML = RULE_COLUMN_KEYS
    .map((column) => `
      <label class="column-menu-item">
        <input
          type="checkbox"
          data-action="rules-column-toggle"
          data-column="${column}"
          ${state.rules.visibleColumns.has(column) ? "checked" : ""}
        >
        <span>${escapeHtml(rulesColumnLabel(column))}</span>
      </label>
    `)
    .join("");
}

function renderAdversariesColumnPicker() {
  const menu = document.getElementById("adversaries-columns-menu");
  if (!menu) return;
  menu.innerHTML = ADVERSARY_COLUMN_KEYS
    .map((column) => `
      <label class="column-menu-item">
        <input
          type="checkbox"
          data-action="adversaries-column-toggle"
          data-column="${column}"
          ${state.adversaries.visibleColumns.has(column) ? "checked" : ""}
        >
        <span>${escapeHtml(adversaryColumnLabel(column))}</span>
      </label>
    `)
    .join("");
}

function setColumnVisibility(targetSet, column, checked, allColumns) {
  if (!allColumns.includes(column)) return false;
  if (checked) {
    targetSet.add(column);
    return true;
  }
  if (targetSet.size <= 1) {
    return false;
  }
  targetSet.delete(column);
  return true;
}

function toggleMenu(menuId, toggleButtonId) {
  const menu = document.getElementById(menuId);
  const button = document.getElementById(toggleButtonId);
  if (!menu || !button) return;
  const shouldOpen = menu.classList.contains("hidden");
  document.querySelectorAll(".column-menu").forEach((node) => node.classList.add("hidden"));
  if (shouldOpen) menu.classList.remove("hidden");
}

function closeColumnMenus() {
  document.querySelectorAll(".column-menu").forEach((node) => node.classList.add("hidden"));
}

function summarizeTargetStatuses(targetStatuses, orderedTargets) {
  return orderedTargets
    .map((target) => `${target}:${statusBucket(targetStatuses?.[target] || "unsupported")}`)
    .join(" | ");
}

function ruleColumnExportValue(entry, column) {
  if (column === "name") return String(entry.name || "");
  if (column === "confidence") return String(entry.confidence ?? "");
  if (column === "tlp") return String(entry.tlp || "");
  if (column === "pap") return String(entry.pap || "");
  if (column === "rule") return String(entry.rule || "");
  if (column === "observables") {
    return (Array.isArray(entry.observables) ? entry.observables : []).join(", ");
  }
  if (column === "indicates") {
    const list = Array.isArray(entry.indicates_list) && entry.indicates_list.length
      ? entry.indicates_list
      : (entry.indicates ? [entry.indicates] : []);
    return list.map((relation) => `${relation.object_name || ""} (${relation.stix_id || ""})`.trim()).join(" | ");
  }
  if (column === "outputs") {
    return summarizeTargetStatuses(entry.target_statuses, RULE_OUTPUT_TARGETS);
  }
  if (column === "emulation") {
    return summarizeTargetStatuses(entry.emulation_statuses, RULE_EMULATION_TARGETS);
  }
  return "";
}

function csvEscape(value) {
  const text = String(value ?? "");
  if (text.includes(",") || text.includes("\"") || text.includes("\n")) {
    return `"${text.replaceAll("\"", "\"\"")}"`;
  }
  return text;
}

function downloadTextFile(content, fileName, mimeType = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function detectionExportExtension(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "sigma") return "yml";
  if (normalized.startsWith("sigma-to-")) return "txt";
  if (normalized === "kql") return "kql";
  if (normalized === "eql") return "eql";
  if (normalized === "snort" || normalized === "suricata") return "rules";
  if (normalized === "yara") return "yar";
  return "txt";
}

function detectionExportMimeType(target) {
  const normalized = String(target || "").toLowerCase();
  if (normalized === "sigma") return "application/x-yaml;charset=utf-8";
  return "text/plain;charset=utf-8";
}

function sanitizeFileToken(value) {
  const cleaned = String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned || "rule";
}

function exportDetectionOutputFromDetail() {
  const payload = state.detailDetectionExport;
  if (!payload || !String(payload.output || "").trim()) {
    showToast("common.no_data", true);
    return;
  }
  const ext = detectionExportExtension(payload.target);
  const fileName = `spuc-${sanitizeFileToken(payload.title)}-${sanitizeFileToken(payload.target)}.${ext}`;
  downloadTextFile(payload.output, fileName, detectionExportMimeType(payload.target));
  showToast("toast.export_ready");
}

function openRulesSelectedExportPreview(entries) {
  const visibleColumns = RULE_COLUMN_KEYS.filter((column) => state.rules.visibleColumns.has(column));
  const headers = [t("common.id"), ...visibleColumns.map((column) => rulesColumnLabel(column))];
  const rows = entries.map((entry) => {
    const values = [entry.id, ...visibleColumns.map((column) => ruleColumnExportValue(entry, column))];
    return values;
  });
  const csvLines = [
    headers.map(csvEscape).join(","),
    ...rows.map((row) => row.map(csvEscape).join(",")),
  ];
  state.rules.lastExportSelectedCsv = csvLines.join("\n");

  const tableHtml = `
    <section class="detail-section">
      <h4>${escapeHtml(tf("rules.export_selected.preview_title", { count: entries.length }))}</h4>
      <div class="table-wrap">
        <table class="export-preview-table">
          <thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>
          <tbody>
            ${rows.map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
  document.getElementById("detail-title").textContent = t("rules.export_selected.title");
  document.getElementById("detail-view").innerHTML = tableHtml;
  document.getElementById("detail-raw").textContent = JSON.stringify(
    { headers, rows, selected: entries.length },
    null,
    2,
  );
  document.getElementById("detail-actions").innerHTML = renderDetailActions(
    `<button class="btn btn-success" data-action="rules-export-selected-download">${escapeHtml(t("rules.export_selected.download_csv"))}</button>`,
  );
  setDetailTab("view");
  document.getElementById("detail-dialog").showModal();
}

async function exportSelectedRules() {
  if (state.rules.selected.size === 0) return;
  const entries = state.rules.allEntries.filter((entry) => state.rules.selected.has(entry.id));
  if (!entries.length) {
    showToast("common.no_data", true);
    return;
  }
  openRulesSelectedExportPreview(entries);
}

function updateRulesBulkState() {
  const count = state.rules.selected.size;
  const filteredEntries = applyRulesClientFilters(state.rules.allEntries);
  const allFilteredSelected = filteredEntries.length > 0
    && filteredEntries.every((entry) => state.rules.selected.has(entry.id));
  const bulkToggleButton = document.getElementById("rules-bulk-toggle");
  const exportSelectedButton = document.getElementById("rules-export-selected");
  const deleteButton = document.getElementById("rules-delete-selected");
  const selectAllButton = document.getElementById("rules-select-all-toggle");
  if (bulkToggleButton) {
    bulkToggleButton.disabled = count === 0;
    bulkToggleButton.classList.toggle("active", state.rules.bulkEditOpen && count > 0);
  }
  if (exportSelectedButton) {
    exportSelectedButton.disabled = count === 0;
  }
  if (deleteButton) {
    deleteButton.disabled = count === 0;
  }
  if (selectAllButton) {
    selectAllButton.disabled = filteredEntries.length === 0;
    selectAllButton.textContent = allFilteredSelected ? t("rules.bulk.deselect_all") : t("rules.bulk.select_all");
  }
  const bulkEdit = document.getElementById("rules-bulk-edit");
  if (bulkEdit) {
    if (count === 0) {
      state.rules.bulkEditOpen = false;
    }
    bulkEdit.classList.toggle("hidden", count === 0 || !state.rules.bulkEditOpen);
  }
  const countLabel = document.getElementById("rules-bulk-count");
  if (countLabel) {
    countLabel.textContent = count > 0 ? tf("rules.bulk.selected_count", { count }) : "";
  }
}

function renderRulesTable() {
  const outputTargets = RULE_OUTPUT_TARGETS;
  const emulationTargets = RULE_EMULATION_TARGETS;
  const currentSort = state.rules.sort || "confidence_desc";
  const isVisible = (column) => state.rules.visibleColumns.has(column);
  const filtered = applyRulesClientFilters(state.rules.allEntries);
  state.rules.total = filtered.length;
  const maxPage = Math.max(1, Math.ceil(filtered.length / state.rules.pageSize));
  state.rules.page = Math.min(Math.max(1, state.rules.page), maxPage);
  const start = (state.rules.page - 1) * state.rules.pageSize;
  state.rules.entries = filtered.slice(start, start + state.rules.pageSize);
  renderRulesColumnPicker();

  const rows = state.rules.entries.map((entry, rowIndex) => {
    const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
      ? entry.indicates_list
      : (entry.indicates ? [entry.indicates] : []);
    const indicatesCount = indicatesList.length;
    const indicatesBadges = indicatesList
      .map((relation) => {
        const typeLabel = stixObjectTypeLabel(relation.stix_id || "");
        const objectName = relation.object_name || relation.stix_id || "";
        return `<span class="indicates-mini" title="${escapeHtml(relation.stix_id || "")}">${escapeHtml(typeLabel)} · ${escapeHtml(objectName)}</span>`;
      })
      .join("");
    const typeTags = detectRuleTypes(entry)
      .map((type) => `<span class="rule-type-tag ${type}">${escapeHtml(type.toUpperCase())}</span>`)
      .join("");
    const observables = (Array.isArray(entry.observables) ? entry.observables : [])
      .map((observable) => String(observable || "").trim().toLowerCase())
      .filter(Boolean);
    const observableTags = observables.length
      ? observables.map((observable) => `<span class="rule-observable-tag">${escapeHtml(observable)}</span>`).join("")
      : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`;

    const outputChips = outputTargets
      .map((target) =>
        renderStatusChip(target.toUpperCase(), entry.target_statuses?.[target] || "unsupported", "rule-target-detail", {
          rule: entry.id,
          target,
        }),
      )
      .join("");

    const emulationChips = emulationTargets
      .map((target) =>
        renderStatusChip(target, entry.emulation_statuses?.[target] || "unsupported", "rule-emulation-detail", {
          rule: entry.id,
          target,
          ability: entry.ability_id || "",
        }),
      )
      .join("");

    const cells = [
      `<td><input type="checkbox" data-action="rule-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.rules.selected.has(entry.id) ? "checked" : ""}></td>`,
    ];
    if (isVisible("name")) {
      cells.push(`
        <td>
          <div class="rule-name">
            <strong>${escapeHtml(entry.name)}</strong>
            <div class="rule-type-tags">${typeTags || `<span class="rule-type-tag">${escapeHtml(t("common.na"))}</span>`}</div>
          </div>
        </td>
      `);
    }
    if (isVisible("confidence")) {
      cells.push(`<td><input type="number" min="0" max="100" class="rules-confidence-input" data-id="${entry.id}" value="${Number(entry.confidence || 0)}"></td>`);
    }
    if (isVisible("tlp")) cells.push(`<td>${trafficBadge(entry.tlp, "tlp")}</td>`);
    if (isVisible("pap")) cells.push(`<td>${trafficBadge(entry.pap, "pap")}</td>`);
    if (isVisible("rule")) {
      cells.push(`
        <td>
          <div class="rule-cell">
            <button class="icon-btn" data-action="rule-copy" data-id="${entry.id}" title="${escapeHtml(t("detail.copy_rule"))}" aria-label="${escapeHtml(t("detail.copy_rule"))}">📋</button>
            <code class="rule-code">${escapeHtml(entry.rule)}</code>
          </div>
        </td>
      `);
    }
    if (isVisible("observables")) {
      cells.push(`<td><div class="rule-observables-cell">${observableTags}</div></td>`);
    }
    if (isVisible("indicates")) {
      cells.push(`
        <td>
          <div class="rule-indicates-cell">
            <div class="indicates-mini-list">${indicatesBadges || `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}</div>
            <button class="icon-btn icon-btn-indicates" data-action="rule-indicates" data-id="${entry.id}" title="${escapeHtml(t("rules.indicates.add"))}" aria-label="${escapeHtml(t("rules.indicates.add"))}">
              ＋
              ${indicatesCount > 0 ? `<span class="indicates-count-badge">${indicatesCount}</span>` : ""}
            </button>
          </div>
        </td>
      `);
    }
    if (isVisible("outputs")) cells.push(`<td><div class="chip-list">${outputChips}</div></td>`);
    if (isVisible("emulation")) {
      cells.push(`
        <td>
          <div class="chip-list">${emulationChips}</div>
        </td>
      `);
    }
    return `<tr data-rule-row-id="${escapeHtml(entry.id)}">${cells.join("")}</tr>`;
  });
  const visibleCount = RULE_COLUMN_KEYS.filter((column) => isVisible(column)).length;
  const emptyRow = `
    <tr class="table-empty-row">
      <td colspan="${1 + visibleCount}">${escapeHtml(t("common.no_data"))}</td>
    </tr>
  `;

  const headers = [`<th></th>`];
  if (isVisible("name")) {
    headers.push(sortableHeader(t("rules.col.name"), "rules-sort-column", "name", currentSort, "name_asc", "name_desc"));
  }
  if (isVisible("confidence")) {
    headers.push(sortableHeader(t("rules.col.confidence"), "rules-sort-column", "confidence", currentSort, "confidence_asc", "confidence_desc"));
  }
  if (isVisible("tlp")) {
    headers.push(sortableHeader("TLP", "rules-sort-column", "tlp", currentSort, "tlp_asc", "tlp_desc"));
  }
  if (isVisible("pap")) {
    headers.push(sortableHeader("PAP", "rules-sort-column", "pap", currentSort, "pap_asc", "pap_desc"));
  }
  if (isVisible("rule")) headers.push(`<th>${escapeHtml(t("rules.col.rule"))}</th>`);
  if (isVisible("observables")) headers.push(`<th>${escapeHtml(t("rules.col.observables"))}</th>`);
  if (isVisible("indicates")) headers.push(`<th>${escapeHtml(t("rules.col.indicates"))}</th>`);
  if (isVisible("outputs")) headers.push(`<th>${escapeHtml(t("rules.col.outputs"))}</th>`);
  if (isVisible("emulation")) headers.push(`<th>${escapeHtml(t("rules.col.emulation"))}</th>`);

  const table = document.getElementById("rules-table");
  table.innerHTML = `
    <thead>
      <tr>${headers.join("")}</tr>
    </thead>
    <tbody>${rows.length ? rows.join("") : emptyRow}</tbody>
  `;
  document.getElementById("rules-meta").textContent = `${state.rules.entries.length}/${state.rules.total} ${t("common.entries")}`;
  renderPager("rules-pager", state.rules.page, state.rules.pageSize, state.rules.total, "rules");
  updateRulesBulkState();
}

async function loadRules(page = state.rules.page) {
  const query = {
    page: 1,
    page_size: 400,
  };
  const response = await api(`/api/rules${toQuery(query)}`);
  state.rules.page = page;
  state.rules.allEntries = response.entries || [];
  const available = new Set(state.rules.allEntries.map((entry) => entry.id));
  state.rules.selected.forEach((id) => {
    if (!available.has(id)) {
      state.rules.selected.delete(id);
    }
  });
  state.rules.lastSelectionIndex = -1;
  renderRulesNameDatalist(state.rules.allEntries);
  renderRulesObservableFilterOptions(state.rules.allEntries);
  renderRulesTable();
  await loadStixObjects();
}

function ruleStatusFromEntry(entry) {
  const statuses = (entry.statuses || []).map((value) => String(value).toLowerCase());
  if (statuses.includes("exact")) return "exact";
  if (statuses.some((value) => value.includes("dependent") || value.includes("lossy") || value.includes("schema") || value.includes("backend"))) return "lossy";
  return "unsupported";
}

function scheduleRulesReload() {
  clearTimeout(state.rulesFilterTimer);
  state.rulesFilterTimer = setTimeout(() => {
    state.rules.page = 1;
    if (state.rules.allEntries.length > 0) {
      renderRulesTable();
    } else {
      loadRules(1);
    }
  }, 120);
}

function toggleRulesSortColumn(column) {
  const current = state.rules.sort || "confidence_desc";
  const pairs = {
    name: { asc: "name_asc", desc: "name_desc" },
    confidence: { asc: "confidence_asc", desc: "confidence_desc" },
    tlp: { asc: "tlp_asc", desc: "tlp_desc" },
    pap: { asc: "pap_asc", desc: "pap_desc" },
  };
  const pair = pairs[column];
  if (!pair) return;
  state.rules.sort = current === pair.asc ? pair.desc : pair.asc;
  scheduleRulesReload();
}

async function loadAbilities() {
  const hasAbilitiesPanel = Boolean(document.getElementById("abilities-table"));
  const response = await api(
    `/api/abilities${toQuery({
      q: hasAbilitiesPanel ? document.getElementById("abilities-search")?.value?.trim() : undefined,
      platform: hasAbilitiesPanel ? document.getElementById("abilities-platform")?.value?.trim() : undefined,
      classification: hasAbilitiesPanel ? document.getElementById("abilities-classification")?.value?.trim() : undefined,
      min_confidence: hasAbilitiesPanel ? document.getElementById("abilities-min-confidence")?.value : undefined,
    })}`,
  );
  state.abilities.entries = response;

  if (!hasAbilitiesPanel) {
    renderAdversaryAbilitySelector();
    return;
  }

  const rows = state.abilities.entries.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.id)}</td>
      <td>${escapeHtml(entry.name)}</td>
      <td>${escapeHtml(entry.platforms.join(", "))}</td>
      <td>${escapeHtml(entry.classification)}</td>
      <td>${entry.confidence}</td>
      <td>
        <button class="btn btn-ghost" data-action="ability-show" data-id="${entry.id}">${escapeHtml(t("common.show"))}</button>
        <button class="btn btn-ghost" data-action="ability-copy-json" data-id="${entry.id}">${escapeHtml(t("abilities.copy_json"))}</button>
        <button class="btn btn-primary" data-action="ability-export" data-id="${entry.id}" data-target="spuc-agent">SPUC</button>
        <button class="btn btn-ghost" data-action="ability-export" data-id="${entry.id}" data-target="bash">Bash</button>
        <button class="btn btn-ghost" data-action="ability-export" data-id="${entry.id}" data-target="powershell">PowerShell</button>
        <button class="btn btn-ghost" data-action="ability-export" data-id="${entry.id}" data-target="atomic-red-team">Atomic</button>
        <button class="btn btn-ghost" data-action="ability-export" data-id="${entry.id}" data-target="mitre-caldera">Caldera</button>
      </td>
    </tr>
  `);

  renderTable(
    "abilities-table",
    [t("abilities.col.id"), t("abilities.col.name"), t("abilities.col.platforms"), t("abilities.col.classification"), t("abilities.col.confidence"), t("abilities.col.actions")],
    rows,
  );
  document.getElementById("abilities-meta").textContent = `${state.abilities.entries.length} ${t("common.entries")}`;
  renderAdversaryAbilitySelector();
}

function applyAdversariesClientSort(entries, sort) {
  const sorted = [...entries];
  if (sort === "name_asc") sorted.sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  else if (sort === "name_desc") sorted.sort((a, b) => String(b.name || "").localeCompare(String(a.name || "")));
  else if (sort === "confidence_asc") sorted.sort((a, b) => Number(a.confidence || 0) - Number(b.confidence || 0));
  else if (sort === "confidence_desc") sorted.sort((a, b) => Number(b.confidence || 0) - Number(a.confidence || 0));
  else if (sort === "tlp_asc") sorted.sort((a, b) => trafficOrder(a.tlp, "tlp") - trafficOrder(b.tlp, "tlp"));
  else if (sort === "tlp_desc") sorted.sort((a, b) => trafficOrder(b.tlp, "tlp") - trafficOrder(a.tlp, "tlp"));
  else if (sort === "pap_asc") sorted.sort((a, b) => trafficOrder(a.pap, "pap") - trafficOrder(b.pap, "pap"));
  else if (sort === "pap_desc") sorted.sort((a, b) => trafficOrder(b.pap, "pap") - trafficOrder(a.pap, "pap"));
  else if (sort === "steps_asc") sorted.sort((a, b) => Number(a.steps || 0) - Number(b.steps || 0));
  else if (sort === "steps_desc") sorted.sort((a, b) => Number(b.steps || 0) - Number(a.steps || 0));
  else if (sort === "platforms_asc") {
    sorted.sort((a, b) => String((a.platforms || []).join(",")).localeCompare(String((b.platforms || []).join(","))));
  } else if (sort === "platforms_desc") {
    sorted.sort((a, b) => String((b.platforms || []).join(",")).localeCompare(String((a.platforms || []).join(","))));
  }
  return sorted;
}

function selectedValues(select) {
  if (!(select instanceof HTMLSelectElement)) return [];
  return [...select.selectedOptions].map((option) => option.value).filter(Boolean);
}

function renderAdversaryPlatformFilterOptions() {
  const select = document.getElementById("adversaries-platform");
  if (!(select instanceof HTMLSelectElement)) return;
  const selectedValue = select.value || "";
  const options = [...new Set((state.adversaries.platformOptions || []).map((value) => String(value || "").trim()).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  select.innerHTML = [
    `<option value="">${escapeHtml(t("common.all_platforms"))}</option>`,
    ...options.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
  ].join("");
  const validValues = new Set(["", ...options]);
  select.value = validValues.has(selectedValue) ? selectedValue : "";
}

function applyAdversariesClientFilters(entries) {
  const search = (document.getElementById("adversaries-search")?.value || "").trim().toLowerCase();
  const minConfidence = Number(document.getElementById("adversaries-min-confidence")?.value || "0");
  const platformSelect = document.getElementById("adversaries-platform");
  const selectedPlatform = String(platformSelect?.value || "").trim().toLowerCase();

  const filtered = entries.filter((entry) => {
    const confidence = Number(entry.confidence || 0);
    if (confidence < minConfidence) return false;

    const platforms = (entry.platforms || []).map((value) => String(value).toLowerCase());
    if (selectedPlatform && !platforms.includes(selectedPlatform)) {
      return false;
    }

    if (!search) return true;
    const haystack = [
      entry.id,
      entry.name,
      entry.description,
      (entry.platforms || []).join(" "),
      entry.tlp,
      entry.pap,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(search);
  });

  return applyAdversariesClientSort(filtered, state.adversaries.sort || "confidence_desc");
}

function adversaryConfidenceBadge(confidence) {
  const value = Number(confidence || 0);
  const severity = value >= 80 ? "success" : value >= 50 ? "warning" : "error";
  return `<span class="badge ${severity} adversary-confidence-tag">${escapeHtml(`${value}/100`)}</span>`;
}

function updateAdversariesBulkState() {
  const count = state.adversaries.selected.size;
  const filteredEntries = applyAdversariesClientFilters(state.adversaries.allEntries || []);
  const allFilteredSelected = filteredEntries.length > 0
    && filteredEntries.every((entry) => state.adversaries.selected.has(entry.id));

  const bulkToggleButton = document.getElementById("adversaries-bulk-toggle");
  const deleteButton = document.getElementById("adversaries-delete-selected");
  const selectAllButton = document.getElementById("adversaries-select-all-toggle");
  if (bulkToggleButton) {
    bulkToggleButton.disabled = count === 0;
    bulkToggleButton.classList.toggle("active", state.adversaries.bulkEditOpen && count > 0);
  }
  if (deleteButton) {
    deleteButton.disabled = count === 0;
  }
  if (selectAllButton) {
    selectAllButton.disabled = filteredEntries.length === 0;
    selectAllButton.textContent = allFilteredSelected ? t("adversaries.bulk.deselect_all") : t("adversaries.bulk.select_all");
  }
  const bulkEdit = document.getElementById("adversaries-bulk-edit");
  if (bulkEdit) {
    if (count === 0) state.adversaries.bulkEditOpen = false;
    bulkEdit.classList.toggle("hidden", count === 0 || !state.adversaries.bulkEditOpen);
  }
  const countLabel = document.getElementById("adversaries-bulk-count");
  if (countLabel) {
    countLabel.textContent = count > 0 ? tf("adversaries.bulk.selected_count", { count }) : "";
  }
}

function renderAdversariesTable() {
  const isVisible = (column) => state.adversaries.visibleColumns.has(column);
  const filtered = applyAdversariesClientFilters(state.adversaries.allEntries || []);
  state.adversaries.total = filtered.length;
  const maxPage = Math.max(1, Math.ceil(filtered.length / state.adversaries.pageSize));
  state.adversaries.page = Math.min(Math.max(1, state.adversaries.page), maxPage);
  const start = (state.adversaries.page - 1) * state.adversaries.pageSize;
  state.adversaries.entries = filtered.slice(start, start + state.adversaries.pageSize);
  renderAdversariesColumnPicker();

  const exportTargets = ["spuc-agent", "bash", "powershell", "atomic-red-team", "mitre-caldera"];
  const rows = state.adversaries.entries.map((entry, rowIndex) => {
    const compatible = new Set((entry.compatible_exports || []).map((target) => String(target).toLowerCase()));
    const exporterPills = exportTargets
      .map((target) => {
        const available = compatible.has(target);
        return `
          <button
            class="export-pill ${available ? "available" : "unavailable"}"
            data-action="adversary-export"
            data-id="${entry.id}"
            data-target="${target}"
            ${available ? "" : "disabled"}
            title="${available ? escapeHtml(t("adversaries.export.available")) : escapeHtml(t("adversaries.export.unavailable"))}"
          >
            ${escapeHtml(target)}
          </button>
        `;
      })
      .join("");
    const cells = [
      `<td><input type="checkbox" data-action="adversary-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.adversaries.selected.has(entry.id) ? "checked" : ""}></td>`,
    ];
    if (isVisible("name")) cells.push(`<td>${escapeHtml(entry.name)}</td>`);
    if (isVisible("confidence")) cells.push(`<td>${adversaryConfidenceBadge(entry.confidence)}</td>`);
    if (isVisible("tlp")) cells.push(`<td>${trafficBadge(entry.tlp || "TLP:GREEN", "tlp")}</td>`);
    if (isVisible("pap")) cells.push(`<td>${trafficBadge(entry.pap || "PAP:GREEN", "pap")}</td>`);
    if (isVisible("steps")) cells.push(`<td>${entry.steps}</td>`);
    if (isVisible("platforms")) cells.push(`<td>${escapeHtml((entry.platforms || []).join(", "))}</td>`);
    if (isVisible("exporters")) {
      cells.push(`
        <td>
          <div class="export-pill-row">${exporterPills}</div>
        </td>
      `);
    }
    return `<tr data-adversary-row-id="${escapeHtml(entry.id)}">${cells.join("")}</tr>`;
  });
  const visibleCount = ADVERSARY_COLUMN_KEYS.filter((column) => isVisible(column)).length;
  const emptyRow = `
    <tr class="table-empty-row">
      <td colspan="${1 + Math.max(1, visibleCount)}">${escapeHtml(t("common.no_data"))}</td>
    </tr>
  `;

  const currentSort = state.adversaries.sort || "confidence_desc";
  const headers = ["<th></th>"];
  if (isVisible("name")) {
    headers.push(sortableHeader(t("adversaries.col.name"), "adversaries-sort-column", "name", currentSort, "name_asc", "name_desc"));
  }
  if (isVisible("confidence")) {
    headers.push(sortableHeader(t("adversaries.col.confidence"), "adversaries-sort-column", "confidence", currentSort, "confidence_asc", "confidence_desc"));
  }
  if (isVisible("tlp")) {
    headers.push(sortableHeader("TLP", "adversaries-sort-column", "tlp", currentSort, "tlp_asc", "tlp_desc"));
  }
  if (isVisible("pap")) {
    headers.push(sortableHeader("PAP", "adversaries-sort-column", "pap", currentSort, "pap_asc", "pap_desc"));
  }
  if (isVisible("steps")) {
    headers.push(sortableHeader(t("adversaries.col.steps"), "adversaries-sort-column", "steps", currentSort, "steps_asc", "steps_desc"));
  }
  if (isVisible("platforms")) {
    headers.push(sortableHeader(t("adversaries.col.platforms"), "adversaries-sort-column", "platforms", currentSort, "platforms_asc", "platforms_desc"));
  }
  if (isVisible("exporters")) headers.push(`<th>${escapeHtml(t("adversaries.col.exporters"))}</th>`);

  const table = document.getElementById("adversaries-table");
  table.innerHTML = `
    <thead>
      <tr>${headers.join("")}</tr>
    </thead>
    <tbody>${rows.length ? rows.join("") : emptyRow}</tbody>
  `;
  document.getElementById("adversaries-meta").textContent = `${state.adversaries.entries.length}/${state.adversaries.total} ${t("common.entries")}`;
  renderPager("adversaries-pager", state.adversaries.page, state.adversaries.pageSize, state.adversaries.total, "adversaries");
  updateAdversariesBulkState();
}

async function toggleAdversariesSortColumn(column) {
  const current = state.adversaries.sort || "confidence_desc";
  const pairs = {
    name: { asc: "name_asc", desc: "name_desc" },
    confidence: { asc: "confidence_asc", desc: "confidence_desc" },
    tlp: { asc: "tlp_asc", desc: "tlp_desc" },
    pap: { asc: "pap_asc", desc: "pap_desc" },
    steps: { asc: "steps_asc", desc: "steps_desc" },
    platforms: { asc: "platforms_asc", desc: "platforms_desc" },
  };
  const pair = pairs[column];
  if (!pair) return;
  const next = current === pair.asc ? pair.desc : pair.asc;
  state.adversaries.sort = next;
  state.adversaries.page = 1;
  renderAdversariesTable();
}

async function loadAdversaries(page = state.adversaries.page) {
  const response = await api(`/api/adversaries${toQuery({ page: 1, page_size: 400 })}`);
  state.adversaries.page = page;
  state.adversaries.allEntries = response.entries || [];
  state.adversaries.pageSize = state.adversaries.pageSize || 20;

  state.adversaries.platformOptions = [...new Set(
    state.adversaries.allEntries
      .flatMap((entry) => Array.isArray(entry.platforms) ? entry.platforms : [])
      .map((value) => String(value || "").trim())
      .filter(Boolean),
  )].sort((a, b) => a.localeCompare(b));
  renderAdversaryPlatformFilterOptions();

  const available = new Set(state.adversaries.allEntries.map((entry) => entry.id));
  state.adversaries.selected.forEach((id) => {
    if (!available.has(id)) state.adversaries.selected.delete(id);
  });
  state.adversaries.lastSelectionIndex = -1;
  renderAdversariesTable();
}

function scheduleAdversariesReload() {
  clearTimeout(state.adversariesFilterTimer);
  state.adversariesFilterTimer = setTimeout(() => {
    state.adversaries.page = 1;
    if (state.adversaries.allEntries.length > 0) {
      renderAdversariesTable();
    } else {
      loadAdversaries(1);
    }
  }, 120);
}

function syncAdversaryComposerFromInputs() {
  const searchNode = document.getElementById("adversary-ability-search");
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const minConfidenceNode = document.getElementById("adversary-ability-min-confidence");
  if (searchNode) state.adversaryCompose.search = searchNode.value.trim();
  if (platformNode) state.adversaryCompose.platform = platformNode.value.trim();
  if (utilityNode) state.adversaryCompose.utility = utilityNode.value.trim();
  if (destinationNode) state.adversaryCompose.destination = destinationNode.value.trim();
  if (minConfidenceNode) {
    const value = Number(minConfidenceNode.value || "0");
    state.adversaryCompose.minConfidence = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  }
}

function resetAdversaryComposer() {
  state.adversaryCompose.search = "";
  state.adversaryCompose.platform = "";
  state.adversaryCompose.utility = "";
  state.adversaryCompose.destination = "";
  state.adversaryCompose.minConfidence = 0;
  state.adversaryCompose.selectedOrder = [];
  state.adversaryCompose.executor = "manifest";
  const searchNode = document.getElementById("adversary-ability-search");
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const minConfidenceNode = document.getElementById("adversary-ability-min-confidence");
  if (searchNode) searchNode.value = "";
  if (platformNode) platformNode.value = "";
  if (utilityNode) utilityNode.value = "";
  if (destinationNode) destinationNode.value = "";
  if (minConfidenceNode) minConfidenceNode.value = "0";
}

function setSelectOptions(selectNode, values, allLabel, selectedValue = "") {
  if (!(selectNode instanceof HTMLSelectElement)) return;
  const unique = [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
  const current = selectedValue || selectNode.value || "";
  selectNode.innerHTML = `
    <option value="">${escapeHtml(allLabel)}</option>
    ${unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("")}
  `;
  selectNode.value = unique.includes(current) ? current : "";
}

function renderAdversaryAbilityFilterOptions() {
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const platforms = state.abilities.entries.flatMap((entry) => entry.platforms || []);
  const utilities = state.abilities.entries.map((entry) => entry.classification || "");
  const destinations = state.abilities.entries.flatMap((entry) => entry.export_targets || []);
  setSelectOptions(platformNode, platforms, t("common.all_platforms"), state.adversaryCompose.platform);
  setSelectOptions(utilityNode, utilities, t("common.all_utility_types"), state.adversaryCompose.utility);
  setSelectOptions(destinationNode, destinations, t("common.all_destinations"), state.adversaryCompose.destination);
}

function filteredAdversaryAbilities() {
  const search = state.adversaryCompose.search.toLowerCase();
  const platform = state.adversaryCompose.platform.toLowerCase();
  const utility = state.adversaryCompose.utility.toLowerCase();
  const destination = state.adversaryCompose.destination.toLowerCase();
  const minConfidence = Number(state.adversaryCompose.minConfidence || 0);
  return state.abilities.entries.filter((entry) => {
    if (Number(entry.confidence || 0) < minConfidence) return false;
    if (platform) {
      const platforms = (entry.platforms || []).map((value) => String(value).toLowerCase());
      const matchesPlatform = platforms.includes(platform)
        || (platform === "any" && platforms.length > 0);
      if (!matchesPlatform) return false;
    }
    if (utility) {
      const entryUtility = String(entry.classification || "").toLowerCase();
      if (entryUtility !== utility) return false;
    }
    if (destination) {
      const exports = (entry.export_targets || []).map((value) => String(value).toLowerCase());
      if (!exports.includes(destination)) return false;
    }
    if (!search) return true;
    const haystack = [
      entry.id,
      entry.name,
      entry.description,
      entry.classification,
      (entry.platforms || []).join(" "),
      (entry.export_targets || []).join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(search);
  });
}

function moveAdversarySelectedAbility(id, direction) {
  const order = state.adversaryCompose.selectedOrder;
  const index = order.indexOf(id);
  if (index < 0) return;
  const targetIndex = index + direction;
  if (targetIndex < 0 || targetIndex >= order.length) return;
  [order[index], order[targetIndex]] = [order[targetIndex], order[index]];
}

function renderAdversaryAbilitySelector() {
  syncAdversaryComposerFromInputs();
  renderAdversaryAbilityFilterOptions();
  const availableRoot = document.getElementById("adversary-abilities");
  const selectedRoot = document.getElementById("adversary-selected");
  const selectedCount = document.getElementById("adversary-selected-count");
  if (!availableRoot || !selectedRoot) return;

  const knownIds = new Set(state.abilities.entries.map((entry) => entry.id));
  state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => knownIds.has(id));
  const selectedSet = new Set(state.adversaryCompose.selectedOrder);
  const filtered = filteredAdversaryAbilities();

  availableRoot.innerHTML = filtered.length === 0
    ? `<p class="muted ability-empty">${escapeHtml(t("adversaries.create.none_available"))}</p>`
    : filtered
      .map((entry) => {
        const selected = selectedSet.has(entry.id);
        const exportTags = (entry.export_targets || [])
          .map((target) => `<span class="export-tag">${escapeHtml(target)}</span>`)
          .join("");
        return `
      <article class="ability-item planner-ability-item">
        <div class="ability-copy">
          <strong>${escapeHtml(entry.name)}</strong>
          <small class="muted">${escapeHtml(entry.id)} · ${escapeHtml((entry.platforms || []).join(", "))}</small>
          <small class="muted">${escapeHtml(entry.classification)} · ${escapeHtml(String(entry.confidence))}/100</small>
          ${exportTags ? `<div class="export-tag-list">${exportTags}</div>` : ""}
        </div>
        <button
          type="button"
          class="btn ${selected ? "btn-ghost" : "btn-primary"}"
          data-action="adversary-select-ability"
          data-id="${entry.id}"
          ${selected ? "disabled" : ""}
        >
          ${escapeHtml(selected ? t("adversaries.create.added") : t("adversaries.create.add"))}
        </button>
      </article>
    `;
      })
      .join("");

  const selectedRows = state.adversaryCompose.selectedOrder
    .map((id, index) => {
      const entry = state.abilities.entries.find((ability) => ability.id === id);
      if (!entry) return "";
      return `
      <article class="ability-item selected-ability-item">
        <div class="selected-step-index">${index + 1}</div>
        <div class="ability-copy">
          <strong>${escapeHtml(entry.name)}</strong>
          <small class="muted">${escapeHtml(entry.id)} · ${escapeHtml((entry.platforms || []).join(", "))}</small>
        </div>
        <div class="selected-step-actions">
          <button type="button" class="btn btn-ghost" data-action="adversary-move-up" data-id="${entry.id}" ${index === 0 ? "disabled" : ""}>${escapeHtml(t("adversaries.create.move_up"))}</button>
          <button type="button" class="btn btn-ghost" data-action="adversary-move-down" data-id="${entry.id}" ${index === state.adversaryCompose.selectedOrder.length - 1 ? "disabled" : ""}>${escapeHtml(t("adversaries.create.move_down"))}</button>
          <button type="button" class="btn btn-danger" data-action="adversary-remove-ability" data-id="${entry.id}">${escapeHtml(t("adversaries.create.remove"))}</button>
        </div>
      </article>
      `;
    })
    .join("");

  selectedRoot.innerHTML = selectedRows || `<p class="muted ability-empty">${escapeHtml(t("adversaries.create.none_selected"))}</p>`;
  if (selectedCount) {
    selectedCount.textContent = String(state.adversaryCompose.selectedOrder.length);
  }
  setAdversaryFormSubmitState();
}

function adversaryFormSignature() {
  const payload = {
    name: document.getElementById("adversary-name")?.value?.trim() || "",
    description: document.getElementById("adversary-description")?.value?.trim() || "",
    confidence: Number(document.getElementById("adversary-confidence")?.value || "70"),
    selected: [...state.adversaryCompose.selectedOrder],
  };
  return JSON.stringify(payload);
}

function syncAdversaryModalTitle() {
  const title = document.getElementById("adversary-form-title");
  const editBtn = document.getElementById("adversary-title-edit");
  if (!title || !editBtn) return;
  if (state.adversaryCompose.mode !== "edit") {
    title.textContent = t("adversaries.create.title");
    editBtn.classList.add("hidden");
    return;
  }
  const name = document.getElementById("adversary-name")?.value?.trim() || "";
  title.textContent = name || t("adversaries.edit.untitled");
  editBtn.classList.remove("hidden");
}

function beginAdversaryTitleEdit() {
  if (state.adversaryCompose.mode !== "edit") return;
  const title = document.getElementById("adversary-form-title");
  const input = document.getElementById("adversary-title-inline");
  const editBtn = document.getElementById("adversary-title-edit");
  if (!(input instanceof HTMLInputElement) || !title || !editBtn) return;
  input.value = document.getElementById("adversary-name")?.value?.trim() || "";
  title.classList.add("hidden");
  input.classList.remove("hidden");
  editBtn.classList.add("hidden");
  input.focus();
  input.select();
}

function commitAdversaryTitleEdit(cancel = false) {
  const title = document.getElementById("adversary-form-title");
  const input = document.getElementById("adversary-title-inline");
  const editBtn = document.getElementById("adversary-title-edit");
  const nameField = document.getElementById("adversary-name");
  if (!(input instanceof HTMLInputElement) || !(nameField instanceof HTMLInputElement) || !title || !editBtn) return;
  if (!cancel) {
    nameField.value = input.value.trim();
    setAdversaryFormSubmitState();
  }
  input.classList.add("hidden");
  title.classList.remove("hidden");
  if (state.adversaryCompose.mode === "edit") {
    editBtn.classList.remove("hidden");
  }
  syncAdversaryModalTitle();
}

function setAdversaryFormMode(mode, adversary = null) {
  const normalized = mode === "edit" ? "edit" : "create";
  state.adversaryCompose.mode = normalized;
  state.adversaryCompose.editingId = normalized === "edit" ? adversary?.id || null : null;
  state.adversaryCompose.compatibleExports = normalized === "edit"
    ? [...new Set((adversary?.compatible_exports || []).map((target) => String(target).toLowerCase()))]
    : [];
  const title = document.getElementById("adversary-form-title");
  const inlineTitle = document.getElementById("adversary-title-inline");
  const editBtn = document.getElementById("adversary-title-edit");
  const submit = document.getElementById("adversary-submit");
  if (title) {
    title.textContent = normalized === "edit" ? (adversary?.name || t("adversaries.edit.untitled")) : t("adversaries.create.title");
  }
  if (inlineTitle instanceof HTMLInputElement) {
    inlineTitle.classList.add("hidden");
    inlineTitle.value = "";
  }
  if (editBtn) {
    editBtn.classList.toggle("hidden", normalized !== "edit");
    editBtn.title = t("adversaries.edit.title_action");
    editBtn.setAttribute("aria-label", t("adversaries.edit.title_action"));
  }
  if (submit) {
    submit.textContent = normalized === "edit" ? t("common.save") : t("common.apply");
  }

  const exportRoot = document.getElementById("adversary-export-inline");
  const exportSelect = document.getElementById("adversary-export-target-inline");
  if (exportRoot && exportSelect) {
    if (normalized === "edit") {
      exportRoot.classList.remove("hidden");
      const options = state.adversaryCompose.compatibleExports;
      exportSelect.innerHTML = options
        .map((target) => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`)
        .join("");
      if (!options.length) {
        exportSelect.innerHTML = `<option value="">${escapeHtml(t("common.no_data"))}</option>`;
      }
      exportSelect.disabled = options.length === 0;
    } else {
      exportRoot.classList.add("hidden");
      exportSelect.innerHTML = "";
      exportSelect.disabled = true;
    }
  }
  const exportButton = document.getElementById("adversary-export-inline-button");
  if (exportButton) {
    exportButton.title = t("adversaries.detail.export");
    exportButton.setAttribute("aria-label", t("adversaries.detail.export"));
  }
  syncAdversaryModalTitle();
}

function setAdversaryFormSubmitState() {
  const submit = document.getElementById("adversary-submit");
  if (!(submit instanceof HTMLButtonElement)) return;
  const hasName = Boolean(document.getElementById("adversary-name")?.value?.trim());
  const hasSteps = state.adversaryCompose.selectedOrder.length > 0;
  if (state.adversaryCompose.mode === "edit") {
    const dirty = adversaryFormSignature() !== state.adversaryCompose.originalSignature;
    submit.disabled = !dirty || !hasName || !hasSteps;
  } else {
    submit.disabled = !hasName || !hasSteps;
  }
}

function openAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  resetAdversaryComposer();
  document.getElementById("adversary-form")?.reset();
  setAdversaryFormMode("create");
  state.adversaryCompose.originalSignature = adversaryFormSignature();
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  renderAdversaryAbilitySelector();
  dialog.showModal();
  setTimeout(() => document.getElementById("adversary-name")?.focus(), 0);
}

async function openAdversaryEditor(adversaryId) {
  const adversary = await api(`/api/adversaries/${encodeURIComponent(adversaryId)}`);
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  resetAdversaryComposer();
  document.getElementById("adversary-name").value = adversary.name || "";
  document.getElementById("adversary-description").value = adversary.description || "";
  document.getElementById("adversary-confidence").value = String(adversary.confidence ?? 70);
  state.adversaryCompose.selectedOrder = Array.isArray(adversary.ability_refs)
    ? [...adversary.ability_refs]
    : [];
  setAdversaryFormMode("edit", adversary);
  state.adversaryCompose.originalSignature = adversaryFormSignature();
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  renderAdversaryAbilitySelector();
  dialog.showModal();
}

function closeAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  dialog.close();
  resetAdversaryComposer();
  setAdversaryFormMode("create");
  state.adversaryCompose.originalSignature = "";
  document.getElementById("adversary-form")?.reset();
  renderAdversaryAbilitySelector();
  if (state.route === "adversaries-create") {
    state.route = "adversaries-catalog";
    localStorage.setItem("spuc-web-last-route", "adversaries-catalog");
    applyNavSelection("adversaries-catalog");
    refreshRouteMeta();
  }
}

async function createAdversary(event) {
  event.preventDefault();
  syncAdversaryComposerFromInputs();
  const selected = [...state.adversaryCompose.selectedOrder];
  if (!selected.length) {
    showToast("adversaries.create.none_selected", true);
    return;
  }
  const executor = state.adversaryCompose.executor || "manifest";
  const payload = {
    name: document.getElementById("adversary-name").value.trim(),
    description: document.getElementById("adversary-description").value.trim(),
    confidence: Number(document.getElementById("adversary-confidence").value || 70),
    ability_ids: selected,
    order: selected,
  };
  const isEdit = state.adversaryCompose.mode === "edit" && state.adversaryCompose.editingId;
  if (isEdit) {
    await api(`/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/update`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showToast("toast.saved");
    closeAdversaryDialog();
    await loadAdversaries(state.adversaries.page);
    return;
  }

  const response = await api("/api/adversaries", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  let downloads = Array.isArray(response.downloads) ? [...response.downloads] : [];
  if (executor !== "manifest" && response?.id) {
    const compiled = await api(`/api/adversaries/${encodeURIComponent(response.id)}/export${toQuery({ to: executor })}`);
    const extraDownloads = Array.isArray(compiled.downloads) ? compiled.downloads : [];
    const known = new Set(downloads.map((entry) => `${entry.name}|${entry.url}`));
    for (const entry of extraDownloads) {
      const key = `${entry.name}|${entry.url}`;
      if (known.has(key)) continue;
      known.add(key);
      downloads.push(entry);
    }
  }

  showToast("toast.saved");
  renderDownloadsModal(response.name || response.id, downloads);
  closeAdversaryDialog();
  event.target.reset();
  resetAdversaryComposer();
  renderAdversaryAbilitySelector();
  await loadAdversaries(1);
}

async function exportAdversaryFromDialog() {
  if (state.adversaryCompose.mode !== "edit" || !state.adversaryCompose.editingId) {
    return;
  }
  const select = document.getElementById("adversary-export-target-inline");
  if (!(select instanceof HTMLSelectElement) || !select.value) {
    showToast("adversaries.export.unavailable", true);
    return;
  }
  const response = await api(
    `/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/export${toQuery({ to: select.value })}`,
  );
  renderDownloadsModal(response.id, response.downloads);
}

function renderRuleLabPreview() {
  const editor = document.getElementById("rulelab-input");
  const overlay = document.getElementById("rulelab-highlight");
  const input = editor.value;
  overlay.innerHTML = `${highlightStix(input)}\n`;
  overlay.scrollTop = editor.scrollTop;
  overlay.scrollLeft = editor.scrollLeft;
  state.ruleLab.syntaxOk = null;
  const statusNode = document.getElementById("rulelab-status");
  if (statusNode) {
    statusNode.textContent = t("rulelab.status.idle");
  }
  setRuleLabSaveEnabled(false);
  setRuleLabError("");
  clearRuleLabCompatibilityView();
  renderRuleLabAutocomplete();
  scheduleRuleLabAnalysis();
}

function setRuleLabEditorState(mode) {
  const shell = document.getElementById("rulelab-editor-shell");
  shell.classList.remove("editor-valid", "editor-invalid", "editor-partial", "editor-neutral");
  shell.classList.add(mode);
}

function setRuleLabSaveEnabled(enabled) {
  const button = document.getElementById("rulelab-save");
  if (!button) return;
  button.disabled = !enabled;
}

function setRuleLabError(message) {
  const box = document.getElementById("rulelab-error-box");
  if (!box) return;
  if (!message) {
    box.classList.add("hidden");
    box.textContent = "";
    return;
  }
  box.classList.remove("hidden");
  box.innerHTML = `<strong>${escapeHtml(t("common.error"))}:</strong> ${escapeHtml(message)}`;
}

function clearRuleLabCompatibilityView() {
  document.getElementById("compatibility-stack").innerHTML = "";
  document.getElementById("compatibility-list").innerHTML = "";
  const meta = document.getElementById("rulelab-compat-meta");
  if (meta) {
    meta.textContent = "";
  }
  state.compatibility = [];
}

function updateLevelSelectStyle(selectId) {
  const select = typeof selectId === "string" ? document.getElementById(selectId) : selectId;
  if (!(select instanceof HTMLSelectElement)) return;
  select.classList.remove("level-clear", "level-green", "level-amber", "level-amber-strict", "level-red");
  select.classList.add(levelClassFromValue(select.value));
}

function filteredCompatibilityEntries() {
  const query = (state.ruleLab.compatFilter || "").trim().toLowerCase();
  if (!query) {
    return state.compatibility;
  }
  return state.compatibility.filter((entry) => {
    const target = String(entry.target || "").toLowerCase();
    const status = String(entry.runtime_status || "").toLowerCase();
    const summary = String(entry.summary || "").toLowerCase();
    return target.includes(query) || status.includes(query) || summary.includes(query);
  });
}

function renderRuleLabCompatibilityResults() {
  const entries = filteredCompatibilityEntries();
  const sigmaDynamicTargets = RULE_OUTPUT_TARGETS.filter((target) => String(target || "").toLowerCase().startsWith("sigma-to-"));
  const grouped = COMPATIBILITY_GROUPS.map((group) => {
    const targets = group.name === "SIEM"
      ? [...new Set([...group.targets, ...sigmaDynamicTargets])]
      : group.targets;
    const subset = entries.filter((entry) => targets.includes(String(entry.target || "").toLowerCase()));
    return {
      name: group.name,
      exact: subset.filter((entry) => statusBucket(entry.runtime_status) === "exact").length,
      lossy: subset.filter((entry) => statusBucket(entry.runtime_status) === "lossy").length,
      unsupported: subset.filter((entry) => statusBucket(entry.runtime_status) === "unsupported").length,
    };
  }).filter((group) => group.exact + group.lossy + group.unsupported > 0);
  renderCompatibilityStack(grouped);

  const meta = document.getElementById("rulelab-compat-meta");
  if (meta) {
    meta.textContent = entries.length === state.compatibility.length
      ? tf("rulelab.outputs_count", { count: entries.length })
      : tf("rulelab.outputs_count_filtered", { shown: entries.length, total: state.compatibility.length });
  }

  const root = document.getElementById("compatibility-list");
  root.innerHTML = entries
    .map(
      (entry) => `
      <article class="compat-row ${compatibilityVisualState(entry).cls}">
        <header>
          <strong>${escapeHtml(entry.target)}</strong>
          <span class="compat-state ${compatibilityVisualState(entry).cls}">
            <span class="state-icon">${compatibilityVisualState(entry).icon}</span>
            ${statusBadge(entry.runtime_status, entry.severity)}
          </span>
        </header>
        <span class="muted">${escapeHtml(entry.summary)}</span>
        ${canShowCompatibilityOutput(entry)
      ? `<div><button class="btn btn-ghost" data-action="compat-show" data-target="${entry.target}">${escapeHtml(t("common.show_output"))}</button></div>`
      : ""}
      </article>
    `,
    )
    .join("");
}

function canShowCompatibilityOutput(entry) {
  if (statusBucket(entry?.runtime_status) === "unsupported") {
    return false;
  }
  if (String(entry?.severity || "").toLowerCase() === "error") {
    return false;
  }
  return Boolean(String(entry?.output || "").trim());
}

function compatibilityVisualState(entry) {
  const bucket = statusBucket(entry.runtime_status);
  if (bucket === "exact") {
    return { cls: "success", icon: "✓" };
  }
  if (bucket === "lossy") {
    return { cls: "warning", icon: "!" };
  }
  return { cls: "error", icon: "×" };
}

function autocompleteContextFromEditor(text, cursor) {
  const left = text.slice(0, cursor);
  const observableMatch = left.match(/([a-z0-9_-]+):([a-z0-9_.\[\]\*-]*)$/i);
  if (observableMatch) {
    const observable = observableMatch[1].toLowerCase();
    const fieldFragment = observableMatch[2] || "";
    const fields = STIX_OBSERVABLE_FIELDS[observable] || [];
    const options = fields
      .filter((field) => field.toLowerCase().startsWith(fieldFragment.toLowerCase()))
      .slice(0, 12)
      .map((field) => ({ label: `${observable}:${field}`, insert: field }));
    return {
      from: cursor - fieldFragment.length,
      to: cursor,
      options,
    };
  }

  const observableTokenMatch = left.match(/([a-z0-9_-]+)$/i);
  if (observableTokenMatch) {
    const fragment = observableTokenMatch[1] || "";
    const observableOptions = STIX_OBSERVABLES
      .filter((observable) => observable.toLowerCase().startsWith(fragment.toLowerCase()))
      .slice(0, 12)
      .map((observable) => ({ label: `${observable}:`, insert: `${observable}:` }));
    const attributeOptions = STIX_OBSERVABLES
      .filter((observable) => observable.toLowerCase().startsWith(fragment.toLowerCase()))
      .slice(0, 4)
      .flatMap((observable) =>
        (STIX_OBSERVABLE_FIELDS[observable] || [])
          .slice(0, 4)
          .map((field) => ({ label: `${observable}:${field}`, insert: `${observable}:${field}` })),
      );
    const seen = new Set();
    const options = [...observableOptions, ...attributeOptions].filter((option) => {
      if (seen.has(option.label)) return false;
      seen.add(option.label);
      return true;
    });
    if (options.length) {
      return {
        from: cursor - fragment.length,
        to: cursor,
        options,
      };
    }
  }

  const tokenMatch = left.match(/([a-z0-9_.\[\]\*-]+)$/i);
  const fragment = tokenMatch?.[1] || "";
  if (!fragment) return null;
  const options = STIX_TOKENS
    .filter((token) => token.toLowerCase().startsWith(fragment.toLowerCase()))
    .slice(0, 12)
    .map((token) => ({ label: token, insert: token }));
  if (!options.length) return null;
  return {
    from: cursor - fragment.length,
    to: cursor,
    options,
  };
}

function hideRuleLabAutocomplete() {
  const root = document.getElementById("rulelab-autocomplete");
  root.hidden = true;
  root.innerHTML = "";
  state.ruleLab.autocomplete = [];
  state.ruleLab.activeSuggestion = 0;
  state.ruleLab.autocompleteContext = null;
}

function renderRuleLabAutocomplete() {
  const editor = document.getElementById("rulelab-input");
  const context = autocompleteContextFromEditor(editor.value, editor.selectionStart);
  const root = document.getElementById("rulelab-autocomplete");
  if (!context || !context.options.length) {
    hideRuleLabAutocomplete();
    return;
  }

  state.ruleLab.autocomplete = context.options;
  state.ruleLab.activeSuggestion = Math.min(state.ruleLab.activeSuggestion, context.options.length - 1);
  state.ruleLab.autocompleteContext = context;

  root.hidden = false;
  root.innerHTML = context.options
    .map(
      (option, idx) => `
      <button type="button" class="autocomplete-option ${idx === state.ruleLab.activeSuggestion ? "active" : ""}" data-action="autocomplete-pick" data-index="${idx}">
        ${escapeHtml(option.label)}
      </button>
    `,
    )
    .join("");
}

function applyRuleLabAutocomplete(index = state.ruleLab.activeSuggestion) {
  const editor = document.getElementById("rulelab-input");
  const context = state.ruleLab.autocompleteContext;
  const selected = state.ruleLab.autocomplete[index];
  if (!context || !selected) return false;

  const before = editor.value.slice(0, context.from);
  const after = editor.value.slice(context.to);
  editor.value = `${before}${selected.insert}${after}`;
  const cursor = before.length + selected.insert.length;
  editor.setSelectionRange(cursor, cursor);
  hideRuleLabAutocomplete();
  renderRuleLabPreview();
  return true;
}

function applyEditorPair(event, editor, rerender) {
  const openClose = { "(": ")", "[": "]", "{": "}", "\"": "\"", "'": "'" };
  const closeToOpen = { ")": "(", "]": "[", "}": "{", "\"": "\"", "'": "'" };
  const open = openClose[event.key];
  const close = closeToOpen[event.key];
  const start = editor.selectionStart;
  const end = editor.selectionEnd;
  const value = editor.value;

  if (open && !event.ctrlKey && !event.metaKey && !event.altKey) {
    event.preventDefault();
    const selected = value.slice(start, end);
    const before = value.slice(0, start);
    const after = value.slice(end);
    const prevChar = value.slice(Math.max(0, start - 1), start);
    const nextChar = value.slice(start, start + 1);
    const isQuote = event.key === "\"" || event.key === "'";

    if (isQuote && selected.length === 0) {
      if (nextChar === event.key) {
        editor.setSelectionRange(start + 1, start + 1);
        return true;
      }
      if (prevChar === event.key) {
        editor.setSelectionRange(start, start);
        return true;
      }
    }

    if (selected.length > 0) {
      editor.value = `${before}${event.key}${selected}${open}${after}`;
      editor.setSelectionRange(start + 1, end + 1);
    } else {
      editor.value = `${before}${event.key}${open}${after}`;
      editor.setSelectionRange(start + 1, start + 1);
    }
    rerender();
    return true;
  }

  if (close && start === end && value.slice(start, start + 1) === event.key) {
    event.preventDefault();
    editor.setSelectionRange(start + 1, start + 1);
    return true;
  }

  return false;
}

function ruleLabPairsKeydown(event) {
  const editor = event.target;
  if (!(editor instanceof HTMLTextAreaElement)) return;

  if (!document.getElementById("rulelab-autocomplete").hidden) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      state.ruleLab.activeSuggestion = Math.min(
        state.ruleLab.autocomplete.length - 1,
        state.ruleLab.activeSuggestion + 1,
      );
      renderRuleLabAutocomplete();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      state.ruleLab.activeSuggestion = Math.max(0, state.ruleLab.activeSuggestion - 1);
      renderRuleLabAutocomplete();
      return;
    }
    if (event.key === "Tab" || event.key === "Enter") {
      event.preventDefault();
      applyRuleLabAutocomplete();
      return;
    }
    if (event.key === "Escape") {
      hideRuleLabAutocomplete();
      return;
    }
  }

  applyEditorPair(event, editor, renderRuleLabPreview);
}

function scheduleRuleLabAnalysis() {
  clearTimeout(state.ruleLab.verifyTimer);
  clearTimeout(state.ruleLab.compatibilityTimer);
  state.ruleLab.verifyTimer = setTimeout(() => {
    verifyRuleLab({ openPreview: false, silent: true });
  }, 280);
  state.ruleLab.compatibilityTimer = setTimeout(() => {
    compatibilityRuleLab({ silent: true });
  }, 620);
}

async function verifyRuleLab({ openPreview = true, silent = false } = {}) {
  const payload = {
    rule: document.getElementById("rulelab-input").value,
    name: document.getElementById("rulelab-title").value,
    description: document.getElementById("rulelab-description").value,
    confidence: Number(document.getElementById("rulelab-confidence").value || 70),
    tlp: document.getElementById("rulelab-tlp").value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap").value || "PAP:GREEN",
  };
  const requestId = ++state.ruleLab.verifyRequestId;
  const response = await api("/api/verify", { method: "POST", body: JSON.stringify(payload) });
  if (requestId !== state.ruleLab.verifyRequestId) return;
  const statusNode = document.getElementById("rulelab-status");
  if (response.syntax_ok) {
    state.ruleLab.syntaxOk = true;
    statusNode.innerHTML = `${statusBadge(t("rulelab.syntax_ok"), "success")} ${escapeHtml(t("rulelab.valid"))}`;
    setRuleLabEditorState("editor-valid");
    setRuleLabError("");
    setRuleLabSaveEnabled(true);
  } else {
    state.ruleLab.syntaxOk = false;
    statusNode.innerHTML = `${statusBadge(t("rulelab.syntax_error"), "error")} ${escapeHtml(response.syntax_error || "")}`;
    setRuleLabEditorState("editor-invalid");
    setRuleLabError(response.syntax_error || t("rulelab.invalid_pattern"));
    setRuleLabSaveEnabled(false);
    clearRuleLabCompatibilityView();
  }
  if (openPreview && response.ability_preview) {
    openDetail(t("rulelab.preview"), response.ability_preview);
  }
  if (!silent && !response.syntax_ok) {
    showToast("rulelab.syntax_error", true);
  }
}

async function compatibilityRuleLab({ silent = false } = {}) {
  if (state.ruleLab.syntaxOk !== true) {
    clearRuleLabCompatibilityView();
    return;
  }
  const payload = {
    rule: document.getElementById("rulelab-input").value,
    name: document.getElementById("rulelab-title").value,
    description: document.getElementById("rulelab-description").value,
    confidence: Number(document.getElementById("rulelab-confidence").value || 70),
  };
  const requestId = ++state.ruleLab.compatibilityRequestId;
  const response = await api("/api/rules/compatibility", { method: "POST", body: JSON.stringify(payload) });
  if (requestId !== state.ruleLab.compatibilityRequestId) return;
  state.compatibility = response.entries || [];
  renderRuleLabCompatibilityResults();

  const exact = state.compatibility.filter((entry) => statusBucket(entry.runtime_status) === "exact").length;
  const lossy = state.compatibility.filter((entry) => statusBucket(entry.runtime_status) === "lossy").length;
  const unsupported = state.compatibility.filter((entry) => statusBucket(entry.runtime_status) === "unsupported").length;

  const statusNode = document.getElementById("rulelab-status");
  if (exact > 0 && lossy === 0 && unsupported === 0) {
    setRuleLabEditorState("editor-valid");
    statusNode.innerHTML = `${statusBadge(t("rules.status.exact"), "success")} ${tf("rulelab.compat_summary_exact", { exact, total: state.compatibility.length })}`;
  } else if (exact > 0 || lossy > 0) {
    setRuleLabEditorState("editor-partial");
    statusNode.innerHTML = `${statusBadge(t("rulelab.compat_partial"), "warning")} ${tf("rulelab.compat_summary_partial", { exact, lossy, unsupported })}`;
  } else {
    setRuleLabEditorState("editor-invalid");
    statusNode.innerHTML = `${statusBadge(t("rules.status.unsupported"), "error")} ${tf("rulelab.compat_summary_unsupported", { unsupported, total: state.compatibility.length })}`;
  }

  if (!silent && state.compatibility.length === 0) {
    showToast("common.no_data", true);
  }
}

async function saveRuleLab() {
  if (state.ruleLab.syntaxOk !== true) {
    showToast("rulelab.syntax_error", true);
    return;
  }
  const payload = {
    rule: document.getElementById("rulelab-input").value,
    name: document.getElementById("rulelab-title").value,
    description: document.getElementById("rulelab-description").value,
    confidence: Number(document.getElementById("rulelab-confidence").value || 70),
    tlp: document.getElementById("rulelab-tlp").value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap").value || "PAP:GREEN",
  };
  const response = await api("/api/rules/save", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  showToast("toast.saved");
  openDetail(t("rulelab.saved"), response);
  await Promise.all([loadRules(1), loadOverview()]);
  renderDashboard();
}

function parseRulesFromText(raw) {
  return String(raw || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  let size = value;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  const precision = size >= 10 || index === 0 ? 0 : 1;
  return `${size.toFixed(precision)} ${units[index]}`;
}

function setRulesImportBusy(busy) {
  const saveButton = document.getElementById("rules-new-save");
  const fileInput = document.getElementById("rules-new-file");
  if (saveButton) saveButton.disabled = busy;
  if (fileInput) fileInput.disabled = busy;
}

function renderRulesImportProgress() {
  const root = document.getElementById("rules-import-progress");
  const statusNode = document.getElementById("rules-import-status");
  const countNode = document.getElementById("rules-import-count");
  const percentNode = document.getElementById("rules-import-percent");
  const barNode = document.getElementById("rules-import-bar");
  if (!root || !statusNode || !countNode || !percentNode || !barNode) return;

  if (!state.rulesImport.active) {
    root.classList.add("hidden");
    return;
  }

  root.classList.remove("hidden");
  const phase = state.rulesImport.phase;
  if (phase === "reading") {
    statusNode.textContent = t("rules.import.progress.reading");
    countNode.textContent = `${formatBytes(state.rulesImport.done)} / ${formatBytes(state.rulesImport.total)}`;
  } else if (phase === "saving") {
    statusNode.textContent = `${t("rules.import.progress.saving")} (${state.rulesImport.ok} OK · ${state.rulesImport.failed} ERR)`;
    countNode.textContent = `${state.rulesImport.done}/${state.rulesImport.total}`;
  } else if (phase === "done") {
    statusNode.textContent = t("rules.import.progress.done");
    countNode.textContent = `${state.rulesImport.ok}/${state.rulesImport.total}`;
  } else if (phase === "done_with_errors") {
    statusNode.textContent = t("rules.import.progress.done_with_errors");
    countNode.textContent = `${state.rulesImport.ok}/${state.rulesImport.total}`;
  } else {
    statusNode.textContent = "";
    countNode.textContent = "0/0";
  }

  const percent = Math.max(0, Math.min(100, Number(state.rulesImport.percent || 0)));
  percentNode.textContent = `${Math.round(percent)}%`;
  barNode.style.width = `${percent}%`;
}

function resetRulesImportProgress() {
  state.rulesImport.active = false;
  state.rulesImport.phase = "idle";
  state.rulesImport.percent = 0;
  state.rulesImport.done = 0;
  state.rulesImport.total = 0;
  state.rulesImport.ok = 0;
  state.rulesImport.failed = 0;
  renderRulesImportProgress();
}

function updateRulesImportProgress(patch) {
  state.rulesImport = { ...state.rulesImport, ...patch };
  renderRulesImportProgress();
}

function readTextFileWithProgress(file, onProgress) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (event) => {
      if (event.lengthComputable) {
        onProgress(event.loaded, event.total);
      }
    };
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(reader.error || new Error("file_read_failed"));
    reader.readAsText(file);
  });
}

async function collectRulesFromFileInput() {
  const fileInput = document.getElementById("rules-new-file");
  const file = fileInput?.files?.[0];
  if (!file) return [];
  updateRulesImportProgress({
    active: true,
    phase: "reading",
    percent: 0,
    done: 0,
    total: file.size || 0,
    ok: 0,
    failed: 0,
  });
  const raw = await readTextFileWithProgress(file, (loaded, total) => {
    const percent = total > 0 ? (loaded / total) * 100 : 0;
    updateRulesImportProgress({
      active: true,
      phase: "reading",
      done: loaded,
      total,
      percent,
    });
  });
  const rules = parseRulesFromText(raw);
  updateRulesImportProgress({
    active: true,
    phase: "saving",
    percent: 0,
    done: 0,
    total: rules.length,
    ok: 0,
    failed: 0,
  });
  return rules;
}

function renderRulesWorkspace() {
  const mode = state.rules.workspaceMode || "explore";
  const welcomeCard = document.getElementById("rules-welcome-card");
  const ingestCard = document.getElementById("rules-ingest-card");
  const exploreShell = document.getElementById("rules-explore-shell");
  const panel = document.getElementById("panel-rules");
  if (welcomeCard) {
    welcomeCard.classList.toggle("hidden", mode !== "welcome");
  }
  if (ingestCard) {
    ingestCard.classList.toggle("hidden", mode !== "file");
  }
  if (exploreShell) {
    exploreShell.classList.toggle("hidden", mode !== "explore");
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", mode === "welcome");
  }
}

function renderAdversaryWorkspace() {
  const mode = state.adversaries.workspaceMode || "welcome";
  const welcomeCard = document.getElementById("adversaries-welcome-card");
  const catalogShell = document.getElementById("adversaries-catalog-shell");
  const safetyToast = document.getElementById("adversaries-safety-toast");
  const panel = document.getElementById("panel-adversaries");
  if (welcomeCard) {
    welcomeCard.classList.toggle("hidden", mode !== "welcome");
  }
  if (catalogShell) {
    catalogShell.classList.toggle("hidden", mode !== "catalog");
  }
  if (safetyToast) {
    const dismissed = localStorage.getItem("spuc-web-adversary-safety-dismissed") === "1";
    safetyToast.classList.toggle("hidden", mode !== "catalog" || dismissed);
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", mode === "welcome");
  }
}

function renderStixObjectsWorkspace() {
  const mode = state.stixObjectsView.workspaceMode || "welcome";
  const welcomeCard = document.getElementById("stix-objects-welcome-card");
  const catalogShell = document.getElementById("stix-objects-catalog-shell");
  const panel = document.getElementById("panel-stix-objects");
  if (welcomeCard) {
    welcomeCard.classList.toggle("hidden", mode !== "welcome");
  }
  if (catalogShell) {
    catalogShell.classList.toggle("hidden", mode !== "catalog");
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", mode === "welcome");
  }
}

function renderRulesAdvancedFilters() {
  const root = document.getElementById("rules-filter-rows");
  root.innerHTML = state.rules.advancedFilters
    .map(
      (filter, index) => `
      <div class="rules-filter-row">
        <select data-filter-id="${filter.id}" data-filter-prop="logic" ${index === 0 ? "disabled" : ""}>
          <option value="and" ${filter.logic === "and" ? "selected" : ""}>AND</option>
          <option value="or" ${filter.logic === "or" ? "selected" : ""}>OR</option>
        </select>
        <select data-filter-id="${filter.id}" data-filter-prop="field">
          <option value="emulable" ${filter.field === "emulable" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.emulable"))}</option>
          <option value="output_target" ${filter.field === "output_target" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.output_target"))}</option>
          <option value="output_reliability" ${filter.field === "output_reliability" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.output_reliability"))}</option>
          <option value="confidence" ${filter.field === "confidence" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.confidence"))}</option>
          <option value="name" ${filter.field === "name" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.name"))}</option>
          <option value="completion" ${filter.field === "completion" ? "selected" : ""}>${escapeHtml(t("rules.advanced.field.completion"))}</option>
        </select>
        <select data-filter-id="${filter.id}" data-filter-prop="op">
          <option value="gt" ${filter.op === "gt" ? "selected" : ""}>></option>
          <option value="lt" ${filter.op === "lt" ? "selected" : ""}><</option>
          <option value="eq" ${filter.op === "eq" ? "selected" : ""}>=</option>
          <option value="contains" ${filter.op === "contains" ? "selected" : ""}>${escapeHtml(t("rules.advanced.op.contains"))}</option>
        </select>
        <input data-filter-id="${filter.id}" data-filter-prop="value" value="${escapeHtml(filter.value || "")}" placeholder="${escapeHtml(t("rules.advanced.value.placeholder"))}">
        <button class="btn btn-danger" data-action="rules-remove-filter" data-id="${filter.id}">X</button>
      </div>
    `,
    )
    .join("");
}

async function saveRulesBatch(rules) {
  if (!rules.length) {
    showToast("rules.no_rules_to_save");
    resetRulesImportProgress();
    return;
  }
  const basePayload = {
    name: undefined,
    description: document.getElementById("rules-new-description").value,
    confidence: Number(document.getElementById("rules-new-confidence").value || 70),
    tlp: document.getElementById("rules-new-tlp").value || "TLP:GREEN",
    pap: document.getElementById("rules-new-pap").value || "PAP:GREEN",
  };
  let ok = 0;
  let failed = 0;
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    try {
      await api("/api/rules/save", {
        method: "POST",
        body: JSON.stringify({ ...basePayload, rule }),
      });
      ok += 1;
    } catch (_error) {
      // Continue to process remaining rules.
      failed += 1;
    }
    updateRulesImportProgress({
      active: true,
      phase: "saving",
      done: index + 1,
      total: rules.length,
      ok,
      failed,
      percent: ((index + 1) / rules.length) * 100,
    });
  }
  updateRulesImportProgress({
    active: true,
    phase: failed > 0 ? "done_with_errors" : "done",
    done: rules.length,
    total: rules.length,
    ok,
    failed,
    percent: 100,
  });
  showToast(tf("rules.saved_batch", { ok, total: rules.length }), false);
  await Promise.all([loadRules(1), loadOverview()]);
}

async function deleteSelectedRules() {
  if (state.rules.selected.size === 0) return;
  const confirmed = confirm(t("rules.confirm_delete_selected"));
  if (!confirmed) return;
  const selectedIds = [...state.rules.selected];
  for (const id of selectedIds) {
    await api(`/api/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: "{}",
    });
  }
  state.rules.selected.clear();
  state.rules.bulkEditOpen = false;
  showToast("toast.saved");
  await Promise.all([loadRules(1), loadOverview()]);
}

async function applyBulkRulesEdit() {
  if (state.rules.selected.size === 0) return;
  const bulkTlp = document.getElementById("rules-bulk-tlp").value;
  const bulkPap = document.getElementById("rules-bulk-pap").value;
  const confidenceRaw = document.getElementById("rules-bulk-confidence").value.trim();
  const updateConfidence = confidenceRaw !== "";
  const parsedConfidence = Number(confidenceRaw || "0");
  if (updateConfidence && (Number.isNaN(parsedConfidence) || parsedConfidence < 0 || parsedConfidence > 100)) {
    showToast("confidence_out_of_range", true);
    return;
  }

  const selectedEntries = state.rules.allEntries.filter((entry) => state.rules.selected.has(entry.id));
  for (const entry of selectedEntries) {
    await api("/api/rules/save", {
      method: "POST",
      body: JSON.stringify({
        rule: entry.rule,
        name: entry.name,
        description: entry.description || "",
        confidence: updateConfidence ? parsedConfidence : Number(entry.confidence || 70),
        tlp: bulkTlp === "KEEP" ? entry.tlp : bulkTlp,
        pap: bulkPap === "KEEP" ? entry.pap : bulkPap,
        indicates: entry.indicates || undefined,
      }),
    });
  }

  state.rules.selected.clear();
  state.rules.bulkEditOpen = false;
  document.getElementById("rules-bulk-confidence").value = "";
  document.getElementById("rules-bulk-tlp").value = "KEEP";
  document.getElementById("rules-bulk-pap").value = "KEEP";
  updateLevelSelectStyle("rules-bulk-tlp");
  updateLevelSelectStyle("rules-bulk-pap");
  showToast("toast.saved");
  await Promise.all([loadRules(state.rules.page), loadOverview()]);
}

function cancelBulkRulesEdit() {
  state.rules.bulkEditOpen = false;
  updateRulesBulkState();
}

async function ensureAdversaryEntryForUpdate(entry) {
  if (Array.isArray(entry.ability_refs) && entry.ability_refs.length > 0) {
    return entry;
  }
  return api(`/api/adversaries/${encodeURIComponent(entry.id)}`);
}

async function deleteSelectedAdversaries() {
  if (state.adversaries.selected.size === 0) return;
  const confirmed = confirm(t("adversaries.confirm_delete_selected"));
  if (!confirmed) return;
  const selectedIds = [...state.adversaries.selected];
  for (const id of selectedIds) {
    await api(`/api/adversaries/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: "{}",
    });
  }
  state.adversaries.selected.clear();
  state.adversaries.bulkEditOpen = false;
  showToast("toast.saved");
  await Promise.all([loadAdversaries(1), loadOverview()]);
}

async function applyBulkAdversariesEdit() {
  if (state.adversaries.selected.size === 0) return;
  const bulkTlp = document.getElementById("adversaries-bulk-tlp").value;
  const bulkPap = document.getElementById("adversaries-bulk-pap").value;
  const confidenceRaw = document.getElementById("adversaries-bulk-confidence").value.trim();
  const updateConfidence = confidenceRaw !== "";
  const parsedConfidence = Number(confidenceRaw || "0");
  if (updateConfidence && (Number.isNaN(parsedConfidence) || parsedConfidence < 0 || parsedConfidence > 100)) {
    showToast("confidence_out_of_range", true);
    return;
  }

  const selectedEntries = state.adversaries.allEntries.filter((entry) => state.adversaries.selected.has(entry.id));
  for (const baseEntry of selectedEntries) {
    const entry = await ensureAdversaryEntryForUpdate(baseEntry);
    const ordered = Array.isArray(entry.ability_refs) ? [...entry.ability_refs] : [];
    if (!ordered.length) continue;
    await api(`/api/adversaries/${encodeURIComponent(entry.id)}/update`, {
      method: "POST",
      body: JSON.stringify({
        name: entry.name,
        description: entry.description || "",
        confidence: updateConfidence ? parsedConfidence : Number(entry.confidence || 70),
        ability_ids: ordered,
        order: ordered,
        tlp: bulkTlp === "KEEP" ? normalizeTlpValue(entry.tlp || "TLP:GREEN") : bulkTlp,
        pap: bulkPap === "KEEP" ? normalizePapValue(entry.pap || "PAP:GREEN") : bulkPap,
      }),
    });
  }

  state.adversaries.selected.clear();
  state.adversaries.bulkEditOpen = false;
  document.getElementById("adversaries-bulk-confidence").value = "";
  document.getElementById("adversaries-bulk-tlp").value = "KEEP";
  document.getElementById("adversaries-bulk-pap").value = "KEEP";
  updateLevelSelectStyle("adversaries-bulk-tlp");
  updateLevelSelectStyle("adversaries-bulk-pap");
  showToast("toast.saved");
  await Promise.all([loadAdversaries(state.adversaries.page), loadOverview()]);
}

function cancelBulkAdversariesEdit() {
  state.adversaries.bulkEditOpen = false;
  updateAdversariesBulkState();
}

function localizeLearningGuide(entry) {
  const localized = LEARNING_GUIDE_LOCALIZATION[state.locale]?.[entry.id];
  if (!localized) return entry;
  return {
    ...entry,
    title: localized.title || entry.title,
    summary: localized.summary || entry.summary,
  };
}

function localizeLearningChallenge(entry) {
  const localized = LEARNING_CHALLENGE_LOCALIZATION[state.locale]?.[entry.id];
  if (!localized) return entry;
  return {
    ...entry,
    title: localized.title || entry.title,
    goal: localized.goal || entry.goal,
    hint: localized.hint || entry.hint,
  };
}

function renderLearningGuides() {
  const root = document.getElementById("learning-grid");
  if (!root) return;
  root.innerHTML = "";
}

function learningPathLabel(pathId) {
  if (!pathId) return "";
  const known = t(`learning.paths.${pathId}`);
  return known === `learning.paths.${pathId}` ? pathId.toUpperCase() : known;
}

function renderLearningPathOptions() {
  const select = document.getElementById("learning-path");
  if (!(select instanceof HTMLSelectElement)) return;
  const paths = [...new Set(state.learning.challenges.map((entry) => String(entry.path_id || "").trim()).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  select.innerHTML = `
    <option value="">${escapeHtml(t("learning.paths.all"))}</option>
    ${paths.map((pathId) => `<option value="${escapeHtml(pathId)}">${escapeHtml(learningPathLabel(pathId))}</option>`).join("")}
  `;
  select.value = paths.includes(state.learning.pathFilter) ? state.learning.pathFilter : "";
  state.learning.pathFilter = select.value;
}

function filteredLearningChallenges() {
  const query = state.learning.search.trim().toLowerCase();
  const pathFilter = String(state.learning.pathFilter || "").toLowerCase();
  return state.learning.challenges.filter((entry) => {
    if (state.learning.onlyPending && state.completedChallenges.has(entry.id)) {
      return false;
    }
    if (pathFilter && String(entry.path_id || "").toLowerCase() !== pathFilter) {
      return false;
    }
    if (!query) return true;
    const haystack = `${entry.id} ${entry.path_id || ""} ${entry.title} ${entry.goal}`.toLowerCase();
    return haystack.includes(query);
  });
}

function renderLearningChallenges() {
  const entries = filteredLearningChallenges();
  document.getElementById("challenges-grid").innerHTML = entries
    .map(
      (entry) => `
      <article class="learning-card glass ${state.completedChallenges.has(entry.id) ? "completed-card" : ""}">
        <div class="learning-card-head">
          <h3>${escapeHtml(entry.title)}</h3>
          <button class="btn btn-primary" data-action="learning-select" data-id="${entry.id}">${escapeHtml(t("learning.start"))}</button>
        </div>
        <p class="muted">${escapeHtml(entry.goal)}</p>
      </article>
    `,
    )
    .join("");

  const completed = state.learning.challenges.filter((entry) => state.completedChallenges.has(entry.id)).length;
  document.getElementById("learning-progress").textContent = t("learning.progress").replace("{done}", String(completed)).replace("{total}", String(state.learning.challenges.length));
}

async function loadLearning() {
  const challenges = await api("/api/tutorial/challenges");
  state.learning.guides = [];
  state.learning.challenges = (challenges || []).map((entry) => localizeLearningChallenge(entry));
  document.getElementById("learning-search").value = state.learning.search;
  renderLearningPathOptions();
  document.getElementById("learning-only-pending").checked = state.learning.onlyPending;
  renderLearningGuides();
  renderLearningChallenges();

  if (state.selectedChallenge) {
    const selectedStillExists = state.learning.challenges.find((item) => item.id === state.selectedChallenge.id);
    if (!selectedStillExists) {
      state.selectedChallenge = null;
    }
  }
  if (state.selectedChallenge) {
    mountLearningPractice(state.selectedChallenge.id);
  } else {
    document.getElementById("learning-hint").classList.add("hidden");
  }
}

function mountLearningPractice(challengeId) {
  const challenge = state.learning.challenges.find((item) => item.id === challengeId);
  if (!challenge) return;
  state.selectedChallenge = challenge;
  document.getElementById("learning-practice").classList.remove("hidden");
  document.getElementById("learning-practice-title").textContent = `${t("learning.exercise")} ${challenge.id} · ${challenge.title}`;
  document.getElementById("learning-goal").textContent = challenge.goal;
  document.getElementById("learning-status").textContent = t("learning.status.write");
  document.getElementById("learning-hint").classList.remove("hidden");
  document.getElementById("learning-input").value = "";
  renderLearningEditorPreview();
}

function hideLearningAutocomplete() {
  const root = document.getElementById("learning-autocomplete");
  root.hidden = true;
  root.innerHTML = "";
  state.learningEditor.autocomplete = [];
  state.learningEditor.activeSuggestion = 0;
  state.learningEditor.context = null;
}

function renderLearningAutocomplete() {
  const editor = document.getElementById("learning-input");
  const context = autocompleteContextFromEditor(editor.value, editor.selectionStart);
  const root = document.getElementById("learning-autocomplete");
  if (!context || !context.options.length) {
    hideLearningAutocomplete();
    return;
  }
  state.learningEditor.autocomplete = context.options;
  state.learningEditor.context = context;
  state.learningEditor.activeSuggestion = Math.min(
    state.learningEditor.activeSuggestion,
    context.options.length - 1,
  );
  root.hidden = false;
  root.innerHTML = context.options
    .map(
      (option, index) => `
      <button type="button" class="autocomplete-option ${index === state.learningEditor.activeSuggestion ? "active" : ""}" data-action="learning-autocomplete-pick" data-index="${index}">
        ${escapeHtml(option.label)}
      </button>
    `,
    )
    .join("");
}

function applyLearningAutocomplete(index = state.learningEditor.activeSuggestion) {
  const editor = document.getElementById("learning-input");
  const context = state.learningEditor.context;
  const selected = state.learningEditor.autocomplete[index];
  if (!context || !selected) return false;
  const before = editor.value.slice(0, context.from);
  const after = editor.value.slice(context.to);
  editor.value = `${before}${selected.insert}${after}`;
  const cursor = before.length + selected.insert.length;
  editor.setSelectionRange(cursor, cursor);
  hideLearningAutocomplete();
  renderLearningEditorPreview();
  return true;
}

function learningEditorKeydown(event) {
  const editor = event.target;
  if (!(editor instanceof HTMLTextAreaElement)) return;

  if (!document.getElementById("learning-autocomplete").hidden) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      state.learningEditor.activeSuggestion = Math.min(
        state.learningEditor.autocomplete.length - 1,
        state.learningEditor.activeSuggestion + 1,
      );
      renderLearningAutocomplete();
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      state.learningEditor.activeSuggestion = Math.max(0, state.learningEditor.activeSuggestion - 1);
      renderLearningAutocomplete();
      return;
    }
    if (event.key === "Tab" || event.key === "Enter") {
      event.preventDefault();
      applyLearningAutocomplete();
      return;
    }
    if (event.key === "Escape") {
      hideLearningAutocomplete();
      return;
    }
  }

  applyEditorPair(event, editor, renderLearningEditorPreview);
}

function renderLearningEditorPreview() {
  const editor = document.getElementById("learning-input");
  const overlay = document.getElementById("learning-highlight");
  overlay.innerHTML = `${highlightStix(editor.value)}\n`;
  overlay.scrollTop = editor.scrollTop;
  overlay.scrollLeft = editor.scrollLeft;
  renderLearningAutocomplete();
  scheduleLearningValidation();
}

function scheduleLearningValidation() {
  clearTimeout(state.learningEditor.verifyTimer);
  state.learningEditor.verifyTimer = setTimeout(() => {
    validateLearningSubmission();
  }, 350);
}

async function validateLearningSubmission() {
  if (!state.selectedChallenge) return;
  const rule = document.getElementById("learning-input").value;
  const requestId = ++state.learningEditor.requestId;
  const payload = {
    challenge_id: state.selectedChallenge.id,
    rule,
  };
  const response = await api("/api/tutorial/validate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (requestId !== state.learningEditor.requestId) return;

  const shell = document.getElementById("learning-editor-shell");
  const status = document.getElementById("learning-status");
  shell.classList.remove("editor-valid", "editor-invalid", "editor-partial", "editor-neutral");

  if (!response.syntax_ok) {
    shell.classList.add("editor-invalid");
    status.innerHTML = `${statusBadge("syntax", "error")} ${escapeHtml(response.message || t("learning.status.invalid"))}`;
    return;
  }

  if (response.solved) {
    shell.classList.add("editor-valid");
    state.completedChallenges.add(state.selectedChallenge.id);
    status.innerHTML = `${statusBadge("success", "success")} ${escapeHtml(t("learning.status.completed"))}`;
    renderLearningChallenges();
    return;
  }

  shell.classList.add("editor-partial");
  status.innerHTML = `${statusBadge("pending", "warning")} ${escapeHtml(response.message || t("learning.status.pending"))}`;
}

async function loadAdminUsers() {
  if (state.principal?.role !== "admin") return;
  const response = await api("/api/admin/users");
  state.adminUsers = response.entries || [];
  const rows = state.adminUsers.map((user) => `
    <tr>
      <td>${escapeHtml(user.username)}</td>
      <td>
        ${
  user.id === state.principal.user_id
    ? statusBadge(user.role, user.role === "admin" ? "warning" : "success")
    : `<select class="admin-role-select" data-admin-role="${user.id}">
              <option value="analyst" ${user.role === "analyst" ? "selected" : ""}>${escapeHtml(t("admin.role.analyst"))}</option>
              <option value="admin" ${user.role === "admin" ? "selected" : ""}>${escapeHtml(t("admin.role.admin"))}</option>
            </select>`
}
      </td>
      <td>${escapeHtml(user.created_at_utc)}</td>
      <td>
        ${
  user.id === state.principal.user_id
    ? (user.enabled ? statusBadge(t("common.enabled"), "success") : statusBadge(t("common.disabled"), "error"))
    : `<label class="admin-enabled-toggle">
            <input type="checkbox" data-admin-enabled="${user.id}" ${user.enabled ? "checked" : ""}>
            <span>${user.enabled ? escapeHtml(t("common.enabled")) : escapeHtml(t("common.disabled"))}</span>
          </label>`
}
      </td>
      <td>
        ${
          user.id === state.principal.user_id
            ? ""
            : `<button class="btn btn-primary" data-action="admin-update-user" data-id="${user.id}">${escapeHtml(t("common.apply"))}</button>
               <button class="btn btn-danger" data-action="admin-delete-user" data-id="${user.id}">${escapeHtml(t("admin.delete"))}</button>`
        }
      </td>
    </tr>
  `);
  renderTable(
    "admin-users-table",
    [t("admin.col.username"), t("admin.col.role"), t("admin.col.created"), t("admin.col.enabled"), t("admin.col.actions")],
    rows,
  );
  await loadAdminOauthProviders();
}

async function loadAdminOauthProviders() {
  const container = document.getElementById("admin-oauth-providers");
  if (!container) return;
  if (state.principal?.role !== "admin") {
    container.innerHTML = "";
    return;
  }
  const response = await api("/api/admin/oauth/providers");
  const entries = response.entries || [];
  container.innerHTML = entries.map((provider) => `
    <article class="admin-oauth-row">
      <div class="admin-oauth-main">
        <strong>${escapeHtml(provider.label || provider.id || "")}</strong>
        <div class="admin-oauth-meta">
          ${provider.configured
      ? statusBadge(t("admin.oauth.configured"), "success")
      : statusBadge(t("admin.oauth.not_configured"), "error")}
        </div>
      </div>
      <div class="admin-oauth-actions">
        <label class="admin-enabled-toggle">
          <input type="checkbox" data-admin-oauth-authorized="${escapeHtml(provider.id || "")}" ${provider.authorized ? "checked" : ""}>
          <span>${provider.authorized ? escapeHtml(t("common.enabled")) : escapeHtml(t("common.disabled"))}</span>
        </label>
        <button class="btn btn-primary" data-action="admin-oauth-update" data-provider="${escapeHtml(provider.id || "")}">${escapeHtml(t("common.apply"))}</button>
      </div>
    </article>
  `).join("");
}

function renderDownloadsModal(title, downloads) {
  const actions = downloads
    .map((item) => `<a class="btn btn-primary" href="${item.url}">${escapeHtml(item.name)}</a>`)
    .join(" ");
  openDetail(title, { downloads }, actions);
}

async function downloadAbility(abilityId, target) {
  const response = await fetch(`/api/abilities/${encodeURIComponent(abilityId)}/export?to=${encodeURIComponent(target)}`, {
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("export_failed");
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  link.href = url;
  link.download = match ? match[1] : `${abilityId}.${target}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function showRuleTargetDetail(ruleId, target) {
  const entry = state.rules.entries.find((item) => item.id === ruleId);
  if (!entry) return;
  const response = await api("/api/rules/compatibility", {
    method: "POST",
    body: JSON.stringify({
      rule: entry.rule,
      description: entry.description || "",
      confidence: entry.confidence || 70,
    }),
  });
  const detail = (response.entries || []).find((row) => row.target === target) || null;
  if (!detail) {
    openDetail(`${entry.name} · ${target.toUpperCase()}`, { error: t("detail.no_compatibility_detail") });
    return;
  }
  openConversionDetail(entry.name, entry.rule, detail);
}

async function showRuleEmulationDetail(ruleId, target, abilityId) {
  const entry = state.rules.entries.find((item) => item.id === ruleId);
  if (!entry) return;
  const availableTargets = availableRuleEmulationTargets(entry);
  if (!abilityId) {
    openEmulationDetail(entry.name, entry.rule, {
      selected_target: target,
      available_targets: availableTargets,
      status: "unsupported",
      note: t("detail.no_cataloged_ability"),
    });
    return;
  }
  const ability = await api(`/api/abilities/${encodeURIComponent(abilityId)}`);
  const status = entry.emulation_statuses?.[target] || "unsupported";
  openEmulationDetail(entry.name, entry.rule, {
    selected_target: target,
    available_targets: availableTargets,
    status,
    ability_id: abilityId,
    ability_name: ability.name,
    platforms: ability.platforms,
    classification: ability.classification,
    emulation_level: ability.emulation_level,
    actions: ability.actions,
  });
}

async function copyRuleEmulation(ruleId, abilityId) {
  const entry = state.rules.entries.find((item) => item.id === ruleId)
    || state.rules.allEntries.find((item) => item.id === ruleId);
  if (!entry || !abilityId) {
    showToast("detail.copy_emulation_not_available", true);
    return;
  }
  const targetSelect = document.getElementById("detail-emulation-target");
  const target = targetSelect instanceof HTMLSelectElement ? targetSelect.value : "";
  if (!target) {
    showToast("detail.copy_emulation_not_available", true);
    return;
  }
  const response = await fetch(`/api/abilities/${encodeURIComponent(abilityId)}/export?to=${encodeURIComponent(target)}`, {
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("export_failed");
  }
  const emulationRule = await response.text();
  if (!emulationRule.trim()) {
    showToast("detail.copy_emulation_not_available", true);
    return;
  }
  await navigator.clipboard.writeText(emulationRule);
  showToast("toast.copied");
}

function ruleExportHintSteps(target) {
  const normalized = String(target || "").toLowerCase().replaceAll("-", "_");
  const steps = [];
  for (let idx = 1; idx <= 4; idx += 1) {
    const key = `rules.export.hint.${normalized}.${idx}`;
    const text = t(key);
    if (text === key) break;
    steps.push(text);
  }
  if (steps.length === 0) {
    return `<ol class="hint-steps"><li>${escapeHtml(t("rules.export.hint.default"))}</li></ol>`;
  }
  return `<ol class="hint-steps">${steps.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`;
}

async function initialize() {
  setTheme(state.theme);
  state.translations = await fetch("/i18n.json").then((response) => response.json());
  applyTranslations();
  installEventHandlers();
  await bootstrap();
}

function installEventHandlers() {
  document.querySelectorAll("dialog.detail-dialog").forEach((dialog) => {
    if (!(dialog instanceof HTMLDialogElement)) return;
    const closeWithPolicy = () => {
      if (dialog.id === "adversary-dialog") {
        closeAdversaryDialog();
      } else {
        dialog.close();
      }
    };
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      closeWithPolicy();
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) {
        closeWithPolicy();
      }
    });
  });

  document.getElementById("locale-select").addEventListener("change", async (event) => {
    state.locale = event.target.value;
    localStorage.setItem("spuc-web-locale", state.locale);
    applyTranslations();
    if (!document.getElementById("app-view").classList.contains("hidden")) {
      renderDashboard();
      await loadRules();
      await loadAbilities();
      await loadAdversaries();
      await loadLearning();
      await loadAdminUsers();
    }
  });

  document.getElementById("theme-toggle").addEventListener("click", () => {
    setTheme(state.theme === "dark" ? "light" : "dark");
  });

  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = document.getElementById("login-error");
    error.hidden = true;
    try {
      await api("/api/login", {
        method: "POST",
        body: JSON.stringify({
          username: document.getElementById("login-username").value,
          password: document.getElementById("login-password").value,
        }),
      });
      await bootstrap();
    } catch (apiError) {
      error.hidden = false;
      error.textContent = t("toast.login_failed");
    }
  });

  document.querySelectorAll("[data-provider]").forEach((button) => {
    button.addEventListener("click", async () => {
      try {
        const payload = await api("/api/login/oauth", {
          method: "POST",
          body: JSON.stringify({ provider: button.dataset.provider }),
        });
        if (payload?.auth_url) {
          window.location.assign(payload.auth_url);
          return;
        }
        showToast("toast.unexpected", true);
      } catch (error) {
        showToast(error.payload?.error || "toast.unexpected", true);
      }
    });
  });

  document.getElementById("logout-button").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST", body: "{}" });
    state.principal = null;
    showLogin();
  });

  document.getElementById("sidebar-toggle").addEventListener("click", () => {
    document.body.classList.toggle("sidebar-open");
    document.getElementById("sidebar-backdrop").classList.toggle("hidden", !document.body.classList.contains("sidebar-open"));
  });
  document.getElementById("sidebar-backdrop").addEventListener("click", () => {
    document.body.classList.remove("sidebar-open");
    document.getElementById("sidebar-backdrop").classList.add("hidden");
  });

  document.querySelectorAll(".nav-item").forEach((item) => {
    if (!item.dataset.route) return;
    item.addEventListener("click", () => {
      localStorage.setItem("spuc-web-last-route", item.dataset.route);
      setRoute(item.dataset.route);
      document.body.classList.remove("sidebar-open");
      document.getElementById("sidebar-backdrop").classList.add("hidden");
    });
  });

  ["rules-search", "rules-min-confidence", "rules-filter-observable"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    const eventName = node.tagName === "SELECT" ? "change" : "input";
    node.addEventListener(eventName, scheduleRulesReload);
  });
  const rulesObservableFilter = document.getElementById("rules-filter-observable");
  if (rulesObservableFilter instanceof HTMLSelectElement) {
    state.rules.observableFilter = rulesObservableFilter.value || "";
    rulesObservableFilter.addEventListener("change", () => {
      state.rules.observableFilter = rulesObservableFilter.value || "";
    });
  }
  const rulesFilterTlp = document.getElementById("rules-filter-tlp");
  if (rulesFilterTlp) {
    state.rules.tlpFilter = rulesFilterTlp.value || "ALL";
    updateLevelSelectStyle(rulesFilterTlp);
    rulesFilterTlp.addEventListener("change", (event) => {
      state.rules.tlpFilter = event.target.value || "ALL";
      updateLevelSelectStyle(event.target);
      scheduleRulesReload();
    });
  }
  const rulesFilterPap = document.getElementById("rules-filter-pap");
  if (rulesFilterPap) {
    state.rules.papFilter = rulesFilterPap.value || "ALL";
    updateLevelSelectStyle(rulesFilterPap);
    rulesFilterPap.addEventListener("change", (event) => {
      state.rules.papFilter = event.target.value || "ALL";
      updateLevelSelectStyle(event.target);
      scheduleRulesReload();
    });
  }
  ["rulelab-tlp", "rulelab-pap", "rules-new-tlp", "rules-new-pap"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    updateLevelSelectStyle(node);
    node.addEventListener("change", (event) => {
      updateLevelSelectStyle(event.target);
      if (id === "rulelab-tlp" || id === "rulelab-pap") {
        scheduleRuleLabAnalysis();
      }
    });
  });
  ["rules-bulk-tlp", "rules-bulk-pap"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    updateLevelSelectStyle(node);
    node.addEventListener("change", (event) => updateLevelSelectStyle(event.target));
  });
  ["adversaries-bulk-tlp", "adversaries-bulk-pap"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    updateLevelSelectStyle(node);
    node.addEventListener("change", (event) => updateLevelSelectStyle(event.target));
  });
  renderRulesWorkspace();
  renderAdversaryWorkspace();
  renderStixObjectsWorkspace();
  const rulesSave = document.getElementById("rules-new-save");
  if (rulesSave) {
    rulesSave.addEventListener("click", async () => {
      try {
        setRulesImportBusy(true);
        const rules = await collectRulesFromFileInput();
        await saveRulesBatch(rules);
      } catch (error) {
        resetRulesImportProgress();
        showToast(error.payload?.error || error.message || "toast.unexpected", true);
      } finally {
        setRulesImportBusy(false);
      }
    });
  }
  const rulesDeleteSelected = document.getElementById("rules-delete-selected");
  if (rulesDeleteSelected) {
    rulesDeleteSelected.addEventListener("click", async () => {
      await deleteSelectedRules();
    });
  }
  const rulesBulkApply = document.getElementById("rules-bulk-apply");
  if (rulesBulkApply) {
    rulesBulkApply.addEventListener("click", async () => {
      await applyBulkRulesEdit();
    });
  }
  const adversariesBulkApply = document.getElementById("adversaries-bulk-apply");
  if (adversariesBulkApply) {
    adversariesBulkApply.addEventListener("click", async () => {
      await applyBulkAdversariesEdit();
    });
  }
  const adversariesDeleteSelected = document.getElementById("adversaries-delete-selected");
  if (adversariesDeleteSelected) {
    adversariesDeleteSelected.addEventListener("click", async () => {
      await deleteSelectedAdversaries();
    });
  }
  const abilitiesApply = document.getElementById("abilities-apply");
  if (abilitiesApply) {
    abilitiesApply.addEventListener("click", () => loadAbilities());
  }
  ["adversaries-search", "adversaries-min-confidence"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener("input", scheduleAdversariesReload);
  });
  const adversariesPlatform = document.getElementById("adversaries-platform");
  if (adversariesPlatform instanceof HTMLSelectElement) {
    adversariesPlatform.addEventListener("change", scheduleAdversariesReload);
  }
  const adversariesCreateOpen = document.getElementById("adversaries-create-open");
  if (adversariesCreateOpen) {
    adversariesCreateOpen.addEventListener("click", () => openAdversaryDialog());
  }
  [
    "adversary-ability-search",
    "adversary-ability-platform",
    "adversary-ability-utility",
    "adversary-ability-destination",
    "adversary-ability-min-confidence",
  ].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    const eventName = node.tagName === "SELECT" ? "change" : "input";
    node.addEventListener(eventName, () => renderAdversaryAbilitySelector());
  });
  const adversaryExportInlineButton = document.getElementById("adversary-export-inline-button");
  if (adversaryExportInlineButton) {
    adversaryExportInlineButton.addEventListener("click", async () => {
      await exportAdversaryFromDialog();
    });
  }
  ["adversary-name", "adversary-description", "adversary-confidence"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener("input", () => {
      if (id === "adversary-description") {
        refreshMarkdownEditorPreview("adversary-description");
      }
      if (id === "adversary-name") {
        syncAdversaryModalTitle();
      }
      setAdversaryFormSubmitState();
    });
  });
  const adversaryTitleEdit = document.getElementById("adversary-title-edit");
  if (adversaryTitleEdit) {
    adversaryTitleEdit.addEventListener("click", () => beginAdversaryTitleEdit());
  }
  const adversaryTitleInline = document.getElementById("adversary-title-inline");
  if (adversaryTitleInline instanceof HTMLInputElement) {
    adversaryTitleInline.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        commitAdversaryTitleEdit(false);
      } else if (event.key === "Escape") {
        event.preventDefault();
        commitAdversaryTitleEdit(true);
      }
    });
    adversaryTitleInline.addEventListener("blur", () => commitAdversaryTitleEdit(false));
  }
  const adversaryCancel = document.getElementById("adversary-cancel");
  if (adversaryCancel) {
    adversaryCancel.addEventListener("click", () => closeAdversaryDialog());
  }

  const ruleLabInput = document.getElementById("rulelab-input");
  ruleLabInput.addEventListener("input", renderRuleLabPreview);
  ruleLabInput.addEventListener("scroll", () => {
    const overlay = document.getElementById("rulelab-highlight");
    overlay.scrollTop = ruleLabInput.scrollTop;
    overlay.scrollLeft = ruleLabInput.scrollLeft;
  });
  ruleLabInput.addEventListener("keydown", ruleLabPairsKeydown);
  ruleLabInput.addEventListener("blur", () => {
    setTimeout(() => hideRuleLabAutocomplete(), 100);
  });
  ["rulelab-title", "rulelab-description", "rulelab-confidence"].forEach((id) => {
    const node = document.getElementById(id);
    node.addEventListener("input", scheduleRuleLabAnalysis);
  });
  document.querySelectorAll("[data-action='markdown-tab']").forEach((button) => {
    button.addEventListener("click", () => {
      const editorId = button.dataset.editor;
      const tab = button.dataset.tab || "edit";
      if (!editorId) return;
      setMarkdownEditorMode(editorId, tab);
    });
  });
  ["rulelab-description", "adversary-description"].forEach((editorId) => {
    const textarea = document.getElementById(editorId);
    if (!(textarea instanceof HTMLTextAreaElement)) return;
    textarea.addEventListener("input", () => refreshMarkdownEditorPreview(editorId));
    refreshMarkdownEditorPreview(editorId);
    setMarkdownEditorMode(editorId, "preview");
  });
  const compatibilityFilter = document.getElementById("rulelab-compat-filter");
  if (compatibilityFilter) {
    compatibilityFilter.addEventListener("input", (event) => {
      state.ruleLab.compatFilter = event.target.value || "";
      renderRuleLabCompatibilityResults();
    });
  }
  document.getElementById("rulelab-save").addEventListener("click", saveRuleLab);
  document.getElementById("adversary-form").addEventListener("submit", createAdversary);

  const learningInput = document.getElementById("learning-input");
  learningInput.addEventListener("input", renderLearningEditorPreview);
  learningInput.addEventListener("scroll", () => {
    const overlay = document.getElementById("learning-highlight");
    overlay.scrollTop = learningInput.scrollTop;
    overlay.scrollLeft = learningInput.scrollLeft;
  });
  learningInput.addEventListener("keydown", learningEditorKeydown);
  learningInput.addEventListener("blur", () => {
    setTimeout(() => hideLearningAutocomplete(), 100);
  });
  document.getElementById("learning-hint").addEventListener("click", () => {
    if (!state.selectedChallenge) return;
    const status = document.getElementById("learning-status");
    status.innerHTML = `${statusBadge("hint", "warning")} ${escapeHtml(state.selectedChallenge.hint)}`;
  });
  document.getElementById("learning-search").addEventListener("input", (event) => {
    state.learning.search = event.target.value || "";
    renderLearningChallenges();
  });
  document.getElementById("learning-path").addEventListener("change", (event) => {
    state.learning.pathFilter = event.target.value || "";
    renderLearningChallenges();
  });
  document.getElementById("learning-only-pending").addEventListener("change", (event) => {
    state.learning.onlyPending = Boolean(event.target.checked);
    renderLearningChallenges();
  });

  document.getElementById("admin-create-user").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("admin-new-username").value,
        password: document.getElementById("admin-new-password").value,
        role: document.getElementById("admin-new-role").value,
      }),
    });
    showToast("toast.saved");
    event.target.reset();
    await loadAdminUsers();
  });

  document.getElementById("admin-change-password").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/admin/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: document.getElementById("admin-current-password").value,
        new_password: document.getElementById("admin-next-password").value,
      }),
    });
    showToast("toast.saved");
    event.target.reset();
  });

  document.getElementById("detail-close").addEventListener("click", () => {
    document.getElementById("detail-dialog").close();
  });
  document.getElementById("indicates-cancel").addEventListener("click", () => {
    document.getElementById("indicates-dialog").close();
  });
  document.getElementById("indicates-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const ruleId = document.getElementById("indicates-rule-id").value;
    const stixId = document.getElementById("indicates-stix-id").value.trim();
    const objectName = document.getElementById("indicates-object-name").value.trim();
    if (!ruleId || !stixId || !objectName) {
      showToast("rules.indicates.invalid_payload", true);
      return;
    }
    await api(`/api/rules/${encodeURIComponent(ruleId)}/indicates`, {
      method: "POST",
      body: JSON.stringify({
        stix_id: stixId,
        object_name: objectName,
      }),
    });
    document.getElementById("indicates-dialog").close();
    showToast("toast.saved");
    await loadRules(state.rules.page);
  });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (!target.closest(".column-picker")) {
      closeColumnMenus();
    }
  });

  document.body.addEventListener("mouseup", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const row = target.closest("#rules-table tbody tr[data-rule-row-id]");
    if (!row) return;
    if (target.closest("button, a, input, select, textarea, label")) return;
    const selectedText = window.getSelection ? String(window.getSelection()) : "";
    if (selectedText.trim().length > 0) return;
    const ruleId = row.getAttribute("data-rule-row-id") || "";
    if (!ruleId) return;
    const entry = state.rules.entries.find((item) => item.id === ruleId);
    if (entry) {
      openRuleDetail(entry);
    }
  });

  document.body.addEventListener("mouseup", async (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const row = target.closest("#adversaries-table tbody tr[data-adversary-row-id]");
    if (!row) return;
    if (target.closest("button, a, input, select, textarea, label")) return;
    const selectedText = window.getSelection ? String(window.getSelection()) : "";
    if (selectedText.trim().length > 0) return;
    const adversaryId = row.getAttribute("data-adversary-row-id") || "";
    if (!adversaryId) return;
    try {
      await openAdversaryEditor(adversaryId);
    } catch (error) {
      showToast(error.payload?.error || error.message || "toast.unexpected", true);
    }
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target.closest("button, a");
    if (!target) return;

    const action = target.dataset.action;
    if (!action) return;

    try {
      if (action === "welcome-nav") {
        localStorage.setItem("spuc-web-last-route", target.dataset.route);
        setRoute(target.dataset.route);
      } else if (action === "welcome-dismiss") {
        localStorage.setItem("spuc-web-welcome-dismissed", "1");
        renderDashboard();
      } else if (action === "adversary-safety-dismiss") {
        localStorage.setItem("spuc-web-adversary-safety-dismissed", "1");
        renderAdversaryWorkspace();
      } else if (action === "rules-columns-toggle") {
        toggleMenu("rules-columns-menu", "rules-columns-toggle");
      } else if (action === "adversaries-columns-toggle") {
        toggleMenu("adversaries-columns-menu", "adversaries-columns-toggle");
      } else if (action === "rules-bulk-toggle") {
        if (state.rules.selected.size === 0) return;
        state.rules.bulkEditOpen = !state.rules.bulkEditOpen;
        updateRulesBulkState();
      } else if (action === "adversaries-bulk-toggle") {
        if (state.adversaries.selected.size === 0) return;
        state.adversaries.bulkEditOpen = !state.adversaries.bulkEditOpen;
        updateAdversariesBulkState();
      } else if (action === "rules-bulk-cancel") {
        cancelBulkRulesEdit();
      } else if (action === "adversaries-bulk-cancel") {
        cancelBulkAdversariesEdit();
      } else if (action === "rules-export-selected") {
        await exportSelectedRules();
      } else if (action === "rules-export-selected-download") {
        if (!state.rules.lastExportSelectedCsv) return;
        const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
        downloadTextFile(state.rules.lastExportSelectedCsv, `spuc-rules-selected-${ts}.csv`, "text/csv;charset=utf-8");
        showToast("toast.export_ready");
      } else if (action === "rules-sort-column") {
        toggleRulesSortColumn(target.dataset.column);
      } else if (action === "adversaries-sort-column") {
        await toggleAdversariesSortColumn(target.dataset.column);
      } else if (action === "rules-type-toggle") {
        const type = target.dataset.type;
        if (!type) return;
        if (state.rules.typeFilters.has(type)) {
          state.rules.typeFilters.delete(type);
        } else {
          state.rules.typeFilters.add(type);
        }
        target.classList.toggle("active", state.rules.typeFilters.has(type));
        scheduleRulesReload();
      } else if (action === "rules-select-all-toggle") {
        const filtered = applyRulesClientFilters(state.rules.allEntries);
        const shouldSelect = !filtered.length || filtered.some((entry) => !state.rules.selected.has(entry.id));
        filtered.forEach((entry) => {
          if (shouldSelect) state.rules.selected.add(entry.id);
          else state.rules.selected.delete(entry.id);
        });
        renderRulesTable();
      } else if (action === "adversaries-select-all-toggle") {
        const filtered = applyAdversariesClientFilters(state.adversaries.allEntries || []);
        const shouldSelect = !filtered.length || filtered.some((entry) => !state.adversaries.selected.has(entry.id));
        filtered.forEach((entry) => {
          if (shouldSelect) state.adversaries.selected.add(entry.id);
          else state.adversaries.selected.delete(entry.id);
        });
        renderAdversariesTable();
      } else if (action === "rules-page") {
        await loadRules(Number(target.dataset.page || "1"));
      } else if (action === "adversaries-page") {
        state.adversaries.page = Number(target.dataset.page || "1");
        renderAdversariesTable();
      } else if (action === "rule-show") {
        const entry = state.rules.entries.find((rule) => rule.id === target.dataset.id);
        if (entry) openRuleDetail(entry);
      } else if (action === "rule-copy") {
        const entry = state.rules.entries.find((rule) => rule.id === target.dataset.id);
        if (entry) {
          await navigator.clipboard.writeText(entry.rule);
          showToast("toast.copied");
        }
      } else if (action === "rule-target-detail") {
        await showRuleTargetDetail(target.dataset.rule, target.dataset.target);
      } else if (action === "rule-emulation-detail") {
        await showRuleEmulationDetail(target.dataset.rule, target.dataset.target, target.dataset.ability);
      } else if (action === "emulation-export-download") {
        const selectedTarget = String(target.dataset.target || "").trim();
        if (!selectedTarget) {
          showToast("detail.copy_emulation_not_available", true);
          return;
        }
        await downloadAbility(target.dataset.ability, selectedTarget);
        showToast("toast.export_ready");
      } else if (action === "rule-export") {
        await downloadAbility(target.dataset.id, target.dataset.target || "spuc-agent");
        showToast("toast.export_ready");
      } else if (action === "ability-show") {
        const entry = state.abilities.entries.find((ability) => ability.id === target.dataset.id);
        if (entry) openDetail(entry.name, entry);
      } else if (action === "ability-copy-json") {
        const entry = state.abilities.entries.find((ability) => ability.id === target.dataset.id);
        if (entry) {
          await navigator.clipboard.writeText(JSON.stringify(entry, null, 2));
          showToast("toast.copied");
        }
      } else if (action === "ability-export") {
        await downloadAbility(target.dataset.id, target.dataset.target || "spuc-agent");
        showToast("toast.export_ready");
      } else if (action === "adversary-export") {
        const response = await api(`/api/adversaries/${encodeURIComponent(target.dataset.id)}/export${toQuery({ to: target.dataset.target })}`);
        renderDownloadsModal(response.id, response.downloads);
      } else if (action === "adversary-select-ability") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        if (!state.adversaryCompose.selectedOrder.includes(abilityId)) {
          state.adversaryCompose.selectedOrder.push(abilityId);
        }
        renderAdversaryAbilitySelector();
      } else if (action === "adversary-remove-ability") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => id !== abilityId);
        renderAdversaryAbilitySelector();
      } else if (action === "adversary-move-up") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, -1);
        renderAdversaryAbilitySelector();
      } else if (action === "adversary-move-down") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, 1);
        renderAdversaryAbilitySelector();
      } else if (action === "rule-copy-emulation") {
        await copyRuleEmulation(target.dataset.id, target.dataset.ability);
      } else if (action === "detail-export-detection") {
        exportDetectionOutputFromDetail();
      } else if (action === "detail-cancel") {
        document.getElementById("detail-dialog").close();
      } else if (action === "compat-show") {
        const entry = state.compatibility.find((item) => item.target === target.dataset.target);
        if (entry && canShowCompatibilityOutput(entry)) {
          openConversionDetail(
            t("detail.conversion.summary"),
            document.getElementById("rulelab-input").value,
            entry,
          );
        } else {
          showToast("detail.no_output_for_target", true);
        }
      } else if (action === "rule-indicates") {
        const entry = state.rules.entries.find((item) => item.id === target.dataset.id);
        if (!entry) return;
        const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
          ? entry.indicates_list
          : (entry.indicates ? [entry.indicates] : []);
        document.getElementById("indicates-rule-id").value = entry.id;
        document.getElementById("indicates-stix-id").value = "";
        document.getElementById("indicates-object-name").value = "";
        const catalogSelect = document.getElementById("indicates-object-select");
        if (catalogSelect instanceof HTMLSelectElement) {
          catalogSelect.value = "";
        }
        renderIndicatesObjectOptions();
        renderIndicatesExistingList(indicatesList);
        document.getElementById("indicates-dialog").showModal();
      } else if (action === "indicates-fill") {
        const stixIdField = document.getElementById("indicates-stix-id");
        const objectNameField = document.getElementById("indicates-object-name");
        if (stixIdField instanceof HTMLInputElement) {
          stixIdField.value = target.dataset.stixId || "";
        }
        if (objectNameField instanceof HTMLInputElement) {
          objectNameField.value = target.dataset.objectName || "";
        }
        const catalogSelect = document.getElementById("indicates-object-select");
        if (catalogSelect instanceof HTMLSelectElement) {
          catalogSelect.value = target.dataset.stixId || "";
        }
      } else if (action === "detail-tab") {
        setDetailTab(target.dataset.tab || "view");
      } else if (action === "detail-copy") {
        const encoded = target.dataset.copy || "";
        await navigator.clipboard.writeText(decodeURIComponent(encoded));
        showToast("toast.copied");
      } else if (action === "autocomplete-pick") {
        applyRuleLabAutocomplete(Number(target.dataset.index || "0"));
      } else if (action === "learning-autocomplete-pick") {
        applyLearningAutocomplete(Number(target.dataset.index || "0"));
      } else if (action === "learning-select") {
        mountLearningPractice(target.dataset.id);
      } else if (action === "admin-delete-user") {
        const confirmDelete = confirm(t("admin.delete_confirm"));
        if (!confirmDelete) return;
        await api(`/api/admin/users/${encodeURIComponent(target.dataset.id)}`, {
          method: "DELETE",
          body: "{}",
        });
        showToast("toast.saved");
        await loadAdminUsers();
      } else if (action === "admin-update-user") {
        const userId = target.dataset.id;
        const role = document.querySelector(`[data-admin-role="${userId}"]`)?.value || "analyst";
        const enabled = Boolean(document.querySelector(`[data-admin-enabled="${userId}"]`)?.checked);
        await api(`/api/admin/users/${encodeURIComponent(userId)}/update`, {
          method: "POST",
          body: JSON.stringify({ role, enabled }),
        });
        showToast("toast.saved");
        await loadAdminUsers();
      } else if (action === "admin-oauth-update") {
        const providerId = target.dataset.provider || "";
        const authorized = Boolean(document.querySelector(`[data-admin-oauth-authorized="${providerId}"]`)?.checked);
        await api(`/api/admin/oauth/providers/${encodeURIComponent(providerId)}/update`, {
          method: "POST",
          body: JSON.stringify({ authorized }),
        });
        showToast("toast.saved");
        await loadAdminUsers();
      }
    } catch (error) {
      showToast(error.payload?.error || error.message || "toast.unexpected", true);
    }
  });

  document.body.addEventListener("change", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    if (target.dataset.action === "rules-column-toggle") {
      const column = target.dataset.column || "";
      const checked = target instanceof HTMLInputElement ? target.checked : false;
      const changed = setColumnVisibility(state.rules.visibleColumns, column, checked, RULE_COLUMN_KEYS);
      if (!changed && target instanceof HTMLInputElement) {
        target.checked = true;
        showToast("rules.columns.keep_one", true);
        return;
      }
      renderRulesTable();
      return;
    }

    if (target.dataset.action === "adversaries-column-toggle") {
      const column = target.dataset.column || "";
      const checked = target instanceof HTMLInputElement ? target.checked : false;
      const changed = setColumnVisibility(state.adversaries.visibleColumns, column, checked, ADVERSARY_COLUMN_KEYS);
      if (!changed && target instanceof HTMLInputElement) {
        target.checked = true;
        showToast("rules.columns.keep_one", true);
        return;
      }
      renderAdversariesTable();
      return;
    }

    if (target.dataset.action === "rule-select") {
      const id = target.dataset.id;
      if (!id) return;
      const checked = target instanceof HTMLInputElement ? target.checked : false;
      const index = Number(target.dataset.index || "-1");
      if (event.shiftKey && index >= 0 && state.rules.lastSelectionIndex >= 0) {
        const [from, to] = [state.rules.lastSelectionIndex, index].sort((a, b) => a - b);
        const checkboxes = [...document.querySelectorAll('#rules-table tbody input[data-action="rule-select"]')];
        checkboxes.forEach((node) => {
          if (!(node instanceof HTMLInputElement)) return;
          const nodeIndex = Number(node.dataset.index || "-1");
          if (nodeIndex < from || nodeIndex > to) return;
          const nodeId = node.dataset.id || "";
          node.checked = checked;
          if (checked) state.rules.selected.add(nodeId);
          else state.rules.selected.delete(nodeId);
        });
      } else if (checked) state.rules.selected.add(id);
      else state.rules.selected.delete(id);
      state.rules.lastSelectionIndex = index >= 0 ? index : state.rules.lastSelectionIndex;
      updateRulesBulkState();
      return;
    }

    if (target.dataset.action === "adversary-select") {
      const id = target.dataset.id;
      if (!id) return;
      const checked = target instanceof HTMLInputElement ? target.checked : false;
      const index = Number(target.dataset.index || "-1");
      if (event.shiftKey && index >= 0 && state.adversaries.lastSelectionIndex >= 0) {
        const [from, to] = [state.adversaries.lastSelectionIndex, index].sort((a, b) => a - b);
        const checkboxes = [...document.querySelectorAll('#adversaries-table tbody input[data-action="adversary-select"]')];
        checkboxes.forEach((node) => {
          if (!(node instanceof HTMLInputElement)) return;
          const nodeIndex = Number(node.dataset.index || "-1");
          if (nodeIndex < from || nodeIndex > to) return;
          const nodeId = node.dataset.id || "";
          node.checked = checked;
          if (checked) state.adversaries.selected.add(nodeId);
          else state.adversaries.selected.delete(nodeId);
        });
      } else if (checked) state.adversaries.selected.add(id);
      else state.adversaries.selected.delete(id);
      state.adversaries.lastSelectionIndex = index >= 0 ? index : state.adversaries.lastSelectionIndex;
      updateAdversariesBulkState();
      return;
    }

    if (target.classList.contains("rules-confidence-input")) {
      const id = target.dataset.id;
      if (!id) return;
      const entry = state.rules.entries.find((item) => item.id === id);
      if (!entry) return;
      const confidence = Math.max(0, Math.min(100, Number(target.value || "0")));
      await api("/api/rules/save", {
        method: "POST",
        body: JSON.stringify({
          rule: entry.rule,
          name: entry.name,
          description: entry.description || "",
          confidence,
          tlp: entry.tlp || "TLP:GREEN",
          pap: entry.pap || "PAP:GREEN",
          indicates: entry.indicates || undefined,
        }),
      });
      showToast("toast.saved");
      await Promise.all([loadRules(state.rules.page), loadOverview()]);
      return;
    }

    if (target.dataset.adminEnabled) {
      const label = target.closest(".admin-enabled-toggle")?.querySelector("span");
      if (label) {
        label.textContent = target.checked ? t("common.enabled") : t("common.disabled");
      }
      return;
    }

    if (target.id === "indicates-object-select" && target instanceof HTMLSelectElement) {
      const selected = state.stixObjects.find((entry) => entry.stix_id === target.value);
      const stixIdField = document.getElementById("indicates-stix-id");
      const objectNameField = document.getElementById("indicates-object-name");
      if (selected && stixIdField instanceof HTMLInputElement && objectNameField instanceof HTMLInputElement) {
        stixIdField.value = selected.stix_id || "";
        objectNameField.value = selected.name || "";
      }
      return;
    }

    const field = target.dataset.filterProp;
    if (!field) return;
    const id = target.dataset.filterId;
    const filter = state.rules.advancedFilters.find((item) => item.id === id);
    if (!filter) return;
    filter[field] = target.value;
    renderRulesTable();
  });
}

initialize().catch((error) => {
  console.error(error);
  showToast(error.message || "toast.unexpected", true);
});
