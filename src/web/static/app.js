function detectInitialLocale() {
  const stored = localStorage.getItem("spuc-web-locale");
  if (stored === "es" || stored === "en") return stored;
  const requested = new URLSearchParams(window.location.search).get("spuc-locale");
  if (requested === "es" || requested === "en") return requested;
  const browserLanguages = [navigator.language, ...(navigator.languages || [])];
  return browserLanguages.some((language) => String(language || "").toLowerCase().startsWith("es"))
    ? "es"
    : "en";
}

const state = {
  locale: detectInitialLocale(),
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
    visibleColumns: new Set(["name", "confidence", "tlp", "pap", "ttp", "rule", "observables", "indicates", "outputs", "emulation"]),
    bulkEditOpen: false,
    lastExportSelectedCsv: "",
    advancedFilters: [],
    workspaceMode: "welcome",
    viewMode: localStorage.getItem("spuc-web-rules-view-mode") || "cards",
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
  ruleDetail: {
    activeTab: "detection",
    focusedTarget: "",
    entry: null,
    detectionRows: [],
    emulationRows: [],
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
    viewMode: localStorage.getItem("spuc-web-adversaries-view-mode") || "cards",
  },
  adversaryCompose: {
    search: "",
    targetPlatform: "",
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
    exportPreviewByTarget: {},
    exportPreviewLoading: false,
    autoSaveTimer: null,
    autoSaving: false,
    activeTab: "plan",
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
    autoSaveTimer: null,
    autoSaving: false,
    autoSaveLastSignature: "",
    savedIndicatorTimer: null,
    isDirty: false,
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
  detailLlmPrompt: null,
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
const RULE_COLUMN_KEYS = ["name", "confidence", "tlp", "pap", "ttp", "rule", "observables", "indicates", "outputs", "emulation"];
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
  document.title = t("app.title");
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
    exportInlineBtn.title = t("detail.rule.export");
    exportInlineBtn.setAttribute("aria-label", t("detail.rule.export"));
  }
  const adversaryDuplicateButton = document.getElementById("adversaries-duplicate-selected");
  if (adversaryDuplicateButton) {
    adversaryDuplicateButton.textContent = t("adversaries.bulk.duplicate_selected");
  }
  [
    ["rules-bulk-toggle", "rules.bulk.enable"],
    ["rules-export-selected-csv", "rules.export_selected.download_csv"],
    ["rules-export-selected-stix", "rules.export_selected.download_bundle"],
    ["rules-duplicate-selected", "rules.bulk.duplicate_selected"],
    ["rules-delete-selected", "rules.bulk.delete_selected"],
    ["rules-columns-toggle", "common.show_hide_columns"],
    ["rules-view-table", "rules.view.table"],
    ["rules-view-cards", "rules.view.cards"],
  ].forEach(([id, key]) => {
    const node = document.getElementById(id);
    if (!node) return;
    const label = t(key);
    node.title = label;
    node.setAttribute("aria-label", label);
  });
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
  toast.classList.remove("toast-check-success");
  toast.hidden = false;
  toast.textContent = asKey ? t(message) : message;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
  }, 2800);
}

function askForConfirmation(message, title = "") {
  const dialog = document.getElementById("confirm-dialog");
  const titleNode = document.getElementById("confirm-title");
  const messageNode = document.getElementById("confirm-message");
  const acceptButton = document.getElementById("confirm-accept");
  const cancelButton = document.getElementById("confirm-cancel");
  if (!(dialog instanceof HTMLDialogElement) || !titleNode || !messageNode || !acceptButton || !cancelButton) {
    return Promise.resolve(confirm(message));
  }

  const resolvedTitle = String(title || "").trim() || t("common.confirm_action");
  titleNode.textContent = resolvedTitle;
  messageNode.textContent = message;

  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => {
      if (done) return;
      done = true;
      acceptButton.removeEventListener("click", onAccept);
      cancelButton.removeEventListener("click", onCancel);
      dialog.removeEventListener("cancel", onCancelEvent);
      dialog.removeEventListener("close", onClose);
      resolve(value);
    };

    const onAccept = () => {
      dialog.close("accept");
      finish(true);
    };
    const onCancel = () => {
      dialog.close("cancel");
      finish(false);
    };
    const onCancelEvent = (event) => {
      event.preventDefault();
      dialog.close("cancel");
      finish(false);
    };
    const onClose = () => {
      finish(dialog.returnValue === "accept");
    };

    acceptButton.addEventListener("click", onAccept);
    cancelButton.addEventListener("click", onCancel);
    dialog.addEventListener("cancel", onCancelEvent);
    dialog.addEventListener("close", onClose);
    dialog.showModal();
  });
}

function showRuleSavedNavigationToast() {
  const toast = document.getElementById("toast");
  toast.hidden = false;
  toast.classList.add("toast-check-success");
  toast.innerHTML = `
    <span class="toast-inline">
      <span class="toast-check" aria-hidden="true">✓</span>
      <span>${escapeHtml(t("toast.saved_navigating_rules"))}</span>
    </span>
  `;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.hidden = true;
    toast.classList.remove("toast-check-success");
    toast.textContent = "";
  }, 2400);
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

function normalizeTtpValue(value) {
  return String(value || "").trim().toUpperCase();
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

function configureDetailTabs(mode = "json") {
  const overviewBtn = document.getElementById("detail-tab-overview");
  const viewBtn = document.getElementById("detail-tab-view");
  const jsonBtn = document.getElementById("detail-tab-json");
  if (!viewBtn || !jsonBtn || !overviewBtn) return;
  if (mode === "rule") {
    const overviewLabel = t("detail.rule.tab.overview");
    const detectionLabel = t("detail.rule.tab.detection");
    const emulationLabel = t("detail.rule.tab.emulation");
    overviewBtn.classList.remove("hidden");
    overviewBtn.innerHTML = `<span class="detail-tab-content"><i class="fa-solid fa-circle-info detail-tab-icon" aria-hidden="true"></i><span>${escapeHtml(overviewLabel)}</span></span>`;
    overviewBtn.dataset.action = "rule-detail-tab";
    overviewBtn.dataset.tab = "overview";
    overviewBtn.title = overviewLabel;
    overviewBtn.setAttribute("aria-label", overviewLabel);
    viewBtn.innerHTML = `<span class="detail-tab-content"><i class="fa-solid fa-shield-halved detail-tab-icon" aria-hidden="true"></i><span>${escapeHtml(detectionLabel)}</span></span>`;
    viewBtn.dataset.action = "rule-detail-tab";
    viewBtn.dataset.tab = "detection";
    viewBtn.title = detectionLabel;
    viewBtn.setAttribute("aria-label", detectionLabel);
    jsonBtn.innerHTML = `<span class="detail-tab-content"><i class="fa-solid fa-gears detail-tab-icon" aria-hidden="true"></i><span>${escapeHtml(emulationLabel)}</span></span>`;
    jsonBtn.dataset.action = "rule-detail-tab";
    jsonBtn.dataset.tab = "emulation";
    jsonBtn.title = emulationLabel;
    jsonBtn.setAttribute("aria-label", emulationLabel);
  } else {
    overviewBtn.classList.add("hidden");
    overviewBtn.innerHTML = "";
    overviewBtn.dataset.action = "";
    overviewBtn.dataset.tab = "";
    viewBtn.textContent = t("common.view");
    viewBtn.dataset.action = "detail-tab";
    viewBtn.dataset.tab = "view";
    jsonBtn.textContent = "JSON";
    jsonBtn.dataset.action = "detail-tab";
    jsonBtn.dataset.tab = "json";
  }
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
  configureDetailTabs("json");
}

function statusLabel(status) {
  const bucket = statusBucket(status);
  if (bucket === "exact") return t("rules.status.exact");
  if (bucket === "lossy") return t("rules.status.lossy");
  return t("rules.status.unsupported");
}

function llmTaskInstruction(task) {
  switch (String(task || "").toLowerCase()) {
    case "generate":
      return "Generate a STIX pattern";
    case "repair":
      return "Repair an invalid STIX pattern";
    case "explain":
      return "Explain pattern coverage";
    default:
      return "Improve an existing pattern";
  }
}

function normalizePromptTask(task, hasPattern = true, syntaxOk = true) {
  const normalized = String(task || "").toLowerCase();
  if (["generate", "repair", "improve", "explain"].includes(normalized)) {
    return normalized;
  }
  if (!hasPattern) return "generate";
  if (!syntaxOk) return "repair";
  return "improve";
}

function normalizePromptObservables(ruleEntry) {
  const observables = Array.isArray(ruleEntry?.observables)
    ? ruleEntry.observables
    : [];
  const clean = observables
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  if (clean.length) {
    return [...new Set(clean)].sort((a, b) => a.localeCompare(b));
  }

  const pattern = String(ruleEntry?.rule || "");
  const inferred = [];
  const rx = /\[\s*([a-z0-9-]+)\s*:/ig;
  let match = rx.exec(pattern);
  while (match) {
    inferred.push(`${match[1]}:*`);
    match = rx.exec(pattern);
  }
  return [...new Set(inferred)].sort((a, b) => a.localeCompare(b));
}

function normalizePromptIndicators(ruleEntry) {
  const fromList = Array.isArray(ruleEntry?.indicates_list) ? ruleEntry.indicates_list : [];
  const fallback = ruleEntry?.indicates ? [ruleEntry.indicates] : [];
  const source = fromList.length ? fromList : fallback;
  return source
    .map((item) => ({
      stixId: String(item?.stix_id || "").trim(),
      objectName: String(item?.object_name || "").trim(),
    }))
    .filter((item) => item.stixId || item.objectName)
    .sort((a, b) => {
      const left = `${a.objectName}|${a.stixId}`.toLowerCase();
      const right = `${b.objectName}|${b.stixId}`.toLowerCase();
      return left.localeCompare(right);
    });
}

function normalizePromptTargetStatuses(ruleEntry) {
  const statuses = new Map();
  const map = ruleEntry?.target_statuses && typeof ruleEntry.target_statuses === "object"
    ? ruleEntry.target_statuses
    : {};

  Object.entries(map).forEach(([target, status]) => {
    const key = String(target || "").trim().toLowerCase();
    if (!key) return;
    statuses.set(key, statusBucket(status || "unsupported"));
  });

  const targets = Array.isArray(ruleEntry?.targets) ? ruleEntry.targets : [];
  const rowStatuses = Array.isArray(ruleEntry?.statuses) ? ruleEntry.statuses : [];
  targets.forEach((target, idx) => {
    const key = String(target || "").trim().toLowerCase();
    if (!key || statuses.has(key)) return;
    statuses.set(key, statusBucket(rowStatuses[idx] || "unsupported"));
  });

  const ordered = [];
  const seen = new Set();
  const preferred = RULE_OUTPUT_TARGETS
    .map((target) => String(target || "").trim().toLowerCase())
    .filter(Boolean);
  const extras = Array.from(statuses.keys())
    .filter((target) => !preferred.includes(target))
    .sort((a, b) => a.localeCompare(b));

  [...preferred, ...extras].forEach((target) => {
    if (!statuses.has(target) || seen.has(target)) return;
    seen.add(target);
    ordered.push({ target, status: statuses.get(target) || "unsupported" });
  });
  return ordered;
}

function normalizePromptEmulationStatuses(ruleEntry) {
  const map = ruleEntry?.emulation_statuses && typeof ruleEntry.emulation_statuses === "object"
    ? ruleEntry.emulation_statuses
    : {};
  return RULE_EMULATION_TARGETS
    .map((target) => ({
      target,
      status: statusBucket(map[target] || map[String(target || "").toLowerCase()] || "unsupported"),
    }))
    .filter((entry) => entry.status !== "unsupported");
}

function buildAdversaryPromptBlock(adversary) {
  if (!adversary || typeof adversary !== "object") return "";
  const lines = ["### Related adversary context"];
  lines.push(`Adversary name: ${adversary.name || "N/A"}`);
  lines.push(`Confidence: ${String(adversary.confidence ?? "N/A")}`);
  lines.push(`TLP / PAP classification: ${adversary.tlp || "N/A"} / ${adversary.pap || "N/A"}`);
  lines.push(`Steps: ${String(adversary.steps ?? 0)}`);
  lines.push(`Platforms: ${Array.isArray(adversary.platforms) && adversary.platforms.length ? adversary.platforms.join(", ") : "N/A"}`);
  lines.push(`Ability refs: ${Array.isArray(adversary.ability_refs) && adversary.ability_refs.length ? adversary.ability_refs.join(", ") : "N/A"}`);
  return lines.join("\n");
}

function buildStixLlmPrompt(ruleEntry, options = {}) {
  const hasPattern = Boolean(String(ruleEntry?.rule || "").trim());
  const task = normalizePromptTask(options.task, hasPattern, options.syntaxOk ?? true);
  const observables = normalizePromptObservables(ruleEntry);
  const indicators = normalizePromptIndicators(ruleEntry);
  const detectionTargets = normalizePromptTargetStatuses(ruleEntry);
  const emulation = normalizePromptEmulationStatuses(ruleEntry);

  const lines = [];
  lines.push("### Detection context");
  lines.push(`Rule name: ${String(ruleEntry?.name || "N/A")}`);
  lines.push(`Rule description: ${String(ruleEntry?.description || "N/A")}`);
  lines.push(`Threat technique (TTP): ${String(ruleEntry?.ttp || "N/A")}`);
  lines.push(`Confidence: ${String(ruleEntry?.confidence ?? "N/A")}`);
  lines.push(`TLP / PAP classification: ${String(ruleEntry?.tlp || "N/A")} / ${String(ruleEntry?.pap || "N/A")}`);

  lines.push("");
  lines.push("### Observables available");
  if (observables.length) {
    observables.forEach((item) => lines.push(`- ${item}`));
  } else {
    lines.push("- none");
  }

  lines.push("");
  lines.push("### Related indicators");
  if (indicators.length) {
    indicators.forEach((item) => {
      const label = [item.objectName, item.stixId].filter(Boolean).join(" | ");
      lines.push(`- ${label || "unknown"}`);
    });
  } else {
    lines.push("- none");
  }

  lines.push("");
  lines.push("### Detection targets");
  if (detectionTargets.length) {
    detectionTargets.forEach((item) => lines.push(`- ${item.target} -> ${item.status}`));
  } else {
    lines.push("- none");
  }

  lines.push("");
  lines.push("### Emulation capability");
  if (emulation.length) {
    emulation.forEach((item) => lines.push(`- ${item.target} -> ${item.status}`));
  } else {
    lines.push("- none");
  }

  lines.push("");
  lines.push("### Existing STIX pattern");
  lines.push(hasPattern ? String(ruleEntry.rule) : "N/A");

  if (options.adversary) {
    lines.push("");
    lines.push(buildAdversaryPromptBlock(options.adversary));
  }

  lines.push("");
  lines.push("### Task for the model");
  lines.push(llmTaskInstruction(task));
  return lines.join("\n").trim();
}

function collectRuleLabPromptContext() {
  const inputRule = String(document.getElementById("rulelab-input")?.value || "").trim();
  const rows = Array.isArray(state.compatibility) ? state.compatibility : [];
  const targetStatuses = {};
  const targets = [];
  const statuses = [];
  rows.forEach((row) => {
    const target = String(row?.target || "").trim().toLowerCase();
    if (!target) return;
    const status = String(row?.runtime_status || "unsupported").toLowerCase();
    targetStatuses[target] = status;
    targets.push(target);
    statuses.push(status);
  });
  return {
    name: document.getElementById("rulelab-title")?.value || ruleLabDefaultTitle(),
    description: document.getElementById("rulelab-description")?.value || "",
    ttp: normalizeTtpValue(document.getElementById("rulelab-ttp")?.value || ""),
    confidence: Number(document.getElementById("rulelab-confidence")?.value || 70),
    tlp: document.getElementById("rulelab-tlp")?.value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap")?.value || "PAP:GREEN",
    rule: inputRule,
    observables: normalizePromptObservables({ rule: inputRule }),
    indicates_list: [],
    targets,
    statuses,
    target_statuses: targetStatuses,
    emulation_statuses: {},
  };
}

async function copyPromptToClipboard(text) {
  const prompt = String(text || "").trim();
  if (!prompt) {
    showToast("common.no_data", true);
    return;
  }
  await navigator.clipboard.writeText(prompt);
  showToast("toast.copied");
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
    "atomic-red-team": "atomic-red",
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

function targetSummaryText(target, family) {
  const normalized = String(target || "").toLowerCase();
  const key = `detail.target.summary.${family}.${normalized}`;
  const text = t(key);
  if (text !== key) return text;
  if (family === "detection") {
    return t("detail.target.summary.default_detection");
  }
  return t("detail.target.summary.default_emulation");
}

function localizeConverterComment(text) {
  const source = String(text || "").trim();
  if (!source || state.locale !== "es") return source;
  let translated = source;
  const exactMap = [
    ["Semantic mapping preserved", "Mapeo semantico preservado"],
    ["Mapping depends on backend schema/profile", "El mapeo depende del esquema/perfil del backend"],
    ["Mapping depends on backend runtime behavior", "El mapeo depende del comportamiento en ejecucion del backend"],
    ["Supported subset emitted", "Se ha emitido un subconjunto soportado"],
    ["Mapping degraded but related", "El mapeo se degrada, pero mantiene relacion"],
    ["No honest mapping available", "No hay un mapeo fiable disponible"],
    ["Parse error", "Error de parseo"],
    ["Normalization error", "Error de normalizacion"],
    ["Emitter not implemented", "Emisor no implementado"],
    ["Backend semantics missing", "Faltan semanticas del backend"],
    ["Schema uncertain", "Esquema incierto"],
  ];
  exactMap.forEach(([needle, replacement]) => {
    if (translated.toLowerCase() === needle.toLowerCase()) {
      translated = replacement;
    }
  });
  const partialMap = [
    [/cannot/gi, "no puede"],
    [/unsupported/gi, "no soportado"],
    [/mapping/gi, "mapeo"],
    [/backend/gi, "backend"],
    [/event/gi, "evento"],
    [/rule/gi, "regla"],
    [/timestamp/gi, "marca de tiempo"],
    [/exact/gi, "exacto"],
    [/lossy/gi, "con perdida"],
  ];
  partialMap.forEach(([pattern, replacement]) => {
    translated = translated.replace(pattern, replacement);
  });
  return translated;
}

function compactConverterComments(item) {
  const comments = [];
  const summary = String(item?.summary || "").trim();
  const cause = String(item?.cause || "").trim();
  if (summary) comments.push(summary);
  if (cause) comments.push(cause);
  const notes = Array.isArray(item?.notes) ? item.notes : [];
  notes
    .map((note) => String(note || "").trim())
    .filter(Boolean)
    .forEach((note) => comments.push(note));
  const unique = [...new Set(comments)];
  return unique
    .map((line) => localizeConverterComment(line))
    .filter(Boolean);
}

function renderGuideLinks(target, family) {
  const links = family === "detection" ? detectionUtilityLinks(target) : emulationUtilityLinks(target);
  if (!links.length) {
    const fallbackKey = family === "detection" ? "detail.detection.no_links" : "detail.emulation.no_links";
    return `<div class="muted">${escapeHtml(t(fallbackKey))}</div>`;
  }
  return `<ul class="hint-steps compact-list">${links.map((item) => `<li><a href="${escapeHtml(item.url)}" target="_blank" rel="noreferrer">${escapeHtml(item.label)}</a></li>`).join("")}</ul>`;
}

function normalizeConfidenceValue(raw) {
  const value = Number(raw);
  if (Number.isFinite(value)) {
    return Math.max(0, Math.min(100, Math.round(value)));
  }
  const text = String(raw || "").trim();
  const match = text.match(/\d{1,3}/);
  if (!match) return null;
  const parsed = Number(match[0]);
  if (!Number.isFinite(parsed)) return null;
  return Math.max(0, Math.min(100, Math.round(parsed)));
}

function renderConfidenceWidget(entry, targetConfidenceRaw) {
  const ruleConfidence = normalizeConfidenceValue(entry?.confidence);
  const targetConfidence = normalizeConfidenceValue(targetConfidenceRaw);
  const targetFallback = String(targetConfidenceRaw ?? "-").trim() || "-";
  const ruleLabel = t("detail.rule.tech.rule_confidence_short");
  const targetLabelText = t("detail.rule.tech.target_confidence_short");
  const renderItem = (label, numericValue, fallbackText, variant) => {
    const valueText = numericValue == null ? fallbackText : `${numericValue}/100`;
    const meter = numericValue == null
      ? `<div class="rule-confidence-meter-empty">${escapeHtml(valueText)}</div>`
      : `<div class="rule-confidence-meter"><span class="rule-confidence-meter-fill ${variant}" style="width:${numericValue}%;"></span></div>`;
    return `
      <div class="rule-confidence-item">
        <div class="rule-confidence-head">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(valueText)}</strong>
        </div>
        ${meter}
      </div>
    `;
  };
  return `
    <div class="rule-confidence-grid">
      ${renderItem(ruleLabel, ruleConfidence, "-", "rule")}
      ${renderItem(targetLabelText, targetConfidence, targetFallback, "target")}
    </div>
  `;
}

function renderConfidenceBar(rawValue, options = {}) {
  const numericValue = normalizeConfidenceValue(rawValue);
  const label = String(options.label || "").trim();
  const variant = options.variant === "target" ? "target" : (options.variant === "warning" ? "warning" : "rule");
  const valueText = numericValue == null ? "-" : `${numericValue}/100`;
  const labelHtml = label ? `<span class="confidence-bar-label">${escapeHtml(label)}</span>` : "";
  const meterHtml = numericValue == null
    ? `<div class="confidence-bar-meter confidence-bar-meter-empty"><span>${escapeHtml(valueText)}</span></div>`
    : `<div class="confidence-bar-meter"><span class="confidence-bar-fill ${variant}" style="width:${numericValue}%;"></span></div>`;
  return `
    <div class="confidence-bar-inline">
      <div class="confidence-bar-head">
        ${labelHtml}
        <strong>${escapeHtml(valueText)}</strong>
      </div>
      ${meterHtml}
    </div>
  `;
}

function renderRuleTechCard(entry, item, family) {
  const normalizedTarget = String(item?.target || "").toLowerCase();
  const heading = targetLabel(normalizedTarget, family);
  const status = item?.status || "unsupported";
  const rawOutput = String(item?.output || "").trim();
  const outputText = rawOutput || t("detail.no_output_for_target");
  const targetConfidence = item?.target_confidence == null || item?.target_confidence === ""
    ? "-"
    : String(item?.target_confidence);
  const guideSteps = family === "detection"
    ? detectionHintSteps(normalizedTarget)
    : ruleExportHintSteps(normalizedTarget);
  const guideCommand = family === "detection"
    ? detectionExecutionCommand(normalizedTarget, entry?.name || "")
    : emulationExecutionCommand(normalizedTarget, {
      ability_id: entry?.ability_id || "",
      export_files: item?.export_files || {},
    });
  const guideLabel = family === "detection" ? t("detail.detection.command") : t("detail.emulation.command");
  const linksLabel = family === "detection" ? t("detail.detection.utility_links") : t("detail.emulation.utility_links");
  const comments = compactConverterComments(item);
  const hasOutput = Boolean(rawOutput);
  const guideId = `rule-tech-guide-${family}-${normalizedTarget.replace(/[^a-z0-9_-]/g, "-")}`;
  const ruleConfidence = normalizeConfidenceValue(entry?.confidence);
  const conversionConfidence = normalizeConfidenceValue(targetConfidence);
  const confidenceSummary = (label, value, fallback) => `
    <span class="rule-tech-summary-metric">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value == null ? fallback : `${value}/100`)}</strong>
    </span>
  `;
  return `
    <details class="rule-tech-card rule-tech-accordion status-${statusBucket(status)}" data-rule-tech-target="${escapeHtml(normalizedTarget)}">
      <summary class="rule-tech-summary">
        <span class="rule-tech-summary-title">${escapeHtml(heading)}</span>
        <span class="rule-tech-summary-metrics">
          <span class="badge ${statusClass(status)}">${escapeHtml(statusLabel(status))}</span>
          ${confidenceSummary(t("detail.rule.tech.rule_confidence_short"), ruleConfidence, "-")}
          ${confidenceSummary(t("detail.rule.tech.target_confidence_short"), conversionConfidence, targetConfidence)}
        </span>
      </summary>
      <div class="rule-tech-body">
        <p class="muted">${escapeHtml(targetSummaryText(normalizedTarget, family))}</p>
        ${renderConfidenceWidget(entry, targetConfidence)}
        ${comments.length
    ? `<div class="rule-tech-comments"><h5>${escapeHtml(t("detail.converter.comments"))}</h5><ul class="hint-steps compact-list">${comments.map((line) => `<li>${escapeHtml(line)}</li>`).join("")}</ul></div>`
    : ""}
        <div class="detail-code-wrap">
          <div class="detail-code-head">
            <h4>${escapeHtml(tf("detail.output_target", { target: heading }))}</h4>
            ${copyButtonFor(rawOutput, t("detail.copy_output"))}
          </div>
          ${hasOutput ? `<pre class="detail-code">${escapeHtml(outputText)}</pre>` : `<div class="rule-output-empty">${escapeHtml(t("detail.output.compact_unavailable"))}</div>`}
        </div>
        <div class="rule-tech-guide-toggle-row">
          <button type="button" class="rule-preview-more" data-action="rule-tech-guide-toggle" data-target-id="${escapeHtml(guideId)}" aria-expanded="false" aria-controls="${escapeHtml(guideId)}">
            <span>${escapeHtml(t("detail.preview.more"))}</span>
            <i class="fa-solid fa-angle-down" aria-hidden="true"></i>
          </button>
        </div>
        <div id="${escapeHtml(guideId)}" class="rule-tech-guide hidden">
          <h5>${escapeHtml(t("detail.rule.how_to_use"))}</h5>
          <div class="rule-tech-guide-body">
            ${guideSteps}
            ${guideCommand ? `<h5>${escapeHtml(guideLabel)}</h5><pre class="detail-code">${escapeHtml(guideCommand)}</pre>` : `<div class="muted">${escapeHtml(t(family === "detection" ? "detail.detection.no_command" : "detail.emulation.no_command"))}</div>`}
            <h5>${escapeHtml(linksLabel)}</h5>
            ${renderGuideLinks(normalizedTarget, family)}
          </div>
        </div>
      </div>
    </details>
  `;
}

function setRuleDetailTab(tab) {
  setDetailTab("view");
  const normalized = tab === "detection" || tab === "emulation" ? tab : "overview";
  state.ruleDetail.activeTab = normalized;
  document.querySelectorAll("[data-action='rule-detail-tab']").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === normalized);
  });
  const overviewPane = document.getElementById("rule-detail-pane-overview");
  const detectionPane = document.getElementById("rule-detail-pane-detection");
  const emulationPane = document.getElementById("rule-detail-pane-emulation");
  if (overviewPane) overviewPane.classList.toggle("hidden", normalized !== "overview");
  if (detectionPane) detectionPane.classList.toggle("hidden", normalized !== "detection");
  if (emulationPane) emulationPane.classList.toggle("hidden", normalized !== "emulation");
  const focusTarget = state.ruleDetail.focusedTarget || "";
  if (!focusTarget) return;
  const pane = normalized === "detection" ? detectionPane : (normalized === "emulation" ? emulationPane : null);
  if (!pane) return;
  const node = pane
    ? Array.from(pane.querySelectorAll("[data-rule-tech-target]")).find((item) => item.getAttribute("data-rule-tech-target") === focusTarget)
    : null;
  if (node) {
    if (node instanceof HTMLDetailsElement) node.open = true;
    node.classList.add("rule-tech-card-focus");
    node.scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(() => node.classList.remove("rule-tech-card-focus"), 1200);
  }
}

function openRuleInLab(entry) {
  if (!entry) return;
  setRoute("rulelab");
  const ruleInput = document.getElementById("rulelab-input");
  const titleInput = document.getElementById("rulelab-title");
  const descriptionInput = document.getElementById("rulelab-description");
  const confidenceInput = document.getElementById("rulelab-confidence");
  const ttpInput = document.getElementById("rulelab-ttp");
  const tlpSelect = document.getElementById("rulelab-tlp");
  const papSelect = document.getElementById("rulelab-pap");

  if (ruleInput instanceof HTMLTextAreaElement) {
    ruleInput.value = entry.rule || "";
  }
  if (titleInput instanceof HTMLInputElement) {
    titleInput.value = entry.name || ruleLabDefaultTitle();
  }
  if (descriptionInput instanceof HTMLTextAreaElement) {
    descriptionInput.value = entry.description || "";
    refreshMarkdownEditorPreview("rulelab-description");
    setMarkdownEditorMode("rulelab-description", "preview");
  }
  if (confidenceInput instanceof HTMLInputElement) {
    confidenceInput.value = String(entry.confidence ?? 70);
  }
  if (ttpInput instanceof HTMLInputElement) {
    ttpInput.value = entry.ttp || "";
  }
  if (tlpSelect instanceof HTMLSelectElement) {
    tlpSelect.value = normalizeTlpValue(entry.tlp || "TLP:GREEN");
    updateLevelSelectStyle(tlpSelect);
  }
  if (papSelect instanceof HTMLSelectElement) {
    papSelect.value = normalizePapValue(entry.pap || "PAP:GREEN");
    updateLevelSelectStyle(papSelect);
  }

  renderRuleLabPreview();
  scheduleRuleLabAnalysis();
  setTimeout(() => {
    if (ruleInput instanceof HTMLTextAreaElement) {
      ruleInput.focus();
      ruleInput.selectionStart = 0;
      ruleInput.selectionEnd = 0;
    }
  }, 0);
}

async function openRuleDetail(entry, options = {}) {
  state.detailDetectionExport = null;
  state.detailLlmPrompt = null;
  const preferredTab = options.tab === "detection" || options.tab === "emulation" ? options.tab : "overview";
  const focusedTarget = String(options.target || "").toLowerCase();
  const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
    ? entry.indicates_list
    : (entry.indicates ? [entry.indicates] : []);
  const observables = (Array.isArray(entry.observables) ? entry.observables : [])
    .map((observable) => String(observable || "").trim().toLowerCase())
    .filter(Boolean);

  let compatibilityEntries = [];
  try {
    const response = await api("/api/rules/compatibility", {
      method: "POST",
      body: JSON.stringify({
        rule: entry.rule,
        description: entry.description || "",
        confidence: entry.confidence || 70,
      }),
    });
    compatibilityEntries = response.entries || [];
  } catch (_error) {
    compatibilityEntries = [];
  }

  let abilityPayload = null;
  if (entry.ability_id) {
    try {
      abilityPayload = await api(`/api/abilities/${encodeURIComponent(entry.ability_id)}`);
    } catch (_error) {
      abilityPayload = null;
    }
  }

  const detectionRows = RULE_OUTPUT_TARGETS.map((target) => {
    const detail = compatibilityEntries.find((row) => String(row.target || "").toLowerCase() === String(target || "").toLowerCase());
    return {
      target,
      status: detail?.runtime_status || entry.target_statuses?.[target] || "unsupported",
      summary: detail?.summary || targetSummaryText(target, "detection"),
      cause: detail?.cause || "",
      notes: Array.isArray(detail?.notes) ? detail.notes : [],
      output: detail?.output || "",
      target_confidence: detail?.conversion_confidence,
    };
  });

  const artifacts = abilityPayload?.export_artifacts || {};
  const exportFiles = abilityPayload?.export_files || {};
  const emulationRows = RULE_EMULATION_TARGETS.map((target) => ({
    target,
    status: entry.emulation_statuses?.[target] || "unsupported",
    summary: targetSummaryText(target, "emulation"),
    output: artifacts[target] || artifacts[String(target || "").toLowerCase()] || "",
    target_confidence: abilityPayload?.emulation_level || "-",
    export_files: exportFiles,
  }));

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

  const detectionExportRows = detectionRows
    .filter((item) => String(item.output || "").trim().length > 0);
  const emulationExportRows = emulationRows
    .filter((item) => String(item.output || "").trim().length > 0);

  const view = `
    <div id="rule-detail-pane-overview" class="rule-tech-list">
      <section class="detail-section">
        <div class="detail-code-head">
          <h4>${escapeHtml(t("detail.rule.summary"))}</h4>
          <div class="detail-summary-actions">
            <button class="btn btn-ghost" data-action="detail-show-json">JSON</button>
            <button class="btn btn-primary" data-action="rule-open-in-lab" data-id="${escapeHtml(entry.id || "")}">${escapeHtml(t("rules.edit"))}</button>
          </div>
        </div>
        <div class="detail-grid">
          <div class="detail-kv"><span class="label">${escapeHtml(t("rules.col.name"))}</span><code>${escapeHtml(entry.name || "-")}</code></div>
          <div class="detail-kv"><span class="label">${escapeHtml(t("common.id"))}</span><code>${escapeHtml(entry.id || "-")}</code></div>
          <div class="detail-kv detail-kv-confidence"><span class="label">${escapeHtml(t("rules.col.confidence"))}</span>${renderConfidenceBar(entry.confidence, { variant: "rule" })}</div>
          <div class="detail-kv"><span class="label">TLP</span>${trafficBadge(entry.tlp, "tlp")}</div>
          <div class="detail-kv"><span class="label">PAP</span>${trafficBadge(entry.pap, "pap")}</div>
          <div class="detail-kv"><span class="label">TTP</span><code>${escapeHtml(entry.ttp || "-")}</code></div>
        </div>
      </section>
      <section class="detail-section">
        <div class="detail-code-wrap">
          <div class="detail-code-head">
            <h4>${escapeHtml(t("rules.col.rule"))}</h4>
            ${copyButtonFor(entry.rule || "", t("detail.copy_rule"))}
          </div>
          <pre class="detail-code">${escapeHtml(entry.rule || "")}</pre>
        </div>
      </section>
      <section class="detail-section">
        <h4>${escapeHtml(t("rules.col.observables"))}</h4>
        <div class="rule-card-tags">
          ${observables.length
            ? observables.map((observable) => `<span class="rule-observable-tag">${escapeHtml(observable)}</span>`).join("")
            : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
        </div>
      </section>
      ${indicatesSection}
    </div>
    <section class="detail-section hidden" id="rule-detail-pane-detection">
      <div class="rule-tech-list">
        ${detectionRows.map((item) => renderRuleTechCard(entry, item, "detection")).join("")}
      </div>
      <div class="rule-detail-export-row">
        <div class="rule-export-combo">
          <button class="btn btn-success" data-action="rule-detail-export" data-family="detection" ${detectionExportRows.length ? "" : "disabled"}>${escapeHtml(t("detail.rule.export"))}</button>
          <select id="rule-detail-export-detection-target" class="rule-export-select" ${detectionExportRows.length ? "" : "disabled"}>
            ${detectionExportRows
              .map((item) => `<option value="${escapeHtml(String(item.target || ""))}">${escapeHtml(targetLabel(item.target, "detection"))}</option>`)
              .join("")}
          </select>
        </div>
      </div>
    </section>
    <section class="detail-section hidden" id="rule-detail-pane-emulation">
      <div class="rule-tech-list">
        ${emulationRows.map((item) => renderRuleTechCard(entry, item, "emulation")).join("")}
      </div>
      <div class="rule-detail-export-row">
        <div class="rule-export-combo">
          <button class="btn btn-success" data-action="rule-detail-export" data-family="emulation" ${entry.ability_id && emulationExportRows.length ? "" : "disabled"}>${escapeHtml(t("detail.rule.export"))}</button>
          <select id="rule-detail-export-emulation-target" class="rule-export-select" ${entry.ability_id && emulationExportRows.length ? "" : "disabled"}>
            ${emulationExportRows
              .map((item) => `<option value="${escapeHtml(String(item.target || ""))}">${escapeHtml(targetLabel(item.target, "emulation"))}</option>`)
              .join("")}
          </select>
        </div>
      </div>
    </section>
  `;

  state.ruleDetail.entry = entry;
  state.ruleDetail.detectionRows = detectionRows;
  state.ruleDetail.emulationRows = emulationRows;
  state.ruleDetail.focusedTarget = focusedTarget;
  document.getElementById("detail-title").textContent = entry.name || t("rules.col.rule");
  setDetailModalMode("detection", t("detail.stix_pattern"), "");
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = JSON.stringify(entry, null, 2);
  document.getElementById("detail-actions").innerHTML = renderDetailActions("");
  configureDetailTabs("rule");
  setDetailTab("view");
  document.getElementById("detail-dialog").showModal();
  setRuleDetailTab(preferredTab);
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
      { label: "Documentacion de Sigma", url: "https://sigmahq.io/" },
      { label: "Proyecto GitHub de sigma-cli", url: "https://github.com/SigmaHQ/sigma-cli" },
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

function detectionExportFileName(title, target) {
  return `spuc-${sanitizeFileToken(title)}-${sanitizeFileToken(target)}.${detectionExportExtension(target)}`;
}

function detectionExecutionCommand(target, title = "") {
  const normalized = String(target || "").toLowerCase();
  const fileName = detectionExportFileName(title || "rule", target);
  if (normalized === "sigma") {
    return `sigma convert -t splunk -r ${fileName}`;
  }
  if (normalized === "snort") {
    return `snort -A console -q -c /etc/snort/snort.conf -R ${fileName} -r <traffic.pcap>`;
  }
  if (normalized === "suricata") {
    return `suricata -S ${fileName} -r <traffic.pcap> -k none`;
  }
  if (normalized === "yara") {
    return `yara ${fileName} <sample_or_directory>`;
  }
  return "";
}

function renderDetectionDetonationGuide(target, title = "") {
  const links = detectionUtilityLinks(target);
  const command = detectionExecutionCommand(target, title);
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
          ${renderConfidenceBar(detail?.conversion_confidence, { variant: "target" })}
        </div>
        <div class="detail-kv">
          <span class="label label-with-help">
            ${escapeHtml(t("detail.rule.confidence"))}
            ${inlineHelpTip(t("detail.tooltip.rule_confidence"))}
          </span>
          ${renderConfidenceBar(detail?.rule_confidence, { variant: "rule" })}
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
          ${copyButtonFor(output || "", t("detail.copy_output"))}
        </div>
        <pre class="detail-code">${escapeHtml(output || t("detail.no_output_for_target"))}</pre>
      </div>
    </section>
    ${renderDetectionDetonationGuide(target, title)}
  `;
  const rightActions = [];
  state.detailLlmPrompt = null;
  if (output && String(output).trim()) {
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
    return [{ label: "atomic-red", url: "https://github.com/redcanaryco/atomic-red-team" }];
  }
  if (normalized === "mitre-caldera") {
    return [{ label: "MITRE CALDERA", url: "https://github.com/mitre/caldera" }];
  }
  return [];
}

function emulationExecutionCommand(target, payload = {}) {
  const normalized = String(target || "").toLowerCase();
  const exportFiles = payload?.export_files || {};
  const fileName = exportFiles[normalized] || exportFiles[target] || defaultEmulationExportFileName(payload?.ability_id, normalized);
  if (normalized === "spuc-agent") {
    return fileName ? `spuc-agent validate --file ${fileName} && spuc-agent run --file ${fileName}` : "";
  }
  if (normalized === "bash") {
    return fileName ? `chmod +x ${fileName} && ./${fileName}` : "";
  }
  if (normalized === "powershell") {
    return fileName ? `powershell -ExecutionPolicy Bypass -File .\\${fileName}` : "";
  }
  if (normalized === "atomic-red-team") {
    return fileName ? `Invoke-AtomicTest <technique_id> -PathToAtomicsFolder <path> -InputArgs @{ Path='${fileName}' }` : "";
  }
  if (normalized === "mitre-caldera") {
    return fileName ? `curl -X POST <caldera_url>/api/rest -H \"KEY:<api_key>\" -d @${fileName}` : "";
  }
  return "";
}

function defaultEmulationExportFileName(abilityId, target) {
  const id = String(abilityId || "").trim();
  const normalized = String(target || "").toLowerCase();
  if (!id || !normalized) return "";
  const extensionMap = {
    "spuc-agent": "json",
    bash: "sh",
    powershell: "ps1",
    "atomic-red-team": "yaml",
    "mitre-caldera": "json",
  };
  const extension = extensionMap[normalized];
  if (!extension) return "";
  return `${id}-${normalized.replaceAll("-", "_")}.${extension}`;
}

function renderEmulationDetonationGuide(target, payload = {}) {
  const links = emulationUtilityLinks(target);
  const command = emulationExecutionCommand(target, payload);
  if (!command) return "";
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
  const alternateTargets = availableTargets.filter((target) => target !== initialTarget);
  const canExport = Boolean(payload?.ability_id && initialTarget);
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
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.ability"))}</span><code>${escapeHtml(payload?.ability_name || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.ability_id"))}</span><code>${escapeHtml(payload?.ability_id || "-")}</code></div>
        <div class="detail-kv"><span class="label">TTP</span><code>${escapeHtml(payload?.ttp || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.level"))}</span><code>${escapeHtml(payload?.emulation_level || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.platforms"))}</span><code>${escapeHtml((payload?.platforms || []).join(", ") || "-")}</code></div>
        <div class="detail-kv"><span class="label">${escapeHtml(t("detail.classification"))}</span><code>${escapeHtml(payload?.classification || "-")}</code></div>
      </div>
      ${payload?.note ? `<div class="muted">${escapeHtml(payload.note)}</div>` : ""}
    </section>
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.available_exports"))}</h4>
      <div class="chip-list">
        ${alternateTargets.map((target) => `<span class="rule-observable-tag">${escapeHtml(targetLabel(target, "emulation"))}</span>`).join("") || `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
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
    <section class="detail-section">
      <h4>${escapeHtml(t("detail.emulation.available_exports"))}</h4>
      <div class="stack">
        ${availableTargets.length
          ? availableTargets
            .map((target) => {
              const artifacts = payload?.export_artifacts || {};
              const content = artifacts[target] || artifacts[String(target || "").toLowerCase()] || "";
              const heading = targetLabel(target, "emulation");
              return `
                <div class="detail-code-wrap">
                  <div class="detail-code-head">
                    <h4>${escapeHtml(heading)}</h4>
                    ${copyButtonFor(String(content || ""), t("common.copy"))}
                  </div>
                  <pre class="detail-code">${escapeHtml(String(content || "").trim() || t("detail.no_output_for_target"))}</pre>
                </div>
              `;
            })
            .join("")
          : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
      </div>
    </section>
    ${actionsHtml}
    ${initialTarget ? `<section id="emulation-detonation-guide">${renderEmulationDetonationGuide(initialTarget, payload)}</section>` : ""}
  `;
  document.getElementById("detail-title").textContent = title;
  setDetailModalMode("emulation", detailBadgeText("emulation", initialTarget || selectedTarget), payload?.status || "unsupported");
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = "";
  document.getElementById("detail-actions").innerHTML = renderDetailActions(
    `<button class="btn btn-success" data-action="emulation-export-download" data-ability="${escapeHtml(payload?.ability_id || "")}" data-target="${escapeHtml(initialTarget || "")}" ${canExport ? "" : "disabled"}>${escapeHtml(t("detail.emulation.download_payload"))}</button>`,
  );
  setDetailTab("view");
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
  const rootRoute = route.startsWith("rules-")
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
  if (state.principal?.role === "admin") {
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
    case "markings": return "Markings";
    case "tlp": return "TLP";
    case "pap": return "PAP";
    case "ttp": return "TTP";
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
    case "markings": return "Markings";
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
  const columns = [
    ...RULE_COLUMN_KEYS.filter((column) => column !== "tlp" && column !== "pap"),
    "markings",
  ];
  const markingsChecked = state.rules.visibleColumns.has("tlp") || state.rules.visibleColumns.has("pap");
  menu.innerHTML = columns
    .map((column) => `
      <label class="column-menu-item">
        <input
          type="checkbox"
          data-action="rules-column-toggle"
          data-column="${column}"
          ${column === "markings" ? (markingsChecked ? "checked" : "") : (state.rules.visibleColumns.has(column) ? "checked" : "")}
        >
        <span>${escapeHtml(rulesColumnLabel(column))}</span>
      </label>
    `)
    .join("");
}

function renderAdversariesColumnPicker() {
  const menu = document.getElementById("adversaries-columns-menu");
  if (!menu) return;
  const columns = [
    ...ADVERSARY_COLUMN_KEYS.filter((column) => column !== "tlp" && column !== "pap"),
    "markings",
  ];
  const markingsChecked = state.adversaries.visibleColumns.has("tlp") || state.adversaries.visibleColumns.has("pap");
  menu.innerHTML = columns
    .map((column) => `
      <label class="column-menu-item">
        <input
          type="checkbox"
          data-action="adversaries-column-toggle"
          data-column="${column}"
          ${column === "markings" ? (markingsChecked ? "checked" : "") : (state.adversaries.visibleColumns.has(column) ? "checked" : "")}
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
  if (column === "ttp") return String(entry.ttp || "");
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
  const fileName = detectionExportFileName(payload.title, payload.target);
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

function buildRulesSelectedCsv(entries) {
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
  return csvLines.join("\n");
}

async function exportSelectedRules(format = "csv") {
  if (state.rules.selected.size === 0) return;
  const entries = state.rules.allEntries.filter((entry) => state.rules.selected.has(entry.id));
  if (!entries.length) {
    showToast("common.no_data", true);
    return;
  }
  if (format === "stix-bundle") {
    const payload = {
      rule_ids: entries.map((entry) => entry.id),
    };
    const response = await fetch("/api/rules/export/bundle", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const maybeJson = await response.json().catch(() => ({ error: "bundle_export_failed" }));
      throw new Error(maybeJson.error || "bundle_export_failed");
    }
    const blob = await response.blob();
    const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = `spuc-rules-${ts}.stix-bundle.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    showToast("toast.export_ready");
    return;
  }
  const csv = buildRulesSelectedCsv(entries);
  const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
  downloadTextFile(csv, `spuc-rules-selected-${ts}.csv`, "text/csv;charset=utf-8");
  showToast("toast.export_ready");
}

async function duplicateSelectedRules() {
  const selected = state.rules.allEntries.filter((entry) => state.rules.selected.has(entry.id));
  if (!selected.length) return;
  for (const entry of selected) {
    const name = `${entry.name || "Rule"} (copy)`;
    const indicatesList = Array.isArray(entry.indicates_list) ? entry.indicates_list : [];
    const firstIndicates = indicatesList[0] || entry.indicates || null;
    await api("/api/rules/save", {
      method: "POST",
      body: JSON.stringify({
        rule: entry.rule,
        name,
        description: entry.description || "",
        confidence: Number(entry.confidence || 70),
        tlp: entry.tlp || "TLP:GREEN",
        pap: entry.pap || "PAP:GREEN",
        ttp: entry.ttp || "",
        indicates: firstIndicates,
      }),
    });
  }
  showToast("toast.saved");
  await loadRules(state.rules.page);
}

async function duplicateSelectedAdversaries() {
  const selected = state.adversaries.allEntries.filter((entry) => state.adversaries.selected.has(entry.id));
  if (!selected.length) return;
  for (const entry of selected) {
    const detail = await api(`/api/adversaries/${encodeURIComponent(entry.id)}`);
    await api("/api/adversaries", {
      method: "POST",
      body: JSON.stringify({
        name: `${detail.name || entry.name || "Adversary"} (copy)`,
        description: detail.description || entry.description || "",
        confidence: Number(detail.confidence || entry.confidence || 70),
        ability_ids: detail.ability_refs || [],
        order: detail.ability_refs || [],
      }),
    });
  }
  showToast("toast.saved");
  await loadAdversaries(state.adversaries.page);
}

function updateRulesBulkState() {
  const count = state.rules.selected.size;
  const filteredEntries = applyRulesClientFilters(state.rules.allEntries);
  const allFilteredSelected = filteredEntries.length > 0
    && filteredEntries.every((entry) => state.rules.selected.has(entry.id));
  const bulkToggleButton = document.getElementById("rules-bulk-toggle");
  const exportSelectedCsvButton = document.getElementById("rules-export-selected-csv");
  const exportSelectedStixButton = document.getElementById("rules-export-selected-stix");
  const duplicateSelectedButton = document.getElementById("rules-duplicate-selected");
  const deleteButton = document.getElementById("rules-delete-selected");
  const selectAllButton = document.getElementById("rules-select-all-toggle");
  if (bulkToggleButton) {
    bulkToggleButton.disabled = count === 0;
    bulkToggleButton.classList.toggle("active", state.rules.bulkEditOpen && count > 0);
  }
  if (exportSelectedCsvButton) {
    exportSelectedCsvButton.disabled = count === 0;
  }
  if (exportSelectedStixButton) {
    exportSelectedStixButton.disabled = count === 0;
  }
  if (deleteButton) {
    deleteButton.disabled = count === 0;
  }
  if (duplicateSelectedButton) {
    duplicateSelectedButton.disabled = count === 0;
  }
  if (selectAllButton) {
    selectAllButton.disabled = filteredEntries.length === 0;
    const selectLabel = allFilteredSelected ? t("rules.bulk.deselect_all") : t("rules.bulk.select_all");
    selectAllButton.title = selectLabel;
    selectAllButton.setAttribute("aria-label", selectLabel);
    selectAllButton.innerHTML = allFilteredSelected
      ? '<i class="fa-regular fa-square-check" aria-hidden="true"></i>'
      : '<i class="fa-regular fa-square" aria-hidden="true"></i>';
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

function renderRulesCards() {
  const cardsRoot = document.getElementById("rules-cards");
  if (!cardsRoot) return;
  if (!state.rules.entries.length) {
    cardsRoot.innerHTML = `<div class="rules-cards-empty">${escapeHtml(t("common.no_data"))}</div>`;
    return;
  }

  cardsRoot.innerHTML = state.rules.entries
    .map((entry, rowIndex) => {
      const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
        ? entry.indicates_list
        : (entry.indicates ? [entry.indicates] : []);
      const observables = (Array.isArray(entry.observables) ? entry.observables : [])
        .map((observable) => String(observable || "").trim().toLowerCase())
        .filter(Boolean);

      const outputChips = RULE_OUTPUT_TARGETS
        .map((target) =>
          renderStatusChip(target.toUpperCase(), entry.target_statuses?.[target] || "unsupported", "rule-target-detail", {
            rule: entry.id,
            target,
          }),
        )
        .join("");
      const emulationChips = RULE_EMULATION_TARGETS
        .map((target) =>
          renderStatusChip(target, entry.emulation_statuses?.[target] || "unsupported", "rule-emulation-detail", {
            rule: entry.id,
            target,
            ability: entry.ability_id || "",
          }),
        )
        .join("");
      const globalStatus = ruleStatusFromEntry(entry);

      return `
        <article class="rule-card ${globalStatus}" data-rule-card-id="${escapeHtml(entry.id)}">
          <header class="rule-card-head">
            <label class="rule-card-check">
              <input type="checkbox" data-action="rule-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.rules.selected.has(entry.id) ? "checked" : ""}>
            </label>
            <div class="rule-card-title-wrap">
              <h4>${escapeHtml(entry.name || t("rules.col.rule"))}</h4>
              <div class="rule-card-subtitle">
                <span class="rule-card-id-stack">
                  <span class="rule-card-id">${escapeHtml(entry.id)}</span>
                  <span class="badge ${statusClass(globalStatus)}">${escapeHtml(statusLabel(globalStatus))}</span>
                </span>
              </div>
            </div>
            <div class="rule-card-markings">
              ${trafficBadge(entry.tlp, "tlp")}
              ${trafficBadge(entry.pap, "pap")}
            </div>
          </header>

          <section class="rule-card-body">
            <div class="rule-card-grid">
              <div class="rule-card-kv rule-card-kv-confidence">${renderConfidenceBar(entry.confidence, { label: t("rules.col.confidence"), variant: "rule" })}</div>
              <div class="rule-card-kv"><span>TTP</span><strong>${escapeHtml(entry.ttp || "-")}</strong></div>
              <div class="rule-card-kv"><span>${escapeHtml(t("rules.col.indicates"))}</span><strong>${escapeHtml(String(indicatesList.length))}</strong></div>
              <div class="rule-card-kv"><span>${escapeHtml(t("rules.col.observables"))}</span><strong>${escapeHtml(String(observables.length))}</strong></div>
            </div>

            <div class="rule-card-code-wrap">
              <div class="detail-code-head">
                <h4>${escapeHtml(t("rules.col.rule"))}</h4>
                <button class="icon-btn icon-only" data-action="rule-copy" data-id="${escapeHtml(entry.id)}" title="${escapeHtml(t("detail.copy_rule"))}" aria-label="${escapeHtml(t("detail.copy_rule"))}">📋</button>
              </div>
              <code class="rule-card-code">${escapeHtml(entry.rule || "")}</code>
            </div>

            <div class="rule-card-pill-columns">
              <div class="rule-card-pill-group">
                <span class="rule-card-pill-label">${escapeHtml(t("detail.rule.tab.detection_short"))}</span>
                <div class="chip-list">${outputChips}</div>
              </div>
              <div class="rule-card-pill-group">
                <span class="rule-card-pill-label">${escapeHtml(t("rules.col.emulation"))}</span>
                <div class="chip-list">${emulationChips}</div>
              </div>
              <div class="rule-card-pill-group">
                <span class="rule-card-pill-label">${escapeHtml(t("rules.col.observables"))}</span>
                <div class="rule-card-tags">
                  ${(observables.length
                    ? observables.map((observable) => `<span class="rule-observable-tag">${escapeHtml(observable)}</span>`).join("")
                    : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`)}
                </div>
              </div>
            </div>
          </section>

          <footer class="rule-card-actions">
            <button class="btn btn-ghost" data-action="rule-show" data-id="${escapeHtml(entry.id)}">${escapeHtml(t("common.details"))}</button>
          </footer>
        </article>
      `;
    })
    .join("");
}

function updateRulesViewModeUI() {
  const mode = state.rules.viewMode === "cards" ? "cards" : "table";
  const tableBtn = document.getElementById("rules-view-table");
  const cardsBtn = document.getElementById("rules-view-cards");
  const tableWrap = document.getElementById("rules-table-wrap");
  const cardsWrap = document.getElementById("rules-cards");
  const columnsToggle = document.getElementById("rules-columns-toggle");

  if (tableBtn) tableBtn.classList.toggle("active", mode === "table");
  if (cardsBtn) cardsBtn.classList.toggle("active", mode === "cards");
  if (tableWrap) tableWrap.classList.toggle("hidden", mode !== "table");
  if (cardsWrap) cardsWrap.classList.toggle("hidden", mode !== "cards");
  if (columnsToggle) columnsToggle.disabled = mode !== "table";
}

function setRulesViewMode(mode) {
  state.rules.viewMode = mode === "cards" ? "cards" : "table";
  localStorage.setItem("spuc-web-rules-view-mode", state.rules.viewMode);
  updateRulesViewModeUI();
  if (state.rules.allEntries.length > 0) {
    renderRulesTable();
  }
}

function renderRulesTable() {
  const outputTargets = RULE_OUTPUT_TARGETS;
  const emulationTargets = RULE_EMULATION_TARGETS;
  const currentSort = state.rules.sort || "confidence_desc";
  const isVisible = (column) => state.rules.visibleColumns.has(column);
  const markingsVisible = isVisible("tlp") || isVisible("pap");
  const displayedRulesColumns = RULE_COLUMN_KEYS.filter((column) => column !== "tlp" && column !== "pap");
  if (markingsVisible) displayedRulesColumns.splice(2, 0, "markings");
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
      cells.push(`<td>${renderConfidenceBar(entry.confidence, { variant: "rule" })}</td>`);
    }
    if (markingsVisible) {
      cells.push(`
        <td>
          <div class="markings-stack">
            ${trafficBadge(entry.tlp, "tlp")}
            ${trafficBadge(entry.pap, "pap")}
          </div>
        </td>
      `);
    }
    if (isVisible("ttp")) cells.push(`<td><code>${escapeHtml(entry.ttp || "-")}</code></td>`);
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
  const visibleCount = displayedRulesColumns.filter((column) => column === "markings" || isVisible(column)).length;
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
  if (markingsVisible) {
    headers.push(`<th>${escapeHtml(rulesColumnLabel("markings"))}</th>`);
  }
  if (isVisible("ttp")) headers.push(`<th>TTP</th>`);
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
  renderRulesCards();
  updateRulesViewModeUI();
  const modeLabel = state.rules.viewMode === "cards" ? t("rules.view.cards") : t("rules.view.table");
  document.getElementById("rules-meta").textContent = `${state.rules.entries.length}/${state.rules.total} ${t("common.entries")} · ${modeLabel}`;
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

function updateAdversariesBulkState() {
  const count = state.adversaries.selected.size;
  const filteredEntries = applyAdversariesClientFilters(state.adversaries.allEntries || []);
  const allFilteredSelected = filteredEntries.length > 0
    && filteredEntries.every((entry) => state.adversaries.selected.has(entry.id));

  const bulkToggleButton = document.getElementById("adversaries-bulk-toggle");
  const deleteButton = document.getElementById("adversaries-delete-selected");
  const duplicateButton = document.getElementById("adversaries-duplicate-selected");
  const selectAllButton = document.getElementById("adversaries-select-all-toggle");
  if (bulkToggleButton) {
    bulkToggleButton.disabled = count === 0;
    bulkToggleButton.classList.toggle("active", state.adversaries.bulkEditOpen && count > 0);
  }
  if (deleteButton) {
    deleteButton.disabled = count === 0;
  }
  if (duplicateButton) {
    duplicateButton.disabled = count === 0;
  }
  if (selectAllButton) {
    selectAllButton.disabled = filteredEntries.length === 0;
    const selectLabel = allFilteredSelected ? t("adversaries.bulk.deselect_all") : t("adversaries.bulk.select_all");
    selectAllButton.title = selectLabel;
    selectAllButton.setAttribute("aria-label", selectLabel);
    selectAllButton.innerHTML = allFilteredSelected
      ? '<i class="fa-regular fa-square-check" aria-hidden="true"></i>'
      : '<i class="fa-regular fa-square" aria-hidden="true"></i>';
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

function renderAdversariesCards() {
  const cardsRoot = document.getElementById("adversaries-cards");
  if (!cardsRoot) return;
  if (!state.adversaries.entries.length) {
    cardsRoot.innerHTML = `<div class="rules-cards-empty">${escapeHtml(t("common.no_data"))}</div>`;
    return;
  }

  const exportTargets = ["spuc-agent", "bash", "powershell", "atomic-red-team", "mitre-caldera"];
  cardsRoot.innerHTML = state.adversaries.entries.map((entry, rowIndex) => {
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

    return `
      <article class="rule-card adversary-card" data-adversary-card-id="${escapeHtml(entry.id)}">
        <header class="rule-card-head">
          <label class="rule-card-check">
            <input type="checkbox" data-action="adversary-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.adversaries.selected.has(entry.id) ? "checked" : ""}>
          </label>
          <div class="rule-card-title-wrap">
            <h4>${escapeHtml(entry.name || t("adversaries.col.name"))}</h4>
            <div class="rule-card-subtitle">
              <span class="rule-card-id-stack">
                <span class="rule-card-id">${escapeHtml(entry.id)}</span>
              </span>
            </div>
          </div>
          <div class="rule-card-markings">
            ${trafficBadge(entry.tlp || "TLP:GREEN", "tlp")}
            ${trafficBadge(entry.pap || "PAP:GREEN", "pap")}
          </div>
        </header>

        <section class="rule-card-body">
          <div class="rule-card-grid">
            <div class="rule-card-kv rule-card-kv-confidence">${renderConfidenceBar(entry.confidence, { label: t("adversaries.col.confidence"), variant: "target" })}</div>
            <div class="rule-card-kv"><span>${escapeHtml(t("adversaries.col.steps"))}</span><strong>${escapeHtml(String(entry.steps ?? 0))}</strong></div>
          </div>

          <div class="rule-card-pill-columns rule-card-pill-columns-2">
            <div class="rule-card-pill-group">
              <span class="rule-card-pill-label">${escapeHtml(t("adversaries.col.platforms"))}</span>
              <div class="rule-card-tags">
                ${(entry.platforms || []).length
                  ? (entry.platforms || []).map((platform) => `<span class="rule-observable-tag">${escapeHtml(platform)}</span>`).join("")
                  : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
              </div>
            </div>
            <div class="rule-card-pill-group">
              <span class="rule-card-pill-label">${escapeHtml(t("adversaries.col.exporters"))}</span>
              <div class="export-pill-row">${exporterPills}</div>
            </div>
          </div>
        </section>

        <footer class="rule-card-actions">
          <button class="btn btn-ghost" data-action="adversary-show" data-id="${escapeHtml(entry.id)}">${escapeHtml(t("common.details"))}</button>
        </footer>
      </article>
    `;
  }).join("");
}

function updateAdversariesViewModeUI() {
  const mode = state.adversaries.viewMode === "table" ? "table" : "cards";
  const tableBtn = document.getElementById("adversaries-view-table");
  const cardsBtn = document.getElementById("adversaries-view-cards");
  const tableWrap = document.getElementById("adversaries-table-wrap");
  const cardsWrap = document.getElementById("adversaries-cards");
  const columnsToggle = document.getElementById("adversaries-columns-toggle");

  if (tableBtn) tableBtn.classList.toggle("active", mode === "table");
  if (cardsBtn) cardsBtn.classList.toggle("active", mode === "cards");
  if (tableWrap) tableWrap.classList.toggle("hidden", mode !== "table");
  if (cardsWrap) cardsWrap.classList.toggle("hidden", mode !== "cards");
  if (columnsToggle) columnsToggle.disabled = mode !== "table";
}

function setAdversariesViewMode(mode) {
  state.adversaries.viewMode = mode === "table" ? "table" : "cards";
  localStorage.setItem("spuc-web-adversaries-view-mode", state.adversaries.viewMode);
  updateAdversariesViewModeUI();
  if (state.adversaries.allEntries.length > 0) {
    renderAdversariesTable();
  }
}

function renderAdversariesTable() {
  const isVisible = (column) => state.adversaries.visibleColumns.has(column);
  const markingsVisible = isVisible("tlp") || isVisible("pap");
  const displayedAdversaryColumns = ADVERSARY_COLUMN_KEYS.filter((column) => column !== "tlp" && column !== "pap");
  if (markingsVisible) displayedAdversaryColumns.splice(2, 0, "markings");
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
    if (isVisible("confidence")) cells.push(`<td>${renderConfidenceBar(entry.confidence, { variant: "target" })}</td>`);
    if (markingsVisible) {
      cells.push(`
        <td>
          <div class="markings-stack">
            ${trafficBadge(entry.tlp || "TLP:GREEN", "tlp")}
            ${trafficBadge(entry.pap || "PAP:GREEN", "pap")}
          </div>
        </td>
      `);
    }
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
  const visibleCount = displayedAdversaryColumns.filter((column) => column === "markings" || isVisible(column)).length;
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
  if (markingsVisible) {
    headers.push(`<th>${escapeHtml(adversaryColumnLabel("markings"))}</th>`);
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
  renderAdversariesCards();
  updateAdversariesViewModeUI();
  const modeLabel = state.adversaries.viewMode === "cards" ? t("rules.view.cards") : t("rules.view.table");
  document.getElementById("adversaries-meta").textContent = `${state.adversaries.entries.length}/${state.adversaries.total} ${t("common.entries")} · ${modeLabel}`;
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
  const targetPlatformNode = document.getElementById("adversary-target-platform");
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const minConfidenceNode = document.getElementById("adversary-ability-min-confidence");
  if (searchNode) state.adversaryCompose.search = searchNode.value.trim();
  if (targetPlatformNode) {
    state.adversaryCompose.targetPlatform = String(targetPlatformNode.value || "").trim().toLowerCase();
  }
  if (platformNode) {
    const forced = state.adversaryCompose.targetPlatform;
    if (forced) {
      platformNode.value = forced;
      state.adversaryCompose.platform = forced;
    } else {
      state.adversaryCompose.platform = platformNode.value.trim();
    }
  }
  if (utilityNode) state.adversaryCompose.utility = utilityNode.value.trim();
  if (destinationNode) state.adversaryCompose.destination = destinationNode.value.trim();
  if (minConfidenceNode) {
    const value = Number(minConfidenceNode.value || "0");
    state.adversaryCompose.minConfidence = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  }
}

function resetAdversaryComposer() {
  state.adversaryCompose.search = "";
  state.adversaryCompose.targetPlatform = "";
  state.adversaryCompose.platform = "";
  state.adversaryCompose.utility = "";
  state.adversaryCompose.destination = "";
  state.adversaryCompose.minConfidence = 0;
  state.adversaryCompose.selectedOrder = [];
  state.adversaryCompose.executor = "manifest";
  state.adversaryCompose.exportPreviewByTarget = {};
  state.adversaryCompose.exportPreviewLoading = false;
  const searchNode = document.getElementById("adversary-ability-search");
  const targetPlatformNode = document.getElementById("adversary-target-platform");
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const minConfidenceNode = document.getElementById("adversary-ability-min-confidence");
  if (searchNode) searchNode.value = "";
  if (targetPlatformNode) targetPlatformNode.value = "";
  if (platformNode) platformNode.value = "";
  if (utilityNode) utilityNode.value = "";
  if (destinationNode) destinationNode.value = "";
  if (minConfidenceNode) minConfidenceNode.value = "0";
}

function selectedAdversaryExportTarget() {
  const exportTarget = document.getElementById("adversary-export-inline-target");
  if (exportTarget instanceof HTMLSelectElement && exportTarget.value) {
    return String(exportTarget.value || "").toLowerCase();
  }
  return String(state.adversaryCompose.compatibleExports?.[0] || "").toLowerCase();
}

function normalizedDownloadName(item) {
  const raw = String(item?.name || "").trim();
  if (raw) return raw;
  const link = String(item?.url || "");
  if (!link) return "";
  const marker = "name=";
  const index = link.indexOf(marker);
  if (index < 0) return "";
  const encoded = link.slice(index + marker.length).split("&")[0] || "";
  try {
    return decodeURIComponent(encoded);
  } catch {
    return encoded;
  }
}

function triggerDownloadByUrl(url, fileName = "") {
  if (!url) return;
  const link = document.createElement("a");
  link.href = url;
  if (fileName) {
    link.download = fileName;
  }
  document.body.appendChild(link);
  link.click();
  link.remove();
}

function pickOperationalDownload(downloads, target) {
  const normalizedTarget = String(target || "").toLowerCase();
  const entries = Array.isArray(downloads) ? downloads : [];
  // Pick the executable file (not YAML manifest)
  const isExecutable = (item) => {
    const name = String(normalizedDownloadName(item) || "").toLowerCase();
    return !name.endsWith(".yaml") && !name.endsWith(".json");
  };
  const inTargetBucket = (item) => String(normalizedDownloadName(item) || "").toLowerCase().startsWith(`${normalizedTarget}-`);
  return entries.find((item) => isExecutable(item))
    || null;
}

function abilityArtifactFilename(target, filenames) {
  const extByTarget = {
    "spuc-agent": ".json",
    bash: ".sh",
    powershell: ".ps1",
    "atomic-red-team": ".yaml",
    "mitre-caldera": ".json",
  };
  const expectedExt = extByTarget[target] || "";
  if (!expectedExt) return "";
  return filenames.find((name) => name.toLowerCase().endsWith(expectedExt) && !name.toLowerCase().endsWith(".yaml"))
    || filenames.find((name) => name.toLowerCase().endsWith(expectedExt))
    || "";
}

async function ensureAdversaryExportPreview(target, force = false) {
  const normalized = String(target || "").toLowerCase();
  if (!normalized) return;
  if (state.adversaryCompose.mode !== "edit" || !state.adversaryCompose.editingId) return;
  if (!force && state.adversaryCompose.exportPreviewByTarget[normalized]) return;
  if (state.adversaryCompose.exportPreviewLoading) return;
  state.adversaryCompose.exportPreviewLoading = true;
  renderAdversaryExecutionCriteria();
  try {
    const response = await api(`/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/export${toQuery({ to: normalized })}`);
    const names = (response.downloads || [])
      .map((item) => normalizedDownloadName(item))
      .filter((value) => Boolean(String(value || "").trim()));
    state.adversaryCompose.exportPreviewByTarget[normalized] = names;
  } catch {
    state.adversaryCompose.exportPreviewByTarget[normalized] = [];
  } finally {
    state.adversaryCompose.exportPreviewLoading = false;
    renderAdversaryExecutionCriteria();
  }
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

function renderAdversaryTargetPlatformOptions() {
  const targetNode = document.getElementById("adversary-target-platform");
  if (!(targetNode instanceof HTMLSelectElement)) return;
  const values = state.abilities.entries
    .flatMap((entry) => entry.platforms || [])
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  const unique = [...new Set(values)].sort((a, b) => a.localeCompare(b));
  const selected = state.adversaryCompose.targetPlatform || "";
  targetNode.innerHTML = [
    '<option value="">--</option>',
    ...unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
  ].join("");
  if (selected && unique.includes(selected)) {
    targetNode.value = selected;
  } else if (!selected) {
    targetNode.value = "";
  }
  
  // Deshabilitar el combo si hay abilities seleccionadas
  const hasSelectedAbilities = state.adversaryCompose.selectedOrder.length > 0;
  targetNode.disabled = hasSelectedAbilities;
}

function recomputeAdversaryCompatibleExportsFromSelection() {
  const selectedAbilities = state.adversaryCompose.selectedOrder
    .map((id) => state.abilities.entries.find((entry) => entry.id === id))
    .filter(Boolean);
  let compatible = [];
  selectedAbilities.forEach((entry, index) => {
    const targets = [...new Set((entry.export_targets || []).map((value) => String(value).toLowerCase()))];
    if (index === 0) {
      compatible = targets;
      return;
    }
    compatible = compatible.filter((target) => targets.includes(target));
  });
  state.adversaryCompose.compatibleExports = [...new Set(compatible)].sort((a, b) => a.localeCompare(b));
}

function syncAdversaryExportInlineControls() {
  const normalized = state.adversaryCompose.mode === "edit" ? "edit" : "create";
  const exportRoot = document.getElementById("adversary-export-inline");
  if (exportRoot) {
    exportRoot.classList.toggle("hidden", normalized !== "edit");
  }

  const exportButton = document.getElementById("adversary-export-inline-button");
  const exportTarget = document.getElementById("adversary-export-inline-target");
  const currentValue = exportTarget instanceof HTMLSelectElement ? String(exportTarget.value || "") : "";
  const options = [...new Set((state.adversaryCompose.compatibleExports || []).map((target) => String(target).toLowerCase()))];

  if (exportTarget instanceof HTMLSelectElement) {
    exportTarget.innerHTML = options
      .map((target) => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`)
      .join("");
    const enabled = normalized === "edit" && Boolean(state.adversaryCompose.editingId) && options.length > 0;
    exportTarget.disabled = !enabled;
    if (enabled) {
      exportTarget.value = options.includes(currentValue) ? currentValue : options[0];
    }
  }
  if (exportButton) {
    const enabled = normalized === "edit" && Boolean(state.adversaryCompose.editingId) && options.length > 0;
    exportButton.disabled = !enabled;
    exportButton.title = t("detail.rule.export");
    exportButton.setAttribute("aria-label", t("detail.rule.export"));
    exportButton.textContent = t("detail.rule.export");
  }
}

function renderAdversaryAbilityFilterOptions() {
  const platformNode = document.getElementById("adversary-ability-platform");
  const utilityNode = document.getElementById("adversary-ability-utility");
  const destinationNode = document.getElementById("adversary-ability-destination");
  const platforms = state.abilities.entries.flatMap((entry) => entry.platforms || []);
  const utilities = state.abilities.entries.map((entry) => entry.classification || "");
  const destinations = state.abilities.entries.flatMap((entry) => entry.export_targets || []);
  setSelectOptions(platformNode, platforms, t("common.all_platforms"), state.adversaryCompose.platform);
  if (platformNode instanceof HTMLSelectElement) {
    const forced = state.adversaryCompose.targetPlatform;
    if (forced) {
      platformNode.value = forced;
      platformNode.disabled = true;
      state.adversaryCompose.platform = forced;
    } else {
      platformNode.disabled = false;
    }
  }
  setSelectOptions(utilityNode, utilities, t("common.all_utility_types"), state.adversaryCompose.utility);
  setSelectOptions(destinationNode, destinations, t("common.all_destinations"), state.adversaryCompose.destination);
}

async function createDummyAbility(params) {
  const response = await api("/api/abilities/dummy", {
    method: "POST",
    body: JSON.stringify(params),
  });
  await loadAbilities();
  const newId = String(response?.id || "").trim();
  if (newId && !state.adversaryCompose.selectedOrder.includes(newId)) {
    state.adversaryCompose.selectedOrder.push(newId);
  }
  renderAdversaryAbilitySelector();
  scheduleAdversaryAutoSave();
  showToast("toast.saved");
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
  renderAdversaryTargetPlatformOptions();
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
          <div class="export-pill-row ability-inline-exports">
            <button type="button" class="export-pill available" data-action="ability-export" data-id="${entry.id}" data-target="spuc-agent">SPUC</button>
            <button type="button" class="export-pill available" data-action="ability-export" data-id="${entry.id}" data-target="bash">Bash</button>
            <button type="button" class="export-pill available" data-action="ability-export" data-id="${entry.id}" data-target="powershell">PowerShell</button>
            <button type="button" class="export-pill available" data-action="ability-export" data-id="${entry.id}" data-target="atomic-red-team">atomic-red</button>
            <button type="button" class="export-pill available" data-action="ability-export" data-id="${entry.id}" data-target="mitre-caldera">Caldera</button>
          </div>
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
  recomputeAdversaryCompatibleExportsFromSelection();
  syncAdversaryExportInlineControls();
  renderAdversaryEmulablePlatforms();
  renderAdversaryExecutionCriteria();
  setAdversaryFormSubmitState();
}

function setAdversaryTab(tab) {
  const normalized = tab === "criteria" ? "criteria" : "plan";
  state.adversaryCompose.activeTab = normalized;
  const settings = document.getElementById("adversary-pane-plan-settings");
  const selected = document.getElementById("adversary-pane-plan-selected");
  const criteria = document.getElementById("adversary-pane-criteria");
  if (settings) settings.classList.toggle("hidden", normalized !== "plan");
  if (selected) selected.classList.toggle("hidden", normalized !== "plan");
  if (criteria) criteria.classList.toggle("hidden", normalized !== "criteria");
  document.querySelectorAll("[data-action='adversary-tab']").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === normalized);
  });
  if (normalized === "criteria") {
    const target = selectedAdversaryExportTarget();
    if (target) {
      void ensureAdversaryExportPreview(target);
    }
  }
}

function renderAdversaryEmulablePlatforms() {
  const root = document.getElementById("adversary-emulable-platforms");
  if (!root) return;
  const selected = state.adversaryCompose.selectedOrder
    .map((id) => state.abilities.entries.find((entry) => entry.id === id))
    .filter(Boolean);
  const platforms = [...new Set(selected.flatMap((entry) => entry.platforms || []))]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  root.innerHTML = platforms.length
    ? platforms.map((platform) => `<span class="rule-observable-tag">${escapeHtml(platform)}</span>`).join("")
    : `<span class="muted">👤 ${escapeHtml(t("adversaries.card.label") || "Adversary")}</span>`;
}

function renderAdversaryExecutionCriteria() {
  const root = document.getElementById("adversary-execution-criteria");
  if (!root) return;
  const selectedCount = state.adversaryCompose.selectedOrder.length;
  const abilityId = state.adversaryCompose.editingId || "<adversary-id>";
  const selectedTarget = selectedAdversaryExportTarget();
  const targetNames = selectedTarget
    ? (state.adversaryCompose.exportPreviewByTarget[selectedTarget] || [])
    : [];
  const targetArtifact = abilityArtifactFilename(selectedTarget, targetNames);
  const criteriaRows = [
    {
      exporter: "spuc-agent",
      instruction: "Validar estructura y ejecutar en entorno controlado con traza completa.",
      command: selectedTarget === "spuc-agent" && targetArtifact
        ? `spuc adversaries export ${abilityId} --to spuc-agent --output ./artifacts && spuc-agent validate --file ./${targetArtifact}`
        : `spuc adversaries export ${abilityId} --to spuc-agent --output ./artifacts && spuc-agent validate --file <artifact.json>`,
    },
    {
      exporter: "bash",
      instruction: "Ejecutar en host Linux/macOS de laboratorio con telemetria habilitada.",
      command: selectedTarget === "bash" && targetArtifact
        ? `spuc adversaries export ${abilityId} --to bash --output ./artifacts && bash ./${targetArtifact}`
        : `spuc adversaries export ${abilityId} --to bash --output ./artifacts && bash ./<script.sh>`,
    },
    {
      exporter: "powershell",
      instruction: "Ejecutar en host Windows monitorizado; para registro usar este exportador.",
      command: selectedTarget === "powershell" && targetArtifact
        ? `spuc adversaries export ${abilityId} --to powershell --output ./artifacts && powershell -ExecutionPolicy Bypass -File .\\${targetArtifact}`
        : `spuc adversaries export ${abilityId} --to powershell --output ./artifacts && powershell -ExecutionPolicy Bypass -File .\\<script.ps1>`,
    },
    {
      exporter: "atomic-red-team",
      instruction: "Importar artefacto atomic-red y mapear parametros seguros del plan.",
      command: `spuc adversaries export ${abilityId} --to atomic-red-team --output ./artifacts`,
    },
    {
      exporter: "mitre-caldera",
      instruction: "Publicar JSON de habilidad en servidor CALDERA y verificar plataforma objetivo.",
      command: `spuc adversaries export ${abilityId} --to mitre-caldera --output ./artifacts`,
    },
  ];
  root.innerHTML = `
    <article class="detail-section">
      <div class="detail-grid">
        <div class="detail-kv"><span class="label">Pasos seleccionados</span><code>${escapeHtml(String(selectedCount))}</code></div>
        <div class="detail-kv"><span class="label">Modo guardado</span><code>Autosave</code></div>
        <div class="detail-kv"><span class="label">Export objetivo</span><code>${escapeHtml(selectedTarget || "sin seleccionar")}</code></div>
      </div>
    </article>
    <article class="rule-tech-card">
      <div class="rule-tech-head">
        <h4>Nombres reales de archivo</h4>
        ${selectedTarget ? `<button type="button" class="btn btn-ghost" data-action="adversary-refresh-execution-help" data-target="${escapeHtml(selectedTarget)}" ${state.adversaryCompose.exportPreviewLoading ? "disabled" : ""}>Actualizar</button>` : ""}
      </div>
      ${selectedTarget
    ? (targetNames.length
      ? `<div class="detail-code-wrap">
              <div class="detail-code-head">
                <small class="muted">${escapeHtml(selectedTarget)}</small>
                <button type="button" class="btn btn-ghost code-copy-btn" data-action="detail-copy" data-copy="${encodeURIComponent(targetNames.join("\n"))}"><i class="fa-regular fa-copy" aria-hidden="true"></i><span>Copiar</span></button>
              </div>
              <pre class="detail-code">${escapeHtml(targetNames.join("\n"))}</pre>
            </div>`
      : `<p class="muted">Aun no hay nombres disponibles para este destino. Pulsa "Actualizar" para generar y ver los nombres reales.</p>`)
    : `<p class="muted">Selecciona un destino de export para mostrar los nombres reales.</p>`}
    </article>
    ${criteriaRows
      .map((row) => `
        <article class="rule-tech-card">
          <div class="rule-tech-head">
            <h4>${escapeHtml(row.exporter)}</h4>
          </div>
          <p class="muted">${escapeHtml(row.instruction)}</p>
          <div class="detail-code-wrap">
            <div class="detail-code-head">
              <small class="muted">Comando sugerido</small>
              <button type="button" class="btn btn-ghost code-copy-btn" data-action="detail-copy" data-copy="${encodeURIComponent(row.command)}"><i class="fa-regular fa-copy" aria-hidden="true"></i><span>Copiar</span></button>
            </div>
            <pre class="detail-code">${escapeHtml(row.command)}</pre>
          </div>
        </article>
      `)
      .join("")}
  `;
}

function openAdversaryAbilityPicker() {
  const dialog = document.getElementById("adversary-ability-picker-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  setAdversaryPickerTab("catalog");
  renderAdversaryAbilitySelector();
  dialog.showModal();
}

function setAdversaryPickerTab(tab) {
  const normalized = tab === "dummy" ? "dummy" : "catalog";
  const catalogPane = document.getElementById("adversary-picker-pane-catalog");
  const dummyPane = document.getElementById("adversary-picker-pane-dummy");
  if (catalogPane) catalogPane.classList.toggle("hidden", normalized !== "catalog");
  if (dummyPane) dummyPane.classList.toggle("hidden", normalized !== "dummy");
  document.querySelectorAll("[data-action='adversary-picker-tab']").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === normalized);
  });
}

function closeAdversaryAbilityPicker() {
  const dialog = document.getElementById("adversary-ability-picker-dialog");
  if (dialog instanceof HTMLDialogElement) {
    dialog.close();
  }
}

function scheduleAdversaryAutoSave() {
  if (state.adversaryCompose.autoSaving) return;
  clearTimeout(state.adversaryCompose.autoSaveTimer);
  state.adversaryCompose.autoSaveTimer = setTimeout(async () => {
    if (!document.getElementById("adversary-dialog")?.open) return;
    await persistAdversaryAutosave();
  }, 520);
}

async function persistAdversaryAutosave() {
  syncAdversaryComposerFromInputs();
  const selected = [...state.adversaryCompose.selectedOrder];
  const name = document.getElementById("adversary-name")?.value?.trim() || "";
  const targetPlatform = String(document.getElementById("adversary-target-platform")?.value || "").trim().toLowerCase();
  if (!name || !targetPlatform || selected.length === 0) return;
  const payload = {
    name,
    description: document.getElementById("adversary-description")?.value?.trim() || "",
    confidence: Number(document.getElementById("adversary-confidence")?.value || 70),
    target_platform: targetPlatform,
    ability_ids: selected,
    order: selected,
  };
  const signature = JSON.stringify(payload);
  if (signature === state.adversaryCompose.originalSignature) {
    return;
  }
  state.adversaryCompose.autoSaving = true;
  try {
    if (state.adversaryCompose.mode === "edit" && state.adversaryCompose.editingId) {
      await api(`/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/update`, {
        method: "POST",
        body: JSON.stringify(payload),
      });
    } else {
      const response = await api("/api/adversaries", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const createdId = response.id || null;
      const created = createdId
        ? await api(`/api/adversaries/${encodeURIComponent(createdId)}`).catch(() => response)
        : response;
      state.adversaryCompose.mode = "edit";
      state.adversaryCompose.editingId = createdId;
      state.adversaryCompose.compatibleExports = [];
      setAdversaryFormMode("edit", created);
    }
    state.adversaryCompose.originalSignature = signature;
    showToast("toast.saved");
    await loadAdversaries(state.adversaries.page);
  } finally {
    state.adversaryCompose.autoSaving = false;
  }
}

function adversaryFormSignature() {
  const payload = {
    name: document.getElementById("adversary-name")?.value?.trim() || "",
    description: document.getElementById("adversary-description")?.value?.trim() || "",
    confidence: Number(document.getElementById("adversary-confidence")?.value || "70"),
    target_platform: String(document.getElementById("adversary-target-platform")?.value || "").trim().toLowerCase(),
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
  const initialTargetPlatform = normalized === "edit"
    ? String(adversary?.target_platform || "").trim().toLowerCase()
    : "";
  state.adversaryCompose.mode = normalized;
  state.adversaryCompose.targetPlatform = initialTargetPlatform;
  state.adversaryCompose.editingId = normalized === "edit" ? adversary?.id || null : null;
  state.adversaryCompose.compatibleExports = normalized === "edit"
    ? [...new Set((adversary?.compatible_exports || []).map((target) => String(target).toLowerCase()))]
    : [];
  state.adversaryCompose.exportPreviewByTarget = {};
  state.adversaryCompose.exportPreviewLoading = false;
  const title = document.getElementById("adversary-form-title");
  const inlineTitle = document.getElementById("adversary-title-inline");
  const submit = document.getElementById("adversary-submit");
  if (title) {
    title.textContent = normalized === "edit" ? (adversary?.name || t("adversaries.edit.untitled")) : t("adversaries.create.title");
  }
  if (inlineTitle instanceof HTMLInputElement) {
    inlineTitle.classList.add("hidden");
    inlineTitle.value = "";
  }
  if (submit) {
    submit.textContent = normalized === "edit" ? t("common.save") : t("adversaries.create.submit");
    submit.classList.remove("hidden", "btn-primary", "btn-success");
    submit.classList.add(normalized === "edit" ? "btn-primary" : "btn-success");
  }
  syncAdversaryExportInlineControls();
  renderAdversaryExecutionCriteria();
  syncAdversaryModalTitle();
}

function setAdversaryFormSubmitState() {
  const submit = document.getElementById("adversary-submit");
  if (!(submit instanceof HTMLButtonElement)) return;
  const hasName = Boolean(document.getElementById("adversary-name")?.value?.trim());
  const hasTargetPlatform = Boolean(String(document.getElementById("adversary-target-platform")?.value || "").trim());
  const hasSteps = state.adversaryCompose.selectedOrder.length > 0;
  submit.disabled = !hasName || !hasTargetPlatform || !hasSteps;
}

function openAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  resetAdversaryComposer();
  document.getElementById("adversary-form")?.reset();
  setAdversaryFormMode("create");
  state.adversaryCompose.originalSignature = adversaryFormSignature();
  state.adversaryCompose.activeTab = "plan";
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  renderAdversaryAbilitySelector();
  setAdversaryTab("plan");
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
  const targetPlatform = document.getElementById("adversary-target-platform");
  if (targetPlatform instanceof HTMLSelectElement) {
    targetPlatform.value = String(adversary.target_platform || "").trim().toLowerCase();
  }
  state.adversaryCompose.selectedOrder = Array.isArray(adversary.ability_refs)
    ? [...adversary.ability_refs]
    : [];
  setAdversaryFormMode("edit", adversary);
  state.adversaryCompose.originalSignature = adversaryFormSignature();
  state.adversaryCompose.activeTab = "plan";
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  renderAdversaryAbilitySelector();
  setAdversaryTab("plan");
  dialog.showModal();
}

function closeAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  dialog.close();
  closeAdversaryAbilityPicker();
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
  await persistAdversaryAutosave();
  closeAdversaryDialog();
}

async function exportAdversaryFromDialog() {
  if (state.adversaryCompose.mode !== "edit" || !state.adversaryCompose.editingId) {
    return;
  }
  const target = document.getElementById("adversary-export-inline-target")?.value || "";
  if (!target) {
    showToast("common.no_data", true);
    return;
  }
  const response = await api(`/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/export${toQuery({ to: target })}`);
  state.adversaryCompose.exportPreviewByTarget[String(target).toLowerCase()] = (response.downloads || [])
    .map((item) => normalizedDownloadName(item))
    .filter((value) => Boolean(String(value || "").trim()));
  renderAdversaryExecutionCriteria();

  const operational = pickOperationalDownload(response.downloads, target);
  if (operational?.url) {
    triggerDownloadByUrl(operational.url, normalizedDownloadName(operational));
    showToast("toast.export_ready");
    return;
  }
  const first = (response.downloads || [])[0] || null;
  if (first?.url) {
    triggerDownloadByUrl(first.url, normalizedDownloadName(first));
    showToast("toast.export_ready");
  } else {
    showToast("common.no_data", true);
  }
}

function renderRuleLabPreview() {
  const editor = document.getElementById("rulelab-input");
  const overlay = document.getElementById("rulelab-highlight");
  const input = editor.value;
  overlay.innerHTML = `${highlightStix(input)}\n`;
  overlay.scrollTop = editor.scrollTop;
  overlay.scrollLeft = editor.scrollLeft;
  state.ruleLab.isDirty = true;
  state.ruleLab.syntaxOk = null;
  const statusNode = document.getElementById("rulelab-status");
  if (statusNode) {
    statusNode.textContent = t("rulelab.status.idle");
  }
  setRuleLabSaveEnabled(false);
  setRuleLabPatternStatus("empty", "");
  clearRuleLabCompatibilityView();
  renderRuleLabAutocomplete();
  scheduleRuleLabAnalysis();
}

function setRuleLabEditorState(mode) {
  const shell = document.getElementById("rulelab-editor-shell");
  shell.classList.remove("editor-valid", "editor-invalid", "editor-partial", "editor-neutral");
  shell.classList.add(mode);
}

function ruleLabDefaultTitle() {
  return `rule-${Math.random().toString(36).slice(2, 8)}`;
}

function setRuleLabSaveEnabled(enabled) {
  const button = document.getElementById("rulelab-save");
  if (!button) return;
  button.disabled = !enabled;
  if (enabled) {
    button.textContent = t("rulelab.save");
    button.classList.remove("btn-ghost");
    button.classList.add("btn-success");
  } else {
    button.classList.remove("btn-success");
    button.classList.add("btn-ghost");
  }
}

function setRuleLabPatternStatus(state_key, message) {
  const widget = document.getElementById("rulelab-pattern-status");
  const textNode = document.getElementById("rulelab-pattern-status-text");
  if (!widget || !textNode) return;
  widget.classList.remove("rulelab-pattern-status-empty", "rulelab-pattern-status-valid", "rulelab-pattern-status-error");
  if (state_key === "valid") {
    widget.classList.add("rulelab-pattern-status-valid");
    textNode.textContent = t("rulelab.pattern_status.valid");
  } else if (state_key === "error") {
    widget.classList.add("rulelab-pattern-status-error");
    textNode.textContent = message || t("rulelab.invalid_pattern");
  } else {
    widget.classList.add("rulelab-pattern-status-empty");
    textNode.textContent = t("rulelab.pattern_status.empty");
  }
}

function setRuleLabError(message) {
  if (!message) {
    setRuleLabPatternStatus("empty", "");
  } else {
    setRuleLabPatternStatus("error", message);
  }
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
    setRuleLabPatternStatus("valid", "");
    setRuleLabSaveEnabled(state.ruleLab.isDirty);
  } else {
    state.ruleLab.syntaxOk = false;
    statusNode.innerHTML = `${statusBadge(t("rulelab.syntax_error"), "error")} ${escapeHtml(response.syntax_error || "")}`;
    setRuleLabEditorState("editor-invalid");
    setRuleLabPatternStatus("error", response.syntax_error || t("rulelab.invalid_pattern"));
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
  scheduleRuleLabAutoSave();
}

async function saveRuleLab() {
  await persistRuleLab({ silent: false });
}

function scheduleRuleLabAutoSave() {
  clearTimeout(state.ruleLab.autoSaveTimer);
  state.ruleLab.autoSaveTimer = setTimeout(async () => {
    await persistRuleLab({ silent: true });
  }, 8000);
}

async function persistRuleLab({ silent = false } = {}) {
  if (state.ruleLab.autoSaving) return;
  if (state.ruleLab.syntaxOk !== true) {
    if (!silent) {
      showToast("rulelab.syntax_error", true);
    }
    return;
  }
  const payload = {
    rule: document.getElementById("rulelab-input").value,
    name: document.getElementById("rulelab-title").value,
    description: document.getElementById("rulelab-description").value,
    confidence: Number(document.getElementById("rulelab-confidence").value || 70),
    tlp: document.getElementById("rulelab-tlp").value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap").value || "PAP:GREEN",
    ttp: normalizeTtpValue(document.getElementById("rulelab-ttp")?.value || ""),
  };
  const signature = JSON.stringify(payload);
  if (signature === state.ruleLab.autoSaveLastSignature) {
    state.ruleLab.isDirty = false;
    setRuleLabSaveEnabled(false);
    return;
  }
  state.ruleLab.autoSaving = true;
  const saveButton = document.getElementById("rulelab-save");
  if (saveButton) {
    saveButton.disabled = true;
    saveButton.textContent = t("rulelab.saving");
    saveButton.classList.remove("btn-success");
    saveButton.classList.add("btn-ghost");
  }
  try {
    await api("/api/rules/save", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.ruleLab.autoSaveLastSignature = signature;
    state.ruleLab.isDirty = false;
    if (saveButton) {
      saveButton.textContent = t("rulelab.saved_ok");
      clearTimeout(state.ruleLab.savedIndicatorTimer);
      state.ruleLab.savedIndicatorTimer = setTimeout(() => {
        setRuleLabSaveEnabled(false);
      }, 2000);
    }
    if (!silent) {
      showToast("toast.saved");
    }
    await Promise.all([loadRules(state.rules.page || 1), loadOverview()]);
    renderDashboard();
  } finally {
    state.ruleLab.autoSaving = false;
  }
}

async function copyRuleLabPrompt(task = "") {
  const context = collectRuleLabPromptContext();
  const normalizedTask = normalizePromptTask(task, Boolean(context.rule), state.ruleLab.syntaxOk === true);
  const prompt = buildStixLlmPrompt(context, {
    task: normalizedTask,
    syntaxOk: state.ruleLab.syntaxOk === true,
  });
  await copyPromptToClipboard(prompt);
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
    ttp: normalizeTtpValue(document.getElementById("rules-new-ttp")?.value || ""),
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
  const confirmed = await askForConfirmation(
    t("rules.confirm_delete_selected"),
    t("common.confirm_action"),
  );
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
        ttp: normalizeTtpValue(entry.ttp || ""),
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

function learningPathSummaries() {
  const summaries = new Map();
  state.learning.challenges.forEach((entry) => {
    const pathId = String(entry.path_id || "core").trim() || "core";
    const summary = summaries.get(pathId) || { pathId, total: 0, completed: 0 };
    summary.total += 1;
    if (state.completedChallenges.has(entry.id)) summary.completed += 1;
    summaries.set(pathId, summary);
  });
  return [...summaries.values()].sort((a, b) => a.pathId.localeCompare(b.pathId));
}

function renderLearningPathSummary() {
  const root = document.getElementById("learning-paths-summary");
  if (!root) return;
  const summaries = learningPathSummaries();
  const allCompleted = state.learning.challenges.filter((entry) => state.completedChallenges.has(entry.id)).length;
  const allTotal = state.learning.challenges.length;
  const allActive = !state.learning.pathFilter;
  root.innerHTML = [
    { pathId: "", total: allTotal, completed: allCompleted },
    ...summaries,
  ]
    .map((summary) => {
      const percent = summary.total > 0 ? Math.round((summary.completed / summary.total) * 100) : 0;
      const active = summary.pathId ? state.learning.pathFilter === summary.pathId : allActive;
      const title = summary.pathId ? learningPathLabel(summary.pathId) : t("learning.paths.all");
      return `
        <button class="learning-path-chip glass ${active ? "active" : ""}" data-action="learning-path-filter" data-path="${escapeHtml(summary.pathId)}">
          <span class="learning-path-chip-title">${escapeHtml(title)}</span>
          <span class="learning-path-chip-count">${escapeHtml(t("learning.progress").replace("{done}", String(summary.completed)).replace("{total}", String(summary.total)))}</span>
          <span class="learning-path-chip-meter" aria-hidden="true"><span style="width: ${percent}%"></span></span>
        </button>
      `;
    })
    .join("");
}

function renderLearningChallenges() {
  const entries = filteredLearningChallenges();
  const grouped = new Map();
  entries.forEach((entry) => {
    const pathId = String(entry.path_id || "core").trim() || "core";
    if (!grouped.has(pathId)) grouped.set(pathId, []);
    grouped.get(pathId).push(entry);
  });

  document.getElementById("challenges-grid").innerHTML = entries
    .length === 0
    ? `<div class="empty-state muted">${escapeHtml(t("common.no_data"))}</div>`
    : [...grouped.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([pathId, pathEntries]) => `
        <section class="learning-path-section">
          <header class="learning-path-section-head">
            <h3>${escapeHtml(learningPathLabel(pathId))}</h3>
            <span class="muted">${pathEntries.length} ${escapeHtml(t("common.entries"))}</span>
          </header>
          <div class="learning-exercise-rows">
            ${pathEntries.map((entry) => {
              const completed = state.completedChallenges.has(entry.id);
              const selected = state.selectedChallenge?.id === entry.id;
              return `
                <article class="learning-exercise-row glass ${completed ? "completed-card" : ""} ${selected ? "active" : ""}">
                  <button class="learning-exercise-main" data-action="learning-select" data-id="${escapeHtml(entry.id)}">
                    <span class="learning-exercise-status ${completed ? "completed" : "pending"}" aria-hidden="true">${completed ? "✓" : ""}</span>
                    <span class="learning-exercise-copy">
                      <strong>${escapeHtml(entry.title)}</strong>
                      <span class="muted">${escapeHtml(entry.goal)}</span>
                    </span>
                  </button>
                  <button class="btn btn-primary" data-action="learning-select" data-id="${escapeHtml(entry.id)}">${escapeHtml(t(completed ? "common.view" : "learning.start"))}</button>
                </article>
              `;
            }).join("")}
          </div>
        </section>
      `)
    .join("");

  const completed = state.learning.challenges.filter((entry) => state.completedChallenges.has(entry.id)).length;
  document.getElementById("learning-progress").textContent = t("learning.progress").replace("{done}", String(completed)).replace("{total}", String(state.learning.challenges.length));
  renderLearningPathSummary();
}

async function loadLearning() {
  const challenges = await api("/api/tutorial/challenges");
  state.learning.guides = [];
  state.learning.challenges = (challenges || []).map((entry) => localizeLearningChallenge(entry));
  document.getElementById("learning-search").value = state.learning.search;
  renderLearningPathOptions();
  document.getElementById("learning-only-pending").checked = state.learning.onlyPending;
  renderLearningGuides();
  renderLearningPathSummary();
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
  await loadAdminRuntimeSettings();
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

async function loadAdminRuntimeSettings() {
  const form = document.getElementById("admin-runtime-settings");
  if (!(form instanceof HTMLFormElement)) return;
  if (state.principal?.role !== "admin") {
    form.classList.add("hidden");
    return;
  }

  const response = await api("/api/admin/settings");
  const entry = response?.entry || {};
  const sigmaUrl = document.getElementById("admin-sigma-rpc-url");
  const sigmaToken = document.getElementById("admin-sigma-rpc-token");
  const noLogin = document.getElementById("admin-no-login");
  const tokenHint = document.getElementById("admin-sigma-rpc-token-hint");

  if (sigmaUrl instanceof HTMLInputElement) {
    sigmaUrl.value = entry.sigma_rpc_url || "";
  }
  if (sigmaToken instanceof HTMLInputElement) {
    sigmaToken.value = "";
  }
  if (noLogin instanceof HTMLInputElement) {
    noLogin.checked = Boolean(entry.no_login);
  }
  if (tokenHint) {
    tokenHint.textContent = entry.sigma_rpc_token_set
      ? t("admin.settings.sigma_token_set")
      : t("admin.settings.sigma_token_unset");
  }
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
  await openRuleDetail(entry, { tab: "detection", target });
}

async function showRuleEmulationDetail(ruleId, target, abilityId) {
  const entry = state.rules.entries.find((item) => item.id === ruleId);
  if (!entry) return;
  await openRuleDetail(entry, { tab: "emulation", target, abilityId });
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
  const ruleLabTitleInput = document.getElementById("rulelab-title");
  if (ruleLabTitleInput instanceof HTMLInputElement && !ruleLabTitleInput.value) {
    ruleLabTitleInput.value = ruleLabDefaultTitle();
  }
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
  updateRulesViewModeUI();
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
  const adversaryTargetPlatform = document.getElementById("adversary-target-platform");
  if (adversaryTargetPlatform instanceof HTMLSelectElement) {
    adversaryTargetPlatform.addEventListener("change", () => {
      renderAdversaryAbilitySelector();
      setAdversaryFormSubmitState();
      scheduleAdversaryAutoSave();
    });
  }
  const adversaryExportInlineButton = document.getElementById("adversary-export-inline-button");
  if (adversaryExportInlineButton) {
    adversaryExportInlineButton.addEventListener("click", async () => {
      await exportAdversaryFromDialog();
    });
  }
  const adversaryExportInlineTarget = document.getElementById("adversary-export-inline-target");
  if (adversaryExportInlineTarget instanceof HTMLSelectElement) {
    adversaryExportInlineTarget.addEventListener("change", () => {
      renderAdversaryExecutionCriteria();
      const target = selectedAdversaryExportTarget();
      if (target && state.adversaryCompose.activeTab === "criteria") {
        void ensureAdversaryExportPreview(target);
      }
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
      scheduleAdversaryAutoSave();
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
  ["rulelab-title", "rulelab-description", "rulelab-confidence", "rulelab-ttp"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener("input", () => {
      scheduleRuleLabAnalysis();
      scheduleRuleLabAutoSave();
    });
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

  const runtimeSettingsForm = document.getElementById("admin-runtime-settings");
  if (runtimeSettingsForm) {
    runtimeSettingsForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const sigmaUrl = document.getElementById("admin-sigma-rpc-url")?.value || "";
      const sigmaToken = document.getElementById("admin-sigma-rpc-token")?.value || "";
      const noLogin = Boolean(document.getElementById("admin-no-login")?.checked);
      await api("/api/admin/settings", {
        method: "POST",
        body: JSON.stringify({
          sigma_rpc_url: sigmaUrl,
          sigma_rpc_token: sigmaToken,
          no_login: noLogin,
        }),
      });
      showToast("toast.saved");
      await bootstrap();
    });
  }

  document.getElementById("detail-close").addEventListener("click", () => {
    document.getElementById("detail-dialog").close();
  });
  document.getElementById("indicates-cancel").addEventListener("click", () => {
    document.getElementById("indicates-dialog").close();
  });
  document.getElementById("stix-object-cancel").addEventListener("click", () => {
    document.getElementById("stix-object-dialog").close();
    state.route = "adversaries-catalog";
    localStorage.setItem("spuc-web-last-route", "adversaries-catalog");
    applyNavSelection("adversaries-catalog");
    refreshRouteMeta();
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

  document.getElementById("stix-object-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const stixId = document.getElementById("stix-object-id").value.trim();
    const objectName = document.getElementById("stix-object-name").value.trim();
    if (!stixId || !objectName) {
      showToast("rules.indicates.invalid_payload", true);
      return;
    }
    await api("/api/stix-objects", {
      method: "POST",
      body: JSON.stringify({
        stix_id: stixId,
        name: objectName,
      }),
    });
    document.getElementById("stix-object-dialog").close();
    showToast("toast.saved");
    await loadStixObjects();
  });

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (!target.closest(".column-picker")) {
      closeColumnMenus();
    }
  });

  document.body.addEventListener("click", async (event) => {
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
      try {
        await openRuleDetail(entry);
      } catch (error) {
        showToast(error.payload?.error || error.message || "toast.unexpected", true);
      }
    }
  });

  document.body.addEventListener("click", async (event) => {
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
        await exportSelectedRules("csv");
      } else if (action === "rules-export-selected-csv") {
        await exportSelectedRules("csv");
      } else if (action === "rules-export-selected-stix") {
        await exportSelectedRules("stix-bundle");
      } else if (action === "rules-duplicate-selected") {
        await duplicateSelectedRules();
      } else if (action === "rules-export-selected-download") {
        if (!state.rules.lastExportSelectedCsv) return;
        const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
        downloadTextFile(state.rules.lastExportSelectedCsv, `spuc-rules-selected-${ts}.csv`, "text/csv;charset=utf-8");
        showToast("toast.export_ready");
      } else if (action === "rules-sort-column") {
        toggleRulesSortColumn(target.dataset.column);
      } else if (action === "rules-view-mode") {
        setRulesViewMode(target.dataset.mode || "table");
      } else if (action === "adversaries-sort-column") {
        await toggleAdversariesSortColumn(target.dataset.column);
      } else if (action === "adversaries-view-mode") {
        setAdversariesViewMode(target.dataset.mode || "table");
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
      } else if (action === "adversary-show") {
        await openAdversaryEditor(target.dataset.id || "");
      } else if (action === "rule-show") {
        const entry = state.rules.entries.find((rule) => rule.id === target.dataset.id);
        if (entry) await openRuleDetail(entry);
      } else if (action === "rule-copy") {
        const entry = state.rules.entries.find((rule) => rule.id === target.dataset.id);
        if (entry) {
          await navigator.clipboard.writeText(entry.rule);
          showToast("toast.copied");
        }
      } else if (action === "rule-copy-llm-prompt") {
        const entry = state.rules.entries.find((rule) => rule.id === target.dataset.id);
        if (!entry) return;
        const prompt = buildStixLlmPrompt(entry, {
          task: normalizePromptTask(target.dataset.task || "", Boolean(entry.rule), true),
        });
        await copyPromptToClipboard(prompt);
      } else if (action === "rule-target-detail") {
        await showRuleTargetDetail(target.dataset.rule, target.dataset.target);
      } else if (action === "rule-emulation-detail") {
        await showRuleEmulationDetail(target.dataset.rule, target.dataset.target, target.dataset.ability);
      } else if (action === "rule-detail-tab") {
        setRuleDetailTab(target.dataset.tab || "detection");
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
        const operational = pickOperationalDownload(response.downloads, target.dataset.target || "");
        if (operational?.url) {
          triggerDownloadByUrl(operational.url, normalizedDownloadName(operational));
          showToast("toast.export_ready");
        } else {
          const first = (response.downloads || [])[0] || null;
          if (first?.url) {
            triggerDownloadByUrl(first.url, normalizedDownloadName(first));
            showToast("toast.export_ready");
          } else {
            showToast("common.no_data", true);
          }
        }
      } else if (action === "adversary-select-ability") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        if (!state.adversaryCompose.selectedOrder.includes(abilityId)) {
          state.adversaryCompose.selectedOrder.push(abilityId);
        }
        renderAdversaryAbilitySelector();
        scheduleAdversaryAutoSave();
      } else if (action === "adversary-remove-ability") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => id !== abilityId);
        renderAdversaryAbilitySelector();
        scheduleAdversaryAutoSave();
      } else if (action === "adversary-move-up") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, -1);
        renderAdversaryAbilitySelector();
        scheduleAdversaryAutoSave();
      } else if (action === "adversary-move-down") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, 1);
        renderAdversaryAbilitySelector();
        scheduleAdversaryAutoSave();
      } else if (action === "adversary-open-ability-picker") {
        openAdversaryAbilityPicker();
      } else if (action === "adversary-close-ability-picker") {
        closeAdversaryAbilityPicker();
      } else if (action === "adversary-tab") {
        setAdversaryTab(target.dataset.tab || "plan");
      } else if (action === "adversary-picker-tab") {
        setAdversaryPickerTab(target.dataset.tab || "catalog");
      } else if (action === "adversary-refresh-execution-help") {
        await ensureAdversaryExportPreview(target.dataset.target || selectedAdversaryExportTarget(), true);
      } else if (action === "adversary-add-dummy-sleep") {
        const secondsRaw = document.getElementById("adversary-dummy-sleep")?.value || "5";
        const seconds = Number(secondsRaw);
        if (!Number.isFinite(seconds) || seconds <= 0) {
          showToast("toast.unexpected", true);
          return;
        }
        await createDummyAbility({
          kind: "sleep",
          seconds: Math.round(seconds),
          platform: document.getElementById("adversary-ability-platform")?.value || "",
        });
      } else if (action === "adversary-add-dummy-label") {
        const label = String(document.getElementById("adversary-dummy-label")?.value || "").trim();
        if (!label) {
          showToast("toast.unexpected", true);
          return;
        }
        await createDummyAbility({
          kind: "label",
          label,
          platform: document.getElementById("adversary-ability-platform")?.value || "",
        });
      } else if (action === "adversaries-duplicate-selected") {
        await duplicateSelectedAdversaries();
      } else if (action === "rule-copy-emulation") {
        await copyRuleEmulation(target.dataset.id, target.dataset.ability);
      } else if (action === "detail-export-detection") {
        exportDetectionOutputFromDetail();
      } else if (action === "detail-cancel") {
        document.getElementById("detail-dialog").close();
      } else if (action === "rulelab-copy-llm-prompt") {
        await copyRuleLabPrompt(target.dataset.task || "");
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
      } else if (action === "detail-show-json") {
        setDetailTab("json");
      } else if (action === "rule-open-in-lab") {
        const ruleId = target.dataset.id || "";
        const entry = state.rules.entries.find((item) => item.id === ruleId)
          || state.rules.allEntries.find((item) => item.id === ruleId)
          || state.ruleDetail.entry;
        if (!entry) return;
        document.getElementById("detail-dialog").close();
        openRuleInLab(entry);
      } else if (action === "rule-detail-export") {
        const family = target.dataset.family || state.ruleDetail.activeTab || "overview";
        if (family === "detection") {
          const select = document.getElementById("rule-detail-export-detection-target");
          if (!(select instanceof HTMLSelectElement) || !select.value) {
            showToast("detail.no_output_for_target", true);
            return;
          }
          const row = (state.ruleDetail.detectionRows || [])
            .find((item) => String(item.target || "").toLowerCase() === String(select.value || "").toLowerCase());
          if (!row || !String(row.output || "").trim()) {
            showToast("detail.no_output_for_target", true);
            return;
          }
          state.detailDetectionExport = {
            title: state.ruleDetail.entry?.name || "rule",
            target: String(row.target || "").toLowerCase(),
            output: row.output || "",
          };
          exportDetectionOutputFromDetail();
        } else if (family === "emulation") {
          const select = document.getElementById("rule-detail-export-emulation-target");
          const entry = state.ruleDetail.entry;
          if (!(select instanceof HTMLSelectElement) || !select.value || !entry?.ability_id) {
            showToast("detail.copy_emulation_not_available", true);
            return;
          }
          await downloadAbility(entry.ability_id, String(select.value || "").toLowerCase());
          showToast("toast.export_ready");
        }
      } else if (action === "rule-tech-guide-toggle") {
        event.preventDefault();
        event.stopPropagation();
        const targetId = target.dataset.targetId || "";
        const panel = targetId ? document.getElementById(targetId) : null;
        if (panel) {
          const hidden = panel.classList.toggle("hidden");
          target.setAttribute("aria-expanded", String(!hidden));
        }
      } else if (action === "detail-copy") {
        event.preventDefault();
        event.stopPropagation();
        const encoded = target.dataset.copy || "";
        await navigator.clipboard.writeText(decodeURIComponent(encoded));
        showToast("toast.copied");
      } else if (action === "autocomplete-pick") {
        applyRuleLabAutocomplete(Number(target.dataset.index || "0"));
      } else if (action === "learning-autocomplete-pick") {
        applyLearningAutocomplete(Number(target.dataset.index || "0"));
      } else if (action === "learning-select") {
        mountLearningPractice(target.dataset.id);
      } else if (action === "learning-path-filter") {
        state.learning.pathFilter = target.dataset.path || "";
        const select = document.getElementById("learning-path");
        if (select instanceof HTMLSelectElement) select.value = state.learning.pathFilter;
        renderLearningChallenges();
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
      } else if (action === "stix-create-open") {
        document.getElementById("stix-object-id").value = "";
        document.getElementById("stix-object-name").value = "";
        document.getElementById("stix-object-dialog").showModal();
      } else if (action === "stix-object-cancel") {
        document.getElementById("stix-object-dialog").close();
      } else if (action === "stix-select-all-toggle") {
        const filtered = state.stixObjects.filter((entry) => {
          const searchLower = (state.stixObjectsView.searchTerm || "").toLowerCase();
          return !searchLower || entry.stix_id.toLowerCase().includes(searchLower) || entry.name.toLowerCase().includes(searchLower);
        });
        const shouldSelect = !filtered.length || filtered.some((entry) => !state.stixObjectsView.selected.has(entry.stix_id));
        filtered.forEach((entry) => {
          if (shouldSelect) state.stixObjectsView.selected.add(entry.stix_id);
          else state.stixObjectsView.selected.delete(entry.stix_id);
        });
        renderStixObjectsTable();
      } else if (action === "stix-bulk-toggle") {
        if (state.stixObjectsView.selected.size === 0) return;
        state.stixObjectsView.bulkEditOpen = !state.stixObjectsView.bulkEditOpen;
        updateStixObjectsBulkState();
      } else if (action === "stix-bulk-cancel") {
        state.stixObjectsView.bulkEditOpen = false;
        state.stixObjectsView.selected.clear();
        updateStixObjectsBulkState();
        renderStixObjectsTable();
      } else if (action === "stix-bulk-clear") {
        state.stixObjectsView.selected.clear();
        updateStixObjectsBulkState();
      } else if (action === "stix-columns-toggle") {
        toggleMenu("stix-columns-menu", "stix-columns-toggle");
      } else if (action === "stix-export-selected") {
        if (state.stixObjectsView.selected.size === 0) return;
        const selected = state.stixObjects.filter((entry) => state.stixObjectsView.selected.has(entry.stix_id));
        const rows = selected.map((entry) => [entry.stix_id, entry.name].join(",")).join("\n");
        const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
        downloadTextFile(rows, `spuc-stix-objects-selected-${ts}.csv`, "text/csv;charset=utf-8");
        showToast("toast.export_ready");
      } else if (action === "stix-delete-selected") {
        if (state.stixObjectsView.selected.size === 0) return;
        const confirmDelete = confirm(t("rules.bulk.delete_confirm"));
        if (!confirmDelete) return;
        await Promise.all(
          Array.from(state.stixObjectsView.selected).map((stixId) =>
            api(`/api/stix-objects/${encodeURIComponent(stixId)}`, { method: "DELETE", body: "{}" })
          )
        );
        showToast("toast.saved");
        state.stixObjectsView.selected.clear();
        await loadStixObjects();
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
      if (column === "markings") {
        if (checked) {
          state.rules.visibleColumns.add("tlp");
          state.rules.visibleColumns.add("pap");
        } else {
          state.rules.visibleColumns.delete("tlp");
          state.rules.visibleColumns.delete("pap");
          if (state.rules.visibleColumns.size === 0) {
            state.rules.visibleColumns.add("name");
          }
        }
        renderRulesTable();
        return;
      }
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
      if (column === "markings") {
        if (checked) {
          state.adversaries.visibleColumns.add("tlp");
          state.adversaries.visibleColumns.add("pap");
        } else {
          state.adversaries.visibleColumns.delete("tlp");
          state.adversaries.visibleColumns.delete("pap");
          if (state.adversaries.visibleColumns.size === 0) {
            state.adversaries.visibleColumns.add("name");
          }
        }
        renderAdversariesTable();
        return;
      }
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
        const checkboxes = [...document.querySelectorAll('input[data-action="rule-select"]')];
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
        const checkboxes = [...document.querySelectorAll('input[data-action="adversary-select"]')];
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
