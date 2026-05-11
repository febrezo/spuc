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

function detectAppMode() {
  return new URLSearchParams(window.location.search).get("spuc-mode") === "gui" ? "gui" : "browser";
}

const state = {
  locale: detectInitialLocale(),
  appMode: detectAppMode(),
  theme: localStorage.getItem("spuc-web-theme") || "dark",
  translations: {},
  bootstrap: null,
  principal: null,
  userSettings: null,
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
    visibleColumns: new Set(["name", "confidence", "tlp", "pap", "rule", "outputs", "emulation"]),
    bulkEditOpen: false,
    lastExportSelectedCsv: "",
    advancedFilters: [],
    workspaceMode: "explore",
    viewMode: localStorage.getItem("spuc-web-rules-view-mode") || "cards",
    filtersOpen: false,
    loaded: false,
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
    searchTerm: "",
    selected: new Set(),
    bulkEditOpen: false,
    expandedDetails: new Set(),
    editingId: "",
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
    workspaceMode: "catalog",
    sort: "confidence_desc",
    visibleColumns: new Set(["name", "confidence", "tlp", "pap", "steps", "platforms", "exporters"]),
    viewMode: localStorage.getItem("spuc-web-adversaries-view-mode") || "cards",
    loaded: false,
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
    editorMounted: false,
    originalEntry: null,
    // New tabbed editor properties
    editorMode: "panel", // "modal" or "panel"
    editorActiveTab: "overview", // "overview" | "flow" | "export" | "json"
    customPayloads: [], // Array of custom payload definitions
    payloadFormOpen: false,
    selectedPayloadFilter: "all", // "all" | "bash" | "powershell" | "python" | "javascript" | "rubber_ducky"
    editorSelectedStepId: null,
    editorLastSavedSignature: "",
  },
  adversaryView: {
    activeId: null,
    activeTab: "summary",
    entry: null,
  },
  customPayloads: {
    entries: [],
    loaded: false,
    editingId: "",
    selected: new Set(),
    filtersOpen: false,
  },
  learning: { guides: [], challenges: [], search: "", pathFilter: "", onlyPending: false },
  settings: {
    activeTab: "personal",
    usersFilters: {
      open: false,
      search: "",
      role: "all",
      status: "all",
    },
  },
  adminUsers: [],
  adminRuntimeSettings: null,
  adminOauthProviders: [],
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
    indicatesList: [],
    editingRuleId: "",
    editingRuleName: "",
  },
  mitreAttack: [],
  indicatesMode: "catalog", // "catalog" | "lab"
  returnToIndicatesDialog: false,
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
  about: {
    donationMethod: "monero",
  },
};

const PROJECT_LINKS = {
  repository: "https://github.com/febrezo/spuc",
  license: "https://github.com/febrezo/spuc/blob/main/LICENSE.md",
  releases: "https://github.com/febrezo/spuc/releases",
  documentation: "https://github.com/febrezo/spuc#readme",
  sponsors: "https://github.com/sponsors/febrezo",
  sponsorsLogo: "/assets/logo-github.png",
};

const PAYLOAD_TYPE_TO_RUNNERS = {
  bash: ["bash", "spuc-agent"],
  powershell: ["powershell", "spuc-agent"],
  python: ["bash", "spuc-agent"],
  javascript: ["spuc-agent"],
  rubber_ducky: ["spuc-agent"],
};

const DONATION_OPTIONS = [
  {
    id: "monero",
    labelKey: "about.donate.monero",
    ticker: "XMR",
    address: "441focuYuGZ3wbF3d7M1QMYAdX1Mvpv3j1Zyg1mjPAJKDJ29q6DGR6mZ7mpuwNiJscUX8oc8pazZQMGRAbnw1iw35kYYViN",
    qr: "/assets/donate-monero.png",
    logo: "/assets/logo-monero.png",
  },
  {
    id: "bitcoin",
    labelKey: "about.donate.bitcoin",
    ticker: "BTC",
    address: "bc1qwrzus8wkvvsdqeuxzl8wca9ecj0v6z8jwx8qzl",
    qr: "/assets/donate-bitcoin.png",
    logo: "/assets/logo-bitcoin.png",
  },
  {
    id: "github-sponsors",
    labelKey: "about.sponsors.title",
    ticker: "GH",
    address: "",
    qr: "",
    logo: "/assets/logo-github.png",
    externalUrl: PROJECT_LINKS.sponsors,
  },
];

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
const ADVERSARY_EXPORTERS = ["spuc-agent", "bash", "powershell", "atomic-red-team", "mitre-caldera"];
const RULE_COLUMN_KEYS = ["name", "confidence", "tlp", "pap", "rule", "outputs", "emulation"];
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
  "adversaries-payloads": { title: "route.payloads.title", subtitle: "route.payloads.subtitle" },
  "stix-objects": { title: "route.stix_objects.title", subtitle: "route.stix_objects.subtitle" },
  "stix-objects-catalog": { title: "route.stix_objects.title", subtitle: "route.stix_objects.subtitle" },
  learning: { title: "route.learning.title", subtitle: "route.learning.subtitle" },
  settings: { title: "route.settings.title", subtitle: "route.settings.subtitle" },
};

const LEARNING_PROGRESS_STORAGE_KEY = "spuc-web-learning-progress";
const CUSTOM_PAYLOADS_STORAGE_KEY = "spuc-web-custom-payloads";

function normalizeCustomPayloadEntry(entry = {}) {
  const id = String(entry.id || `payload-${Date.now()}`);
  const technology = String(entry.technology || "bash").toLowerCase();
  const runner = String((entry.compatibleRunners || [])[0] || "spuc-agent").toLowerCase();
  return {
    id,
    name: String(entry.name || "").trim(),
    technology,
    compatibleRunners: [runner],
    description: String(entry.description || "").trim(),
    content: String(entry.content || ""),
    createdAt: String(entry.createdAt || new Date().toISOString()),
    updatedAt: String(entry.updatedAt || entry.createdAt || new Date().toISOString()),
  };
}

function persistCustomPayloadCatalog() {
  try {
    localStorage.setItem(CUSTOM_PAYLOADS_STORAGE_KEY, JSON.stringify(state.customPayloads.entries || []));
  } catch (_error) {
    // Keep UX resilient if localStorage is unavailable.
  }
}

function loadCustomPayloadCatalog() {
  try {
    const raw = localStorage.getItem(CUSTOM_PAYLOADS_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    const entries = Array.isArray(parsed)
      ? parsed.map((entry) => normalizeCustomPayloadEntry(entry)).filter((entry) => entry.name && entry.content)
      : [];
    state.customPayloads.entries = entries;
    state.customPayloads.loaded = true;
    state.customPayloads.editingId = "";
    state.customPayloads.selected = new Set();
    state.adversaryCompose.customPayloads = [...entries];
  } catch (_error) {
    state.customPayloads.entries = [];
    state.customPayloads.loaded = true;
    state.customPayloads.editingId = "";
    state.customPayloads.selected = new Set();
    state.adversaryCompose.customPayloads = [];
  }
}

function loadLearningProgress() {
  try {
    const raw = localStorage.getItem(LEARNING_PROGRESS_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    const completed = Array.isArray(parsed?.completed) ? parsed.completed : [];
    state.completedChallenges = new Set(completed.map((item) => String(item || "")).filter(Boolean));
    state.learning.search = typeof parsed?.search === "string" ? parsed.search : "";
    state.learning.pathFilter = typeof parsed?.pathFilter === "string" ? parsed.pathFilter : "";
    state.learning.onlyPending = Boolean(parsed?.onlyPending);
  } catch (_error) {
    state.completedChallenges = new Set();
    state.learning.search = "";
    state.learning.pathFilter = "";
    state.learning.onlyPending = false;
  }
}

function saveLearningProgress() {
  const payload = {
    completed: [...state.completedChallenges],
    search: state.learning.search,
    pathFilter: state.learning.pathFilter,
    onlyPending: state.learning.onlyPending,
  };
  localStorage.setItem(LEARNING_PROGRESS_STORAGE_KEY, JSON.stringify(payload));
}

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

function setLocale(locale) {
  state.locale = locale === "es" ? "es" : "en";
  localStorage.setItem("spuc-web-locale", state.locale);
  document.documentElement.lang = state.locale;
}

function isCustomComboboxCandidate(select) {
  if (!(select instanceof HTMLSelectElement)) return false;
  if (select.multiple) return false;
  const size = Number(select.getAttribute("size") || "1");
  if (Number.isFinite(size) && size > 1) return false;
  return select.dataset.nativeSelect !== "true";
}

function comboboxClassName(token) {
  return `combobox-${String(token || "").replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

function closeAllCustomComboboxes(except = null) {
  document.querySelectorAll(".spuc-combobox.open").forEach((node) => {
    if (except && node === except) return;
    node.classList.remove("open");
    node.querySelector(".spuc-combobox-trigger")?.setAttribute("aria-expanded", "false");
  });
}

function syncCustomComboboxClasses(select, wrapper) {
  [...wrapper.classList].forEach((className) => {
    if (className.startsWith("combobox-")) wrapper.classList.remove(className);
  });
  select.classList.forEach((className) => {
    wrapper.classList.add(comboboxClassName(className));
  });
}

function buildCustomComboboxOptions(select, menu, triggerLabel) {
  const items = [];
  [...select.children].forEach((node) => {
    if (node instanceof HTMLOptGroupElement) {
      const label = String(node.label || "").trim();
      if (label) {
        items.push(`<div class="spuc-combobox-group">${escapeHtml(label)}</div>`);
      }
      [...node.children].forEach((child) => {
        if (!(child instanceof HTMLOptionElement)) return;
        const value = String(child.value || "");
        const text = child.textContent || value;
        const selected = child.selected;
        items.push(`
          <button
            type="button"
            class="spuc-combobox-option${selected ? " is-selected" : ""}"
            data-combobox-option="${escapeHtml(value)}"
            ${child.disabled ? "disabled" : ""}
        >${escapeHtml(text)}</button>
        `);
        if (selected) triggerLabel.textContent = text;
      });
      return;
    }
    if (!(node instanceof HTMLOptionElement)) return;
    const value = String(node.value || "");
    const text = node.textContent || value;
    const selected = node.selected;
    items.push(`
      <button
        type="button"
        class="spuc-combobox-option${selected ? " is-selected" : ""}"
        data-combobox-option="${escapeHtml(value)}"
        ${node.disabled ? "disabled" : ""}
      >${escapeHtml(text)}</button>
    `);
    if (selected) triggerLabel.textContent = text;
  });
  const selectedOption = select.selectedOptions?.[0];
  if (selectedOption) {
    triggerLabel.textContent = selectedOption.textContent || triggerLabel.textContent;
  }
  menu.innerHTML = items.join("");
}

function syncCustomCombobox(select) {
  if (!isCustomComboboxCandidate(select)) return;
  if (!select.id) {
    select.id = `spuc-select-${Math.random().toString(36).slice(2, 9)}`;
  }
  let wrapper = select.closest(".spuc-combobox");
  if (!(wrapper instanceof HTMLDivElement)) {
    wrapper = document.createElement("div");
    wrapper.className = "spuc-combobox";
    select.parentNode?.insertBefore(wrapper, select);
    wrapper.appendChild(select);

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "spuc-combobox-trigger";
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    trigger.innerHTML = `
      <span class="spuc-combobox-trigger-label"></span>
      <span class="spuc-combobox-chevron" aria-hidden="true"></span>
    `;
    wrapper.appendChild(trigger);

    const menu = document.createElement("div");
    menu.className = "spuc-combobox-menu";
    menu.setAttribute("role", "listbox");
    wrapper.appendChild(menu);

    select.classList.add("spuc-combobox-native");

    trigger.addEventListener("click", () => {
      if (select.disabled) return;
      const isOpen = wrapper.classList.contains("open");
      closeAllCustomComboboxes(wrapper);
      wrapper.classList.toggle("open", !isOpen);
      trigger.setAttribute("aria-expanded", String(!isOpen));
    });

    trigger.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        if (!wrapper.classList.contains("open")) {
          closeAllCustomComboboxes(wrapper);
          wrapper.classList.add("open");
          trigger.setAttribute("aria-expanded", "true");
        }
        menu.querySelector(".spuc-combobox-option:not(:disabled)")?.focus();
      } else if (event.key === "Escape") {
        closeAllCustomComboboxes();
      }
    });

    menu.addEventListener("click", (event) => {
      const option = event.target.closest("[data-combobox-option]");
      if (!(option instanceof HTMLButtonElement) || option.disabled) return;
      const value = option.dataset.comboboxOption ?? "";
      select.value = value;
      select.dispatchEvent(new Event("input", { bubbles: true }));
      select.dispatchEvent(new Event("change", { bubbles: true }));
      syncCustomCombobox(select);
      closeAllCustomComboboxes();
      trigger.focus();
    });
  }

  syncCustomComboboxClasses(select, wrapper);
  wrapper.classList.toggle("is-disabled", Boolean(select.disabled));
  wrapper.classList.toggle("is-empty", !String(select.value || "").trim());

  const trigger = wrapper.querySelector(".spuc-combobox-trigger");
  const triggerLabel = wrapper.querySelector(".spuc-combobox-trigger-label");
  const menu = wrapper.querySelector(".spuc-combobox-menu");
  if (!(trigger instanceof HTMLButtonElement) || !(triggerLabel instanceof HTMLSpanElement) || !(menu instanceof HTMLDivElement)) {
    return;
  }
  trigger.disabled = Boolean(select.disabled);
  buildCustomComboboxOptions(select, menu, triggerLabel);
}

function refreshCustomComboboxes(root = document) {
  root.querySelectorAll?.("select").forEach((select) => {
    if (!(select instanceof HTMLSelectElement)) return;
    if (!isCustomComboboxCandidate(select)) return;
    syncCustomCombobox(select);
  });
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
    ["stix-create-open-table", "stix_objects.create"],
    ["stix-export-selected", "rules.bulk.export_selected"],
    ["stix-delete-selected", "rules.bulk.delete_selected"],
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
  refreshCustomComboboxes(document);
  refreshRouteMeta();
}

function refreshRouteMeta() {
  const meta = ROUTE_META[state.route] || ROUTE_META.dashboard;
  const route = state.route || "home";
  const titleRoute = route === "adversaries-payloads" ? "adversaries-payloads" : "";
  const rootRoute = route.startsWith("rules-")
    ? "rules"
    : route.startsWith("adversaries-")
      ? "adversaries"
      : route.startsWith("stix-objects")
        ? "stix-objects"
      : route;
  const navItem = document.querySelector(`.nav-item[data-route="${titleRoute || rootRoute}"]`)
    || document.querySelector(`.nav-item[data-route="${rootRoute}"]`);
  const routeTitleIcon = document.getElementById("route-title-icon");
  const routeTitleText = document.getElementById("route-title-text");
  if (routeTitleIcon && navItem) {
    const iconNode = navItem.querySelector(".nav-icon");
    routeTitleIcon.innerHTML = iconNode ? iconNode.innerHTML : "";
  }
  if (routeTitleText) {
    const navLabel = navItem?.querySelector("span[data-i18n], span:not(.nav-icon)")?.textContent?.trim();
    routeTitleText.textContent = navLabel || t(meta.title);
  }
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

function askForConfirmation(message, title = "", options = {}) {
  const dialog = document.getElementById("confirm-dialog");
  const titleNode = document.getElementById("confirm-title");
  const messageNode = document.getElementById("confirm-message");
  const acceptButton = document.getElementById("confirm-accept");
  const cancelButton = document.getElementById("confirm-cancel");
  if (!(dialog instanceof HTMLDialogElement) || !titleNode || !messageNode || !acceptButton || !cancelButton) {
    return Promise.resolve(false);
  }

  const resolvedTitle = String(title || "").trim() || t("common.confirm_action");
  titleNode.textContent = resolvedTitle;
  messageNode.textContent = message;
  acceptButton.textContent = options.acceptLabel || t("common.confirm");
  cancelButton.textContent = options.cancelLabel || t("common.cancel");

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
  return rightHtml ? `<div class="detail-actions-right">${rightHtml}</div>` : "";
}

function aboutProjectLinks() {
  const app = state.bootstrap?.app || {};
  return {
    repository: app.project_url || PROJECT_LINKS.repository,
    license: app.license_url || PROJECT_LINKS.license,
    releases: PROJECT_LINKS.releases,
    documentation: app.documentation_url || PROJECT_LINKS.documentation,
    sponsors: PROJECT_LINKS.sponsors,
    sponsorsLogo: PROJECT_LINKS.sponsorsLogo,
  };
}

function selectedDonationOption() {
  return DONATION_OPTIONS.find((option) => option.id === state.about.donationMethod) || DONATION_OPTIONS[0];
}

function renderAboutDialog(section = "") {
  const root = document.getElementById("about-view");
  if (!root) return;
  const app = state.bootstrap?.app || {};
  const links = aboutProjectLinks();
  const donation = selectedDonationOption();
  const version = app.version ? tf("about.version", { version: app.version }) : t("about.version_unknown");
  const donationTabs = DONATION_OPTIONS.map((option) => `
    <button
      type="button"
      class="about-donation-tab ${option.id === donation.id ? "active" : ""}"
      data-action="about-donation-method"
      data-method="${escapeHtml(option.id)}"
      aria-pressed="${option.id === donation.id ? "true" : "false"}"
    >
      <img class="about-donation-tab-logo" src="${escapeHtml(option.logo || "")}" alt="${escapeHtml(tf("about.donate.logo_alt", { method: t(option.labelKey) }))}">
      <span>${escapeHtml(t(option.labelKey))}</span>
      <small>${escapeHtml(option.ticker)}</small>
    </button>
  `).join("");
  const isSponsors = donation.id === "github-sponsors";
  const addressBlock = isSponsors
    ? `
      <div class="about-donation-empty about-sponsors-card">
        <strong>${escapeHtml(t("about.sponsors.title"))}</strong>
        <a class="btn btn-primary about-github-sponsors-link" href="${escapeHtml(links.sponsors)}" target="_blank" rel="noreferrer">
          <img class="about-github-sponsors-logo" src="${escapeHtml(links.sponsorsLogo || "")}" alt="GitHub">
          <span>${escapeHtml(t("about.open_project"))}</span>
        </a>
      </div>
    `
    : donation.address
    ? `
      <input
        class="about-donation-address"
        type="text"
        value="${escapeHtml(donation.address)}"
        readonly
        spellcheck="false"
        aria-label="${escapeHtml(t("about.donate.copy"))}"
      >
      <button type="button" class="btn btn-primary about-donation-action" data-action="about-copy-donation" data-method="${escapeHtml(donation.id)}">${escapeHtml(t("about.donate.copy"))}</button>
    `
    : `
      <div class="about-donation-empty">
        <strong>${escapeHtml(t("about.donate.empty"))}</strong>
        <span>${escapeHtml(t("about.donate.empty_hint"))}</span>
      </div>
    `;
  const qrBlock = isSponsors
    ? `<div class="about-donation-qr-empty">${escapeHtml(t("about.sponsors.title"))}</div>`
    : donation.qr
    ? `<img class="about-donation-qr-img" src="${escapeHtml(donation.qr)}" alt="${escapeHtml(tf("about.donate.qr_alt", { method: t(donation.labelKey) }))}">`
    : `<div class="about-donation-qr-empty">${escapeHtml(t("about.donate.qr_placeholder"))}</div>`;

  root.innerHTML = `
    <section class="about-hero-panel">
      <div>
        <span class="about-version-badge">${escapeHtml(version)}</span>
        <p>${escapeHtml(t("about.body"))}</p>
      </div>
      <div class="about-link-grid">
        <a class="btn btn-primary" href="${escapeHtml(links.repository)}" target="_blank" rel="noreferrer" data-i18n="about.open_project">${escapeHtml(t("about.open_project"))}</a>
        <a class="btn btn-ghost" href="${escapeHtml(links.license)}" target="_blank" rel="noreferrer" data-i18n="about.view_license">${escapeHtml(t("about.view_license"))}</a>
        <a class="btn btn-ghost" href="${escapeHtml(links.releases)}" target="_blank" rel="noreferrer" data-i18n="about.releases">${escapeHtml(t("about.releases"))}</a>
        <a class="btn btn-ghost" href="${escapeHtml(links.documentation)}" target="_blank" rel="noreferrer" data-i18n="about.documentation">${escapeHtml(t("about.documentation"))}</a>
      </div>
    </section>
    <section id="about-donation-section" class="about-section about-donation-section">
      <div class="about-section-head">
        <div>
          <p class="eyebrow">${escapeHtml(t("about.donate.eyebrow"))}</p>
          <h4>${escapeHtml(t("about.donate.title"))}</h4>
        </div>
        <p class="muted">${escapeHtml(t("about.donate.body"))}</p>
      </div>
      <div class="about-donation-tabs" role="tablist" aria-label="${escapeHtml(t("about.donate.method"))}">
        ${donationTabs}
      </div>
      <article class="about-donation-card">
        <div class="about-donation-network">
          <span>${escapeHtml(t("about.donate.network"))}</span>
          <strong>
            <img class="about-donation-network-logo" src="${escapeHtml(donation.logo || "")}" alt="${escapeHtml(tf("about.donate.logo_alt", { method: t(donation.labelKey) }))}">
            <span>${escapeHtml(t(donation.labelKey))}${donation.ticker ? ` · ${escapeHtml(donation.ticker)}` : ""}</span>
          </strong>
        </div>
        <div class="about-donation-main">
          <div class="about-donation-copy">${addressBlock}</div>
          <div class="about-donation-qr">${qrBlock}</div>
        </div>
      </article>
    </section>
  `;

  if (section === "donate") {
    setTimeout(() => document.getElementById("about-donation-section")?.scrollIntoView({ block: "center" }), 0);
  }
}

async function copyDonationAddress(method) {
  const option = DONATION_OPTIONS.find((entry) => entry.id === method) || selectedDonationOption();
  if (option.id === "github-sponsors") {
    window.open(PROJECT_LINKS.sponsors, "_blank", "noopener,noreferrer");
    return;
  }
  if (!option.address) {
    showToast("about.donate.empty", true);
    return;
  }
  try {
    await navigator.clipboard.writeText(option.address);
    showToast("about.donate.copied");
  } catch (_error) {
    showToast("about.donate.copy_failed", true);
  }
}

function configureDetailTabs(mode = "json") {
  const overviewBtn = document.getElementById("detail-tab-overview");
  const viewBtn = document.getElementById("detail-tab-view");
  const jsonBtn = document.getElementById("detail-tab-json");
  const inlineEditBtn = document.getElementById("detail-rule-edit-inline");
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
    if (inlineEditBtn) {
      inlineEditBtn.classList.remove("hidden");
      inlineEditBtn.title = t("rules.edit");
      inlineEditBtn.setAttribute("aria-label", t("rules.edit"));
    }
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
    if (inlineEditBtn) {
      inlineEditBtn.classList.add("hidden");
      inlineEditBtn.dataset.id = "";
    }
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

function compatibilityStatusLabel(status) {
  const bucket = statusBucket(status);
  if (bucket === "exact") return t("rules.compat.exact");
  if (bucket === "lossy") return t("rules.compat.lossy");
  return t("rules.compat.unsupported");
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
    ttp: "",
    confidence: Number(document.getElementById("rulelab-confidence")?.value || 70),
    tlp: document.getElementById("rulelab-tlp")?.value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap")?.value || "PAP:GREEN",
    rule: inputRule,
    observables: normalizePromptObservables({ rule: inputRule }),
    indicates_list: state.ruleLab.indicatesList || [],
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

function setDetailTitle(title, subtitle = "") {
  const titleNode = document.getElementById("detail-title");
  if (!titleNode) return;
  if (!subtitle) {
    titleNode.textContent = title;
    return;
  }
  titleNode.innerHTML = `
    <span class="detail-title-main">${escapeHtml(title || "")}</span>
    <code class="detail-title-subtitle">${escapeHtml(subtitle || "")}</code>
  `;
}

function formatDateShort(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw;
  return date.toLocaleDateString(state.locale === "es" ? "es-ES" : "en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function closeDetailDialogIfOpen() {
  const dialog = document.getElementById("detail-dialog");
  if (dialog instanceof HTMLDialogElement && dialog.open) {
    dialog.close();
  }
}

async function ensureAbilitiesLoaded() {
  if ((state.abilities.entries || []).length > 0) return;
  await loadAbilities();
}

function resolveAdversaryPlanSteps(stepIds = []) {
  const byId = new Map((state.abilities.entries || []).map((ability) => [ability.id, ability]));
  return (Array.isArray(stepIds) ? stepIds : [])
    .map((id) => {
      const ability = byId.get(id);
      if (ability) return ability;
      return {
        id,
        name: id,
        description: "",
        export_targets: [],
        platforms: [],
        classification: "unknown",
      };
    });
}

function isExporterCompatibleWithPlan(exporter, selectedSteps) {
  const normalizedExporter = String(exporter || "").toLowerCase();
  const steps = Array.isArray(selectedSteps) ? selectedSteps : [];
  if (!normalizedExporter || steps.length === 0) return false;
  return steps.every((step) => {
    const targets = Array.isArray(step?.export_targets)
      ? step.export_targets.map((target) => String(target || "").toLowerCase())
      : [];
    return targets.includes(normalizedExporter);
  });
}

function getExporterIncompatibilityReasons(exporter, selectedSteps) {
  const normalizedExporter = String(exporter || "").toLowerCase();
  const steps = Array.isArray(selectedSteps) ? selectedSteps : [];
  if (!normalizedExporter) return [t("adversaries.validation.exporters_missing")];
  if (steps.length === 0) return [t("adversaries.validation.steps_missing")];

  const missing = steps.filter((step) => {
    const targets = Array.isArray(step?.export_targets)
      ? step.export_targets.map((target) => String(target || "").toLowerCase())
      : [];
    return !targets.includes(normalizedExporter);
  });

  if (!missing.length) return [];
  return [tf("adversaries.export.incompatible_steps", { count: missing.length })];
}

function renderAdversaryMainTabs(activeTab) {
  const tabs = [
    { id: "summary", label: t("adversaries.view.tab.summary") },
    { id: "plan", label: t("adversaries.view.tab.plan") },
    { id: "export", label: t("adversaries.view.tab.export") },
  ];
  return tabs
    .map((tab) => `
      <button type="button" class="btn btn-ghost ${activeTab === tab.id ? "active" : ""}" data-action="adversary-detail-tab" data-tab="${tab.id}">
        ${escapeHtml(tab.label)}
      </button>
    `)
    .join("");
}

function renderAdversaryViewSummary(adversary, stepEntries) {
  const platformLabel = adversary.target_platform || t("common.no_data");
  const stepsCount = Number(adversary.steps ?? stepEntries.length ?? 0);
  const confidence = Number(adversary.confidence ?? 0);
  return `
    <section class="adversary-main-grid">
      <article class="adversary-detail-panel">
        <div class="adversary-detail-panel-head">
          <h4>${escapeHtml(t("adversaries.create.description"))}</h4>
        </div>
        <p class="muted">${escapeHtml(adversary.description || t("adversaries.detail.empty_description"))}</p>
      </article>
      <article class="adversary-detail-panel">
        <div class="adversary-detail-panel-head">
          <h4>${escapeHtml(t("adversaries.editor.validation_title"))}</h4>
        </div>
        <div class="adversary-detail-metrics">
          <div><span>${escapeHtml(t("common.id"))}</span><strong>${escapeHtml(adversary.id || "")}</strong></div>
          <div><span>${escapeHtml(t("adversaries.create.target_platform"))}</span><strong>${escapeHtml(platformLabel)}</strong></div>
          <div><span>${escapeHtml(t("adversaries.col.steps"))}</span><strong>${escapeHtml(String(stepsCount))}</strong></div>
          <div><span>${escapeHtml(t("adversaries.col.confidence"))}</span><strong>${escapeHtml(String(confidence))}</strong></div>
        </div>
      </article>
      <article class="adversary-detail-panel adversary-flow-placeholder">
        <div class="adversary-detail-panel-head">
          <h4>${escapeHtml(t("adversaries.flow.title"))}</h4>
        </div>
        <p class="muted">${escapeHtml(t("adversaries.flow.empty"))}</p>
      </article>
      <article class="adversary-detail-panel adversary-detail-safety">
        ${escapeHtml(t("adversaries.payload.safety"))}<br>
        ${escapeHtml(t("adversaries.security.review_plan"))}
      </article>
    </section>
  `;
}

function renderAdversaryViewPlan(stepEntries) {
  const rows = stepEntries.map((step, index) => {
    const platforms = Array.isArray(step.platforms) && step.platforms.length
      ? step.platforms.join(", ")
      : t("common.no_data");
    const badge = isCustomPayloadAbility(step)
      ? ` <span class="custom-payload-badge">${escapeHtml(t("adversaries.payload.badge"))}</span>`
      : "";
    return `
      <li class="adversary-detail-step">
        <span class="selected-step-index">${index + 1}</span>
        <span>
          <strong>${escapeHtml(step.name || step.id || "")}${badge}</strong>
          <small class="muted">${escapeHtml(step.id || "")} · ${escapeHtml(platforms)}</small>
        </span>
      </li>
    `;
  }).join("");

  return `
    <section class="adversary-main-grid">
      <article class="adversary-detail-panel">
        <div class="adversary-detail-panel-head">
          <h4>${escapeHtml(t("adversaries.detail.steps"))}</h4>
          <span class="badge">${escapeHtml(tf("adversaries.validation.steps_ok", { count: stepEntries.length }))}</span>
        </div>
        <ol class="adversary-detail-steps">${rows || `<li class="muted">${escapeHtml(t("adversaries.create.none_selected"))}</li>`}</ol>
      </article>
    </section>
  `;
}

function renderAdversaryViewExport(adversary, stepEntries) {
  const cards = ADVERSARY_EXPORTERS.map((exporter) => {
    const compatible = isExporterCompatibleWithPlan(exporter, stepEntries);
    const reasons = compatible ? [] : getExporterIncompatibilityReasons(exporter, stepEntries);
    const statusText = compatible ? t("adversaries.export.compatible") : t("adversaries.export.not_compatible");
    return `
      <article class="adversary-export-card ${compatible ? "compatible" : "incompatible"}">
        <div>
          <strong>${escapeHtml(exporter)}</strong>
          <small>${escapeHtml(statusText)}</small>
          ${reasons.length ? `<p class="muted adversary-export-reason">${escapeHtml(reasons.join(" "))}</p>` : `<p class="muted adversary-export-reason">${escapeHtml(t("adversaries.detail.compile_hint"))}</p>`}
        </div>
        <button class="btn ${compatible ? "btn-success" : "btn-ghost"}" data-action="adversary-export" data-id="${escapeHtml(adversary.id)}" data-target="${escapeHtml(exporter)}" ${compatible ? "" : "disabled"}>
          ${escapeHtml(compatible ? t("adversaries.detail.export") : t("adversaries.export.disabled"))}
        </button>
      </article>
    `;
  }).join("");

  return `
    <section class="adversary-main-grid">
      <article class="adversary-detail-panel adversary-detail-compile-panel">
        <div class="adversary-detail-panel-head">
          <div>
            <h4>${escapeHtml(t("adversaries.detail.compile_title"))}</h4>
            <p class="muted">${escapeHtml(t("adversaries.detail.compile_hint"))}</p>
          </div>
        </div>
        <div class="adversary-export-grid">${cards}</div>
      </article>
    </section>
  `;
}

function renderAdversaryDetailMain(adversary) {
  const mount = document.getElementById("adversary-editor-mount");
  if (!mount) return;
  const activeTab = state.adversaryView.activeTab || "summary";
  const stepEntries = resolveAdversaryPlanSteps(adversary.ability_refs || []);
  let body = "";
  if (activeTab === "plan") body = renderAdversaryViewPlan(stepEntries);
  else if (activeTab === "export") body = renderAdversaryViewExport(adversary, stepEntries);
  else body = renderAdversaryViewSummary(adversary, stepEntries);

  mount.innerHTML = `
    <article class="glass detail-card adversary-main-view">
      <div class="adversary-main-tabs" role="tablist" aria-label="${escapeHtml(t("adversaries.detail.tabs_aria"))}">
        ${renderAdversaryMainTabs(activeTab)}
      </div>
      ${body}
    </article>
  `;
}

function setAdversaryDetailTab(tab) {
  const normalized = ["summary", "plan", "export", "json"].includes(tab) ? tab : "summary";
  state.adversaryView.activeTab = normalized;
  if (state.adversaryView.entry) {
    renderAdversaryDetailMain(state.adversaryView.entry);
  }
}

async function openAdversaryDetail(adversaryId) {
  if (!adversaryId) return;
  await ensureAbilitiesLoaded();
  const adversary = await api(`/api/adversaries/${encodeURIComponent(adversaryId)}`);
  state.adversaryCompose.mode = "view";
  state.adversaryCompose.editingId = adversary.id || null;
  state.adversaryView.activeId = adversary.id || null;
  state.adversaryView.activeTab = "summary";
  state.adversaryView.entry = adversary;
  showAdversaryEditorWorkspace();
  renderAdversaryDetailMain(adversary);
  renderAdversaryWorkspaceHeader();
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
  state.ruleLab.editingRuleId = entry.id || entry.rule_id || "";
  state.ruleLab.editingRuleName = entry.name || "";
  const ruleInput = document.getElementById("rulelab-input");
  const titleInput = document.getElementById("rulelab-title");
  const descriptionInput = document.getElementById("rulelab-description");
  const confidenceInput = document.getElementById("rulelab-confidence");
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
  if (tlpSelect instanceof HTMLSelectElement) {
    tlpSelect.value = normalizeTlpValue(entry.tlp || "TLP:GREEN");
    updateLevelSelectStyle(tlpSelect);
  }
  if (papSelect instanceof HTMLSelectElement) {
    papSelect.value = normalizePapValue(entry.pap || "PAP:GREEN");
    updateLevelSelectStyle(papSelect);
  }

  // Populate STIX relations
  const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
    ? entry.indicates_list
    : (entry.indicates ? [entry.indicates] : []);
  state.ruleLab.indicatesList = indicatesList.map((item) => ({ ...item }));
  renderRuleLabIndicates();

  renderRuleLabPreview();
  updateRuleLabEditingContext();
  scheduleRuleLabAnalysis();
  setTimeout(() => {
    if (ruleInput instanceof HTMLTextAreaElement) {
      ruleInput.focus();
      ruleInput.selectionStart = 0;
      ruleInput.selectionEnd = 0;
    }
  }, 0);
}

function clearRuleLabEditingContext() {
  state.ruleLab.editingRuleId = "";
  state.ruleLab.editingRuleName = "";
  updateRuleLabEditingContext();
}

function updateRuleLabEditingContext() {
  const banner = document.getElementById("rulelab-editing-banner");
  const note = document.getElementById("rulelab-save-editing-note");
  const editing = Boolean(state.ruleLab.editingRuleId || state.ruleLab.editingRuleName);
  const text = editing
    ? tf("rulelab.editing_existing", {
        name: state.ruleLab.editingRuleName || state.ruleLab.editingRuleId || t("rules.col.name"),
        id: state.ruleLab.editingRuleId || "",
      })
    : "";
  [banner, note].forEach((node) => {
    if (!node) return;
    node.classList.toggle("hidden", !editing);
    node.textContent = text;
  });
}

function renderRuleLabIndicates() {
  const container = document.getElementById("rulelab-indicates-list");
  if (!container) return;
  const list = state.ruleLab.indicatesList || [];
  if (!list.length) {
    container.innerHTML = `<span class="muted indicates-empty">${escapeHtml(t("rulelab.stix_relations.empty"))}</span>`;
    return;
  }
  container.innerHTML = list
    .map((item, idx) => {
      const label = item.object_name || item.stix_id || "?";
      const badge = stixTypeBadge(item.stix_id || "");
      return `<span class="indicates-pill" title="${escapeHtml(item.stix_id)}">
        ${badge ? `<span class="stix-type-badge">${escapeHtml(badge)}</span>` : ""}
        ${escapeHtml(label)}
        <button type="button" class="indicates-pill-remove" data-action="rulelab-indicates-remove" data-idx="${idx}" title="${escapeHtml(t("adversaries.create.remove"))}" aria-label="${escapeHtml(t("adversaries.create.remove"))}">×</button>
      </span>`;
    })
    .join("");
}

function stixTypeBadge(stixId) {
  const type = String(stixId || "").split("--")[0].trim();
  if (!type) return "";
  const map = {
    "attack-pattern": "TTP",
    "malware": "MAL",
    "threat-actor": "TA",
    "intrusion-set": "IS",
    "tool": "TOOL",
    "vulnerability": "CVE",
    "campaign": "CAM",
  };
  return map[type] || type.toUpperCase().slice(0, 4);
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
  const observableTypes = [...new Set((observables.length ? observables : normalizePromptObservables(entry))
    .map((observable) => String(observable || "").split(":")[0].trim().toLowerCase())
    .filter(Boolean))]
    .sort((a, b) => a.localeCompare(b));
  const legacySummaryLabel = t("detail.rule.summary");
  const observableTags = observableTypes.length
    ? observableTypes.map((observable) => `<span class="rule-observable-tag">${escapeHtml(observable)}</span>`).join("")
    : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`;

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

  const observablesAndRelationsSection = `
      <section class="detail-section rule-detail-context-section">
        <h4>${escapeHtml(t("rules.detail.observables.title"))}</h4>
        ${observableTypes.length
          ? `<ol class="rule-detail-observable-list">
              ${observableTypes.map((observable) => `<li><span>${escapeHtml(observable)}</span></li>`).join("")}
            </ol>`
          : `<span class="muted">${escapeHtml(t("common.no_data"))}</span>`}
        <div class="rule-detail-related-head">
          <h4>${escapeHtml(t("rules.detail.related.title"))}</h4>
          <button class="btn btn-ghost icon-only" data-action="rule-indicates" data-id="${escapeHtml(entry.id || "")}" title="${escapeHtml(t("rules.indicates.add"))}" aria-label="${escapeHtml(t("rules.indicates.add"))}"><i class="fa-solid fa-plus" aria-hidden="true"></i></button>
        </div>
        ${indicatesList.length
          ? `<div class="rule-detail-stix-card-list">
              ${indicatesList
                .map((relation) => {
                  const relationName = relation.relationship || relation.relationship_type || "indicates";
                  return `
                    <article class="rule-detail-stix-card" title="${escapeHtml(relation.stix_id || "")}">
                      <div class="rule-detail-stix-card-head">
                        <span class="rule-detail-stix-type">${escapeHtml(stixObjectTypeLabel(relation.stix_id))}</span>
                        <span class="rule-detail-relation">${escapeHtml(relationName)}</span>
                      </div>
                      <strong>${escapeHtml(relation.object_name || relation.stix_id || t("rules.indicates.object_unknown"))}</strong>
                      <small>${escapeHtml(relation.stix_id || "-")}</small>
                    </article>
                  `;
                })
                .join("")}
            </div>`
          : `<span class="muted">${escapeHtml(t("rules.detail.related.empty"))}</span>`}
      </section>
    `;

  const detectionExportRows = detectionRows
    .filter((item) => String(item.output || "").trim().length > 0);
  const emulationExportRows = emulationRows
    .filter((item) => String(item.output || "").trim().length > 0);

  const view = `
    <div id="rule-detail-pane-overview" class="rule-tech-list">
      <section class="detail-section">
        <div class="detail-code-head">
          <h4 title="${escapeHtml(legacySummaryLabel)}">${escapeHtml(t("detail.rule.tab.overview"))}</h4>
          <div class="detail-summary-actions">
            <button class="btn btn-ghost" data-action="detail-show-json">JSON</button>
            <button class="btn btn-primary hidden" data-action="rule-open-in-lab" data-id="${escapeHtml(entry.id || "")}">${escapeHtml(t("rules.edit"))}</button>
          </div>
        </div>
        <div class="detail-grid rule-summary-grid">
          <div class="detail-kv detail-kv-confidence"><span class="label">${escapeHtml(t("rules.col.confidence"))}</span>${renderConfidenceBar(entry.confidence, { variant: "rule" })}</div>
          <div class="detail-kv rule-summary-levels">
            <div class="detail-kv"><span class="label">TLP</span>${trafficBadge(entry.tlp, "tlp")}</div>
            <div class="detail-kv"><span class="label">PAP</span>${trafficBadge(entry.pap, "pap")}</div>
          </div>
          <div class="detail-kv"><span class="label">${escapeHtml(t("rules.col.indicates"))}</span><code>${escapeHtml(String(indicatesList.length || 0))}</code></div>
        </div>
        <div class="detail-kv">
          <span class="label">${escapeHtml(t("rules.col.observables"))}</span>
          <div class="rule-observables-cell">${observableTags}</div>
        </div>
        ${entry.description ? `<p class="muted rule-detail-summary-text">${escapeHtml(entry.description)}</p>` : ""}
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
      ${observablesAndRelationsSection}
    </div>
    <section class="detail-section hidden" id="rule-detail-pane-detection">
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
      <div class="rule-tech-list">
        ${detectionRows.map((item) => renderRuleTechCard(entry, item, "detection")).join("")}
      </div>
    </section>
    <section class="detail-section hidden" id="rule-detail-pane-emulation">
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
      <div class="rule-tech-list">
        ${emulationRows.map((item) => renderRuleTechCard(entry, item, "emulation")).join("")}
      </div>
    </section>
  `;

  state.ruleDetail.entry = entry;
  state.ruleDetail.detectionRows = detectionRows;
  state.ruleDetail.emulationRows = emulationRows;
  state.ruleDetail.focusedTarget = focusedTarget;
  setDetailTitle(entry.name || t("rules.col.rule"), entry.id || "");
  setDetailModalMode("detection", t("detail.stix_pattern"), "");
  document.getElementById("detail-view").innerHTML = view;
  document.getElementById("detail-raw").textContent = JSON.stringify(entry, null, 2);
  document.getElementById("detail-actions").innerHTML = renderDetailActions("");
  configureDetailTabs("rule");
  const inlineEditButton = document.getElementById("detail-rule-edit-inline");
  if (inlineEditButton) {
    inlineEditButton.dataset.id = String(entry.id || "");
  }
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
  const title = tf("rules.status_chip.title", { target: label, status: compatibilityStatusLabel(status) });
  return `<button class="status-chip ${statusClass(status)}" data-action="${action}" ${Object.entries(payload)
    .map(([key, value]) => `data-${key}="${escapeHtml(String(value))}"`)
    .join(" ")} title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">${escapeHtml(label)}</button>`;
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
  const projectLink = document.getElementById("footer-project-link");
  if (projectLink) {
    projectLink.href = app.project_url;
    if (app.project_name && !projectLink.dataset.i18n) {
      projectLink.textContent = app.project_name;
    }
  }
  const licenseLink = document.getElementById("footer-license-link");
  if (licenseLink) {
    licenseLink.href = app.license_url;
    if (app.license_name && !licenseLink.dataset.i18n) {
      licenseLink.textContent = app.license_name;
    }
  }
}

function setupLoginProviders() {
  const providers = state.bootstrap.auth.providers || [];
  const buttons = document.querySelectorAll("[data-provider]");
  buttons.forEach((button) => {
    const provider = providers.find((item) => item.id === button.dataset.provider);
    const enabled = Boolean(provider?.configured && provider?.enabled);
    button.disabled = !enabled;
    button.setAttribute("aria-disabled", enabled ? "false" : "true");
    if (enabled) {
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

function currentDisplayName() {
  return state.userSettings?.display_name
    || state.principal?.display_name
    || state.principal?.username
    || "";
}

function refreshIdentityPill() {
  const pill = document.getElementById("identity-pill");
  if (!pill) return;
  const noLoginActive = Boolean(state.bootstrap?.auth?.no_login);
  if (noLoginActive) {
    pill.textContent = currentDisplayName() || t("common.local_user");
    return;
  }
  if (!state.principal) {
    pill.textContent = t("common.not_authenticated");
    return;
  }
  const name = currentDisplayName() || state.principal.username;
  pill.textContent = `${name} · ${state.principal.role}`;
}

function applyBootstrapPreferences() {
  const defaults = state.bootstrap?.auth || {};
  const user = state.bootstrap?.user || null;
  state.userSettings = user;
  setLocale(user?.locale || defaults.default_locale || state.locale);
  setTheme(user?.theme || defaults.default_theme || state.theme);
  if (state.principal) {
    state.principal.display_name = user?.display_name || state.principal.display_name || state.principal.username;
  }
  applyTranslations();
  refreshIdentityPill();
}

async function reloadLocalizedAppData() {
  if (document.getElementById("app-view").classList.contains("hidden")) return;
  refreshRouteMeta();
  if (state.route === "dashboard") renderDashboard();
  if (state.route === "rules" || state.route === "rules-catalog") await loadRules();
  if (state.route === "adversaries" || state.route === "adversaries-catalog" || state.route === "adversaries-payloads") {
    await loadAdversaries();
  }
  if (state.route === "stix-objects" || state.route === "stix-objects-catalog") {
    await loadStixObjects();
  }
  if (state.route === "learning") await loadLearning();
  if (state.route === "settings") await loadSettingsView();
}

function applyNavSelection(route) {
  const rootRoute = route === "adversaries-payloads"
    ? "adversaries-payloads"
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
  if (route === "rules-import" || route === "rules-catalog") route = "rules";
  if (route === "adversaries-catalog") route = "adversaries";
  state.route = route;
  if (route !== "adversaries-create") {
    document.getElementById("panel-adversary-editor")?.classList.add("hidden");
    document.getElementById("panel-adversary-editor")?.classList.remove("active");
  }
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
    state.rules.workspaceMode = "explore";
    renderRulesWorkspace();
    loadRules();
  }
  if (panelRoute === "rulelab") {
    setMarkdownEditorMode("rulelab-description", "preview");
    refreshMarkdownEditorPreview("rulelab-description");
    renderRuleLabPreview();
    updateRuleLabEditingContext();
    setTimeout(() => document.getElementById("rulelab-input")?.focus(), 0);
  }
  if (panelRoute === "adversaries") {
    state.adversaries.workspaceMode = route === "adversaries-payloads" ? "payloads" : "catalog";
    renderAdversaryWorkspace();
    loadAdversaries();
    if (route === "adversaries-create") {
      setTimeout(() => createNewAdversaryInEditor(), 0);
    }
  }
  if (panelRoute === "stix-objects") {
    state.stixObjectsView.workspaceMode = route === "stix-objects-catalog" ? "catalog" : "welcome";
    renderStixObjectsWorkspace();
    loadStixObjects();
  }
  if (route === "learning") loadLearning();
  if (route === "settings") loadSettingsView();

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
  applyBootstrapPreferences();
  RULE_OUTPUT_TARGETS = normalizeDetectionTargets(state.bootstrap?.translation?.available_targets);
  loadCustomPayloadCatalog();

  populateFooter();
  setupLoginProviders();
  document.getElementById("logout-button").classList.toggle("hidden", !state.bootstrap.auth.show_logout);
  refreshIdentityPill();
  const noLoginActive = state.bootstrap.auth.no_login;
  if (noLoginActive) {
    showBootGate();
  } else if (state.bootstrap.auth.authenticated) {
    enterApplication();
  } else {
    showPasswordLogin();
  }
}

function showBootGate() {
  document.getElementById("boot-view")?.classList.remove("hidden");
  document.getElementById("login-view")?.classList.add("hidden");
  document.getElementById("app-view")?.classList.add("hidden");
  document.getElementById("boot-enter-button")?.classList.remove("hidden");
  document.getElementById("boot-message")?.classList.remove("hidden");
}

function showLogin() {
  document.getElementById("boot-view")?.classList.add("hidden");
  const loginView = document.getElementById("login-view");
  loginView.classList.remove("hidden");
  document.getElementById("app-view").classList.add("hidden");
  document.getElementById("boot-enter-button")?.classList.add("hidden");
  document.getElementById("boot-message")?.classList.add("hidden");
}

function showPasswordLogin() {
  showLogin();
}

function enterApplication() {
  document.getElementById("boot-view")?.classList.add("hidden");
  document.getElementById("login-view").classList.add("hidden");
  document.getElementById("app-view").classList.remove("hidden");
  const remembered = state.appMode === "gui" && state.bootstrap?.auth?.no_login
    ? "home"
    : localStorage.getItem("spuc-web-last-route") || "home";
  setRoute(remembered);
  loadSharedData();
}

async function loadSharedData() {
  await Promise.all([loadOverview(), loadRules(), loadAbilities(), loadAdversaries(), loadStixObjects(), loadMitreAttack()]);
  await loadLearning();
  if (state.principal?.role === "admin") {
    await loadAdminRuntimeSettings();
    await loadAdminOauthProviders();
    if (!isNoLoginSession()) {
      const usersResponse = await api("/api/admin/users");
      state.adminUsers = usersResponse.entries || [];
      renderAdminUsersTable();
    }
  }
  renderDashboard();
  renderAdversaryAbilitySelector();
}

async function loadOverview() {
  state.overview = await api("/api/overview");
}

async function loadMitreAttack() {
  try {
    const data = await api("/api/mitre-attack");
    state.mitreAttack = Array.isArray(data) ? data : [];
  } catch (_) {
    state.mitreAttack = [];
  }
}

function renderDashboard() {
  if (!state.overview) return;

  const welcome = document.getElementById("welcome-card");
  welcome.classList.add("hidden");

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
  refreshCustomComboboxes(document);
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

function stixObjectMatchesSearch(entry, searchTerm) {
  const needle = String(searchTerm || "").trim().toLowerCase();
  if (!needle) return true;
  const haystacks = [
    entry?.name,
    entry?.stix_id,
    entry?.description,
    entry?.stix_type,
  ];
  return haystacks.some((value) => String(value || "").toLowerCase().includes(needle));
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
  refreshCustomComboboxes(document);
}

function renderRuleLabSaveStixOptions() {
  const select = document.getElementById("rulelab-stix-object-select");
  if (!(select instanceof HTMLSelectElement)) return;
  const current = select.value || "";
  const options = Array.isArray(state.stixObjects) ? state.stixObjects : [];
  select.innerHTML = `
    <option value="">${escapeHtml(t("rules.indicates.catalog_placeholder"))}</option>
    ${options
      .map((entry) => `<option value="${escapeHtml(entry.stix_id)}">${escapeHtml(`${entry.name} · ${entry.stix_type}`)}</option>`)
      .join("")}
  `;
  if (options.some((entry) => entry.stix_id === current)) {
    select.value = current;
  }
  refreshCustomComboboxes(document);
}

function renderStixObjectsTable() {
  const table = document.getElementById("stix-objects-table");
  const meta = document.getElementById("stix-objects-meta");
  if (!table || !meta) return;
  const searchTerm = (state.stixObjectsView?.searchTerm || "").toLowerCase();
  const all = Array.isArray(state.stixObjects) ? state.stixObjects : [];
  const entries = searchTerm
    ? all.filter((entry) => stixObjectMatchesSearch(entry, searchTerm))
    : all;
  meta.textContent = `${entries.length} ${t("common.entries")}`;
  const visibleIds = new Set(entries.map((entry) => entry.stix_id));
  state.stixObjectsView.selected = new Set(
    Array.from(state.stixObjectsView.selected).filter((stixId) => visibleIds.has(stixId)),
  );
  if (!entries.length) {
    table.innerHTML = `
      <thead><tr>
        <th><input type="checkbox" id="stix-select-all-header" data-action="stix-select-all-toggle" aria-label="${escapeHtml(t("rules.bulk.select_all"))}"></th>
        <th>${escapeHtml(t("rules.stix_objects.col.type"))}</th>
        <th>${escapeHtml(t("rules.stix_objects.col.name"))}</th>
        <th>TLP / PAP</th>
        <th>${escapeHtml(t("stix_objects.form.created_at") || "Created")}</th>
        <th>${escapeHtml(t("common.actions"))}</th>
      </tr></thead>
      <tbody><tr class="table-empty-row"><td colspan="6">${escapeHtml(t("common.no_data"))}</td></tr></tbody>
    `;
    updateStixObjectsBulkState();
    return;
  }
  const rows = entries.map((entry) => {
    const type = entry.stix_type || entry.stix_id.split("--")[0] || "-";
    const badge = stixTypeBadge(entry.stix_id || "");
    const tlp = normalizeTlpValue(entry.tlp || "TLP:GREEN");
    const pap = normalizePapValue(entry.pap || "PAP:GREEN");
    const createdAt = entry.created_at || "";
    const detailId = `stix-detail-${entry.stix_id.replace(/[^a-zA-Z0-9]/g, "-")}`;
    const checked = state.stixObjectsView.selected.has(entry.stix_id);
    const expanded = state.stixObjectsView.expandedDetails.has(entry.stix_id);
    return `<tr data-stix-row-id="${escapeHtml(entry.stix_id)}" aria-expanded="${expanded ? "true" : "false"}">
      <td>
        <input type="checkbox" data-action="stix-select-row" data-stix-id="${escapeHtml(entry.stix_id)}" ${checked ? "checked" : ""} aria-label="${escapeHtml(t("rules.bulk.select_all"))}">
      </td>
      <td><span class="stix-type-badge">${escapeHtml(badge)}</span> <span class="muted">${escapeHtml(type)}</span></td>
      <td>${escapeHtml(entry.name || "-")}</td>
      <td>
        ${trafficBadge(tlp, "tlp")}
        ${trafficBadge(pap, "pap")}
      </td>
      <td class="muted">${escapeHtml(createdAt)}</td>
      <td class="stix-row-actions">
        <button class="icon-btn" data-action="stix-edit-object" data-stix-id="${escapeHtml(entry.stix_id)}" title="${escapeHtml(t("stix_objects.edit") || "Edit")}" aria-label="${escapeHtml(t("stix_objects.edit") || "Edit")}"><i class="fa-solid fa-pen-to-square" aria-hidden="true"></i></button>
        <button class="icon-btn" data-action="stix-delete" data-stix-id="${escapeHtml(entry.stix_id)}" title="${escapeHtml(t("common.delete") || "Delete")}" aria-label="${escapeHtml(t("common.delete") || "Delete")}"><i class="fa-solid fa-trash" aria-hidden="true"></i></button>
      </td>
    </tr>
    <tr class="stix-detail-row${expanded ? "" : " hidden"}">
      <td colspan="6">
        <details id="${escapeHtml(detailId)}" open>
          <summary class="stix-name-summary">${escapeHtml(t("stix_objects.more_info") || "Details")}</summary>
          <div class="stix-detail-body">
            ${renderStixObjectDetails(entry)}
          </div>
        </details>
      </td>
    </tr>`;
  }).join("");
  table.innerHTML = `
    <thead><tr>
      <th><input type="checkbox" id="stix-select-all-header" data-action="stix-select-all-toggle" aria-label="${escapeHtml(t("rules.bulk.select_all"))}"></th>
      <th>${escapeHtml(t("rules.stix_objects.col.type"))}</th>
      <th>${escapeHtml(t("rules.stix_objects.col.name"))}</th>
      <th>TLP / PAP</th>
      <th>${escapeHtml(t("stix_objects.form.created_at") || "Created")}</th>
      <th>${escapeHtml(t("common.actions"))}</th>
    </tr></thead>
    <tbody>${rows}</tbody>
  `;
  updateStixObjectsBulkState();
}

function renderStixObjectDetails(entry) {
  const stixId = String(entry?.stix_id || "");
  const description = String(entry?.description || "").trim() || t("stix_objects.no_description") || "No description";
  return `
    <div class="stix-detail-compact">
      <div class="stix-detail-id-row">
        <span class="label">${escapeHtml(t("rules.stix_objects.col.id") || "ID")}:</span>
        <code class="stix-detail-id mono">${escapeHtml(stixId)}</code>
      </div>
      <div class="stix-detail-description">
        <span class="label">${escapeHtml(t("rulelab.description") || t("stix_objects.form.description") || "Description")}:</span>
        <div class="markdown-preview stix-detail-markdown">${renderMarkdown(description)}</div>
      </div>
    </div>
  `;
}

function toggleStixObjectDetails(stixId) {
  if (!stixId) return;
  if (state.stixObjectsView.expandedDetails.has(stixId)) {
    state.stixObjectsView.expandedDetails.delete(stixId);
  } else {
    state.stixObjectsView.expandedDetails.add(stixId);
  }
  renderStixObjectsTable();
}

function updateStixObjectsBulkState() {
  const selectedCount = state.stixObjectsView.selected.size;
  const countNode = document.getElementById("stix-bulk-count");
  const bulkEditNode = document.getElementById("stix-bulk-edit");
  const exportButton = document.getElementById("stix-export-selected");
  const deleteButton = document.getElementById("stix-delete-selected");
  const bulkToggle = document.getElementById("stix-bulk-toggle");
  const selectAllCheckbox = document.getElementById("stix-select-all-header");
  if (countNode) {
    countNode.textContent = t("rules.bulk.selected_count").replace("{count}", String(selectedCount));
  }
  if (bulkEditNode) {
    bulkEditNode.classList.toggle("hidden", !state.stixObjectsView.bulkEditOpen);
  }
  if (exportButton) exportButton.disabled = selectedCount === 0;
  if (deleteButton) deleteButton.disabled = selectedCount === 0;
  if (bulkToggle) {
    bulkToggle.disabled = selectedCount === 0;
    bulkToggle.classList.toggle("active", state.stixObjectsView.bulkEditOpen && selectedCount > 0);
  }
  if (selectAllCheckbox) {
    const visible = (state.stixObjects || []).filter((entry) => stixObjectMatchesSearch(entry, state.stixObjectsView.searchTerm));
    const allSelected = visible.length > 0 && visible.every((entry) => state.stixObjectsView.selected.has(entry.stix_id));
    selectAllCheckbox.checked = allSelected;
    selectAllCheckbox.indeterminate = selectedCount > 0 && !allSelected;
  }
}

async function loadStixObjects() {
  const response = await api("/api/stix-objects");
  state.stixObjects = response.entries || [];
  const existingIds = new Set(state.stixObjects.map((entry) => entry.stix_id));
  state.stixObjectsView.selected = new Set(
    Array.from(state.stixObjectsView.selected).filter((stixId) => existingIds.has(stixId)),
  );
  state.stixObjectsView.expandedDetails = new Set(
    Array.from(state.stixObjectsView.expandedDetails).filter((stixId) => existingIds.has(stixId)),
  );
  renderStixObjectsTable();
  renderIndicatesObjectOptions();
  renderRuleLabSaveStixOptions();
  renderStixObjectsWorkspace();
}

function openPayloadCatalogDocs() {
  const url = state.bootstrap?.app?.documentation_url || PROJECT_LINKS.documentation;
  window.open(url, "_blank", "noopener,noreferrer");
}

async function importStixObjectsFromFile(file) {
  if (!(file instanceof File)) return;
  let parsed;
  try {
    parsed = JSON.parse(await file.text());
  } catch (_error) {
    showToast("toast.unexpected", true);
    return;
  }

  const candidates = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.objects)
      ? parsed.objects
      : [parsed];

  const entries = candidates
    .filter((item) => item && typeof item === "object")
    .map((item) => {
      const stixId = String(item.id || item.stix_id || "").trim();
      const name = String(item.name || item.title || item.value || "").trim();
      if (!stixId || !name) return null;
      return {
        stix_id: stixId,
        name,
        description: String(item.description || "").trim(),
        tlp: String(item.tlp || "TLP:AMBER"),
        pap: String(item.pap || "PAP:GREEN"),
        created_at: String(item.created || item.created_at || "").trim(),
        first_seen: String(item.first_seen || "").trim(),
      };
    })
    .filter(Boolean);

  if (!entries.length) {
    showToast("toast.unexpected", true);
    return;
  }

  for (const entry of entries) {
    await api("/api/stix-objects", {
      method: "POST",
      body: JSON.stringify(entry),
    });
  }

  showToast("toast.saved");
  await loadStixObjects();
}

async function openRuleLabSaveDialog() {
  if (!Array.isArray(state.stixObjects) || state.stixObjects.length === 0) {
    await loadStixObjects();
  } else {
    renderRuleLabSaveStixOptions();
  }
  renderRuleLabIndicates();
  updateRuleLabEditingContext();
  const dialog = document.getElementById("rulelab-save-dialog");
  if (dialog instanceof HTMLDialogElement) {
    dialog.showModal();
  }
}

function addRuleLabSelectedStixRelation() {
  const select = document.getElementById("rulelab-stix-object-select");
  if (!(select instanceof HTMLSelectElement) || !select.value) return;
  const selected = (state.stixObjects || []).find((entry) => entry.stix_id === select.value);
  if (!selected) return;
  const alreadyExists = (state.ruleLab.indicatesList || []).some((entry) => entry.stix_id === selected.stix_id);
  if (alreadyExists) return;
  state.ruleLab.indicatesList.push({ stix_id: selected.stix_id, object_name: selected.name });
  renderRuleLabIndicates();
}

function openStixObjectDialog(entry = null) {
  const typeSelect = document.getElementById("stix-object-type");
  const nameInput = document.getElementById("stix-object-name");
  const descInput = document.getElementById("stix-object-description");
  const tlpSelect = document.getElementById("stix-object-tlp");
  const papSelect = document.getElementById("stix-object-pap");
  const firstSeenInput = document.getElementById("stix-object-first-seen");
  const createdAtInput = document.getElementById("stix-object-created-at");
  const idInput = document.getElementById("stix-object-id");
  const similarDiv = document.getElementById("stix-name-similar");
  const titleNode = document.getElementById("stix-object-dialog-title");
  const editing = Boolean(entry?.stix_id);
  const type = editing ? (entry.stix_type || stixObjectTypeFromId(entry.stix_id || "") || "malware") : "malware";

  const today = new Date().toISOString().slice(0, 10);
  state.stixObjectsView.editingId = editing ? String(entry.stix_id || "") : "";
  if (titleNode) titleNode.textContent = editing ? (t("stix_objects.edit") || "Edit STIX object") : (t("stix_objects.create") || "Create new STIX object");
  if (typeSelect instanceof HTMLSelectElement) {
    typeSelect.disabled = editing;
    typeSelect.value = type;
  }
  if (nameInput instanceof HTMLInputElement) nameInput.value = editing ? String(entry.name || "") : "";
  if (descInput instanceof HTMLTextAreaElement) descInput.value = editing ? String(entry.description || "") : "";
  if (tlpSelect instanceof HTMLSelectElement) { tlpSelect.value = editing ? normalizeTlpValue(entry.tlp || "TLP:AMBER") : "TLP:AMBER"; updateLevelSelectStyle(tlpSelect); }
  if (papSelect instanceof HTMLSelectElement) { papSelect.value = editing ? normalizePapValue(entry.pap || "PAP:GREEN") : "PAP:GREEN"; updateLevelSelectStyle(papSelect); }
  if (firstSeenInput instanceof HTMLInputElement) firstSeenInput.value = editing ? String(entry.first_seen || today) : today;
  if (createdAtInput instanceof HTMLInputElement) createdAtInput.value = editing ? String(entry.created_at || today) : today;
  if (idInput instanceof HTMLInputElement) idInput.value = editing ? String(entry.stix_id || "") : generateStixId(type);
  if (similarDiv) similarDiv.innerHTML = "";
  document.getElementById("stix-object-dialog").showModal();
}

function generateStixId(type) {
  const hex = () => Math.floor(Math.random() * 0x10000).toString(16).padStart(4, "0");
  const uuid = `${hex()}${hex()}-${hex()}-4${hex().slice(1)}-${["8","9","a","b"][Math.floor(Math.random()*4)]}${hex().slice(1)}-${hex()}${hex()}${hex()}`;
  return `${type}--${uuid}`;
}

function renderIndicatesSearchResults(query) {
  const resultsDiv = document.getElementById("indicates-search-results");
  if (!resultsDiv) return;
  const catalog = Array.isArray(state.stixObjects) ? state.stixObjects : [];
  if (catalog.length === 0) {
    resultsDiv.innerHTML = `<div class="indicates-no-results muted">${escapeHtml(t("rules.indicates.no_objects"))}</div>`;
    return;
  }
  if (!query) {
    resultsDiv.innerHTML = "";
    return;
  }
  const lower = query.toLowerCase();
  const filtered = catalog.map((o) => ({
    stix_id: o.stix_id,
    object_name: o.name,
    stix_type: o.stix_id.split("--")[0],
  })).filter((o) =>
    o.object_name.toLowerCase().includes(lower) ||
    o.stix_id.toLowerCase().includes(lower)
  ).slice(0, 20);
  if (!filtered.length) {
    resultsDiv.innerHTML = `<div class="indicates-no-results muted">${escapeHtml(t("common.no_results") || "No results")}</div>`;
    return;
  }
  resultsDiv.innerHTML = filtered.map((o) => {
    const badge = stixTypeBadge(o.stix_id);
    return `<button type="button" class="indicates-search-result-item" data-action="indicates-pick"
      data-stix-id="${escapeHtml(o.stix_id)}" data-object-name="${escapeHtml(o.object_name)}">
      ${badge ? `<span class="stix-type-badge">${escapeHtml(badge)}</span>` : ""}
      <span class="indicates-result-name">${escapeHtml(o.object_name)}</span>
    </button>`;
  }).join("");
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
  refreshCustomComboboxes(document);
}

function rulesColumnLabel(columnKey) {
  switch (columnKey) {
    case "name": return t("rules.col.name");
    case "confidence": return t("rules.col.confidence");
    case "markings": return "Markings";
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
  const exportSelectedCsvButton = document.getElementById("rules-export-selected-csv");
  const exportSelectedStixButton = document.getElementById("rules-export-selected-stix");
  const duplicateSelectedButton = document.getElementById("rules-duplicate-selected");
  const deleteButton = document.getElementById("rules-delete-selected");
  const selectAllButton = document.getElementById("rules-select-all-header");
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
    selectAllButton.checked = allFilteredSelected;
    selectAllButton.indeterminate = count > 0 && !allFilteredSelected;
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
          renderStatusChip(targetLabel(target, "detection"), entry.target_statuses?.[target] || "unsupported", "rule-target-detail", {
            rule: entry.id,
            target,
          }),
        )
        .join("");
      const emulationChips = RULE_EMULATION_TARGETS
        .map((target) =>
          renderStatusChip(targetLabel(target, "emulation"), entry.emulation_statuses?.[target] || "unsupported", "rule-emulation-detail", {
            rule: entry.id,
            target,
            ability: entry.ability_id || "",
          }),
        )
        .join("");
      const globalStatus = ruleStatusFromEntry(entry);
      const stixObjectsTitle = indicatesList.length
        ? indicatesList.map((item) => [item.object_name, item.stix_id].filter(Boolean).join(" | ")).join("\n")
        : t("common.no_data");
      const observablesTitle = observables.length ? observables.join(", ") : t("common.no_data");

      return `
        <article class="rule-card ${globalStatus}" data-rule-card-id="${escapeHtml(entry.id)}">
          <header class="rule-card-head">
            <label class="rule-card-check">
              <input type="checkbox" data-action="rule-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.rules.selected.has(entry.id) ? "checked" : ""}>
            </label>
            <div class="rule-card-title-wrap">
              <div class="rule-card-title-line">
                <h4>${escapeHtml(entry.name || t("rules.col.rule"))}</h4>
                <div class="rule-card-markings">
                  ${trafficBadge(entry.tlp, "tlp")}
                  ${trafficBadge(entry.pap, "pap")}
                </div>
              </div>
              <div class="rule-card-subtitle">
                <span class="rule-card-id-stack">
                  <span class="rule-card-id">${escapeHtml(entry.id)}</span>
                </span>
              </div>
            </div>
          </header>

          <section class="rule-card-body">
            <div class="rule-card-grid">
              <div class="rule-card-kv rule-card-kv-confidence">${renderConfidenceBar(entry.confidence, { label: t("rules.col.confidence"), variant: "rule" })}</div>
              <div class="rule-card-kv rule-card-count" title="${escapeHtml(stixObjectsTitle)}"><span>${escapeHtml(t("rules.col.indicates"))}</span><strong>${escapeHtml(String(indicatesList.length))}</strong></div>
              <div class="rule-card-kv rule-card-count" title="${escapeHtml(observablesTitle)}"><span>${escapeHtml(t("rules.col.observables"))}</span><strong>${escapeHtml(String(observables.length))}</strong></div>
            </div>

            <div class="rule-card-code-wrap">
              <div class="detail-code-head">
                <span class="badge warning stix-pattern-bubble">${escapeHtml(t("detail.stix_pattern"))}</span>
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

  if (tableBtn) tableBtn.classList.toggle("active", mode === "table");
  if (cardsBtn) cardsBtn.classList.toggle("active", mode === "cards");
  if (tableWrap) tableWrap.classList.toggle("hidden", mode !== "table");
  if (cardsWrap) cardsWrap.classList.toggle("hidden", mode !== "cards");
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
  const filtered = applyRulesClientFilters(state.rules.allEntries);
  state.rules.total = filtered.length;
  const maxPage = Math.max(1, Math.ceil(filtered.length / state.rules.pageSize));
  state.rules.page = Math.min(Math.max(1, state.rules.page), maxPage);
  const start = (state.rules.page - 1) * state.rules.pageSize;
  state.rules.entries = filtered.slice(start, start + state.rules.pageSize);

  const rows = state.rules.entries.map((entry, rowIndex) => {
    const typeTags = detectRuleTypes(entry)
      .map((type) => `<span class="rule-type-tag ${type}">${escapeHtml(type.toUpperCase())}</span>`)
      .join("");

    const outputChips = outputTargets
      .map((target) =>
        renderStatusChip(targetLabel(target, "detection"), entry.target_statuses?.[target] || "unsupported", "rule-target-detail", {
          rule: entry.id,
          target,
        }),
      )
      .join("");

    const emulationChips = emulationTargets
      .map((target) =>
        renderStatusChip(targetLabel(target, "emulation"), entry.emulation_statuses?.[target] || "unsupported", "rule-emulation-detail", {
          rule: entry.id,
          target,
          ability: entry.ability_id || "",
        }),
      )
      .join("");

    const cells = [
      `<td><input type="checkbox" data-action="rule-select" data-id="${entry.id}" data-index="${rowIndex}" ${state.rules.selected.has(entry.id) ? "checked" : ""}></td>`,
      `
        <td>
          <div class="rule-name">
            <strong>${escapeHtml(entry.name)}</strong>
            <div class="rule-type-tags">${typeTags || `<span class="rule-type-tag">${escapeHtml(t("common.na"))}</span>`}</div>
          </div>
        </td>
      `,
      `<td>${renderConfidenceBar(entry.confidence, { variant: "rule" })}</td>`,
      `
        <td>
          <div class="markings-stack">
            ${trafficBadge(entry.tlp, "tlp")}
            ${trafficBadge(entry.pap, "pap")}
          </div>
        </td>
      `,
      `
        <td>
          <div class="rule-cell">
            <button class="icon-btn" data-action="rule-copy" data-id="${entry.id}" title="${escapeHtml(t("detail.copy_rule"))}" aria-label="${escapeHtml(t("detail.copy_rule"))}">📋</button>
            <code class="rule-code">${escapeHtml(entry.rule)}</code>
          </div>
        </td>
      `,
      `<td><div class="chip-list">${outputChips}</div></td>`,
      `<td><div class="chip-list">${emulationChips}</div></td>`,
    ];
    return `<tr data-rule-row-id="${escapeHtml(entry.id)}">${cells.join("")}</tr>`;
  });

  const emptyRow = `
    <tr class="table-empty-row">
      <td colspan="7">${escapeHtml(t("common.no_data"))}</td>
    </tr>
  `;

  const headers = [
    `<th><input type="checkbox" id="rules-select-all-header" data-action="rules-select-all-toggle" aria-label="${escapeHtml(t("rules.bulk.select_all"))}"></th>`,
    sortableHeader(t("rules.col.name"), "rules-sort-column", "name", currentSort, "name_asc", "name_desc"),
    sortableHeader(t("rules.col.confidence"), "rules-sort-column", "confidence", currentSort, "confidence_asc", "confidence_desc"),
    `<th>${escapeHtml(rulesColumnLabel("markings"))}</th>`,
    `<th>${escapeHtml(t("rules.col.rule"))}</th>`,
    `<th>${escapeHtml(t("rules.col.outputs"))}</th>`,
    `<th>${escapeHtml(t("rules.col.emulation"))}</th>`,
  ];

  const table = document.getElementById("rules-table");
  const cardsRoot = document.getElementById("rules-cards");
  const meta = document.getElementById("rules-meta");
  const pager = document.getElementById("rules-pager");
  if (!state.rules.allEntries.length) {
    if (table) table.innerHTML = "";
    if (cardsRoot) cardsRoot.innerHTML = "";
    if (meta) meta.textContent = "";
    if (pager) pager.innerHTML = "";
    updateRulesViewModeUI();
    updateRulesBulkState();
    renderRulesWorkspace();
    return;
  }

  table.innerHTML = `
    <thead>
      <tr>${headers.join("")}</tr>
    </thead>
    <tbody>${rows.length ? rows.join("") : emptyRow}</tbody>
  `;
  renderRulesCards();
  updateRulesViewModeUI();
  const modeLabel = state.rules.viewMode === "cards" ? t("rules.view.cards") : t("rules.view.table");
  if (meta) meta.textContent = `${state.rules.entries.length}/${state.rules.total} ${t("common.entries")} · ${modeLabel}`;
  renderPager("rules-pager", state.rules.page, state.rules.pageSize, state.rules.total, "rules");
  updateRulesBulkState();
  renderRulesWorkspace();
}

async function loadRules(page = state.rules.page) {
  const query = {
    page: 1,
    page_size: 400,
  };
  const response = await api(`/api/rules${toQuery(query)}`);
  state.rules.page = page;
  state.rules.allEntries = response.entries || [];
  state.rules.loaded = true;
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
  renderRulesWorkspace();
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
  refreshCustomComboboxes(document);
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
  const selectAllButton = document.getElementById("adversaries-select-all-header");
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
    selectAllButton.checked = allFilteredSelected;
    selectAllButton.indeterminate = count > 0 && !allFilteredSelected;
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

  const exportTargets = ADVERSARY_EXPORTERS;
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
          <button class="btn btn-primary" data-action="adversary-edit" data-id="${escapeHtml(entry.id)}">${escapeHtml(t("adversaries.view.details"))}</button>
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

  const exportTargets = ADVERSARY_EXPORTERS;
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
    cells.push(`
      <td>
        <div class="adversary-row-actions">
          <button class="btn btn-primary" data-action="adversary-edit" data-id="${escapeHtml(entry.id)}">${escapeHtml(t("adversaries.view.details"))}</button>
        </div>
      </td>
    `);
    return `<tr data-adversary-row-id="${escapeHtml(entry.id)}">${cells.join("")}</tr>`;
  });
  const visibleCount = displayedAdversaryColumns.filter((column) => column === "markings" || isVisible(column)).length;
  const emptyRow = `
    <tr class="table-empty-row">
      <td colspan="${2 + Math.max(1, visibleCount)}">${escapeHtml(t("common.no_data"))}</td>
    </tr>
  `;

  const currentSort = state.adversaries.sort || "confidence_desc";
  const headers = [`<th><input type="checkbox" id="adversaries-select-all-header" data-action="adversaries-select-all-toggle" aria-label="${escapeHtml(t("adversaries.bulk.select_all"))}"></th>`];
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
  headers.push(`<th>${escapeHtml(t("common.actions"))}</th>`);

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
  state.adversaries.loaded = true;
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
  renderAdversaryWorkspace();
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
  clearCustomPayloadForm();
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
      const customPayload = isCustomPayloadAbility(entry);
      return `
      <article class="ability-item selected-ability-item">
        <div class="selected-step-index">${index + 1}</div>
        <div class="ability-copy">
          <strong>${escapeHtml(entry.name)} ${customPayload ? `<span class="custom-payload-badge">${escapeHtml(t("adversaries.payload.badge"))}</span>` : ""}</strong>
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
          <button type="button" class="btn btn-ghost" data-action="ability-show" data-id="${entry.id}">${escapeHtml(t("common.details"))}</button>
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
  renderAdversaryValidationSummary();
  setAdversaryFormSubmitState();
}

function setAdversaryTab(tab) {
  const normalized = tab === "criteria" ? "criteria" : "plan";
  state.adversaryCompose.activeTab = normalized;
  const settings = document.getElementById("adversary-pane-plan-settings");
  const selected = document.getElementById("adversary-pane-plan-selected");
  const customPayload = document.getElementById("adversary-pane-custom-payload");
  const criteria = document.getElementById("adversary-pane-criteria");
  if (settings) settings.classList.toggle("hidden", normalized !== "plan");
  if (selected) selected.classList.toggle("hidden", normalized !== "plan");
  if (customPayload) customPayload.classList.toggle("hidden", normalized !== "plan");
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

function isCustomPayloadAbility(entry) {
  return Array.isArray(entry?.actions)
    && entry.actions.some((action) => String(action?.action_type || "").toLowerCase() === "custom_payload");
}

function renderAdversaryValidationSummary() {
  const root = document.getElementById("adversary-validation-summary");
  if (!root) return;
  const name = document.getElementById("adversary-name")?.value?.trim() || "";
  const targetPlatform = String(document.getElementById("adversary-target-platform")?.value || "").trim();
  const selected = state.adversaryCompose.selectedOrder || [];
  const exportCount = state.adversaryCompose.compatibleExports?.length || 0;
  const rows = [
    {
      ok: Boolean(name),
      title: t("adversaries.validation.name"),
      body: name ? t("adversaries.validation.name_ok") : t("adversaries.validation.name_missing"),
    },
    {
      ok: Boolean(targetPlatform),
      title: t("adversaries.validation.platform"),
      body: targetPlatform ? targetPlatform : t("adversaries.validation.platform_missing"),
    },
    {
      ok: selected.length > 0,
      title: t("adversaries.validation.steps"),
      body: selected.length > 0
        ? tf("adversaries.validation.steps_ok", { count: selected.length })
        : t("adversaries.validation.steps_missing"),
    },
    {
      ok: exportCount > 0,
      title: t("adversaries.validation.exporters"),
      body: exportCount > 0
        ? state.adversaryCompose.compatibleExports.join(", ")
        : t("adversaries.validation.exporters_missing"),
    },
  ];
  root.innerHTML = rows
    .map((row) => `
      <div class="adversary-validation-item ${row.ok ? "ok" : "warn"}">
        <strong>${escapeHtml(row.title)}</strong>
        <span class="muted">${escapeHtml(row.body)}</span>
      </div>
    `)
    .join("");
}

function mapLangToHljs(lang) {
  const map = { bash: "bash", powershell: "powershell", python: "python", javascript: "javascript", rubber_ducky: "plaintext" };
  return map[String(lang).toLowerCase()] || "plaintext";
}

function initCodeEditor(textarea) {
  if (!textarea || textarea.closest(".code-editor-wrap")) return null;
  const lang = mapLangToHljs(textarea.dataset.lang || "plaintext");
  const wrap = document.createElement("div");
  wrap.className = "code-editor-wrap";
  const pre = document.createElement("pre");
  const code = document.createElement("code");
  code.className = `language-${lang}`;
  pre.appendChild(code);
  textarea.parentNode.insertBefore(wrap, textarea);
  wrap.appendChild(pre);
  wrap.appendChild(textarea);
  function syncHighlight() {
    code.textContent = textarea.value + "\n";
    if (window.hljs) hljs.highlightElement(code);
  }
  textarea.addEventListener("input", syncHighlight);
  textarea.addEventListener("scroll", () => {
    pre.scrollTop = textarea.scrollTop;
    pre.scrollLeft = textarea.scrollLeft;
  });
  textarea.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = textarea.selectionStart;
      const end = textarea.selectionEnd;
      textarea.value = textarea.value.substring(0, s) + "  " + textarea.value.substring(end);
      textarea.selectionStart = textarea.selectionEnd = s + 2;
      syncHighlight();
    }
  });
  wrap._codeEl = code;
  wrap._sync = syncHighlight;
  syncHighlight();
  return wrap;
}

function updateCodeEditorLang(textarea, lang) {
  const wrap = textarea?.closest(".code-editor-wrap");
  if (!wrap || !wrap._codeEl) return;
  wrap._codeEl.className = `language-${mapLangToHljs(lang)}`;
  if (wrap._sync) wrap._sync();
}

function payloadPlatformForComposer() {
  return String(document.getElementById("adversary-target-platform")?.value || "").trim().toLowerCase()
    || String(document.getElementById("adversary-ability-platform")?.value || "").trim().toLowerCase()
    || "any";
}

function syncPayloadLanguageWithRunner() {
  const runner = document.getElementById("adversary-payload-runner");
  const language = document.getElementById("adversary-payload-language");
  if (!(runner instanceof HTMLSelectElement) || !(language instanceof HTMLSelectElement)) return;
  const value = runner.value === "spuc-agent" ? language.value : runner.value;
  if ([...language.options].some((option) => option.value === value)) {
    language.value = value;
  }
}

function renderCustomPayloadPreview() {
  const preview = document.getElementById("adversary-payload-preview");
  if (!preview) return;
  const name = document.getElementById("adversary-flow-payload-name")?.value?.trim() || t("adversaries.payload.untitled");
  const runner = document.getElementById("adversary-flow-payload-runner")?.value || "spuc-agent";
  const language = document.getElementById("adversary-flow-payload-tech")?.value || runner;
  const platform = payloadPlatformForComposer();
  const payload = document.getElementById("adversary-flow-payload-content")?.value || "";
  preview.textContent = [
    `${t("adversaries.payload.name")}: ${name}`,
    `${t("adversaries.payload.runner")}: ${runner}`,
    `${t("adversaries.create.target_platform")}: ${platform}`,
    `${t("adversaries.payload.language")}: ${language}`,
    "",
    payload || t("adversaries.payload.empty_preview"),
  ].join("\n");
  preview.classList.remove("hidden");
}

function clearCustomPayloadForm() {
  ["adversary-flow-payload-name", "adversary-flow-payload-desc", "adversary-flow-payload-content"].forEach((id) => {
    const node = document.getElementById(id);
    if (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement) {
      node.value = "";
      node.dispatchEvent(new Event("input"));
    }
  });
  const preview = document.getElementById("adversary-payload-preview");
  if (preview) {
    preview.textContent = "";
    preview.classList.add("hidden");
  }
}

async function addCustomPayloadStep() {
  const name = document.getElementById("adversary-payload-name")?.value?.trim() || "";
  const payload = document.getElementById("adversary-payload-content")?.value?.trim() || "";
  if (!name || !payload) {
    showToast("adversaries.payload.validation_missing", true);
    return;
  }
  const runner = document.getElementById("adversary-payload-runner")?.value || "spuc-agent";
  const payloadLanguage = document.getElementById("adversary-payload-language")?.value || runner;
  await createDummyAbility({
    kind: "custom_payload",
    name,
    description: document.getElementById("adversary-payload-description")?.value || "",
    platform: payloadPlatformForComposer(),
    runner,
    payload_language: payloadLanguage,
    payload,
    safety_notes: t("adversaries.payload.safety"),
  });
  clearCustomPayloadForm();
}

function openAdversaryAbilityPicker() {
  const dialog = document.getElementById("adversary-ability-picker-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  setAdversaryPickerTab("catalog");
  renderAdversaryAbilitySelector();
  dialog.showModal();
  setTimeout(() => document.getElementById("adversary-ability-search")?.focus(), 0);
}

function openAdversaryPayloadPicker() {
  const dialog = document.getElementById("adversary-payload-picker-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  renderAdversaryEditorPayloadsList();
  dialog.showModal();
  setTimeout(() => document.getElementById("adversary-flow-payload-search")?.focus(), 0);
}

function closeAdversaryPayloadPicker() {
  const dialog = document.getElementById("adversary-payload-picker-dialog");
  if (dialog instanceof HTMLDialogElement) {
    dialog.close();
  }
}

function openAdversaryPayloadForm() {
  const dialog = document.getElementById("adversary-payload-form-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  clearCustomPayloadForm();
  renderCustomPayloadPreview();
  dialog.showModal();
  const contentTextarea = document.getElementById("adversary-flow-payload-content");
  if (contentTextarea) {
    const lang = String(document.getElementById("adversary-flow-payload-tech")?.value || "bash");
    if (!contentTextarea.closest(".code-editor-wrap")) {
      initCodeEditor(contentTextarea);
    } else {
      updateCodeEditorLang(contentTextarea, lang);
    }
  }
  setTimeout(() => document.getElementById("adversary-flow-payload-name")?.focus(), 0);
}

function openPayloadCatalogCreateModal(payloadId = "") {
  const dialog = document.getElementById("payload-catalog-form-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  const form = document.getElementById("payload-catalog-create-form");
  const existing = payloadId ? (state.customPayloads.entries || []).find((entry) => entry.id === payloadId) : null;
  state.customPayloads.editingId = existing?.id || "";
  if (form instanceof HTMLFormElement) form.reset();
  const title = document.getElementById("payload-catalog-form-title");
  const submit = document.getElementById("payload-catalog-save-create");
  if (title) {
    title.textContent = existing ? t("payloads.create.edit_title") : t("payloads.create.title");
  }
  if (submit) {
    submit.textContent = existing ? t("adversaries.payload.update") : t("adversaries.payload.save");
  }
  if (existing) {
    const nameInput = document.getElementById("payload-catalog-create-name");
    const techSelect = document.getElementById("payload-catalog-create-tech");
    const descInput = document.getElementById("payload-catalog-create-desc");
    const contentInput = document.getElementById("payload-catalog-create-content");
    if (nameInput instanceof HTMLInputElement) nameInput.value = existing.name || "";
    if (techSelect instanceof HTMLSelectElement) techSelect.value = existing.technology || "bash";
    if (descInput instanceof HTMLTextAreaElement) descInput.value = existing.description || "";
    if (contentInput instanceof HTMLTextAreaElement) contentInput.value = existing.content || "";
  }
  dialog.showModal();
  const contentTextarea = document.getElementById("payload-catalog-create-content");
  if (contentTextarea) {
    const lang = String(document.getElementById("payload-catalog-create-tech")?.value || "bash");
    if (!contentTextarea.closest(".code-editor-wrap")) {
      initCodeEditor(contentTextarea);
    } else {
      updateCodeEditorLang(contentTextarea, lang);
    }
  }
  setTimeout(() => document.getElementById("payload-catalog-create-name")?.focus(), 0);
}

function closePayloadCatalogCreateModal() {
  const dialog = document.getElementById("payload-catalog-form-dialog");
  if (dialog instanceof HTMLDialogElement) dialog.close();
  state.customPayloads.editingId = "";
}

function savePayloadFromCatalogModal() {
  const name = String(document.getElementById("payload-catalog-create-name")?.value || "").trim();
  const technology = String(document.getElementById("payload-catalog-create-tech")?.value || "bash").toLowerCase();
  const compatibleRunners = PAYLOAD_TYPE_TO_RUNNERS[technology] || ["spuc-agent"];
  const description = String(document.getElementById("payload-catalog-create-desc")?.value || "").trim();
  const content = String(document.getElementById("payload-catalog-create-content")?.value || "");
  if (!name || !content.trim()) {
    showToast("adversaries.payload.validation_missing", true);
    return false;
  }
  const now = new Date().toISOString();
  const editingId = String(state.customPayloads.editingId || "");
  const existing = editingId ? (state.customPayloads.entries || []).find((entry) => entry.id === editingId) : null;
  const payloadId = existing?.id || `payload-${Date.now()}`;
  const entry = normalizeCustomPayloadEntry({
    id: payloadId,
    name,
    technology,
    compatibleRunners,
    description,
    content,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  });
  state.customPayloads.entries = existing
    ? [entry, ...(state.customPayloads.entries || []).filter((item) => item.id !== entry.id)]
    : [entry, ...(state.customPayloads.entries || [])];
  state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
  persistCustomPayloadCatalog();
  closePayloadCatalogCreateModal();
  renderAdversaryWorkspace();
  renderPayloadCatalogWorkspace();
  showToast("toast.saved");
  return true;
}

function closeAdversaryPayloadForm() {
  const dialog = document.getElementById("adversary-payload-form-dialog");
  if (dialog instanceof HTMLDialogElement) {
    dialog.close();
  clearCustomPayloadForm();
  }
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
  // Editing is explicit: save/cancel are controlled from the workspace header.
}

async function persistAdversaryAutosave() {
  syncAdversaryComposerFromInputs();
  const selected = [...state.adversaryCompose.selectedOrder];
  const name = document.getElementById("adversary-name")?.value?.trim() || "";
  const targetPlatform = String(document.getElementById("adversary-target-platform")?.value || "").trim().toLowerCase();
  if (!name || !targetPlatform || selected.length === 0) {
    showToast("adversaries.validation.steps_missing", true);
    return null;
  }
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
    if (state.adversaryCompose.editingId) {
      return api(`/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}`);
    }
    return null;
  }
  state.adversaryCompose.autoSaving = true;
  try {
    let savedId = state.adversaryCompose.editingId || null;
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
      savedId = createdId;
      const created = createdId ? await api(`/api/adversaries/${encodeURIComponent(createdId)}`).catch(() => response) : response;
      state.adversaryCompose.mode = "edit";
      state.adversaryCompose.editingId = createdId;
      state.adversaryCompose.compatibleExports = [];
      setAdversaryFormMode("edit", created);
    }
    state.adversaryCompose.originalSignature = signature;
    const saved = savedId ? await api(`/api/adversaries/${encodeURIComponent(savedId)}`) : null;
    if (saved) {
      state.adversaryView.entry = saved;
      state.adversaryView.activeId = saved.id || null;
    }
    return saved;
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
  updateAdversaryEditorHeading();
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
  state.adversaryCompose.originalEntry = adversary ? JSON.parse(JSON.stringify(adversary)) : null;
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
    submit.classList.add("btn-primary");
  }
  syncAdversaryExportInlineControls();
  renderAdversaryExecutionCriteria();
  syncAdversaryModalTitle();
  renderAdversaryWorkspaceHeader();
}

function setAdversaryFormSubmitState() {
  const submit = document.getElementById("adversary-submit");
  if (!(submit instanceof HTMLButtonElement)) return;
  const hasName = Boolean(document.getElementById("adversary-name")?.value?.trim());
  const hasTargetPlatform = Boolean(String(document.getElementById("adversary-target-platform")?.value || "").trim());
  submit.disabled = !hasName || !hasTargetPlatform;
}

function populateAdversaryCreatePlatformOptions() {
  const targetPlatform = document.getElementById("adversary-target-platform");
  if (!(targetPlatform instanceof HTMLSelectElement)) return;
  const values = state.abilities.entries
    .flatMap((entry) => entry.platforms || [])
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  const unique = [...new Set(values)].sort((a, b) => a.localeCompare(b));
  targetPlatform.innerHTML = [
    `<option value="">${escapeHtml(t("common.all_platforms"))}</option>`,
    ...unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
  ].join("");
  refreshCustomComboboxes(document);
}

function openAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  document.getElementById("adversary-form")?.reset();
  populateAdversaryCreatePlatformOptions();
  const title = document.getElementById("adversary-form-title");
  if (title) title.textContent = t("adversaries.create.title");
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  setAdversaryFormSubmitState();
  if (!dialog.open) {
    dialog.showModal();
  }
}

async function openAdversaryEditor(adversaryId) {
  if (!adversaryId) return;
  await ensureAbilitiesLoaded();
  const adversary = await api(`/api/adversaries/${encodeURIComponent(adversaryId)}`);
  mountAdversaryEditorSurface();
  resetAdversaryComposer();
  document.getElementById("adversary-name").value = adversary.name || "";
  document.getElementById("adversary-description").value = adversary.description || "";
  const targetPlatform = document.getElementById("adversary-target-platform");
  if (targetPlatform instanceof HTMLSelectElement) {
    targetPlatform.value = String(adversary.target_platform || "").trim().toLowerCase();
  }
  state.adversaryCompose.selectedOrder = Array.isArray(adversary.ability_refs)
    ? [...adversary.ability_refs]
    : [];
  state.adversaryView.entry = adversary;
  state.adversaryView.activeId = adversary.id || null;
  state.adversaryView.activeTab = "plan";
  setAdversaryFormMode("edit", adversary);
  state.adversaryCompose.originalSignature = adversaryFormSignature();
  state.adversaryCompose.activeTab = "plan";
  setMarkdownEditorMode("adversary-description", "preview");
  refreshMarkdownEditorPreview("adversary-description");
  renderAdversaryAbilitySelector();
  setAdversaryTab("plan");
  showAdversaryEditorWorkspace();
  renderAdversaryWorkspaceHeader();
}

function closeAdversaryDialog() {
  const dialog = document.getElementById("adversary-dialog");
  if (dialog instanceof HTMLDialogElement && dialog.open) {
    dialog.close();
  }
  closeAdversaryAbilityPicker();
  resetAdversaryComposer();
  setAdversaryFormMode("create");
  state.adversaryCompose.originalSignature = "";
  state.adversaryCompose.originalEntry = null;
  state.adversaryView.entry = null;
  state.adversaryView.activeId = null;
  state.adversaryView.activeTab = "summary";
  document.getElementById("adversary-form")?.reset();
  renderAdversaryAbilitySelector();
  returnAdversaryEditorToList();
}

async function createAdversary(event) {
  event.preventDefault();
  const name = String(document.getElementById("adversary-name")?.value || "").trim();
  const targetPlatform = String(document.getElementById("adversary-target-platform")?.value || "").trim().toLowerCase();
  const description = String(document.getElementById("adversary-description")?.value || "").trim();
  if (!name || !targetPlatform) {
    showToast("toast.error_saving", true);
    return;
  }
  state.adversaryCompose.selectedOrder = [];
  state.adversaryCompose.editorSelectedStepId = null;
  state.adversaryCompose.editingId = null;
  state.adversaryCompose.mode = "create";
  state.adversaryCompose.editorLastSavedSignature = "";
  state.adversaryView.entry = {
    id: "",
    name,
    confidence: 70,
    target_platform: targetPlatform,
    description,
    ability_refs: [],
    steps: 0,
    compatible_exports: [],
  };
  state.adversaryView.activeId = null;
  state.adversaryView.activeTab = "summary";
  document.getElementById("adversary-dialog")?.close();
  showAdversaryEditorPanel();
  setAdversaryEditorTab("overview");
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
  setRuleLabEditorState("editor-neutral");
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
    button.classList.remove("btn-ghost");
    button.classList.add("btn-success");
  } else {
    button.classList.remove("btn-success");
    button.classList.add("btn-ghost");
  }
}

function setRuleLabExportBundleEnabled(enabled) {
  const button = document.getElementById("rulelab-export-bundle");
  if (!button) return;
  button.disabled = !enabled;
}

async function exportRuleLabBundle() {
  const rule = document.getElementById("rulelab-input")?.value || "";
  if (!rule.trim()) {
    showToast("common.no_data", true);
    return;
  }
  const payload = {
    rule,
    name: document.getElementById("rulelab-title")?.value || "Lab Rule",
    description: document.getElementById("rulelab-description")?.value || "",
    confidence: Number(document.getElementById("rulelab-confidence")?.value || 70),
    tlp: document.getElementById("rulelab-tlp")?.value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap")?.value || "PAP:GREEN",
    indicates_list: state.ruleLab.indicatesList || [],
  };
  const response = await fetch("/api/rules/export/bundle-from-pattern", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const maybeJson = await response.json().catch(() => ({ error: "bundle_export_failed" }));
    showToast(maybeJson.error || "bundle_export_failed", true);
    return;
  }
  const blob = await response.blob();
  const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
  const link = document.createElement("a");
  const url = URL.createObjectURL(blob);
  link.href = url;
  link.download = `spuc-lab-bundle-${ts}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  showToast("toast.export_ready");
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
  const panel = document.querySelector(".compatibility-inline");
  if (panel) {
    panel.classList.add("is-empty");
  }
  document.getElementById("compatibility-stack").innerHTML = "";
  document.getElementById("compatibility-list").innerHTML = `<div class="rule-output-empty">${escapeHtml(t("rulelab.compatibility.empty"))}</div>`;
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
  return state.compatibility;
}

function renderRuleLabCompatibilityResults() {
  const panel = document.querySelector(".compatibility-inline");
  if (panel) {
    panel.classList.remove("is-empty");
  }
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
    meta.textContent = tf("rulelab.outputs_count", { count: entries.length });
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
        <div class="compat-row-main">
          <span class="muted compat-row-summary">${escapeHtml(entry.summary)}</span>
          <div class="compat-row-actions">
            ${canShowCompatibilityOutput(entry)
      ? `<button class="btn btn-ghost" data-action="compat-show" data-target="${escapeHtml(entry.target)}">${escapeHtml(t("common.details"))}</button>
               <button class="btn btn-ghost" data-action="compat-copy" data-target="${escapeHtml(entry.target)}">${escapeHtml(t("detail.copy_rule"))}</button>`
      : ""}
          </div>
        </div>
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
  const rule = document.getElementById("rulelab-input").value;
  if (!rule.trim()) {
    state.ruleLab.syntaxOk = null;
    const statusNode = document.getElementById("rulelab-status");
    if (statusNode) {
      statusNode.textContent = t("rulelab.status.idle");
    }
    setRuleLabEditorState("editor-neutral");
    setRuleLabPatternStatus("empty", "");
    setRuleLabSaveEnabled(false);
    setRuleLabExportBundleEnabled(false);
    clearRuleLabCompatibilityView();
    return;
  }
  const payload = {
    rule,
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
    setRuleLabExportBundleEnabled(true);
  } else {
    state.ruleLab.syntaxOk = false;
    statusNode.innerHTML = `${statusBadge(t("rulelab.syntax_error"), "error")} ${escapeHtml(response.syntax_error || "")}`;
    setRuleLabEditorState("editor-invalid");
    setRuleLabPatternStatus("error", response.syntax_error || t("rulelab.invalid_pattern"));
    setRuleLabSaveEnabled(false);
    setRuleLabExportBundleEnabled(false);
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
  return persistRuleLab({ silent: false });
}

function scheduleRuleLabAutoSave() {
  // Rule Lab is intentionally manual-save only.
}

async function persistRuleLab({ silent = false } = {}) {
  if (state.ruleLab.autoSaving) return;
  if (state.ruleLab.syntaxOk !== true) {
    if (!silent) {
      showToast("rulelab.syntax_error", true);
    }
    return false;
  }
  const payload = {
    rule: document.getElementById("rulelab-input").value,
    name: document.getElementById("rulelab-title").value,
    description: document.getElementById("rulelab-description").value,
    confidence: Number(document.getElementById("rulelab-confidence").value || 70),
    tlp: document.getElementById("rulelab-tlp").value || "TLP:GREEN",
    pap: document.getElementById("rulelab-pap").value || "PAP:GREEN",
    indicates_list: state.ruleLab.indicatesList || [],
  };
  const signature = JSON.stringify(payload);
  if (signature === state.ruleLab.autoSaveLastSignature) {
    state.ruleLab.isDirty = false;
    setRuleLabSaveEnabled(false);
    return true;
  }
  state.ruleLab.autoSaving = true;
  try {
    await api("/api/rules/save", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.ruleLab.autoSaveLastSignature = signature;
    state.ruleLab.isDirty = false;
    setRuleLabSaveEnabled(false);
    if (!silent) {
      showToast("toast.saved");
    }
    await Promise.all([loadRules(state.rules.page || 1), loadOverview()]);
    renderDashboard();
    return true;
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

async function collectRulesFromFileInput(inputId = "rules-new-file") {
  const fileInput = document.getElementById(inputId);
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
  if (fileInput instanceof HTMLInputElement) {
    fileInput.value = "";
  }
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
  const emptyState = document.getElementById("rules-empty-state");
  const catalogMain = document.getElementById("rules-catalog-main");
  const panel = document.getElementById("panel-rules");
  const hasEntries = (state.rules.allEntries || []).length > 0;
  const visibleTotal = Number(state.rules.total || 0);
  const showEmptyState = mode === "explore" && (visibleTotal === 0 || !hasEntries);
  if (welcomeCard) {
    welcomeCard.classList.toggle("hidden", mode !== "welcome");
  }
  if (ingestCard) {
    ingestCard.classList.toggle("hidden", mode !== "file");
  }
  if (exploreShell) {
    exploreShell.classList.toggle("hidden", mode !== "explore");
  }
  if (emptyState) {
    emptyState.classList.toggle("hidden", !showEmptyState);
  }
  if (catalogMain) {
    catalogMain.classList.toggle("hidden", showEmptyState);
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", mode === "welcome" || showEmptyState);
  }
  renderRulesFiltersRevealer();
  refreshCustomComboboxes(document);
}

function renderRulesFiltersRevealer() {
  const revealer = document.getElementById("rules-filters-revealer");
  const toggle = document.getElementById("rules-filters-toggle");
  if (revealer) {
    revealer.classList.toggle("open", Boolean(state.rules.filtersOpen));
  }
  if (toggle) {
    toggle.setAttribute("aria-expanded", String(Boolean(state.rules.filtersOpen)));
    toggle.classList.toggle("active", Boolean(state.rules.filtersOpen));
  }
}

function renderAdversaryWorkspace() {
  const mode = state.adversaries.workspaceMode || "welcome";
  const welcomeCard = document.getElementById("adversaries-welcome-card");
  const catalogShell = document.getElementById("adversaries-catalog-shell");
  const payloadWelcomeCard = document.getElementById("payloads-welcome-card");
  const payloadCatalogShell = document.getElementById("payloads-catalog-shell");
  const payloadShell = document.getElementById("adversaries-payloads-shell");
  const editorView = document.getElementById("adversary-editor-view");
  const editorPanel = document.getElementById("panel-adversary-editor");
  const emptyState = document.getElementById("adversaries-empty-state");
  const catalogMain = document.getElementById("adversaries-catalog-main");
  const panel = document.getElementById("panel-adversaries");
  const hasEntries = (state.adversaries.allEntries || []).length > 0;
  const hasPayloads = (state.customPayloads.entries || []).length > 0;
  const showCatalog = mode === "catalog";
  const showPayloads = mode === "payloads";
  const showEditor = mode === "editor";
  const showEmptyState = showCatalog && state.adversaries.loaded && !hasEntries;
  const showPayloadWelcome = showPayloads && state.customPayloads.loaded && !hasPayloads;
  const showPayloadCatalog = showPayloads && hasPayloads;
  if (welcomeCard) {
    welcomeCard.classList.add("hidden");
  }
  if (catalogShell) {
    catalogShell.classList.toggle("hidden", !showCatalog);
  }
  if (payloadWelcomeCard) {
    payloadWelcomeCard.classList.toggle("hidden", !showPayloadWelcome);
  }
  if (payloadCatalogShell) {
    payloadCatalogShell.classList.toggle("hidden", !showPayloadCatalog);
  }
  if (payloadShell) {
    payloadShell.classList.toggle("hidden", !showPayloads);
  }
  if (editorView) {
    editorView.classList.toggle("hidden", !showEditor);
  }
  if (editorPanel && !showEditor) {
    editorPanel.classList.add("hidden");
    editorPanel.classList.remove("active");
  }
  if (emptyState) {
    emptyState.classList.toggle("hidden", !showEmptyState);
  }
  if (catalogMain) {
    catalogMain.classList.toggle("hidden", showEmptyState);
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", showEmptyState || showPayloadWelcome);
  }
  if (showPayloadCatalog) {
    renderPayloadCatalogFiltersRevealer();
    renderPayloadCatalogWorkspace();
  }
  refreshCustomComboboxes(document);
}

function mountAdversaryEditorSurface() {
  const mount = document.getElementById("adversary-editor-mount");
  const dialog = document.getElementById("adversary-dialog");
  const form = document.getElementById("adversary-form");
  const card = form?.closest(".detail-card") || dialog?.querySelector(".detail-card");
  if (!mount || !card) return;
  mount.innerHTML = "";
  if (!mount.contains(card)) {
    mount.appendChild(card);
  }
  state.adversaryCompose.editorMounted = true;
}

function updateAdversaryEditorHeading() {
  const heading = document.getElementById("adversary-editor-heading");
  const subtitle = document.getElementById("adversary-editor-subtitle");
  if (!heading) return;
  if (state.adversaryCompose.mode === "view" && state.adversaryView.entry) {
    const entry = state.adversaryView.entry;
    heading.textContent = entry.name || t("adversaries.edit.untitled");
    if (subtitle) {
      subtitle.textContent = tf("adversaries.detail.id_platform_steps", {
        id: entry.id || "-",
        platform: entry.target_platform || t("common.no_data"),
        steps: entry.steps ?? (entry.ability_refs || []).length,
      });
    }
    return;
  }

  const name = document.getElementById("adversary-name")?.value?.trim() || "";
  heading.textContent = state.adversaryCompose.mode === "edit"
    ? tf("adversaries.editor.editing_title", { name: name || t("adversaries.edit.untitled") })
    : t("adversaries.editor.new_title");
  if (subtitle) {
    subtitle.textContent = t("adversaries.editor.subtitle");
  }
}

function renderAdversaryWorkspaceHeader() {
  updateAdversaryEditorHeading();
  const primary = document.getElementById("adversary-editor-primary");
  const secondary = document.getElementById("adversary-editor-secondary");
  if (!(primary instanceof HTMLButtonElement) || !(secondary instanceof HTMLButtonElement)) return;

  if (state.adversaryCompose.mode === "view") {
    primary.classList.remove("hidden", "btn-success");
    primary.classList.add("btn-primary");
    primary.dataset.action = "adversary-enter-edit";
    primary.textContent = t("common.edit");
    secondary.classList.add("hidden");
    return;
  }

  primary.classList.remove("hidden", "btn-primary");
  primary.classList.add("btn-success");
  primary.dataset.action = "adversary-save";
  primary.textContent = t("common.save");
  const payload = adversaryEditorPayload();
  primary.disabled = !payload.name || !payload.target_platform || state.adversaryCompose.selectedOrder.length === 0;

  secondary.classList.add("hidden");
  secondary.dataset.action = "adversary-cancel-edit";
  secondary.textContent = t("common.cancel");
}

function showAdversaryEditorWorkspace() {
  state.adversaries.workspaceMode = "editor";
  renderAdversaryWorkspace();
  renderAdversaryWorkspaceHeader();
  localStorage.setItem("spuc-web-last-route", "adversaries");
  if (state.adversaryCompose.mode !== "view") {
    setTimeout(() => document.getElementById("adversary-name")?.focus(), 0);
  }
}

function returnAdversaryEditorToList() {
  closeAdversaryAbilityPicker();
  state.adversaryView.entry = null;
  state.adversaryView.activeId = null;
  state.adversaryView.activeTab = "summary";
  state.route = "adversaries";
  document.getElementById("panel-adversaries")?.classList.add("active");
  applyNavSelection("adversaries");
  refreshRouteMeta();
  state.adversaries.workspaceMode = "catalog";
  renderAdversaryWorkspace();
  void loadAdversaries(state.adversaries.page);
}

function openAdversaryAgentHelp() {
  const steps = [
    t("adversaries.help_agent.step1"),
    t("adversaries.help_agent.step2"),
    t("adversaries.help_agent.step3"),
    t("adversaries.help_agent.step4"),
  ];
  const body = [t("adversaries.help_agent.body"), "", ...steps.map((step, index) => `${index + 1}. ${step}`)].join("\n");
  openDetail(t("adversaries.help_agent.title"), body);
}

function renderStixObjectsWorkspace() {
  const hasEntries = (state.stixObjects || []).length > 0;
  const mode = state.route === "stix-objects-catalog" || hasEntries ? "catalog" : "welcome";
  state.stixObjectsView.workspaceMode = mode;
  const welcomeCard = document.getElementById("stix-objects-welcome-card");
  const catalogShell = document.getElementById("stix-objects-catalog-shell");
  const panel = document.getElementById("panel-stix-objects");
  const showWelcome = mode === "welcome" || !hasEntries;
  const showCatalog = mode === "catalog" && hasEntries;
  if (welcomeCard) {
    welcomeCard.classList.toggle("hidden", !showWelcome);
  }
  if (catalogShell) {
    catalogShell.classList.toggle("hidden", !showCatalog);
  }
  if (panel) {
    panel.classList.toggle("workspace-center-mode", showWelcome);
  }
  refreshCustomComboboxes(document);
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
  refreshCustomComboboxes(document);
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
    { acceptLabel: t("rules.delete_action") },
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
  const confirmed = await askForConfirmation(
    t("adversaries.confirm_delete_selected"),
    t("common.confirm_action"),
    { acceptLabel: t("adversaries.delete_action") },
  );
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
  refreshCustomComboboxes(document);
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
  const challengeIds = new Set(state.learning.challenges.map((entry) => String(entry.id || "")).filter(Boolean));
  state.completedChallenges = new Set(
    [...state.completedChallenges].filter((challengeId) => challengeIds.has(challengeId)),
  );
  document.getElementById("learning-search").value = state.learning.search;
  renderLearningPathOptions();
  document.getElementById("learning-only-pending").checked = state.learning.onlyPending;
  renderLearningGuides();
  renderLearningPathSummary();
  renderLearningChallenges();
  saveLearningProgress();

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
    saveLearningProgress();
    status.innerHTML = `${statusBadge("success", "success")} ${escapeHtml(t("learning.status.completed"))}`;
    renderLearningChallenges();
    return;
  }

  shell.classList.add("editor-partial");
  status.innerHTML = `${statusBadge("pending", "warning")} ${escapeHtml(response.message || t("learning.status.pending"))}`;
}

function isNoLoginSession() {
  return Boolean(state.bootstrap?.auth?.no_login);
}

function setSettingsTab(tab) {
  const normalized = ["personal", "application", "users"].includes(tab) ? tab : "personal";
  const noLoginActive = isNoLoginSession();
  const isAdmin = state.principal?.role === "admin";
  const applicationEnabled = isAdmin;
  const usersEnabled = isAdmin && !noLoginActive;
  const effective = normalized === "application" && !applicationEnabled
    ? "personal"
    : normalized === "users" && !usersEnabled
      ? "personal"
      : normalized;
  state.settings.activeTab = effective;

  document.querySelectorAll("[data-action='settings-tab']").forEach((button) => {
    const tabId = button.dataset.tab || "personal";
    const enabled = tabId === "personal"
      || (tabId === "application" && applicationEnabled)
      || (tabId === "users" && usersEnabled);
    button.disabled = !enabled;
    button.classList.toggle("active", tabId === effective);
    button.classList.toggle("is-disabled", !enabled);
  });

  document.querySelectorAll("[data-settings-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.settingsPanel !== effective);
  });
}

function userMatchesSettingsFilters(user) {
  const filters = state.settings.usersFilters;
  const search = String(filters.search || "").trim().toLowerCase();
  const roleMatch = filters.role === "all" || String(user.role || "") === filters.role;
  const statusMatch = filters.status === "all"
    || (filters.status === "enabled" && Boolean(user.enabled))
    || (filters.status === "disabled" && !Boolean(user.enabled));
  if (!roleMatch || !statusMatch) return false;
  if (!search) return true;
  const haystack = [user.username, user.display_name, user.id]
    .map((value) => String(value || "").toLowerCase())
    .join(" ");
  return haystack.includes(search);
}

function renderAdminUsersTable() {
  const noLoginActive = isNoLoginSession();
  const users = state.adminUsers.filter((entry) => userMatchesSettingsFilters(entry));
  const rows = users.map((user) => `
    <tr>
      <td>
        <div class="settings-user-main">
          <strong>${escapeHtml(user.username)}</strong>
          <small class="muted mono">${escapeHtml(user.id)}</small>
        </div>
      </td>
      <td>
        ${
          user.id === state.principal.user_id
            ? escapeHtml(user.display_name || user.username)
            : `<input class="admin-user-display-input" data-admin-display-name="${user.id}" value="${escapeHtml(user.display_name || user.username)}">`
        }
      </td>
      <td>
        ${
  user.id === state.principal.user_id || noLoginActive
    ? statusBadge(user.role, user.role === "admin" ? "warning" : "success")
    : `<select class="admin-role-select" data-admin-role="${user.id}">
              <option value="analyst" ${user.role === "analyst" ? "selected" : ""}>${escapeHtml(t("admin.role.analyst"))}</option>
              <option value="admin" ${user.role === "admin" ? "selected" : ""}>${escapeHtml(t("admin.role.admin"))}</option>
            </select>`
}
      </td>
      <td>${user.local_auth ? statusBadge(t("settings.admin.users.local_account"), "success") : statusBadge(t("settings.admin.users.external_account"), "warning")}</td>
      <td>
        ${
  !user.local_auth
    ? statusBadge(t("settings.password.unavailable"), "warning")
    : `<label class="admin-enabled-toggle">
            <input type="checkbox" data-admin-totp="${user.id}" ${user.totp_enabled ? "checked" : ""} ${noLoginActive ? "disabled" : ""}>
            <span>${user.totp_enabled ? escapeHtml(t("common.enabled")) : escapeHtml(t("common.disabled"))}</span>
          </label>`
}
      </td>
      <td>${escapeHtml(user.created_at_utc)}</td>
      <td>
        ${
  user.id === state.principal.user_id || noLoginActive
    ? (user.enabled ? statusBadge(t("common.enabled"), "success") : statusBadge(t("common.disabled"), "error"))
    : `<label class="admin-enabled-toggle">
            <input type="checkbox" data-admin-enabled="${user.id}" ${user.enabled ? "checked" : ""}>
            <span>${user.enabled ? escapeHtml(t("common.enabled")) : escapeHtml(t("common.disabled"))}</span>
          </label>`
}
      </td>
      <td>
        ${
          user.id === state.principal.user_id || !user.local_auth || noLoginActive
            ? statusBadge(t("settings.password.unavailable"), "warning")
            : `<div class="settings-user-password-row">
                <input type="password" data-admin-password="${user.id}" data-i18n-placeholder="admin.password.new" placeholder="New password">
                <button class="btn btn-primary" data-action="admin-reset-password" data-id="${user.id}">${escapeHtml(t("settings.admin.users.change_password"))}</button>
              </div>`
        }
      </td>
      <td>
        ${
          user.id === state.principal.user_id || noLoginActive
            ? ""
            : `<button class="btn btn-primary" data-action="admin-update-user" data-id="${user.id}">${escapeHtml(t("common.apply"))}</button>
               <button class="btn btn-danger" data-action="admin-delete-user" data-id="${user.id}">${escapeHtml(t("admin.delete"))}</button>`
        }
      </td>
    </tr>
  `);
  renderTable(
    "admin-users-table",
    [
      t("admin.col.username"),
      t("settings.admin.users.display_name"),
      t("admin.col.role"),
      t("settings.admin.users.account_type"),
      t("settings.admin.users.totp"),
      t("admin.col.created"),
      t("admin.col.enabled"),
      t("settings.admin.users.password"),
      t("admin.col.actions"),
    ],
    rows,
  );
  refreshCustomComboboxes(document);
}

async function loadAdminOauthProviders() {
  const container = document.getElementById("admin-oauth-providers");
  if (!container) return;
  if (state.principal?.role !== "admin") {
    container.innerHTML = "";
    return;
  }
  const noLoginActive = isNoLoginSession();
  let entries = [];
  if (noLoginActive) {
    entries = (state.bootstrap?.auth?.providers || []).map((provider) => ({
      id: provider.id,
      label: provider.label,
      configured: Boolean(provider.configured),
      authorized: Boolean(provider.authorized),
      enabled: Boolean(provider.enabled),
      auth_url: provider.auth_url || "",
    }));
  } else {
    const response = await api("/api/admin/oauth/providers");
    entries = (response.entries || []).map((provider) => {
      const bootstrapProvider = (state.bootstrap?.auth?.providers || []).find((item) => item.id === provider.id);
      return {
        ...provider,
        auth_url: bootstrapProvider?.auth_url || "",
      };
    });
  }
  state.adminOauthProviders = entries;
  container.innerHTML = entries.map((provider) => `
    <article class="admin-oauth-row">
      <div class="admin-oauth-main">
        <strong>${escapeHtml(provider.label || provider.id || "")}</strong>
        <div class="admin-oauth-meta">
          ${provider.configured
      ? statusBadge(t("admin.oauth.configured"), "success")
      : statusBadge(t("admin.oauth.not_configured"), "error")}
          ${provider.authorized
      ? statusBadge(t("common.enabled"), "success")
      : statusBadge(t("common.disabled"), "warning")}
        </div>
      </div>
      <div class="admin-oauth-actions">
        <button class="btn btn-primary" data-action="admin-oauth-configure" data-provider="${escapeHtml(provider.id || "")}" ${noLoginActive ? "disabled" : ""}>${escapeHtml(t("admin.oauth.configure"))}</button>
      </div>
    </article>
  `).join("");
}

function openAdminProviderConfigDialog(providerId) {
  const dialog = document.getElementById("admin-provider-dialog");
  if (!(dialog instanceof HTMLDialogElement)) return;
  const provider = state.adminOauthProviders.find((entry) => String(entry.id || "") === String(providerId || ""));
  if (!provider) return;

  const providerIdInput = document.getElementById("admin-provider-id");
  const providerName = document.getElementById("admin-provider-name");
  const providerAuthUrl = document.getElementById("admin-provider-auth-url");
  const providerAuthorized = document.getElementById("admin-provider-authorized");
  const providerSummary = document.getElementById("admin-provider-config-summary");
  const saveButton = document.getElementById("admin-provider-save");
  const noLoginActive = isNoLoginSession();

  if (providerIdInput instanceof HTMLInputElement) providerIdInput.value = String(provider.id || "");
  if (providerName instanceof HTMLInputElement) providerName.value = String(provider.label || provider.id || "");
  if (providerAuthUrl instanceof HTMLInputElement) {
    providerAuthUrl.value = String(provider.auth_url || "");
    providerAuthUrl.placeholder = t("admin.oauth.configure.auth_url_unavailable");
  }
  if (providerAuthorized instanceof HTMLInputElement) {
    providerAuthorized.checked = Boolean(provider.authorized);
    providerAuthorized.disabled = noLoginActive || !provider.configured;
  }
  if (saveButton instanceof HTMLButtonElement) {
    saveButton.disabled = noLoginActive || !provider.configured;
  }
  if (providerSummary) {
    providerSummary.textContent = provider.configured
      ? t("admin.oauth.configure.configured")
      : t("admin.oauth.configure.not_configured");
  }

  dialog.showModal();
}

function closeAdminProviderConfigDialog() {
  const dialog = document.getElementById("admin-provider-dialog");
  if (dialog instanceof HTMLDialogElement) {
    dialog.close();
  }
}

function toggleSettingsUsersFilters() {
  state.settings.usersFilters.open = !state.settings.usersFilters.open;
  const panel = document.getElementById("settings-users-filters");
  panel?.classList.toggle("hidden", !state.settings.usersFilters.open);
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
  const defaultLocale = document.getElementById("admin-default-locale");
  const defaultTheme = document.getElementById("admin-default-theme");
  const defaultTotp = document.getElementById("admin-default-totp");
  const tokenHint = document.getElementById("admin-sigma-rpc-token-hint");
  const noLoginActive = isNoLoginSession();
  state.adminRuntimeSettings = entry;

  if (sigmaUrl instanceof HTMLInputElement) {
    sigmaUrl.value = entry.sigma_rpc_url || "";
  }
  if (sigmaToken instanceof HTMLInputElement) {
    sigmaToken.value = "";
  }
  if (defaultLocale instanceof HTMLSelectElement) {
    defaultLocale.value = entry.default_locale || "en";
    defaultLocale.disabled = noLoginActive;
  }
  if (defaultTheme instanceof HTMLSelectElement) {
    defaultTheme.value = entry.default_theme || "dark";
    defaultTheme.disabled = noLoginActive;
  }
  if (defaultTotp instanceof HTMLSelectElement) {
    defaultTotp.value = entry.default_totp_required ? "required" : "disabled";
    defaultTotp.disabled = noLoginActive;
  }
  if (tokenHint) {
    tokenHint.textContent = entry.sigma_rpc_token_set
      ? t("admin.settings.sigma_token_set")
      : t("admin.settings.sigma_token_unset");
  }

  const disabledNote = document.getElementById("settings-application-disabled-note");
  disabledNote?.classList.toggle("hidden", !noLoginActive);
  refreshCustomComboboxes(document);
}

function populateSettingsProfileForm() {
  const entry = state.userSettings || state.bootstrap?.user;
  if (!entry) return;
  const displayName = document.getElementById("settings-display-name");
  const locale = document.getElementById("settings-locale");
  const theme = document.getElementById("settings-theme");
  const accountId = document.getElementById("settings-account-id");
  const currentPassword = document.getElementById("settings-current-password");
  const nextPassword = document.getElementById("settings-next-password");
  const submit = document.getElementById("settings-password-submit");
  const disabledReason = document.getElementById("settings-password-disabled");
  const passwordForm = document.getElementById("settings-password-form");
  const passwordSection = document.getElementById("settings-password-section");

  if (displayName instanceof HTMLInputElement) {
    displayName.value = entry.display_name || entry.username || "";
  }
  if (locale instanceof HTMLSelectElement) {
    locale.value = entry.locale || "en";
  }
  if (theme instanceof HTMLSelectElement) {
    theme.value = entry.theme || "dark";
  }
  if (accountId instanceof HTMLInputElement) {
    accountId.value = entry.account_id || "";
  }

  const canChangePassword = Boolean(entry.can_change_password);
  const noLoginActive = Boolean(entry.no_login);
  if (passwordSection) {
    passwordSection.classList.toggle("hidden", noLoginActive);
  }
  const reasonKey = entry.no_login
    ? "settings.password.disabled_no_login"
    : entry.is_bootstrap_admin
      ? "settings.password.disabled_bootstrap_admin"
      : !entry.local_auth
        ? "settings.password.disabled_external_account"
        : "";

  if (currentPassword instanceof HTMLInputElement) currentPassword.disabled = !canChangePassword;
  if (nextPassword instanceof HTMLInputElement) nextPassword.disabled = !canChangePassword;
  if (submit instanceof HTMLButtonElement) submit.disabled = !canChangePassword;
  if (passwordForm instanceof HTMLFormElement) {
    passwordForm.classList.toggle("is-disabled", !canChangePassword);
  }
  if (disabledReason) {
    disabledReason.classList.toggle("hidden", canChangePassword || !reasonKey);
    disabledReason.textContent = reasonKey ? t(reasonKey) : "";
  }
  refreshCustomComboboxes(document);
}

async function loadSettingsView() {
  const response = await api("/api/settings/profile");
  state.userSettings = response.entry || state.bootstrap?.user || null;
  if (state.principal) {
    state.principal.display_name = state.userSettings?.display_name || state.principal.username;
  }
  populateSettingsProfileForm();
  refreshIdentityPill();
  const adminSections = document.getElementById("settings-admin-sections");
  const usersDisabledNote = document.getElementById("settings-users-disabled-note");
  const isAdmin = state.principal?.role === "admin";
  const noLoginActive = isNoLoginSession();
  adminSections?.classList.toggle("hidden", !isAdmin);
  if (isAdmin) {
    await loadAdminRuntimeSettings();
    await loadAdminOauthProviders();
    if (noLoginActive) {
      state.adminUsers = [];
      renderAdminUsersTable();
    } else {
      const usersResponse = await api("/api/admin/users");
      state.adminUsers = usersResponse.entries || [];
      renderAdminUsersTable();
    }
  }
  usersDisabledNote?.classList.toggle("hidden", !noLoginActive);
  setSettingsTab(state.settings.activeTab || "personal");
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
  loadLearningProgress();
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
  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element) || !event.target.closest(".spuc-combobox")) {
      closeAllCustomComboboxes();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeAllCustomComboboxes();
    }
  });
  document.addEventListener("change", (event) => {
    if (event.target instanceof HTMLSelectElement && isCustomComboboxCandidate(event.target)) {
      syncCustomCombobox(event.target);
    }
  });

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
    showPasswordLogin();
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
  const rulesImportShortcut = document.getElementById("rules-import-file-shortcut");
  if (rulesImportShortcut instanceof HTMLInputElement) {
    rulesImportShortcut.addEventListener("change", async () => {
      try {
        setRulesImportBusy(true);
        const rules = await collectRulesFromFileInput("rules-import-file-shortcut");
        if (!rules.length) return;
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
    adversariesCreateOpen.addEventListener("click", () => createNewAdversaryInEditor());
  }
  ["payload-catalog-search", "payload-catalog-tech", "payload-catalog-runner"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener(node.tagName === "SELECT" ? "change" : "input", () => {
      renderPayloadCatalogWorkspace();
    });
  });
  const stixImportInput = document.getElementById("stix-import-file");
  if (stixImportInput instanceof HTMLInputElement) {
    stixImportInput.addEventListener("change", async () => {
      const [file] = Array.from(stixImportInput.files || []);
      if (!file) return;
      try {
        await importStixObjectsFromFile(file);
      } finally {
        stixImportInput.value = "";
      }
    });
  }
  [
    "adversary-editor-name",
    "adversary-editor-name",
    "adversary-editor-confidence",
    "adversary-editor-target-platform",
    "adversary-editor-description-input",
  ].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener("blur", () => {
      void saveAdversaryFromNewEditor({ showSavedToast: true });
    });
    node.addEventListener(node.tagName === "SELECT" ? "change" : "input", () => {
      if (id === "adversary-editor-confidence") {
        updateAdversaryEditorConfidenceValue();
      }
      renderAdversaryEditorHeader();
    });
  });
  ["adversary-flow-ability-search", "adversary-flow-ability-platform", "adversary-flow-ability-utility"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener(node.tagName === "SELECT" ? "change" : "input", () => {
      renderAdversaryEditorFlowAbilityOptions();
    });
  });
  ["adversary-flow-payload-search", "adversary-flow-payload-technology"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener(node.tagName === "SELECT" ? "change" : "input", () => {
      renderAdversaryEditorPayloadsList();
    });
  });
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
  const adversaryPayloadRunner = document.getElementById("adversary-payload-runner");
  if (adversaryPayloadRunner instanceof HTMLSelectElement) {
    adversaryPayloadRunner.addEventListener("change", () => {
      syncPayloadLanguageWithRunner();
      renderCustomPayloadPreview();
    });
  }
  ["adversary-payload-name", "adversary-payload-description", "adversary-payload-content", "adversary-payload-language"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener(node.tagName === "SELECT" ? "change" : "input", () => {
      const preview = document.getElementById("adversary-payload-preview");
      if (preview && !preview.classList.contains("hidden")) {
        renderCustomPayloadPreview();
      }
    });
  });
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
  ["adversary-name", "adversary-description"].forEach((id) => {
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
  const rulelabExportBundle = document.getElementById("rulelab-export-bundle");
  if (rulelabExportBundle) {
    rulelabExportBundle.addEventListener("click", async () => {
      await exportRuleLabBundle();
    });
  }
  document.getElementById("rulelab-save").addEventListener("click", async () => {
    await openRuleLabSaveDialog();
  });
  const ruleLabSaveDialog = document.getElementById("rulelab-save-dialog");
  const ruleLabSaveDialogClose = document.getElementById("rulelab-save-dialog-close");
  const ruleLabSaveCancel = document.getElementById("rulelab-save-cancel");
  if (ruleLabSaveDialogClose) {
    ruleLabSaveDialogClose.addEventListener("click", () => {
      if (ruleLabSaveDialog instanceof HTMLDialogElement) {
        ruleLabSaveDialog.close();
      }
    });
  }
  if (ruleLabSaveCancel) {
    ruleLabSaveCancel.addEventListener("click", () => {
      if (ruleLabSaveDialog instanceof HTMLDialogElement) {
        ruleLabSaveDialog.close();
      }
    });
  }
  const ruleLabSaveForm = document.getElementById("rulelab-save-form");
  if (ruleLabSaveForm instanceof HTMLFormElement) {
    ruleLabSaveForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const ok = await saveRuleLab();
      if (ok && ruleLabSaveDialog instanceof HTMLDialogElement) {
        ruleLabSaveDialog.close();
      }
    });
  }
  const ruleLabStixAdd = document.getElementById("rulelab-stix-add");
  if (ruleLabStixAdd) {
    ruleLabStixAdd.addEventListener("click", () => addRuleLabSelectedStixRelation());
  }
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
    saveLearningProgress();
    renderLearningChallenges();
  });
  document.getElementById("learning-path").addEventListener("change", (event) => {
    state.learning.pathFilter = event.target.value || "";
    saveLearningProgress();
    renderLearningChallenges();
  });
  document.getElementById("learning-only-pending").addEventListener("change", (event) => {
    state.learning.onlyPending = Boolean(event.target.checked);
    saveLearningProgress();
    renderLearningChallenges();
  });

  document.getElementById("admin-create-user").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/admin/users", {
      method: "POST",
      body: JSON.stringify({
        username: document.getElementById("admin-new-username").value,
        display_name: document.getElementById("admin-new-display-name").value,
        password: document.getElementById("admin-new-password").value,
        role: document.getElementById("admin-new-role").value,
      }),
    });
    showToast("toast.saved");
    event.target.reset();
    const dialog = document.getElementById("admin-create-user-dialog");
    if (dialog instanceof HTMLDialogElement) {
      dialog.close();
    }
    await loadSettingsView();
  });

  const createUserCancel = document.getElementById("admin-create-user-cancel");
  if (createUserCancel) {
    createUserCancel.addEventListener("click", () => {
      const dialog = document.getElementById("admin-create-user-dialog");
      if (dialog instanceof HTMLDialogElement) {
        dialog.close();
      }
    });
  }

  const providerCancel = document.getElementById("admin-provider-cancel");
  if (providerCancel) {
    providerCancel.addEventListener("click", () => {
      closeAdminProviderConfigDialog();
    });
  }

  const providerForm = document.getElementById("admin-provider-form");
  if (providerForm instanceof HTMLFormElement) {
    providerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (isNoLoginSession()) return;
      const providerId = document.getElementById("admin-provider-id")?.value || "";
      const authorized = Boolean(document.getElementById("admin-provider-authorized")?.checked);
      await api(`/api/admin/oauth/providers/${encodeURIComponent(providerId)}/update`, {
        method: "POST",
        body: JSON.stringify({ authorized }),
      });
      closeAdminProviderConfigDialog();
      showToast("toast.saved");
      await loadAdminOauthProviders();
    });
  }

  const usersFilterSearch = document.getElementById("admin-users-filter-search");
  const usersFilterRole = document.getElementById("admin-users-filter-role");
  const usersFilterStatus = document.getElementById("admin-users-filter-status");
  if (usersFilterSearch instanceof HTMLInputElement) {
    usersFilterSearch.addEventListener("input", (event) => {
      state.settings.usersFilters.search = event.target.value || "";
      renderAdminUsersTable();
    });
  }
  if (usersFilterRole instanceof HTMLSelectElement) {
    usersFilterRole.addEventListener("change", (event) => {
      state.settings.usersFilters.role = event.target.value || "all";
      renderAdminUsersTable();
    });
  }
  if (usersFilterStatus instanceof HTMLSelectElement) {
    usersFilterStatus.addEventListener("change", (event) => {
      state.settings.usersFilters.status = event.target.value || "all";
      renderAdminUsersTable();
    });
  }

  document.getElementById("settings-profile-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const response = await api("/api/settings/profile", {
      method: "POST",
      body: JSON.stringify({
        display_name: document.getElementById("settings-display-name").value,
        locale: document.getElementById("settings-locale").value,
        theme: document.getElementById("settings-theme").value,
      }),
    });
    state.userSettings = response.entry || state.userSettings;
    state.principal.display_name = state.userSettings?.display_name || state.principal?.username || "";
    setLocale(state.userSettings?.locale || state.locale);
    setTheme(state.userSettings?.theme || state.theme);
    applyTranslations();
    populateSettingsProfileForm();
    refreshIdentityPill();
    showToast("toast.saved");
    await reloadLocalizedAppData();
  });

  document.getElementById("settings-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/admin/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: document.getElementById("settings-current-password").value,
        new_password: document.getElementById("settings-next-password").value,
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
      const defaultTotpRequired = (document.getElementById("admin-default-totp")?.value || "disabled") === "required";
      await api("/api/admin/settings", {
        method: "POST",
        body: JSON.stringify({
          sigma_rpc_url: sigmaUrl,
          sigma_rpc_token: sigmaToken,
          default_locale: document.getElementById("admin-default-locale")?.value || "en",
          default_theme: document.getElementById("admin-default-theme")?.value || "dark",
          default_totp_required: defaultTotpRequired,
        }),
      });
      showToast("toast.saved");
      await loadAdminRuntimeSettings();
    });
  }

  document.getElementById("detail-close").addEventListener("click", () => {
    document.getElementById("detail-dialog").close();
  });
  const indicatesDialogClose = document.getElementById("indicates-dialog-close");
  if (indicatesDialogClose) {
    indicatesDialogClose.addEventListener("click", () => {
      document.getElementById("indicates-dialog").close();
    });
  }
  document.getElementById("indicates-cancel").addEventListener("click", () => {
    document.getElementById("indicates-dialog").close();
  });
  const stixObjectDialogClose = document.getElementById("stix-object-dialog-close");
  if (stixObjectDialogClose) {
    stixObjectDialogClose.addEventListener("click", () => {
      document.getElementById("stix-object-dialog").close();
      state.stixObjectsView.editingId = "";
      if (state.returnToIndicatesDialog) {
        state.returnToIndicatesDialog = false;
        renderIndicatesObjectOptions();
        document.getElementById("indicates-dialog").showModal();
      }
    });
  }
  document.getElementById("stix-object-cancel").addEventListener("click", () => {
    document.getElementById("stix-object-dialog").close();
    state.stixObjectsView.editingId = "";
    if (state.returnToIndicatesDialog) {
      state.returnToIndicatesDialog = false;
      renderIndicatesObjectOptions();
      document.getElementById("indicates-dialog").showModal();
    }
  });
  const indicatesSearch = document.getElementById("indicates-search");
  if (indicatesSearch) {
    indicatesSearch.addEventListener("input", () => {
      renderIndicatesSearchResults(indicatesSearch.value.trim());
    });
  }
  const stixObjectNameInput = document.getElementById("stix-object-name");
  if (stixObjectNameInput) {
    stixObjectNameInput.addEventListener("input", () => {
      const query = stixObjectNameInput.value.trim().toLowerCase();
      const similarDiv = document.getElementById("stix-name-similar");
      if (!similarDiv) return;
      if (!query || query.length < 2) { similarDiv.innerHTML = ""; similarDiv.classList.add("hidden"); return; }
      const matches = [
        ...state.stixObjects.map((o) => o.name),
        ...state.mitreAttack.map((o) => o.name),
      ].filter((n) => n.toLowerCase().includes(query)).slice(0, 5);
      if (!matches.length) { similarDiv.innerHTML = ""; similarDiv.classList.add("hidden"); return; }
      similarDiv.innerHTML = matches.map((n) => `<span class="stix-similar-item">${escapeHtml(n)}</span>`).join("");
      similarDiv.classList.remove("hidden");
    });
  }
  const stixSearchInput = document.getElementById("stix-objects-search");
  if (stixSearchInput instanceof HTMLInputElement) {
    stixSearchInput.addEventListener("input", () => {
      state.stixObjectsView.searchTerm = stixSearchInput.value.trim();
      renderStixObjectsTable();
    });
  }
  document.getElementById("indicates-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const catalogSelect = document.getElementById("indicates-object-select");
    const selectedStixId = catalogSelect instanceof HTMLSelectElement ? catalogSelect.value : "";
    const selectedObject = state.stixObjects.find((entry) => entry.stix_id === selectedStixId);
    if (!selectedObject) {
      showToast("rules.indicates.invalid_payload", true);
      return;
    }
    const stixId = selectedObject.stix_id;
    const objectName = selectedObject.name;
    if (state.indicatesMode === "lab") {
      state.ruleLab.indicatesList.push({ stix_id: stixId, object_name: objectName });
      document.getElementById("indicates-dialog").close();
      renderRuleLabIndicates();
      return;
    }
    const ruleId = document.getElementById("indicates-rule-id").value;
    if (!ruleId) {
      showToast("rules.indicates.invalid_payload", true);
      return;
    }
    await api(`/api/rules/${encodeURIComponent(ruleId)}/indicates`, {
      method: "POST",
      body: JSON.stringify({ stix_id: stixId, object_name: objectName }),
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
    const description = document.getElementById("stix-object-description")?.value?.trim() || "";
    const tlp = document.getElementById("stix-object-tlp")?.value || "TLP:AMBER";
    const pap = document.getElementById("stix-object-pap")?.value || "PAP:GREEN";
    const firstSeen = document.getElementById("stix-object-first-seen")?.value || "";
    const createdAt = document.getElementById("stix-object-created-at")?.value || "";
    await api("/api/stix-objects", {
      method: "POST",
      body: JSON.stringify({ stix_id: stixId, name: objectName, description, tlp, pap, first_seen: firstSeen, created_at: createdAt }),
    });
    document.getElementById("stix-object-dialog").close();
    state.stixObjectsView.editingId = "";
    showToast("toast.saved");
    await loadStixObjects();
    if (state.returnToIndicatesDialog) {
      state.returnToIndicatesDialog = false;
      renderIndicatesObjectOptions();
      const select = document.getElementById("indicates-object-select");
      const idInput = document.getElementById("indicates-stix-id");
      const nameInput = document.getElementById("indicates-object-name");
      if (select instanceof HTMLSelectElement) {
        select.value = stixId;
      }
      if (idInput instanceof HTMLInputElement) idInput.value = stixId;
      if (nameInput instanceof HTMLInputElement) nameInput.value = objectName;
      document.getElementById("indicates-dialog").showModal();
    }
  });

function applyPayloadCatalogClientFilters(entries) {
  const search = String(document.getElementById("payload-catalog-search")?.value || "")
    .trim()
    .toLowerCase();
  const techSelect = document.getElementById("payload-catalog-tech");
  const runnerSelect = document.getElementById("payload-catalog-runner");
  const technologies = techSelect instanceof HTMLSelectElement
    ? [...techSelect.selectedOptions].map((option) => String(option.value || "").toLowerCase()).filter(Boolean)
    : [];
  const runnersSelected = runnerSelect instanceof HTMLSelectElement
    ? [...runnerSelect.selectedOptions].map((option) => String(option.value || "").toLowerCase()).filter(Boolean)
    : [];

  return entries.filter((entry) => {
    const entryTech = String(entry.technology || "").toLowerCase();
    const matchesTechnology = technologies.length === 0 || technologies.includes(entryTech);
    const runners = entry.compatibleRunners?.length ? entry.compatibleRunners : ["spuc-agent"];
    const lowerRunners = runners.map((item) => item.toLowerCase());
    const matchesRunner = runnersSelected.length === 0
      || runnersSelected.some((runner) => lowerRunners.includes(runner));
    if (!search) return matchesTechnology && matchesRunner;
    const haystack = [entry.id, entry.name, entry.description, entry.technology, ...runners].join(" ").toLowerCase();
    return matchesTechnology && matchesRunner && haystack.includes(search);
  });
}

function renderPayloadCatalogFiltersRevealer() {
  const revealer = document.getElementById("payload-catalog-filters-revealer");
  const toggle = document.getElementById("payload-catalog-filters-toggle");
  if (revealer) {
    revealer.classList.toggle("open", Boolean(state.customPayloads.filtersOpen));
  }
  if (toggle) {
    toggle.classList.toggle("active", Boolean(state.customPayloads.filtersOpen));
    toggle.setAttribute("aria-expanded", String(Boolean(state.customPayloads.filtersOpen)));
  }
}

function updatePayloadCatalogBulkState(filteredEntries = null) {
  const entries = Array.isArray(filteredEntries)
    ? filteredEntries
    : applyPayloadCatalogClientFilters(state.customPayloads.entries || []);
  const selectedCount = state.customPayloads.selected.size;
  const selectAll = document.getElementById("payload-catalog-select-all");
  const deleteSelected = document.getElementById("payload-catalog-delete-selected");
  const countLabel = document.getElementById("payload-catalog-bulk-count");
  const selectedVisible = entries.filter((entry) => state.customPayloads.selected.has(entry.id)).length;
  const allVisibleSelected = entries.length > 0 && selectedVisible === entries.length;

  if (selectAll instanceof HTMLInputElement) {
    selectAll.disabled = entries.length === 0;
    selectAll.checked = allVisibleSelected;
    selectAll.indeterminate = selectedVisible > 0 && !allVisibleSelected;
  }
  if (deleteSelected instanceof HTMLButtonElement) {
    deleteSelected.disabled = selectedCount === 0;
  }
  if (countLabel) {
    countLabel.textContent = selectedCount > 0 ? tf("rules.bulk.selected_count", { count: selectedCount }) : "";
  }
}

async function deleteSelectedPayloads() {
  if (state.customPayloads.selected.size === 0) return;
  const confirmed = await askForConfirmation(
    t("payloads.confirm_delete_selected"),
    t("common.confirm_action"),
    { acceptLabel: t("payloads.delete_action") },
  );
  if (!confirmed) return;

  const selectedIds = new Set([...state.customPayloads.selected]);
  state.customPayloads.entries = (state.customPayloads.entries || []).filter((entry) => !selectedIds.has(entry.id));
  state.customPayloads.selected.clear();
  state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
  state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => !selectedIds.has(id));
  persistCustomPayloadCatalog();
  renderAdversaryWorkspace();
  renderPayloadCatalogWorkspace();
  renderAdversaryFlowSteps();
}

function renderPayloadCatalogWorkspace() {
  const root = document.getElementById("payload-catalog-list");
  const toolbar = document.getElementById("payload-catalog-toolbar");
  if (!root) return;
  const allEntries = state.customPayloads.entries || [];
  const hasCatalogEntries = allEntries.length > 0;
  if (toolbar) toolbar.classList.toggle("hidden", !hasCatalogEntries);
  if (!hasCatalogEntries) {
    state.customPayloads.selected.clear();
    updatePayloadCatalogBulkState([]);
    root.innerHTML = "";
    return;
  }

  const validIds = new Set(allEntries.map((entry) => entry.id));
  state.customPayloads.selected = new Set([...state.customPayloads.selected].filter((id) => validIds.has(id)));
  const entries = applyPayloadCatalogClientFilters(allEntries);
  const rows = entries.map((entry) => {
    const runners = entry.compatibleRunners?.length ? entry.compatibleRunners : ["spuc-agent"];
    const runnerBadges = runners
      .map((runner) => `<span class="runner-badge">${escapeHtml(runner)}</span>`)
      .join("");
    const detailId = `payload-detail-${entry.id.replace(/[^a-zA-Z0-9]/g, "-")}`;
    const stixId = `x-spuc-payload--${entry.id}`;
    const selected = state.customPayloads.selected.has(entry.id);
    const technology = String(entry.technology || "-");
    return `
      <details class="payload-catalog-accordion" id="${escapeHtml(detailId)}">
        <summary class="payload-accordion-summary">
          <span class="payload-row-check" onclick="event.stopPropagation()">
            <input type="checkbox" data-action="payload-catalog-select" data-id="${escapeHtml(entry.id)}" ${selected ? "checked" : ""} aria-label="${escapeHtml(tf("rules.bulk.row_select", { name: entry.name || entry.id }))}">
          </span>
          <span class="payload-accordion-expander" aria-hidden="true">▶</span>
          <span class="payload-col-main payload-cell-main"><strong>${escapeHtml(entry.name || t("adversaries.payload.untitled"))}</strong></span>
          <span class="payload-col-type payload-cell-type"><span class="payload-tech-badge">${escapeHtml(technology)}</span></span>
          <span class="payload-col-runners payload-cell-runners">${runnerBadges}</span>
          <span class="payload-col-actions payload-cell-actions" onclick="event.stopPropagation()">
            <button type="button" class="btn btn-ghost icon-only" data-action="payload-catalog-edit" data-payload-id="${escapeHtml(entry.id)}" title="${escapeHtml(t("common.edit"))}" aria-label="${escapeHtml(t("common.edit"))}"><i class="fa-solid fa-pen-to-square" aria-hidden="true"></i></button>
            <button type="button" class="btn btn-danger icon-only" data-action="payload-catalog-delete" data-payload-id="${escapeHtml(entry.id)}" title="${escapeHtml(t("adversaries.create.remove"))}" aria-label="${escapeHtml(t("adversaries.create.remove"))}"><i class="fa-solid fa-trash-can" aria-hidden="true"></i></button>
          </span>
        </summary>
        <div class="payload-accordion-body">
          <div class="payload-detail-section payload-detail-id-row">
            <span class="label">${escapeHtml(t("common.id"))}:</span>
            <code class="payload-detail-id">${escapeHtml(stixId)}</code>
          </div>
          ${entry.description ? `
          <div class="payload-detail-section">
            <span class="label">${escapeHtml(t("adversaries.payload.description"))}:</span>
            <div class="payload-detail-description">${escapeHtml(entry.description)}</div>
          </div>
          ` : ""}
          <div class="payload-detail-section">
            <div class="payload-detail-content-header">
              <span class="label">${escapeHtml(t("adversaries.payload.content"))}:</span>
            </div>
            <pre class="payload-detail-code">${escapeHtml(entry.content || "")}</pre>
          </div>
        </div>
      </details>
    `;
  });

  root.innerHTML = `
    <div class="payload-accordion-table-head">
      <span class="payload-col-select"><input type="checkbox" id="payload-catalog-select-all" data-action="payload-catalog-select-all-toggle" aria-label="${escapeHtml(t("rules.bulk.select_all"))}"></span>
      <span class="payload-col-toggle" aria-hidden="true"></span>
      <span class="payload-col-main">${escapeHtml(t("adversaries.payload.catalog_col.name"))}</span>
      <span class="payload-col-type">${escapeHtml(t("adversaries.payload.catalog_col.type"))}</span>
      <span class="payload-col-runners">${escapeHtml(t("adversaries.payload.catalog_col.runners"))}</span>
      <span class="payload-col-actions">${escapeHtml(t("common.actions"))}</span>
    </div>
    <div class="payload-accordion-list">${rows.join("")}</div>
  `;

  updatePayloadCatalogBulkState(entries);
}

function openPayloadCatalogDetail(payloadId) {
  // No longer needed - details are inline in accordion
  console.warn("openPayloadCatalogDetail is deprecated; details are now inline in accordion");
}

function savePayloadFromCatalogForm() {
  const name = String(document.getElementById("payload-catalog-name")?.value || "").trim();
  const technology = String(document.getElementById("payload-catalog-language")?.value || "bash").toLowerCase();
  const runner = String(document.getElementById("payload-catalog-runner")?.value || "spuc-agent").toLowerCase();
  const description = String(document.getElementById("payload-catalog-description")?.value || "").trim();
  const content = String(document.getElementById("payload-catalog-content")?.value || "");
  if (!name || !content.trim()) {
    showToast("adversaries.payload.validation_missing", true);
    return false;
  }
  const editingId = state.customPayloads.editingId;
  const entry = normalizeCustomPayloadEntry({
    id: editingId || `payload-${Date.now()}`,
    name,
    technology,
    compatibleRunners,
    description,
    content,
    createdAt: new Date().toISOString(),
  });
  state.customPayloads.entries.unshift(entry);
  state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
  persistCustomPayloadCatalog();
  renderPayloadCatalogWorkspace();
  showToast("toast.saved");
  return true;
}

// ==================== New Tabbed Adversary Editor Functions ====================

function adversaryEditorPayload() {
  return {
    name: String(document.getElementById("adversary-editor-name")?.value || "").trim(),
    confidence: Number(document.getElementById("adversary-editor-confidence")?.value || 70),
    target_platform: String(document.getElementById("adversary-editor-target-platform")?.value || "").trim(),
    description: String(document.getElementById("adversary-editor-description-input")?.value || ""),
    ability_refs: [...state.adversaryCompose.selectedOrder],
  };
}

function updateAdversaryEditorConfidenceValue() {
  const input = document.getElementById("adversary-editor-confidence");
  const value = document.getElementById("adversary-editor-confidence-value");
  if (!(input instanceof HTMLInputElement) || !value) return;
  value.textContent = String(Math.max(0, Math.min(100, Number(input.value || 70) || 70)));
}

function canPersistAdversaryEditorPayload(payload) {
  return Boolean(payload?.name)
    && Boolean(String(payload?.target_platform || "").trim())
    && Array.isArray(payload?.ability_refs)
    && payload.ability_refs.length > 0;
}

function renderAdversaryEditorExportMenu() {
  const toggleButton = document.getElementById("adversary-editor-export-toggle");
  const menu = document.getElementById("adversary-editor-export-menu");
  if (!(toggleButton instanceof HTMLButtonElement) || !menu) return;

  const steps = resolveAdversaryPlanSteps(state.adversaryCompose.selectedOrder);
  const compatible = ADVERSARY_EXPORTERS.filter((target) => isExporterCompatibleWithPlan(target, steps));

  toggleButton.disabled = compatible.length === 0;
  toggleButton.title = compatible.length === 0 ? t("adversaries.export.none_available") : t("adversaries.detail.export");

  if (compatible.length === 0) {
    menu.innerHTML = `<span class="muted">${escapeHtml(t("adversaries.export.none_available"))}</span>`;
    return;
  }

  menu.innerHTML = compatible
    .map((target) => `<button type="button" class="btn btn-ghost" data-action="adversary-editor-export" data-target="${escapeHtml(target)}">${escapeHtml(target)}</button>`)
    .join("");
}

function renderAdversaryEditorHeader() {
  const title = document.getElementById("adversary-editor-title");
  if (title) {
    const name = String(document.getElementById("adversary-editor-name")?.value || "").trim();
    title.textContent = state.adversaryCompose.mode === "edit"
      ? tf("adversaries.editor.editing_title", { name: name || t("adversaries.edit.untitled") })
      : t("adversaries.editor.new_title");
  }
  const planButton = document.getElementById("adversary-editor-plan");
  if (planButton) {
    planButton.classList.toggle("btn-primary", state.adversaryCompose.editorActiveTab !== "flow");
    planButton.classList.toggle("btn-ghost", state.adversaryCompose.editorActiveTab === "flow");
  }
  renderAdversaryEditorExportMenu();
}

async function saveAdversaryFromNewEditor(options = {}) {
  const {
    showSavedToast = false,
    force = false,
  } = options;
  const payload = adversaryEditorPayload();
  if (!canPersistAdversaryEditorPayload(payload)) return null;

  const signature = JSON.stringify(payload);
  if (!force && signature === state.adversaryCompose.editorLastSavedSignature) {
    return state.adversaryView.entry;
  }

  try {
    const endpoint = state.adversaryCompose.mode === "edit" && state.adversaryCompose.editingId
      ? `/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}`
      : "/api/adversaries";
    const method = state.adversaryCompose.mode === "edit" && state.adversaryCompose.editingId ? "PUT" : "POST";
    const response = await fetch(endpoint, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      showToast("toast.error_saving", true);
      return null;
    }

    const saved = await response.json();
    state.adversaryCompose.mode = "edit";
    state.adversaryCompose.editingId = saved.id || state.adversaryCompose.editingId;
    state.adversaryCompose.editorLastSavedSignature = signature;
    state.adversaryView.entry = {
      ...(state.adversaryView.entry || {}),
      ...saved,
      ...payload,
      id: saved.id || state.adversaryCompose.editingId,
      ability_refs: [...payload.ability_refs],
    };
    if (showSavedToast) {
      showToast("adversaries.editor.saved_blur");
    }
    await loadAdversaries(state.adversaries.page);
    renderAdversaryEditorHeader();
    return saved;
  } catch (err) {
    console.error("Error saving adversary:", err);
    showToast("toast.error_saving", true);
    return null;
  }
}

async function saveCustomPayloadFromForm() {
  const nameInput = document.getElementById("adversary-flow-payload-name");
  const techSelect = document.getElementById("adversary-flow-payload-tech");
  const runnerSelect = document.getElementById("adversary-flow-payload-runner");
  const descInput = document.getElementById("adversary-flow-payload-desc");
  const contentInput = document.getElementById("adversary-flow-payload-content");

  if (!nameInput?.value.trim() || !contentInput?.value.trim()) {
    showToast("adversaries.validation.payload_required", true);
    return;
  }

  const payload = {
    id: `payload-${Date.now()}`,
    name: nameInput.value.trim(),
    technology: techSelect?.value || "bash",
    compatibleRunners: [runnerSelect?.value || "spuc-agent"],
    description: descInput?.value || "",
    content: contentInput.value,
    createdAt: new Date().toISOString(),
  };

  state.customPayloads.entries.unshift(normalizeCustomPayloadEntry(payload));
  state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
  persistCustomPayloadCatalog();

  if (!state.adversaryCompose.selectedOrder.includes(payload.id)) {
    state.adversaryCompose.selectedOrder.push(payload.id);
  }
  state.adversaryCompose.editorSelectedStepId = payload.id;
  renderAdversaryFlowSteps();
  void saveAdversaryFromNewEditor({ showSavedToast: true });

  nameInput.value = "";
  techSelect.value = "bash";
  runnerSelect.value = "spuc-agent";
  descInput.value = "";
  contentInput.value = "";

  const dialog = document.getElementById("adversary-payload-form-dialog");
  if (dialog instanceof HTMLDialogElement) {
  }
  showToast("toast.saved");
}

async function exportAdversaryFromEditor(target) {
  if (!state.adversaryCompose.editingId) return;

  try {
    const response = await api(
      `/api/adversaries/${encodeURIComponent(state.adversaryCompose.editingId)}/export${toQuery({ to: target })}`
    );
    if (response && response.output) {
      const timestamp = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
      const filename = `${target}-${state.adversaryCompose.editingId}-${timestamp}`;
      downloadTextFile(response.output, filename, "text/plain");
      showToast("toast.export_ready");
    } else {
      showToast("adversaries.export.error", true);
    }
  } catch (err) {
    console.error("Export error:", err);
    showToast("adversaries.export.error", true);
  }
}

function showAdversaryEditorPanel() {
  const panel = document.getElementById("panel-adversary-editor");
  if (panel) {
    panel.classList.remove("hidden");
    panel.classList.add("active");
  }
  document.getElementById("panel-adversaries")?.classList.remove("active");
  state.route = "adversaries-create";
  applyNavSelection("adversaries");
  refreshRouteMeta();
  state.adversaries.workspaceMode = "editor";
  renderAdversaryWorkspace();
  renderAdversaryWorkspaceHeader();
  renderAdversaryEditorHeader();
}

function hideAdversaryEditorPanel() {
  const panel = document.getElementById("panel-adversary-editor");
  if (panel) {
    panel.classList.add("hidden");
    panel.classList.remove("active");
  }
  returnAdversaryEditorToList();
}

function setAdversaryEditorTab(tabName) {
  const normalized = ["overview", "flow"].includes(tabName) ? tabName : "overview";
  state.adversaryCompose.editorActiveTab = normalized;

  // Hide all tabs
  document.querySelectorAll(".adversary-editor-tab").forEach((tab) => {
    tab.classList.remove("active");
    tab.classList.add("hidden");
  });

  // Show active tab
  const activeTabEl = document.getElementById(`adversary-editor-${normalized}`);
  if (activeTabEl) {
    activeTabEl.classList.add("active");
    activeTabEl.classList.remove("hidden");
  }

  // Render tab content
  if (normalized === "overview") renderAdversaryEditorOverview();
  else if (normalized === "flow") renderAdversaryEditorFlow();
  renderAdversaryEditorHeader();
}

function renderAdversaryEditorOverview() {
  // Load form values from state
  const nameInput = document.getElementById("adversary-editor-name");
  const confidenceInput = document.getElementById("adversary-editor-confidence");
  const platformSelect = document.getElementById("adversary-editor-target-platform");
  const descriptionInput = document.getElementById("adversary-editor-description-input");

  const current = state.adversaryView.entry || {};
  if (nameInput) nameInput.value = String(current.name || "");
  if (confidenceInput) confidenceInput.value = String(current.confidence ?? 70);
  if (platformSelect) {
    const values = state.abilities.entries
      .flatMap((entry) => entry.platforms || [])
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
    const unique = [...new Set(values)].sort((a, b) => a.localeCompare(b));
    platformSelect.innerHTML = [
      `<option value="">${escapeHtml(t("common.all_platforms"))}</option>`,
      ...unique.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`),
    ].join("");
    platformSelect.value = String(current.target_platform || "").toLowerCase();
  }
  if (descriptionInput) descriptionInput.value = String(current.description || "");
  updateAdversaryEditorConfidenceValue();
  refreshCustomComboboxes(document);
  renderAdversaryEditorHeader();
}

function renderAdversaryEditorFlow() {
  renderAdversaryFlowSteps();
  renderAdversaryEditorFlowAbilityOptions();
  renderAdversaryEditorFlowPayloadOptions();
  renderAdversaryEditorHeader();
}

function renderAdversaryFlowSteps() {
  const stepsList = document.getElementById("adversary-flow-steps");
  const countBadge = document.getElementById("adversary-flow-count");
  if (!stepsList) return;

  const stepEntries = resolveAdversaryPlanSteps(state.adversaryCompose.selectedOrder);
  countBadge.textContent = String(stepEntries.length);
  if (!state.adversaryCompose.editorSelectedStepId && stepEntries.length) {
    state.adversaryCompose.editorSelectedStepId = stepEntries[0].id;
  }
  if (!stepEntries.find((step) => step.id === state.adversaryCompose.editorSelectedStepId)) {
    state.adversaryCompose.editorSelectedStepId = stepEntries[0]?.id || null;
  }

  stepsList.innerHTML = stepEntries
    .map((step, index) => {
      const platformLabel = Array.isArray(step.platforms) ? step.platforms.join(", ") : t("common.no_data");
      const isCustom = isCustomPayloadAbility(step);
      const badge = isCustom ? ` <span class="custom-payload-badge" data-i18n="adversaries.payload.badge">${escapeHtml(t("adversaries.payload.badge"))}</span>` : "";

      return `
        <li class="flow-step-item ${step.id === state.adversaryCompose.editorSelectedStepId ? "is-selected" : ""}" data-step-id="${escapeHtml(step.id || "")}" data-action="flow-step-select">
          <div class="flow-step-position">${index + 1}</div>
          <div class="flow-step-content">
            <div class="flow-step-name">
              <strong>${escapeHtml(step.name || step.id || "")}</strong>${badge}
            </div>
            <div class="flow-step-meta">
              <small class="muted">${escapeHtml(step.id || "")} · ${escapeHtml(platformLabel)}</small>
            </div>
          </div>
          <div class="flow-step-actions">
            <button type="button" class="icon-btn" data-action="flow-step-up" data-step-index="${index}" title="Move up" ${index === 0 ? "disabled" : ""} aria-label="Move step up">
              <i class="fa-solid fa-arrow-up" aria-hidden="true"></i>
            </button>
            <button type="button" class="icon-btn" data-action="flow-step-down" data-step-index="${index}" title="Move down" ${index === stepEntries.length - 1 ? "disabled" : ""} aria-label="Move step down">
              <i class="fa-solid fa-arrow-down" aria-hidden="true"></i>
            </button>
            <button type="button" class="icon-btn" data-action="flow-step-detail" data-step-id="${escapeHtml(step.id || "")}" title="${escapeHtml(t("adversaries.view.details"))}" aria-label="${escapeHtml(t("adversaries.view.details"))}">
              <i class="fa-solid fa-info-circle" aria-hidden="true"></i>
            </button>
            <button type="button" class="icon-btn btn-danger" data-action="flow-step-remove" data-step-index="${index}" title="Remove step" aria-label="Remove step">
              <i class="fa-solid fa-times" aria-hidden="true"></i>
            </button>
          </div>
        </li>
      `;
    })
    .join("");
  renderAdversaryEditorSelectedStepDetail();
  renderAdversaryEditorExportMenu();
}

function renderAdversaryEditorSelectedStepDetail() {
  const root = document.getElementById("adversary-flow-step-detail");
  if (!root) return;
  const selectedId = state.adversaryCompose.editorSelectedStepId;
  const step = resolveAdversaryPlanSteps(state.adversaryCompose.selectedOrder)
    .find((entry) => entry.id === selectedId);
  if (!step) {
    root.innerHTML = `<p class="muted">${escapeHtml(t("adversaries.create.none_selected"))}</p>`;
    root.classList.remove("is-selected");
    return;
  }
  root.classList.add("is-selected");
  root.innerHTML = `
    <h5>${escapeHtml(step.name || step.id || "")}</h5>
    <div class="flow-step-detail-meta">
      <div>
        <span>${escapeHtml(t("common.id"))}</span>
        <strong>${escapeHtml(step.id || "-")}</strong>
      </div>
      <div>
        <span>${escapeHtml(t("adversaries.create.target_platform"))}</span>
        <strong>${escapeHtml((step.platforms || []).join(", ") || t("common.no_data"))}</strong>
      </div>
      <div>
        <span>${escapeHtml(t("adversaries.payload.runner"))}</span>
        <strong>${escapeHtml((step.export_targets || []).join(", ") || t("common.no_data"))}</strong>
      </div>
    </div>
    <p class="muted">${escapeHtml(step.description || t("adversaries.detail.empty_description"))}</p>
  `;
}

function renderAdversaryEditorFlowAbilityOptions() {
  const searchInput = document.getElementById("adversary-flow-ability-search");
  const platformSelect = document.getElementById("adversary-flow-ability-platform");
  const utilitySelect = document.getElementById("adversary-flow-ability-utility");
  const root = document.getElementById("adversary-flow-abilities");
  if (!root) return;

  if (platformSelect instanceof HTMLSelectElement && !platformSelect.dataset.loaded) {
    const values = [...new Set(state.abilities.entries.flatMap((entry) => entry.platforms || []))]
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean)
      .sort((a, b) => a.localeCompare(b));
    platformSelect.innerHTML = [`<option value="">${escapeHtml(t("common.all_platforms"))}</option>`, ...values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)].join("");
    platformSelect.dataset.loaded = "1";
  }
  if (utilitySelect instanceof HTMLSelectElement && !utilitySelect.dataset.loaded) {
    const values = [...new Set(state.abilities.entries.map((entry) => String(entry.classification || "").trim().toLowerCase()).filter(Boolean))]
      .sort((a, b) => a.localeCompare(b));
    utilitySelect.innerHTML = [`<option value="">${escapeHtml(t("common.all_utility_types"))}</option>`, ...values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)].join("");
    utilitySelect.dataset.loaded = "1";
  }
  refreshCustomComboboxes(document);

  const search = String(searchInput?.value || "").toLowerCase();
  const platform = String(platformSelect?.value || "").toLowerCase();
  const utility = String(utilitySelect?.value || "").toLowerCase();

  const filtered = (state.abilities.entries || []).filter((entry) => {
    if (platform) {
      const platforms = (entry.platforms || []).map((value) => String(value || "").toLowerCase());
      if (!platforms.includes(platform)) return false;
    }
    if (utility && String(entry.classification || "").toLowerCase() !== utility) return false;
    const haystack = [entry.id, entry.name, entry.description, entry.classification].join(" ").toLowerCase();
    return !search || haystack.includes(search);
  });

  root.innerHTML = filtered.length
    ? filtered.map((entry) => `
      <article class="flow-payload-item">
        <div class="payload-item-header">
          <strong>${escapeHtml(entry.name || entry.id || "")}</strong>
          <span class="payload-tech-badge">${escapeHtml(String(entry.classification || "ability"))}</span>
        </div>
        <p class="payload-item-desc muted">${escapeHtml(entry.description || t("common.no_data"))}</p>
        <button type="button" class="btn btn-primary" data-action="flow-add-ability" data-ability-id="${escapeHtml(entry.id || "")}">${escapeHtml(t("adversaries.create.add"))}</button>
      </article>
    `).join("")
    : `<p class="muted">${escapeHtml(t("adversaries.create.none_available"))}</p>`;
}

function renderAdversaryEditorFlowPayloadOptions() {
  renderAdversaryEditorPayloadsList();
}

function renderAdversaryEditorPayloadsList() {
  const payloadsList = document.getElementById("adversary-flow-payloads");
  if (!payloadsList) return;

  const payloads = state.customPayloads.entries || [];
  const filterTech = document.getElementById("adversary-flow-payload-technology")?.value || "all";
  const searchTerm = (document.getElementById("adversary-flow-payload-search")?.value || "").toLowerCase();

  const filtered = payloads.filter((payload) => {
    const matchesTech = filterTech === "all" || payload.technology === filterTech;
    const matchesSearch = !searchTerm || payload.name.toLowerCase().includes(searchTerm) || payload.id.toLowerCase().includes(searchTerm);
    return matchesTech && matchesSearch;
  });

  payloadsList.innerHTML = filtered
    .map(
      (payload) => `
      <div class="flow-payload-item" data-payload-id="${escapeHtml(payload.id || "")}">
        <div class="payload-item-header">
          <strong>${escapeHtml(payload.name)}</strong>
          <span class="payload-tech-badge">${escapeHtml(payload.technology)}</span>
        </div>
        <p class="payload-item-desc muted">${escapeHtml(payload.description || t("common.no_data"))}</p>
        <button type="button" class="btn btn-primary" data-action="flow-add-custom-payload" data-payload-id="${escapeHtml(payload.id || "")}" data-i18n="adversaries.editor.add">Add to flow</button>
      </div>
    `,
    )
    .join("");

  if (!filtered.length) {
    payloadsList.innerHTML = `<p class="muted">${escapeHtml(t("adversaries.create.none_selected"))}</p>`;
  }
}

async function openAdversaryInNewEditor(adversaryId) {
  if (!adversaryId) return;
  await ensureAbilitiesLoaded();
  const adversary = await api(`/api/adversaries/${encodeURIComponent(adversaryId)}`);
  state.adversaryView.entry = adversary;
  state.adversaryView.activeId = adversaryId;
  state.adversaryCompose.selectedOrder = Array.isArray(adversary.ability_refs) ? [...adversary.ability_refs] : [];
  state.adversaryCompose.editorSelectedStepId = state.adversaryCompose.selectedOrder[0] || null;
  state.adversaryCompose.editingId = adversaryId;
  state.adversaryCompose.mode = "edit";
  state.adversaryCompose.editorMode = "panel";
  state.adversaryCompose.editorActiveTab = "overview";
  state.adversaryCompose.editorLastSavedSignature = JSON.stringify({
    name: adversary.name || "",
    confidence: Number(adversary.confidence || 70),
    target_platform: adversary.target_platform || "",
    description: adversary.description || "",
    ability_refs: [...state.adversaryCompose.selectedOrder],
  });
  state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
  showAdversaryEditorPanel();
  setAdversaryEditorTab("overview");
}

function createNewAdversaryInEditor() {
  openAdversaryDialog();
}

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (!target.closest(".column-picker")) {
      closeColumnMenus();
    }
    if (!target.closest(".adversary-editor-export-menu-wrap")) {
      document.getElementById("adversary-editor-export-menu")?.classList.add("hidden");
    }
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const row = target.closest("#stix-objects-table tbody tr[data-stix-row-id]");
    if (!row) return;
    if (target.closest("button, a, input, select, textarea, label, summary")) return;
    const selectedText = window.getSelection ? String(window.getSelection()) : "";
    if (selectedText.trim().length > 0) return;
    toggleStixObjectDetails(row.getAttribute("data-stix-row-id") || "");
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
      await openAdversaryDetail(adversaryId);
    } catch (error) {
      showToast(error.payload?.error || error.message || "toast.unexpected", true);
    }
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const card = target.closest(".adversary-card[data-adversary-card-id]");
    if (!card) return;
    if (target.closest("button, a, input, select, textarea, label")) return;
    const selectedText = window.getSelection ? String(window.getSelection()) : "";
    if (selectedText.trim().length > 0) return;
    const adversaryId = card.getAttribute("data-adversary-card-id") || "";
    if (!adversaryId) return;
    try {
      await openAdversaryDetail(adversaryId);
    } catch (error) {
      showToast(error.payload?.error || error.message || "toast.unexpected", true);
    }
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const row = target.closest(".flow-step-item[data-step-id]");
    if (!row) return;
    if (target.closest("button, a")) return;
    const stepId = row.getAttribute("data-step-id") || "";
    if (!stepId) return;
    state.adversaryCompose.editorSelectedStepId = stepId;
    renderAdversaryFlowSteps();
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
      } else if (action === "local-login") {
        enterApplication();
      } else if (action === "open-support") {
        renderAboutDialog(target.dataset.supportSection || "");
        document.getElementById("support-dialog")?.showModal();
      } else if (action === "close-support") {
        document.getElementById("support-dialog")?.close();
      } else if (action === "about-donation-method") {
        state.about.donationMethod = target.dataset.method || "monero";
        renderAboutDialog("donate");
      } else if (action === "about-copy-donation") {
        await copyDonationAddress(target.dataset.method || "");
      } else if (action === "welcome-dismiss") {
        localStorage.setItem("spuc-web-welcome-dismissed", "1");
        renderDashboard();
      } else if (action === "adversaries-empty-create") {
        createNewAdversaryInEditor();
      } else if (action === "adversary-back-to-list") {
        hideAdversaryEditorPanel();
      } else if (action === "adversary-enter-edit") {
        const adversaryId = state.adversaryView.activeId || state.adversaryCompose.editingId;
        if (!adversaryId) {
          createNewAdversaryInEditor();
        } else {
          await openAdversaryInNewEditor(adversaryId);
        }
      } else if (action === "adversary-save") {
        const saved = await persistAdversaryAutosave();
        if (!saved?.id) return;
        showToast("toast.saved");
        await loadAdversaries(state.adversaries.page);
        await openAdversaryDetail(saved.id);
      } else if (action === "adversary-cancel-edit") {
        const editingId = state.adversaryCompose.editingId;
        if (editingId) {
          await openAdversaryDetail(editingId);
        } else {
          returnAdversaryEditorToList();
        }
      } else if (action === "adversary-new-inline") {
        createNewAdversaryInEditor();
      } else if (action === "adversary-editor-plan") {
        setAdversaryEditorTab("flow");
      } else if (action === "adversary-editor-export-toggle") {
        const menu = document.getElementById("adversary-editor-export-menu");
        if (menu) menu.classList.toggle("hidden");
      } else if (action === "payload-catalog-filters-toggle") {
        state.customPayloads.filtersOpen = !state.customPayloads.filtersOpen;
        renderPayloadCatalogFiltersRevealer();
      } else if (action === "payload-catalog-delete") {
        const payloadId = String(target.dataset.payloadId || "");
        if (!payloadId) return;
        const confirmed = await askForConfirmation(
          t("payloads.confirm_delete_one"),
          t("common.confirm_action"),
          { acceptLabel: t("payloads.delete_one_action") },
        );
        if (!confirmed) return;
        state.customPayloads.entries = (state.customPayloads.entries || []).filter((entry) => entry.id !== payloadId);
        state.customPayloads.selected.delete(payloadId);
        state.adversaryCompose.customPayloads = [...state.customPayloads.entries];
        state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => id !== payloadId);
        persistCustomPayloadCatalog();
        renderAdversaryWorkspace();
        renderPayloadCatalogWorkspace();
        renderAdversaryFlowSteps();
      } else if (action === "payload-catalog-delete-selected") {
        await deleteSelectedPayloads();
      } else if (action === "payload-catalog-preview") {
        const payloadId = String(target.dataset.payloadId || "");
        if (!payloadId) return;
        openPayloadCatalogDetail(payloadId);
      } else if (action === "payload-catalog-edit") {
        const payloadId = String(target.dataset.payloadId || "");
        if (!payloadId) return;
        openPayloadCatalogCreateModal(payloadId);
      } else if (action === "payload-catalog-open-create") {
        openPayloadCatalogCreateModal();
      } else if (action === "payload-catalog-open-docs") {
        openPayloadCatalogDocs();
      } else if (action === "payload-catalog-close-create") {
        closePayloadCatalogCreateModal();
      } else if (action === "payload-catalog-save-create") {
        savePayloadFromCatalogModal();
      } else if (action === "payload-catalog-open-editor") {
        createNewAdversaryInEditor();
        setAdversaryEditorTab("flow");
      } else if (action === "adversaries-help-open") {
        openAdversaryAgentHelp();
      } else if (action === "rules-columns-toggle") {
        toggleMenu("rules-columns-menu", "rules-columns-toggle");
      } else if (action === "rules-filters-toggle") {
        state.rules.filtersOpen = !state.rules.filtersOpen;
        renderRulesFiltersRevealer();
      } else if (action === "rules-open-lab") {
        clearRuleLabEditingContext();
        localStorage.setItem("spuc-web-last-route", "rulelab");
        setRoute("rulelab");
      } else if (action === "rules-import-stix") {
        const input = document.getElementById("rules-import-file-shortcut");
        if (input instanceof HTMLInputElement) {
          input.click();
        }
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
        await openAdversaryDetail(target.dataset.id || "");
      } else if (action === "adversary-edit") {
        await openAdversaryInNewEditor(target.dataset.id || "");
      } else if (action === "adversary-detail-tab") {
        setAdversaryDetailTab(target.dataset.tab || "summary");
      } else if (action === "adversary-json-copy") {
        if (!state.adversaryView.entry) return;
        await navigator.clipboard.writeText(JSON.stringify(state.adversaryView.entry, null, 2));
        showToast("toast.copied");
      } else if (action === "adversary-json-download") {
        if (!state.adversaryView.entry) return;
        const fileToken = sanitizeFileToken(target.dataset.id || state.adversaryView.entry.id || "adversary");
        downloadTextFile(JSON.stringify(state.adversaryView.entry, null, 2), `${fileToken}.json`, "application/json;charset=utf-8");
        showToast("toast.export_ready");
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
          state.adversaryCompose.editorSelectedStepId = abilityId;
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
        closeAdversaryAbilityPicker();
      } else if (action === "adversary-remove-ability") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        const confirmed = await askForConfirmation(
          t("adversaries.confirm_remove_step"),
          t("common.confirm_action"),
          { acceptLabel: t("adversaries.create.remove") },
        );
        if (!confirmed) return;
        state.adversaryCompose.selectedOrder = state.adversaryCompose.selectedOrder.filter((id) => id !== abilityId);
        renderAdversaryFlowSteps();
        void saveAdversaryFromNewEditor({ showSavedToast: true });
      } else if (action === "adversary-move-up") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, -1);
        renderAdversaryFlowSteps();
        void saveAdversaryFromNewEditor({ showSavedToast: true });
      } else if (action === "adversary-move-down") {
        const abilityId = target.dataset.id;
        if (!abilityId) return;
        moveAdversarySelectedAbility(abilityId, 1);
        renderAdversaryFlowSteps();
        void saveAdversaryFromNewEditor({ showSavedToast: true });
      } else if (action === "adversary-close-ability-picker") {
        closeAdversaryAbilityPicker();
      } else if (action === "adversary-tab") {
        setAdversaryTab(target.dataset.tab || "plan");
      } else if (action === "adversary-picker-tab") {
        setAdversaryPickerTab(target.dataset.tab || "catalog");
      } else if (action === "adversary-editor-tab") {
        setAdversaryEditorTab(target.dataset.tab || "overview");
      } else if (action === "adversary-editor-save") {
        await saveAdversaryFromNewEditor({ showSavedToast: true, force: true });
      } else if (action === "adversary-editor-cancel") {
        hideAdversaryEditorPanel();
      } else if (action === "flow-step-select") {
        const stepId = target.closest("[data-step-id]")?.getAttribute("data-step-id") || "";
        if (!stepId) return;
        state.adversaryCompose.editorSelectedStepId = stepId;
        renderAdversaryFlowSteps();
      } else if (action === "flow-step-up") {
        const stepIndex = Number(target.dataset.stepIndex || -1);
        if (stepIndex > 0) {
          [state.adversaryCompose.selectedOrder[stepIndex - 1], state.adversaryCompose.selectedOrder[stepIndex]] =
            [state.adversaryCompose.selectedOrder[stepIndex], state.adversaryCompose.selectedOrder[stepIndex - 1]];
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
      } else if (action === "flow-step-down") {
        const stepIndex = Number(target.dataset.stepIndex || -1);
        if (stepIndex >= 0 && stepIndex < state.adversaryCompose.selectedOrder.length - 1) {
          [state.adversaryCompose.selectedOrder[stepIndex], state.adversaryCompose.selectedOrder[stepIndex + 1]] =
            [state.adversaryCompose.selectedOrder[stepIndex + 1], state.adversaryCompose.selectedOrder[stepIndex]];
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
      } else if (action === "flow-step-remove") {
        const stepIndex = Number(target.dataset.stepIndex || -1);
        if (stepIndex >= 0 && stepIndex < state.adversaryCompose.selectedOrder.length) {
          const confirmed = await askForConfirmation(
            t("adversaries.confirm_remove_step"),
            t("common.confirm_action"),
            { acceptLabel: t("adversaries.create.remove") },
          );
          if (!confirmed) return;
          state.adversaryCompose.selectedOrder.splice(stepIndex, 1);
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
      } else if (action === "flow-step-detail") {
        const stepId = target.dataset.stepId;
        if (stepId) {
          state.adversaryCompose.editorSelectedStepId = stepId;
          renderAdversaryFlowSteps();
        }
      } else if (action === "flow-add-ability") {
        const abilityId = String(target.dataset.abilityId || "");
        if (!abilityId) return;
        if (!state.adversaryCompose.selectedOrder.includes(abilityId)) {
          state.adversaryCompose.selectedOrder.push(abilityId);
          state.adversaryCompose.editorSelectedStepId = abilityId;
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
        closeAdversaryAbilityPicker();
      } else if (action === "adversary-open-ability-picker") {
        openAdversaryAbilityPicker();
      } else if (action === "adversary-open-payload-picker") {
        openAdversaryPayloadPicker();
      } else if (action === "adversary-close-payload-picker") {
        closeAdversaryPayloadPicker();
      } else if (action === "adversary-open-payload-form") {
        openAdversaryPayloadForm();
      } else if (action === "adversary-cancel-payload-form") {
        closeAdversaryPayloadForm();
      } else if (action === "adversary-save-custom-payload") {
        await saveCustomPayloadFromForm();
      } else if (action === "flow-add-custom-payload") {
        const payloadId = target.dataset.payloadId;
        if (payloadId && !state.adversaryCompose.selectedOrder.includes(payloadId)) {
          state.adversaryCompose.selectedOrder.push(payloadId);
          state.adversaryCompose.editorSelectedStepId = payloadId;
          renderAdversaryFlowSteps();
          void saveAdversaryFromNewEditor({ showSavedToast: true });
        }
        closeAdversaryPayloadPicker();
      } else if (action === "adversary-editor-export") {
        const exportTarget = target.dataset.target;
        if (state.adversaryCompose.editingId && exportTarget) {
          await exportAdversaryFromEditor(exportTarget);
          document.getElementById("adversary-editor-export-menu")?.classList.add("hidden");
        }
      } else if (action === "adversary-json-copy") {
        const codeEl = document.getElementById("adversary-json-content");
        if (codeEl) {
          const text = codeEl.textContent || "";
          navigator.clipboard.writeText(text);
          showToast("toast.copied");
        }
      } else if (action === "adversary-json-download") {
        const codeEl = document.getElementById("adversary-json-content");
        if (codeEl) {
          const text = codeEl.textContent || "{}";
          const filename = state.adversaryCompose.editingId
            ? `adversary-${state.adversaryCompose.editingId}.json`
            : `adversary-new-${Date.now()}.json`;
          downloadTextFile(text, filename, "application/json");
        }
      } else if (action === "adversary-refresh-execution-help") {
        await ensureAdversaryExportPreview(target.dataset.target || selectedAdversaryExportTarget(), true);
      } else if (action === "adversary-preview-payload") {
        renderCustomPayloadPreview();
      } else if (action === "adversary-add-custom-payload") {
        await addCustomPayloadStep();
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
      } else if (action === "compat-copy") {
        const entry = state.compatibility.find((item) => item.target === target.dataset.target);
        if (entry && canShowCompatibilityOutput(entry)) {
          await navigator.clipboard.writeText(String(entry.output || ""));
          showToast("toast.copied");
        } else {
          showToast("detail.no_output_for_target", true);
        }
      } else if (action === "rule-indicates") {
        const entry = state.rules.entries.find((item) => item.id === target.dataset.id);
        if (!entry) return;
        state.indicatesMode = "catalog";
        const indicatesList = Array.isArray(entry.indicates_list) && entry.indicates_list.length
          ? entry.indicates_list
          : (entry.indicates ? [entry.indicates] : []);
        document.getElementById("indicates-rule-id").value = entry.id;
        const searchInput = document.getElementById("indicates-search");
        const resultsDiv = document.getElementById("indicates-search-results");
        const idInput = document.getElementById("indicates-stix-id");
        const nameInput = document.getElementById("indicates-object-name");
        const select = document.getElementById("indicates-object-select");
        if (searchInput instanceof HTMLInputElement) searchInput.value = "";
        if (resultsDiv) resultsDiv.innerHTML = "";
        if (idInput instanceof HTMLInputElement) idInput.value = "";
        if (nameInput instanceof HTMLInputElement) nameInput.value = "";
        renderIndicatesObjectOptions();
        if (select instanceof HTMLSelectElement) select.value = "";
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
        saveLearningProgress();
        renderLearningChallenges();
      } else if (action === "settings-tab") {
        setSettingsTab(target.dataset.tab || "personal");
      } else if (action === "settings-users-toggle-filters") {
        toggleSettingsUsersFilters();
      } else if (action === "admin-open-create-user") {
        if (isNoLoginSession()) return;
        const dialog = document.getElementById("admin-create-user-dialog");
        if (dialog instanceof HTMLDialogElement) {
          dialog.showModal();
        }
      } else if (action === "admin-delete-user") {
        const confirmDelete = await askForConfirmation(
          t("admin.delete_confirm"),
          t("common.confirm_action"),
          { acceptLabel: t("admin.delete_action") },
        );
        if (!confirmDelete) return;
        await api(`/api/admin/users/${encodeURIComponent(target.dataset.id)}`, {
          method: "DELETE",
          body: "{}",
        });
        showToast("toast.saved");
        await loadSettingsView();
      } else if (action === "admin-update-user") {
        const userId = target.dataset.id;
        const role = document.querySelector(`[data-admin-role="${userId}"]`)?.value || "analyst";
        const enabled = Boolean(document.querySelector(`[data-admin-enabled="${userId}"]`)?.checked);
        const totpEnabled = Boolean(document.querySelector(`[data-admin-totp="${userId}"]`)?.checked);
        const displayName = document.querySelector(`[data-admin-display-name="${userId}"]`)?.value || "";
        await api(`/api/admin/users/${encodeURIComponent(userId)}/update`, {
          method: "POST",
          body: JSON.stringify({ role, enabled, display_name: displayName, totp_enabled: totpEnabled }),
        });
        showToast("toast.saved");
        await loadSettingsView();
      } else if (action === "admin-reset-password") {
        const userId = target.dataset.id || "";
        const newPassword = document.querySelector(`[data-admin-password="${userId}"]`)?.value || "";
        if (!newPassword.trim()) {
          showToast("settings.admin.users.password_required", true);
          return;
        }
        await api("/api/admin/change-password", {
          method: "POST",
          body: JSON.stringify({ user_id: userId, new_password: newPassword }),
        });
        const passwordInput = document.querySelector(`[data-admin-password="${userId}"]`);
        if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
        showToast("toast.saved");
      } else if (action === "admin-oauth-configure") {
        openAdminProviderConfigDialog(target.dataset.provider || "");
      } else if (action === "admin-oauth-update") {
        if (isNoLoginSession()) return;
        const providerId = target.dataset.provider || "";
        const authorized = Boolean(document.querySelector(`[data-admin-oauth-authorized="${providerId}"]`)?.checked);
        await api(`/api/admin/oauth/providers/${encodeURIComponent(providerId)}/update`, {
          method: "POST",
          body: JSON.stringify({ authorized }),
        });
        showToast("toast.saved");
        await loadAdminOauthProviders();
      } else if (action === "stix-create-open") {
        openStixObjectDialog();
      } else if (action === "stix-edit-object") {
        const stixId = target.dataset.stixId || "";
        const entry = state.stixObjects.find((item) => item.stix_id === stixId);
        if (entry) {
          openStixObjectDialog(entry);
        }
      } else if (action === "stix-import-open") {
        const input = document.getElementById("stix-import-file");
        if (input instanceof HTMLInputElement) {
          input.click();
        }
      } else if (action === "stix-object-cancel") {
        document.getElementById("stix-object-dialog").close();
      } else if (action === "rulelab-indicates-open") {
        state.indicatesMode = "lab";
        const searchInput = document.getElementById("indicates-search");
        const resultsDiv = document.getElementById("indicates-search-results");
        const idInput = document.getElementById("indicates-stix-id");
        const nameInput = document.getElementById("indicates-object-name");
        const select = document.getElementById("indicates-object-select");
        if (searchInput instanceof HTMLInputElement) searchInput.value = "";
        if (resultsDiv) resultsDiv.innerHTML = "";
        if (idInput instanceof HTMLInputElement) idInput.value = "";
        if (nameInput instanceof HTMLInputElement) nameInput.value = "";
        renderIndicatesObjectOptions();
        if (select instanceof HTMLSelectElement) select.value = "";
        document.getElementById("indicates-dialog").showModal();
      } else if (action === "rulelab-indicates-remove") {
        const idx = Number(target.dataset.idx || "-1");
        if (idx >= 0 && state.ruleLab.indicatesList[idx] !== undefined) {
          state.ruleLab.indicatesList.splice(idx, 1);
          renderRuleLabIndicates();
        }
      } else if (action === "indicates-pick") {
        const idInput = document.getElementById("indicates-stix-id");
        const nameInput = document.getElementById("indicates-object-name");
        const select = document.getElementById("indicates-object-select");
        const stixId = target.dataset.stixId || "";
        if (idInput instanceof HTMLInputElement) idInput.value = target.dataset.stixId || "";
        if (nameInput instanceof HTMLInputElement) nameInput.value = target.dataset.objectName || "";
        if (select instanceof HTMLSelectElement) select.value = stixId;
      } else if (action === "indicates-create-object") {
        state.returnToIndicatesDialog = true;
        document.getElementById("indicates-dialog").close();
        openStixObjectDialog();
      } else if (action === "stix-select-all-toggle") {
        const filtered = state.stixObjects.filter((entry) => stixObjectMatchesSearch(entry, state.stixObjectsView.searchTerm));
        if (!filtered.length) return;
        const shouldSelect = target instanceof HTMLInputElement
          ? target.checked
          : filtered.some((entry) => !state.stixObjectsView.selected.has(entry.stix_id));
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
      } else if (action === "stix-select-row") {
        const stixId = target.dataset.stixId || "";
        if (!stixId) return;
        if (target instanceof HTMLInputElement && target.checked) state.stixObjectsView.selected.add(stixId);
        else state.stixObjectsView.selected.delete(stixId);
        updateStixObjectsBulkState();
      } else if (action === "stix-toggle-details") {
        const stixId = target.dataset.stixId || "";
        toggleStixObjectDetails(stixId);
      } else if (action === "stix-export-selected") {
        if (state.stixObjectsView.selected.size === 0) return;
        const selected = state.stixObjects.filter((entry) => state.stixObjectsView.selected.has(entry.stix_id));
        const rows = selected.map((entry) => [entry.stix_id, entry.name].join(",")).join("\n");
        const ts = new Date().toISOString().slice(0, 19).replaceAll(":", "-");
        downloadTextFile(rows, `spuc-stix-objects-selected-${ts}.csv`, "text/csv;charset=utf-8");
        showToast("toast.export_ready");
      } else if (action === "stix-delete") {
        const stixId = target.dataset.stixId || "";
        if (!stixId) return;
        const confirmDelete = await askForConfirmation(
          t("stix_objects.confirm_delete_one"),
          t("common.confirm_action"),
          { acceptLabel: t("stix_objects.delete_one_action") },
        );
        if (!confirmDelete) return;
        await api(`/api/stix-objects/${encodeURIComponent(stixId)}`, { method: "DELETE", body: "{}" });
        showToast("toast.saved");
        await loadStixObjects();
      } else if (action === "stix-delete-selected") {
        if (state.stixObjectsView.selected.size === 0) return;
        const confirmDelete = await askForConfirmation(
          t("stix_objects.confirm_delete_selected"),
          t("common.confirm_action"),
          { acceptLabel: t("stix_objects.delete_selected_action") },
        );
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

    if (target.id === "stix-object-type" && target instanceof HTMLSelectElement) {
      if (state.stixObjectsView.editingId) return;
      const idInput = document.getElementById("stix-object-id");
      if (idInput instanceof HTMLInputElement) {
        idInput.value = generateStixId(target.value);
      }
    }

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

    if (target.dataset.action === "rules-select-all-toggle") {
      const filtered = applyRulesClientFilters(state.rules.allEntries);
      const shouldSelect = target instanceof HTMLInputElement
        ? target.checked
        : filtered.some((entry) => !state.rules.selected.has(entry.id));
      filtered.forEach((entry) => {
        if (shouldSelect) state.rules.selected.add(entry.id);
        else state.rules.selected.delete(entry.id);
      });
      renderRulesTable();
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

    if (target.dataset.action === "adversaries-select-all-toggle") {
      const filtered = applyAdversariesClientFilters(state.adversaries.allEntries || []);
      const shouldSelect = target instanceof HTMLInputElement
        ? target.checked
        : filtered.some((entry) => !state.adversaries.selected.has(entry.id));
      filtered.forEach((entry) => {
        if (shouldSelect) state.adversaries.selected.add(entry.id);
        else state.adversaries.selected.delete(entry.id);
      });
      renderAdversariesTable();
      return;
    }

    if (target.dataset.action === "payload-catalog-select") {
      const payloadId = String(target.dataset.id || "");
      if (!payloadId) return;
      if (target instanceof HTMLInputElement && target.checked) state.customPayloads.selected.add(payloadId);
      else state.customPayloads.selected.delete(payloadId);
      updatePayloadCatalogBulkState();
      return;
    }

    if (target.dataset.action === "payload-catalog-select-all-toggle") {
      const filtered = applyPayloadCatalogClientFilters(state.customPayloads.entries || []);
      const shouldSelect = target instanceof HTMLInputElement
        ? target.checked
        : filtered.some((entry) => !state.customPayloads.selected.has(entry.id));
      filtered.forEach((entry) => {
        if (shouldSelect) state.customPayloads.selected.add(entry.id);
        else state.customPayloads.selected.delete(entry.id);
      });
      renderPayloadCatalogWorkspace();
      return;
    }

    if (target.dataset.action === "stix-select-row") {
      const stixId = target.dataset.stixId || "";
      if (!stixId) return;
      if (target instanceof HTMLInputElement && target.checked) state.stixObjectsView.selected.add(stixId);
      else state.stixObjectsView.selected.delete(stixId);
      updateStixObjectsBulkState();
      return;
    }

    if (target.dataset.action === "stix-select-all-toggle") {
      const filtered = state.stixObjects.filter((entry) => stixObjectMatchesSearch(entry, state.stixObjectsView.searchTerm));
      const shouldSelect = target instanceof HTMLInputElement
        ? target.checked
        : filtered.some((entry) => !state.stixObjectsView.selected.has(entry.stix_id));
      filtered.forEach((entry) => {
        if (shouldSelect) state.stixObjectsView.selected.add(entry.stix_id);
        else state.stixObjectsView.selected.delete(entry.stix_id);
      });
      renderStixObjectsTable();
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
