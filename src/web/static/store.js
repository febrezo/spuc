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
    filtersOpen: false,
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
    viewMode: localStorage.getItem("spuc-web-payloads-view-mode") || "table",
    sort: "name_asc",
    visibleColumns: new Set(["name", "technology", "runner", "description"]),
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


export { state, detectInitialLocale, detectAppMode };
