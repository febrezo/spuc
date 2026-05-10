pub(crate) const INDEX_HTML: &str = include_str!("static/index.html");
pub(crate) const APP_CSS: &str = include_str!("static/app.css");
pub(crate) const APP_JS: &str = include_str!("static/app.js");
pub(crate) const LOGO_SPUTNIK_PNG: &[u8] = include_bytes!("../../kb/assets/logo-sputnik.png");
pub(crate) const DONATE_BITCOIN_PNG: &[u8] = include_bytes!("../../kb/assets/donate-bitcoin.png");
pub(crate) const DONATE_MONERO_PNG: &[u8] = include_bytes!("../../kb/assets/donate-monero.png");
pub(crate) const LOGO_BITCOIN_PNG: &[u8] = include_bytes!("../../kb/assets/logo-bitcoin.png");
pub(crate) const LOGO_MONERO_PNG: &[u8] = include_bytes!("../../kb/assets/logo-monero.png");
pub(crate) const LOGO_GITHUB_PNG: &[u8] = include_bytes!("../../kb/assets/logo-github.png");
pub(crate) const MITRE_ATTACK_COMPACT_JSON: &str =
    include_str!("../../kb/assets/mitre-attack-compact.json");

#[cfg(test)]
mod tests {
    use crate::web::i18n::TRANSLATIONS_JSON;

    use super::{APP_CSS, APP_JS, INDEX_HTML};

    #[test]
    fn app_js_defines_status_label_helper_for_detail_modal() {
        assert!(APP_JS.contains("function statusLabel(status) {"));
        assert!(APP_JS.contains("statusLabel(normalized)"));
    }

    #[test]
    fn app_js_resets_detail_tab_when_opening_emulation_modal() {
        let start = APP_JS
            .find("function openEmulationDetail(")
            .expect("openEmulationDetail exists");
        let end = APP_JS[start..]
            .find("function renderTable(")
            .map(|offset| start + offset)
            .expect("openEmulationDetail terminator exists");
        let body = &APP_JS[start..end];
        assert!(body.contains("setDetailTab(\"view\");"));
    }

    #[test]
    fn app_js_keeps_rule_row_click_detail_handler() {
        assert!(APP_JS.contains("#rules-table tbody tr[data-rule-row-id]"));
        assert!(APP_JS.contains("openRuleDetail(entry);"));
    }

    #[test]
    fn app_js_uses_detection_export_file_names_in_commands() {
        assert!(APP_JS.contains("function detectionExportFileName(title, target) {"));
        assert!(
            APP_JS.contains("const fileName = detectionExportFileName(title || \"rule\", target);")
        );
        assert!(APP_JS.contains("sigma convert -t splunk -r ${fileName}"));
        assert!(APP_JS.contains(
            "snort -A console -q -c /etc/snort/snort.conf -R ${fileName} -r <traffic.pcap>"
        ));
    }

    #[test]
    fn app_js_hides_emulation_detonation_when_no_command_exists() {
        assert!(APP_JS.contains("if (!command) return \"\";"));
    }

    #[test]
    fn app_js_opens_stix_rule_detail_with_detection_layout() {
        assert!(APP_JS.contains(
            "setDetailModalMode(\"detection\", detailBadgeText(\"detection\", target), detail?.runtime_status || \"unsupported\");"
        ));
        assert!(!APP_JS.contains("conversionBadge.textContent = \"ESTADO:EXACTO\";"));
        assert!(APP_JS.contains("t(\"detail.rule.summary\")"));
        assert!(APP_JS.contains("t(\"detail.rule.tab.detection\")"));
        assert!(APP_JS.contains("t(\"detail.rule.tab.emulation\")"));
    }

    #[test]
    fn app_js_places_copy_output_button_inline_in_detection_code_block() {
        assert!(APP_JS.contains("${copyButtonFor(output || \"\", t(\"detail.copy_output\"))}"));
        assert!(!APP_JS.contains(
            "data-action=\"detail-copy\" data-copy=\"${escapeHtml(encodeURIComponent(output))}\""
        ));
    }

    #[test]
    fn app_js_uses_clear_sigma_link_labels() {
        assert!(APP_JS.contains("Documentacion de Sigma"));
        assert!(APP_JS.contains("Proyecto GitHub de sigma-cli"));
    }

    #[test]
    fn app_js_defines_structured_llm_prompt_builder_sections() {
        assert!(APP_JS.contains("function buildStixLlmPrompt(ruleEntry, options = {}) {"));
        assert!(APP_JS.contains("### Detection context"));
        assert!(APP_JS.contains("### Observables available"));
        assert!(APP_JS.contains("### Related indicators"));
        assert!(APP_JS.contains("### Detection targets"));
        assert!(APP_JS.contains("### Emulation capability"));
        assert!(APP_JS.contains("### Existing STIX pattern"));
        assert!(APP_JS.contains("### Task for the model"));
    }

    #[test]
    fn app_js_includes_prompt_copy_actions_for_rule_and_rulelab() {
        assert!(APP_JS.contains("action === \"rulelab-copy-llm-prompt\""));
        assert!(APP_JS.contains("copyRuleLabPrompt(task = \"\")"));
        assert!(APP_JS.contains("data-action=\"rule-open-in-lab\""));
    }

    #[test]
    fn app_js_supports_rules_cards_view_mode() {
        assert!(APP_JS
            .contains("viewMode: localStorage.getItem(\"spuc-web-rules-view-mode\") || \"cards\""));
        assert!(APP_JS.contains("function renderRulesCards() {"));
        assert!(APP_JS.contains("setRulesViewMode(target.dataset.mode || \"table\")"));
        let start = APP_JS
            .find("function renderRulesCards() {")
            .expect("renderRulesCards exists");
        let end = APP_JS[start..]
            .find("function updateRulesViewModeUI() {")
            .map(|offset| start + offset)
            .expect("renderRulesCards terminator exists");
        let body = &APP_JS[start..end];
        assert!(body.contains("\"rule-target-detail\""));
        assert!(body.contains("\"rule-emulation-detail\""));
        assert!(body.contains("rule-card-pill-label"));
        assert!(body.contains("rule-card-title-line"));
        assert!(!body.contains("rule-card-status-summary"));
        assert!(body.contains("detail.rule.tab.detection_short"));
        assert!(body.contains("data-action=\"rule-copy\""));
    }

    #[test]
    fn app_js_renders_rule_detail_detection_and_emulation_tabs() {
        assert!(APP_JS.contains("function setRuleDetailTab(tab) {"));
        assert!(APP_JS.contains("overviewBtn.dataset.action = \"rule-detail-tab\""));
        assert!(APP_JS.contains("detail.rule.tab.overview"));
        assert!(APP_JS.contains("viewBtn.dataset.action = \"rule-detail-tab\""));
        assert!(APP_JS.contains("jsonBtn.dataset.action = \"rule-detail-tab\""));
        assert!(APP_JS.contains("rule-detail-pane-overview"));
        assert!(APP_JS.contains("rule-detail-pane-detection"));
        assert!(APP_JS.contains("rule-detail-pane-emulation"));
        assert!(APP_JS.contains("data-action=\"rule-open-in-lab\""));
        assert!(APP_JS.contains("data-action=\"rule-detail-export\""));
        assert!(APP_JS.contains("openRuleInLab(entry)"));
        assert!(APP_JS.contains("detail.rule.how_to_use"));
        assert!(APP_JS.contains("configureDetailTabs(\"rule\")"));
        assert!(APP_JS.contains("data-action=\"detail-show-json\""));
        assert!(APP_JS.contains("rules.detail.observables.title"));
        assert!(APP_JS.contains("rule-detail-observable-list"));
        assert!(APP_JS.contains("rule-detail-stix-card"));
        assert!(APP_JS
            .contains("const relationName = relation.relationship || relation.relationship_type || \"indicates\";"));
        assert!(APP_CSS.contains(".rule-detail-observable-list li::before"));
        assert!(APP_CSS.contains(".rule-detail-stix-card {"));
        assert!(TRANSLATIONS_JSON
            .contains("\"rules.detail.observables.title\": \"Tipos de observables mencionados\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"rules.detail.related.title\": \"Objetos STIX relacionados\""));
        assert!(APP_JS.contains("await openRuleDetail(entry, { tab: \"detection\""));
        assert!(APP_JS.contains("await openRuleDetail(entry, { tab: \"emulation\""));
        assert!(APP_JS.contains("detail?.notes"));
        assert!(APP_JS.contains("detail.converter.comments"));
        assert!(APP_JS.contains("selectAllButton.checked"));
        assert!(APP_JS.contains("selectAllButton.indeterminate"));
        assert!(APP_JS.contains("fa-circle-info"));
        assert!(APP_JS.contains("fa-shield-halved"));
        assert!(APP_JS.contains("fa-gears"));
        assert!(APP_JS.contains("detail.preview.more"));
        assert!(APP_JS.contains("function renderConfidenceWidget(entry, targetConfidenceRaw) {"));
        assert!(APP_JS.contains("function renderConfidenceBar(rawValue, options = {}) {"));
        assert!(APP_JS.contains("rule-confidence-grid"));
        assert!(APP_JS.contains("data-action=\"rule-tech-guide-toggle\""));
        assert!(APP_JS.contains("detail.output.compact_unavailable"));
        assert!(APP_JS.contains("rule-card-id-stack"));
    }

    #[test]
    fn app_js_shows_saved_rule_navigation_toast_and_returns_to_rules_explorer() {
        assert!(APP_JS.contains("function showRuleSavedNavigationToast() {"));
        assert!(APP_JS.contains("toast.saved_navigating_rules"));
        assert!(APP_JS.contains("toast-check-success"));
        assert!(APP_JS.contains("class=\"toast-inline\""));
    }

    #[test]
    fn app_css_defines_rules_cards_visual_layout() {
        assert!(APP_CSS.contains(".rules-cards {"));
        assert!(APP_CSS.contains(".rule-card {"));
        assert!(APP_CSS.contains(".rule-card-status-line {"));
        assert!(APP_CSS.contains("#rules-explore-shell .icon-only {"));
        assert!(APP_CSS.contains(".rule-card-title-line"));
        assert!(APP_CSS.contains("grid-template-columns: minmax(0, 1fr) auto;"));
        assert!(APP_CSS.contains("overflow-wrap: anywhere;"));
        assert!(APP_CSS.contains(".rule-card-pill-columns"));
        assert!(APP_CSS.contains(".rule-card-pill-label"));
        assert!(APP_CSS.contains(".rule-card-id-stack"));
        assert!(APP_CSS.contains(".confidence-bar-inline"));
        assert!(APP_CSS.contains(".confidence-bar-meter"));
        assert!(APP_CSS.contains(".rule-tech-card"));
        assert!(APP_CSS.contains(".rule-tech-body"));
        assert!(APP_CSS.contains(".rule-export-combo"));
        assert!(APP_CSS.contains(".rule-export-select"));
        assert!(APP_CSS.contains(".rule-tech-guide"));
        assert!(APP_CSS.contains(".rule-tech-guide-toggle-row"));
        assert!(APP_CSS.contains("min-width: 116px;"));
        assert!(APP_CSS.contains(".compact-list"));
        assert!(APP_CSS.contains(".rule-tech-comments"));
        assert!(APP_CSS.contains(".toast-check-success"));
        assert!(APP_CSS.contains("@keyframes toast-check-pop"));
        assert!(APP_CSS.contains("@keyframes toast-check-pulse"));
        assert!(APP_CSS.contains(".detail-tab-content"));
        assert!(APP_CSS.contains(".detail-tab-icon"));
        assert!(APP_CSS.contains(".rule-preview-more"));
        assert!(APP_CSS.contains(".rule-confidence-grid"));
        assert!(APP_CSS.contains(".rule-confidence-meter"));
        assert!(APP_CSS.contains(".rule-output-empty"));
        assert!(APP_CSS.contains("#adversaries-catalog-shell .icon-only"));
    }

    #[test]
    fn index_html_uses_font_awesome_for_rules_toolbar_icons() {
        assert!(INDEX_HTML.contains("font-awesome/6.5.2/css/all.min.css"));
        assert!(INDEX_HTML.contains("fa-table-cells-large"));
        assert!(INDEX_HTML.contains("fa-table-list"));
        assert!(INDEX_HTML.contains("fa-pen-to-square"));
        assert!(INDEX_HTML.contains("fa-table-columns"));
        assert!(INDEX_HTML.contains("fa-file-csv"));
        assert!(INDEX_HTML.contains("fa-file-code"));
        assert!(INDEX_HTML.contains("fa-file-export"));
        assert!(APP_JS.contains("fa-circle-info"));
        assert!(INDEX_HTML.contains("fa-trash-can"));
        assert!(INDEX_HTML.contains("adversaries-view-cards"));
        assert!(INDEX_HTML.contains("adversaries-view-table"));
        assert!(INDEX_HTML.contains("adversaries-table-wrap"));
        assert!(INDEX_HTML.contains("adversaries-cards"));
    }

    #[test]
    fn index_html_keeps_sidebar_shell_and_single_adversary_toolbar() {
        assert!(INDEX_HTML.contains("<div id=\"app-view\" class=\"app-layout hidden\">"));
        assert!(INDEX_HTML.contains("<aside class=\"sidebar glass\">"));
        assert!(INDEX_HTML.contains("<div class=\"sidebar-brand-line\">"));
        assert!(INDEX_HTML.contains("id=\"route-title-icon\""));
        assert!(INDEX_HTML.contains("id=\"route-title-text\""));
        let lab_idx = INDEX_HTML
            .find("data-route=\"rulelab\"")
            .expect("rulelab nav item");
        let rules_idx = INDEX_HTML
            .find("data-route=\"rules\"")
            .expect("rules nav item");
        let payloads_idx = INDEX_HTML
            .find("data-route=\"adversaries-payloads\"")
            .expect("payloads nav item");
        let stix_idx = INDEX_HTML
            .find("data-route=\"stix-objects\"")
            .expect("stix nav item");
        let adversaries_idx = INDEX_HTML
            .find("data-route=\"adversaries\"")
            .expect("adversaries nav item");
        assert!(lab_idx < rules_idx);
        assert!(rules_idx < payloads_idx);
        assert!(payloads_idx < stix_idx);
        assert!(stix_idx < adversaries_idx);
        assert_eq!(
            INDEX_HTML.matches("id=\"adversaries-view-cards\"").count(),
            1
        );
        assert_eq!(
            INDEX_HTML.matches("id=\"adversaries-view-table\"").count(),
            1
        );
        assert_eq!(
            APP_JS
                .matches("id=\"adversaries-select-all-header\"")
                .count(),
            1
        );
        assert_eq!(
            INDEX_HTML.matches("id=\"adversaries-bulk-toggle\"").count(),
            1
        );
        assert_eq!(
            INDEX_HTML
                .matches("id=\"adversaries-columns-toggle\"")
                .count(),
            1
        );
    }

    #[test]
    fn about_spuc_modal_replaces_support_placeholder() {
        assert!(INDEX_HTML.contains("id=\"support-dialog\" class=\"detail-dialog about-dialog\""));
        assert!(INDEX_HTML.contains("id=\"about-view\" class=\"about-layout\""));
        assert!(INDEX_HTML.contains("class=\"about-logo\""));
        assert_eq!(
            INDEX_HTML.matches("class=\"sidebar-about-link\"").count(),
            1
        );
        assert!(!INDEX_HTML.contains("class=\"sidebar-support-link\""));
        assert!(!INDEX_HTML.contains("data-i18n=\"about.eyebrow\""));
        assert!(INDEX_HTML.contains("data-action=\"open-support\""));
        assert!(INDEX_HTML.contains("data-support-section=\"donate\""));
        assert!(!INDEX_HTML.contains("pendiente de configurar"));
        assert!(APP_JS.contains("const PROJECT_LINKS = {"));
        assert!(APP_JS.contains("const DONATION_OPTIONS = ["));
        assert!(
            APP_JS.contains("documentation: app.documentation_url || PROJECT_LINKS.documentation")
        );
        assert!(APP_JS.contains("/assets/donate-bitcoin.png"));
        assert!(APP_JS.contains("/assets/donate-monero.png"));
        assert!(APP_JS.contains("/assets/logo-bitcoin.png"));
        assert!(APP_JS.contains("/assets/logo-monero.png"));
        assert!(APP_JS.contains("/assets/logo-github.png"));
        assert!(APP_JS.contains("441focuYuGZ3wbF3d7M1QMYAdX1Mvpv3j1Zyg1mjPAJKDJ29q6DGR6mZ7mpuwNiJscUX8oc8pazZQMGRAbnw1iw35kYYViN"));
        assert!(APP_JS.contains("bc1qwrzus8wkvvsdqeuxzl8wca9ecj0v6z8jwx8qzl"));
        assert!(APP_JS.contains("https://github.com/sponsors/febrezo"));
        assert!(APP_JS.contains("about-github-sponsors-link"));
        assert!(APP_JS.contains("about-donation-action"));
        assert!(APP_JS.contains("function renderAboutDialog(section = \"\")"));
        assert!(APP_JS.contains("function copyDonationAddress(method)"));
        assert!(APP_JS.contains("action === \"about-donation-method\""));
        assert!(APP_JS.contains("action === \"about-copy-donation\""));
        assert!(APP_CSS.contains(".about-card {"));
        assert!(APP_CSS.contains(".about-donation-card {"));
        assert!(APP_CSS.contains(".about-github-sponsors-link {"));
        assert!(APP_CSS.contains("grid-template-columns: minmax(0, 1fr) 220px;"));
        assert!(APP_CSS.contains(".about-card .detail-close-btn {"));
        assert!(TRANSLATIONS_JSON.contains("\"about.title\": \"Acerca de SPUC\""));
        assert!(TRANSLATIONS_JSON.contains("\"about.sponsors.title\": \"GitHub Sponsors\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"about.donate.title\": \"Colabora con alguno de estos métodos\""));
        assert!(TRANSLATIONS_JSON.contains("\"about.donate.eyebrow\": \"Apoyo al proyecto\""));
        assert!(TRANSLATIONS_JSON.contains("\"about.releases\": \"Lanzamientos\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"about.donate.empty\": \"Dirección no configurada todavía.\""));
        assert!(TRANSLATIONS_JSON.contains("\"about.donate.copied\": \"Dirección copiada\""));
    }

    #[test]
    fn index_html_keeps_rulelab_save_button_visible() {
        assert!(INDEX_HTML.contains("class=\"rulelab-head-actions\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-export-bundle\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-success icon-only\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-success icon-only\" data-i18n-title=\"rulelab.save\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-success icon-only\" data-i18n-title=\"rulelab.save\" aria-label=\"Save Rule\" title=\"Save Rule\" disabled"));
        assert!(APP_CSS.contains(".rulelab-head-actions {"));
        assert!(INDEX_HTML.contains("id=\"rulelab-save-dialog\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save-form\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-editing-banner\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save-editing-note\""));
        assert!(APP_JS.contains("function updateRuleLabEditingContext()"));
        assert!(APP_JS.contains("state.ruleLab.editingRuleId = entry.id || entry.rule_id || \"\";"));
        assert!(APP_JS.contains("clearRuleLabEditingContext();"));
        assert!(TRANSLATIONS_JSON
            .contains("\"rulelab.editing_existing\": \"Editando regla existente: {name} {id}\""));
        assert!(
            TRANSLATIONS_JSON.contains("\"rulelab.stix_relations\": \"Objetos STIX relacionados\"")
        );
        assert!(TRANSLATIONS_JSON
            .contains("\"rulelab.stix_relations.empty\": \"Sin objetos relacionados\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-stix-object-select\""));
        assert!(!INDEX_HTML.contains("data-action=\"rulelab-indicates-open\""));
    }

    #[test]
    fn rules_route_uses_direct_explore_with_revealer_filters() {
        assert!(INDEX_HTML.contains("id=\"rules-filters-toggle\""));
        assert!(INDEX_HTML.contains("id=\"rules-open-lab\""));
        assert!(INDEX_HTML.contains("id=\"rules-import-stix\""));
        assert!(INDEX_HTML.contains("id=\"rules-filters-revealer\""));
        assert!(APP_CSS.contains(".rules-filters-revealer {"));
        assert!(APP_CSS.contains(".rules-filters-revealer.open {"));
        assert!(APP_JS.contains(
            "if (route === \"rules-import\" || route === \"rules-catalog\") route = \"rules\";"
        ));
        assert!(APP_JS.contains("state.rules.workspaceMode = \"explore\";"));
        assert!(APP_JS.contains("action === \"rules-filters-toggle\""));
        assert!(APP_JS.contains("action === \"rules-open-lab\""));
        assert!(APP_JS.contains("action === \"rules-import-stix\""));
    }

    #[test]
    fn adversaries_route_uses_direct_explorer_with_empty_state_and_help() {
        assert!(INDEX_HTML.contains("id=\"adversaries-empty-state\""));
        assert!(INDEX_HTML.contains("id=\"adversaries-catalog-main\""));
        assert!(INDEX_HTML.contains("id=\"adversaries-payloads-shell\""));
        assert!(INDEX_HTML.contains("id=\"payloads-welcome-card\""));
        assert!(INDEX_HTML.contains("id=\"payloads-catalog-shell\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-list\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-toolbar\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-runner\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-search\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-tech\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-create-header\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-create-form\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-form-title\""));
        assert!(INDEX_HTML.contains("id=\"payload-catalog-save-create\""));
        assert!(INDEX_HTML.contains("data-route=\"adversaries-payloads\""));
        assert!(INDEX_HTML.contains("data-i18n=\"nav.payloads\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-view\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-mount\""));
        assert!(INDEX_HTML.contains("id=\"panel-adversary-editor\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-plan\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-export-toggle\""));
        assert!(!INDEX_HTML.contains("id=\"adversary-editor-json\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-primary\""));
        assert!(INDEX_HTML.contains("id=\"adversary-editor-secondary\""));
        assert!(INDEX_HTML.contains("id=\"adversary-payload-picker-dialog\""));
        assert!(INDEX_HTML.contains("id=\"adversary-payload-form-dialog\""));
        assert!(INDEX_HTML.contains("data-action=\"adversary-open-payload-picker\""));
        assert!(INDEX_HTML.contains("data-action=\"adversary-open-payload-form\""));
        assert!(INDEX_HTML.contains("data-action=\"adversaries-help-open\""));
        assert!(INDEX_HTML.contains("data-i18n=\"adversaries.flow.sequence\""));
        assert!(INDEX_HTML.contains("data-i18n=\"adversaries.flow.steps_label\""));
        assert!(INDEX_HTML.contains("data-i18n=\"adversaries.flow.add_behaviors\""));
        assert!(INDEX_HTML.contains("data-i18n=\"adversaries.editor.add_payload\""));
        assert!(APP_CSS.contains(".adversaries-empty-state {"));
        assert!(APP_CSS.contains(".adversary-editor-hero {"));
        assert!(APP_CSS.contains(".adversary-custom-payload-card"));
        assert!(APP_CSS.contains(".payload-search-wrap {"));
        assert!(APP_CSS.contains(".payload-catalog-list {"));
        assert!(APP_CSS.contains(".payload-accordion-summary"));
        assert!(APP_CSS.contains(".payload-detail-id-row"));
        assert!(APP_CSS.contains(".payload-detail-code {"));
        assert!(APP_CSS.contains(".payload-filters-row {"));
        assert!(APP_CSS.contains(".payload-catalog-table {"));
        assert!(APP_CSS.contains(".payload-table-actions {"));
        assert!(APP_CSS.contains(".adversary-editor-export-menu"));
        assert!(APP_JS.contains("if (route === \"adversaries-catalog\") route = \"adversaries\";"));
        assert!(APP_JS.contains("route === \"adversaries-payloads\" ? \"payloads\" : \"catalog\""));
        assert!(APP_JS.contains("mountAdversaryEditorSurface();"));
        assert!(APP_JS.contains("state.adversaries.workspaceMode = \"editor\";"));
        assert!(APP_JS.contains("function renderPayloadCatalogWorkspace()"));
        assert!(APP_JS.contains("const runner = String(document.getElementById(\"payload-catalog-runner\")"));
        assert!(APP_JS.contains("x-spuc-payload--"));
        assert!(APP_JS.contains("payload-accordion-list"));
        assert!(APP_JS.contains("action === \"payload-catalog-open-create\""));
        assert!(APP_JS.contains("action === \"payload-catalog-open-docs\""));
        assert!(APP_JS.contains("action === \"payload-catalog-save-create\""));
        assert!(APP_JS.contains("action === \"payload-catalog-close-create\""));
        assert!(APP_JS.contains("action === \"payload-catalog-edit\""));
        assert!(APP_JS.contains("const hasCatalogEntries = allEntries.length > 0;"));
        assert!(APP_JS.contains("const showPayloadWelcome = showPayloads && state.customPayloads.loaded && !hasPayloads;"));
        assert!(APP_JS.contains("const showPayloadCatalog = showPayloads && hasPayloads;"));
        assert!(APP_JS.contains("state.customPayloads.editingId = existing?.id || \"\";"));
        assert!(APP_JS.contains("function openAdversaryPayloadPicker()"));
        assert!(APP_JS.contains("function openAdversaryPayloadForm()"));
        assert!(APP_JS.contains("async function addCustomPayloadStep()"));
        assert!(APP_JS.contains("kind: \"custom_payload\""));
        assert!(APP_JS.contains("const PAYLOAD_TYPE_TO_RUNNERS = {"));
        assert!(APP_JS.contains("const compatibleRunners = PAYLOAD_TYPE_TO_RUNNERS[technology]"));
        assert!(APP_JS.contains(
            "const showEmptyState = showCatalog && state.adversaries.loaded && !hasEntries;"
        ));
        assert!(APP_JS.contains("action === \"adversaries-help-open\""));
        assert!(APP_JS.contains("action === \"adversaries-empty-create\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.editor.editing_title\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.payload.title\""));
        assert!(TRANSLATIONS_JSON.contains("\"payloads.create.title\""));
        assert!(TRANSLATIONS_JSON.contains("\"payloads.create.edit_title\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.payload.search_label\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.flow.steps_label\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.view.details\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.welcome.payloads.title\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.editor.saved_blur\""));
        assert!(TRANSLATIONS_JSON.contains(
            "\"adversaries.payload.empty.title\": \"No existe ningún payload cargado todavía\""
        ));
    }

    #[test]
    fn rule_detail_title_uses_name_and_monospace_id_stack() {
        assert!(APP_JS.contains("function setDetailTitle(title, subtitle = \"\") {"));
        assert!(APP_JS
            .contains("setDetailTitle(entry.name || t(\"rules.col.rule\"), entry.id || \"\");"));
        assert!(APP_CSS.contains(".detail-title-main {"));
        assert!(APP_CSS.contains(".detail-title-subtitle {"));
        assert!(APP_JS.contains("rule-detail-summary-text"));
    }

    #[test]
    fn app_js_keeps_adversary_detail_separate_from_editor() {
        assert!(APP_JS.contains("async function openAdversaryDetail(adversaryId)"));
        assert!(APP_JS.contains("function renderAdversaryDetailMain(adversary)"));
        assert!(APP_JS.contains("function isExporterCompatibleWithPlan(exporter, selectedSteps)"));
        assert!(
            APP_JS.contains("function getExporterIncompatibilityReasons(exporter, selectedSteps)")
        );
        assert!(APP_JS.contains("openAdversaryInNewEditor(adversaryId)"));
        assert!(APP_JS.contains(".adversary-card[data-adversary-card-id]"));
        assert!(APP_JS.contains("action === \"adversary-show\""));
        assert!(APP_JS.contains("await openAdversaryDetail(target.dataset.id || \"\");"));
        assert!(APP_JS.contains("action === \"adversary-edit\""));
        assert!(APP_JS.contains("action === \"adversary-detail-tab\""));
        assert!(APP_JS.contains("action === \"adversary-enter-edit\""));
        assert!(APP_JS.contains("action === \"adversary-save\""));
        assert!(APP_JS.contains("action === \"adversary-json-copy\""));
        assert!(APP_JS.contains("state.adversaryCompose.mode = \"view\";"));
        assert!(APP_JS.contains("await openAdversaryInNewEditor(target.dataset.id || \"\");"));
        assert!(APP_JS.contains("class=\"adversary-main-tabs\""));
        assert!(APP_JS.contains("class=\"adversary-detail-steps\""));
        assert!(APP_JS.contains("class=\"adversary-export-grid\""));
        assert!(APP_JS.contains("class=\"adversary-row-actions\""));
        assert!(APP_CSS.contains(".adversary-main-tabs {"));
        assert!(APP_CSS.contains(".adversary-detail-step {"));
        assert!(APP_CSS.contains(".adversary-export-card {"));
        assert!(TRANSLATIONS_JSON.contains("\"common.edit\": \"Editar\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.detail.steps\": \"Pasos del plan\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.view.tab.summary\": \"Resumen\""));
        assert!(
            TRANSLATIONS_JSON.contains("\"adversaries.export.not_compatible\": \"No compatible\"")
        );
    }

    #[test]
    fn app_js_hides_admin_route_in_no_login_mode() {
        assert!(APP_JS.contains(
            "if (route === \"admin\" && (state.bootstrap?.auth?.no_login || state.principal?.role !== \"admin\"))"
        ));
        assert!(APP_JS.contains(
            "if (state.bootstrap.auth.no_login || !state.principal || state.principal.role !== \"admin\")"
        ));
        assert!(APP_JS.contains("function detectAppMode()"));
        assert!(APP_JS.contains("spuc-mode"));
        assert!(APP_JS.contains("const noLoginActive = state.bootstrap.auth.no_login;"));
        assert!(APP_JS.contains("if (noLoginActive) {"));
        assert!(APP_JS.contains("showBootGate();"));
        assert!(APP_JS.contains("} else if (state.bootstrap.auth.authenticated) {"));
        assert!(APP_JS.contains("enterApplication();"));
        assert!(INDEX_HTML.contains("id=\"boot-view\" class=\"boot-layout\""));
        assert!(INDEX_HTML.contains("class=\"boot-shell glass\""));
        assert!(INDEX_HTML.contains("id=\"login-view\" class=\"login-layout hidden\""));
        assert!(INDEX_HTML.contains("id=\"boot-enter-button\""));
        assert!(INDEX_HTML.contains("data-i18n=\"boot.enter\""));
        assert!(
            APP_JS.contains("document.getElementById(\"boot-view\")?.classList.add(\"hidden\");")
        );
        assert!(APP_JS.contains("function showBootGate()"));
        assert!(APP_JS.contains("showBootGate();"));
        assert!(APP_CSS.contains(".boot-layout,"));
        assert!(APP_CSS.contains(".boot-shell {"));
        assert!(APP_JS.contains("action === \"local-login\""));
        assert!(APP_JS.contains(
            "document.getElementById(\"boot-enter-button\")?.classList.remove(\"hidden\");"
        ));
        assert!(TRANSLATIONS_JSON.contains("\"boot.enter\": \"Iniciar SPUC\""));
        assert!(
            TRANSLATIONS_JSON.contains("\"login.coded_with_love\": \"Codificado con amor por febrezo\"")
        );
        assert!(INDEX_HTML.contains("data-i18n=\"common.github_project\">GitHub Project</a>"));
        assert!(INDEX_HTML.contains(
            "data-i18n=\"common.license_sspl\">Server Side Public License</a>"
        ));
        assert!(INDEX_HTML.contains("id=\"footer-license-link-boot\""));
        assert!(INDEX_HTML.contains("id=\"footer-license-link\""));
        assert!(APP_CSS.contains("position: fixed;"));
        assert!(APP_CSS.contains("bottom: 18px;"));
        assert!(APP_CSS.contains(".login-footer-row {"));
        assert!(APP_CSS.contains(".auth-footer {"));
    }

    #[test]
    fn stix_route_switches_between_entity_welcome_and_catalog() {
        assert!(INDEX_HTML.contains("data-action=\"stix-import-open\""));
        assert!(INDEX_HTML.contains("data-i18n=\"stix_objects.welcome.standard.title\""));
        assert!(INDEX_HTML.contains("id=\"stix-import-file\""));
        assert!(APP_JS.contains("function importStixObjectsFromFile(file) {"));
        assert!(APP_JS.contains("action === \"stix-import-open\""));
        assert!(APP_JS.contains(
            "state.route === \"stix-objects-catalog\" || hasEntries ? \"catalog\" : \"welcome\""
        ));
        assert!(TRANSLATIONS_JSON.contains("\"route.stix_objects.title\": \"Catálogo de objetos\""));
        assert!(TRANSLATIONS_JSON.contains("\"nav.stix_objects\": \"Catálogo de objetos\""));
    }

    #[test]
    fn adversary_delete_uses_in_app_confirmation_dialog() {
        assert!(APP_JS.contains("async function deleteSelectedAdversaries() {"));
        assert!(APP_JS.contains("await askForConfirmation("));
        assert!(!APP_JS
            .contains("const confirmed = confirm(t(\"adversaries.confirm_delete_selected\"));"));
    }

    #[test]
    fn rulelab_empty_state_stays_brief() {
        assert!(!INDEX_HTML.contains("data-i18n=\"rulelab.compat.hint\""));
        assert!(INDEX_HTML.contains("class=\"compatibility-inline is-empty\""));
        assert!(APP_CSS.contains(".compatibility-inline.is-empty .status-box"));
        assert!(APP_JS.contains("panel.classList.add(\"is-empty\");"));
        assert!(APP_JS.contains("panel.classList.remove(\"is-empty\");"));
        assert!(
            TRANSLATIONS_JSON.contains("\"rulelab.compatibility.empty\": \"Sin patrón todavía.\"")
        );
        assert!(TRANSLATIONS_JSON.contains("\"rulelab.status.idle\": \"Sin patrón todavía.\""));
    }

    #[test]
    fn app_title_is_localized_and_browser_locale_detected() {
        assert!(INDEX_HTML.contains("<title>SPUC: A behavioural IOC mapping lab</title>"));
        assert!(
            TRANSLATIONS_JSON.contains("\"app.title\": \"SPUC: A behavioural IOC mapping lab\"")
        );
        assert!(TRANSLATIONS_JSON.contains(
            "\"app.title\": \"SPUC: Laboratorio de mapeo de comportamientos adversarios\""
        ));
        assert!(APP_JS.contains("function detectInitialLocale()"));
        assert!(APP_JS.contains("navigator.languages"));
        assert!(APP_JS.contains("spuc-locale"));
        assert!(APP_JS.contains("spuc-mode"));
        assert!(APP_JS.contains("document.title = t(\"app.title\");"));
        assert!(TRANSLATIONS_JSON.contains(
            "\"login.subtitle\": \"Plataforma para la detección y emulación\\nde comportamientos adversarios.\""
        ));
        assert!(APP_CSS.contains("white-space: pre-line;"));
    }

    #[test]
    fn oauth_buttons_start_disabled_and_enable_only_configured_providers() {
        assert!(INDEX_HTML.contains("data-provider=\"google\" disabled>Google</button>"));
        assert!(INDEX_HTML.contains("data-provider=\"github\" disabled>GitHub</button>"));
        assert!(
            APP_JS.contains("const enabled = Boolean(provider?.configured && provider?.enabled);")
        );
        assert!(APP_JS.contains("button.disabled = !enabled;"));
        assert!(APP_JS
            .contains("button.setAttribute(\"aria-disabled\", enabled ? \"false\" : \"true\");"));
    }

    #[test]
    fn sidebar_omits_product_tagline() {
        assert!(!INDEX_HTML.contains("data-i18n=\"app.tagline\""));
    }

    #[test]
    fn app_css_aligns_detail_labels_and_confidence_values() {
        assert!(APP_CSS.contains("grid-template-columns: minmax(0, 1fr) auto;"));
        assert!(APP_CSS.contains("min-height: 32px;"));
        assert!(APP_CSS.contains("display: inline-flex;"));
    }

    #[test]
    fn app_css_centers_detail_tooltip_and_refines_icon() {
        assert!(APP_CSS.contains(".detail-help-tip .help-tip-content"));
        assert!(APP_CSS.contains("left: 50%;"));
        assert!(APP_CSS.contains("transform: translate(-50%, 4px);"));
        assert!(APP_CSS.contains("width: 18px;"));
        assert!(APP_CSS.contains("height: 18px;"));
    }

    #[test]
    fn app_css_keeps_floating_footer_visible_and_brand_aligned() {
        assert!(INDEX_HTML.contains("class=\"app-floating-footer muted\""));
        assert!(APP_CSS.contains("height: calc(100vh - 64px);"));
        assert!(APP_CSS.contains("grid-template-rows: auto minmax(0, 1fr) auto;"));
        assert!(INDEX_HTML.contains("class=\"sidebar-footer\""));
        assert!(APP_CSS.contains(".sidebar-footer {"));
        assert!(APP_CSS.contains(".sidebar-brand-line {"));
        assert!(APP_CSS.contains("flex-direction: column;"));
        assert!(APP_CSS.contains("align-items: center;"));
        assert!(APP_CSS.contains(".main-shell {"));
        assert!(APP_CSS.contains("padding-top: 10px;"));
        assert!(APP_CSS.contains("overflow-y: auto;"));
        assert!(APP_CSS.contains(".app-floating-footer {"));
        assert!(APP_CSS.contains("position: fixed;"));
        assert!(APP_CSS.contains("font-size: calc(0.82rem - 2px);"));
    }

    #[test]
    fn app_css_compacts_home_workspace_card_to_fit_viewport() {
        assert!(APP_CSS.contains("max-width: 1160px;"));
        assert!(APP_CSS.contains("width: min(1140px, 100%);"));
        assert!(APP_CSS.contains("min-height: min(680px, calc(100vh - 150px));"));
        assert!(APP_CSS.contains("width: min(288px, 72vw);"));
        assert!(APP_CSS.contains("max-height: calc(100vh - 166px);"));
    }

    #[test]
    fn app_css_gives_light_theme_welcome_actions_light_surfaces() {
        assert!(APP_CSS.contains("body.theme-light .welcome-action {"));
        assert!(APP_CSS.contains("background: rgba(255, 255, 255, 0.84);"));
        assert!(APP_CSS.contains("body.theme-light .welcome-action:hover"));
        assert!(APP_CSS.contains("body.theme-light .welcome-action.active"));
    }

    #[test]
    fn learning_toolbar_keeps_pending_toggle_and_progress_separated() {
        assert!(INDEX_HTML.contains("class=\"learning-toolbar-controls\""));
        assert!(INDEX_HTML.contains("class=\"learning-toggle learning-pending-toggle\""));
        assert!(INDEX_HTML.contains("class=\"learning-progress-control\""));
        assert!(APP_CSS.contains(".learning-toolbar-controls {"));
        assert!(APP_CSS.contains("grid-template-columns: minmax(0, 1fr) minmax(0, max-content);"));
        assert!(APP_CSS.contains("min-width: 0;"));
        assert!(APP_CSS.contains("overflow: hidden;"));
        assert!(APP_CSS.contains(".learning-pending-toggle {"));
        assert!(APP_CSS.contains("justify-content: center;"));
        assert!(APP_CSS.contains("text-overflow: ellipsis;"));
        assert!(APP_CSS.contains(".learning-progress-control {"));
        assert!(APP_CSS.contains("#learning-progress {"));
        assert!(APP_CSS.contains("width: auto;"));
        assert!(APP_CSS.contains("white-space: nowrap;"));
    }

    #[test]
    fn learning_progress_is_persisted_locally() {
        assert!(APP_JS
            .contains("const LEARNING_PROGRESS_STORAGE_KEY = \"spuc-web-learning-progress\";"));
        assert!(APP_JS.contains("function loadLearningProgress()"));
        assert!(APP_JS.contains("function saveLearningProgress()"));
        assert!(APP_JS.contains("state.completedChallenges.add(state.selectedChallenge.id);"));
        assert!(APP_JS.contains("saveLearningProgress();"));
    }

    #[test]
    fn learning_uses_compact_path_summary_and_exercise_rows() {
        assert!(INDEX_HTML.contains("id=\"learning-paths-summary\""));
        assert!(INDEX_HTML.contains("class=\"learning-exercise-list\""));
        assert!(APP_JS.contains("function renderLearningPathSummary()"));
        assert!(APP_JS.contains("data-action=\"learning-path-filter\""));
        assert!(APP_JS.contains("class=\"learning-exercise-row glass"));
        assert!(APP_CSS.contains(".learning-paths-summary {"));
        assert!(APP_CSS.contains(".learning-exercise-row {"));
        assert!(!APP_CSS.contains("grid-auto-flow: column;"));
    }

    #[test]
    fn rule_detail_uses_collapsed_target_accordions_with_conversion_confidence() {
        assert!(APP_JS.contains("<details class=\"rule-tech-card rule-tech-accordion"));
        assert!(APP_JS.contains("class=\"rule-tech-summary-metrics\""));
        assert!(APP_JS.contains("if (node instanceof HTMLDetailsElement) node.open = true;"));
        assert!(TRANSLATIONS_JSON
            .contains("\"detail.rule.tech.target_confidence_short\": \"Conversion confidence\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"detail.rule.tech.target_confidence_short\": \"Confianza de conversión\""));
    }

    #[test]
    fn rule_detail_summary_aligns_tlp_pap_and_uses_top_close_button() {
        assert!(INDEX_HTML.contains("class=\"icon-btn detail-close-btn\""));
        assert!(APP_JS.contains("class=\"detail-grid rule-summary-grid\""));
        assert!(APP_JS.contains("class=\"detail-kv rule-summary-levels\""));
        assert!(APP_CSS.contains(".rule-summary-grid {"));
        assert!(APP_CSS.contains(".rule-summary-levels {"));
        assert!(APP_JS.contains(
            "return rightHtml ? `<div class=\"detail-actions-right\">${rightHtml}</div>` : \"\";"
        ));
        assert!(!APP_JS.contains("data-action=\"detail-cancel\""));
    }

    #[test]
    fn rulelab_hides_copy_prompt_button() {
        assert!(!INDEX_HTML.contains("id=\"rulelab-copy-prompt\""));
    }

    #[test]
    fn rulelab_trust_row_keeps_four_then_two_columns() {
        assert!(APP_CSS.contains(".trust-row {"));
        assert!(APP_CSS.contains("grid-template-columns: repeat(4, minmax(0, 1fr));"));
        assert!(APP_CSS.contains("@media (max-width: 1080px)"));
        assert!(APP_CSS.contains("grid-template-columns: repeat(2, minmax(0, 1fr));"));
    }

    #[test]
    fn rulelab_compatibility_uses_details_and_copy_actions() {
        assert!(APP_JS.contains("data-action=\"compat-show\""));
        assert!(APP_JS.contains("data-action=\"compat-copy\""));
        assert!(APP_JS.contains("t(\"common.details\")"));
        assert!(APP_JS.contains("t(\"detail.copy_rule\")"));
        assert!(APP_JS.contains("action === \"compat-copy\""));
        assert!(APP_CSS.contains(".compat-row-actions {"));
    }

    #[test]
    fn stix_catalog_uses_icon_only_actions_and_no_columns_toggle() {
        assert!(INDEX_HTML.contains("id=\"stix-create-open-table\""));
        assert!(INDEX_HTML.contains("id=\"stix-objects-search\" type=\"search\""));
        assert!(INDEX_HTML.contains("class=\"btn btn-primary btn-import icon-only stix-import-label\""));
        assert!(!INDEX_HTML.contains("id=\"stix-bulk-toggle\" class=\"btn btn-ghost icon-only\""));
        assert!(
            INDEX_HTML.contains("id=\"stix-export-selected\" class=\"btn btn-success icon-only\"")
        );
        assert!(
            INDEX_HTML.contains("id=\"stix-delete-selected\" class=\"btn btn-danger icon-only\"")
        );
        assert!(!INDEX_HTML.contains("id=\"stix-columns-toggle\""));
        assert!(!APP_JS.contains("action === \"stix-columns-toggle\""));
        assert!(APP_JS.contains("function stixObjectMatchesSearch("));
        assert!(APP_JS.contains("data-stix-row-id"));
        assert!(APP_JS.contains("toggleStixObjectDetails("));
        assert!(APP_JS.contains("action === \"stix-toggle-details\""));
        assert!(APP_JS.contains("data-action=\"stix-edit-object\""));
        assert!(APP_JS.contains("openStixObjectDialog(entry = null)"));
        assert!(APP_JS.contains("function renderStixObjectDetails(entry)"));
        assert!(APP_CSS.contains(".stix-search-wrap {"));
        assert!(APP_CSS.contains(".stix-detail-compact {"));
        assert!(APP_CSS.contains(".stix-description-head {"));
    }

    #[test]
    fn adversary_export_uses_single_operational_flow() {
        assert!(!INDEX_HTML.contains("id=\"adversary-export-operational-button\""));
        assert!(!APP_JS.contains("function exportAdversaryOperationalFromDialog()"));
        assert!(APP_JS.contains("function exportAdversaryFromDialog()"));
        assert!(APP_JS.contains("pickOperationalDownload(response.downloads, target)"));
    }
}
