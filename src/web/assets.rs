pub(crate) const INDEX_HTML: &str = include_str!("static/index.html");
pub(crate) const APP_CSS: &str = include_str!("static/app.css");
pub(crate) const APP_ENTRY_JS: &str = include_str!("static/app.js");
pub(crate) const APP_JS: &str = include_str!("static/boot.js");
pub(crate) const API_CLIENT_JS: &str = include_str!("static/api-client.js");
pub(crate) const STORE_JS: &str = include_str!("static/store.js");
pub(crate) const ACTION_REGISTRY_JS: &str = include_str!("static/action-registry.js");
pub(crate) const UI_DOM_JS: &str = include_str!("static/ui/dom.js");
pub(crate) const UI_TOAST_JS: &str = include_str!("static/ui/toast.js");
pub(crate) const UI_MODAL_JS: &str = include_str!("static/ui/modal.js");
pub(crate) const RULES_FEATURE_JS: &str = include_str!("static/features/rules/index.js");
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

    use super::{APP_CSS, APP_ENTRY_JS, APP_JS, INDEX_HTML, STORE_JS, UI_TOAST_JS};

    #[test]
    fn app_entry_module_imports_boot_module() {
        assert!(APP_ENTRY_JS.contains("import \"./boot.js\";"));
    }

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
        assert!(STORE_JS
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
        assert!(APP_JS.contains("action === \"rule-copy\""));
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
        assert!(UI_TOAST_JS.contains("toast.saved_navigating_rules"));
        assert!(APP_JS.contains("toast.rule_save_success"));
        assert!(APP_JS.contains("toast.rule_save_error"));
        assert!(UI_TOAST_JS.contains("class=\"toast-close\""));
        assert!(UI_TOAST_JS.contains("toast-variant-warning"));
        assert!(UI_TOAST_JS.contains("toast-check-success"));
        assert!(UI_TOAST_JS.contains("class=\"toast-inline\""));
        assert!(
            TRANSLATIONS_JSON.contains("\"toast.rule_save_success\": \"Rule saved successfully\"")
        );
        assert!(TRANSLATIONS_JSON
            .contains("\"toast.rule_save_error\": \"The rule could not be saved\""));
    }

    #[test]
    fn app_js_supports_opencti_visibility_and_personal_api_tokens() {
        assert!(APP_JS.contains("function toggleOpenCtiConfigVisibility(sourceValue) {"));
        assert!(APP_JS.contains("function renderTranslationCurlExample() {"));
        assert!(APP_JS.contains("function installSettingsPersonalAccordionBehavior() {"));
        assert!(APP_JS.contains("settings-opencti-config-fields"));
        assert!(APP_JS.contains("settings-opencti-bundle-curl-example"));
        assert!(APP_JS.contains("settings-code-tab"));
        assert!(APP_JS.contains("settings-code-copy"));
        assert!(APP_JS.contains("settings-opencti-summary-curl-example"));
        assert!(APP_JS.contains("settings-opencti-summary-python-example"));
        assert!(APP_JS.contains("settings-opencti-curl-endpoint"));
        assert!(APP_JS.contains("settings-opencti-curl-token"));
        assert!(APP_JS.contains("/api/user/tokens"));
        assert!(APP_JS.contains("settings-token-rotate"));
        assert!(APP_JS.contains("settings-token-revoke"));
        assert!(APP_JS.contains("settings-api-token-secret-copy"));
        assert!(TRANSLATIONS_JSON
            .contains("\"settings.opencti.curl_title\": \"Translation API examples\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"settings.opencti.curl_title\": \"Ejemplos de API de traducción\""));
        assert!(
            TRANSLATIONS_JSON.contains("\"settings.api_tokens.title\": \"Personal API tokens\"")
        );
        assert!(
            TRANSLATIONS_JSON.contains("\"settings.api_tokens.title\": \"Tokens API personales\"")
        );
        assert!(TRANSLATIONS_JSON
            .contains("\"settings.personal.storage_group_title\": \"Document management\""));
        assert!(TRANSLATIONS_JSON.contains(
            "\"settings.personal.api_group_title\": \"Tokens API personales y API de traducción\""
        ));
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
        assert!(APP_CSS.contains(".toast-variant-success"));
        assert!(APP_CSS.contains(".toast-variant-error"));
        assert!(APP_CSS.contains(".toast-variant-warning"));
        assert!(APP_CSS.contains(".toast-close"));
        assert!(APP_CSS.contains("@keyframes toast-check-pop"));
        assert!(APP_CSS.contains("@keyframes toast-check-pulse"));
        assert!(APP_CSS.contains(".settings-personal-accordion {"));
        assert!(APP_CSS.contains(".settings-personal-accordion-summary {"));
        assert!(APP_CSS.contains(".detail-tab-content"));
        assert!(APP_CSS.contains(".detail-tab-icon"));
        assert!(APP_CSS.contains(".rule-preview-more"));
        assert!(APP_CSS.contains(".rule-confidence-grid"));
        assert!(APP_CSS.contains(".rule-confidence-meter"));
        assert!(APP_CSS.contains(".rule-output-empty"));
        assert!(APP_CSS.contains("#adversaries-catalog-shell .icon-only"));
    }

    #[test]
    fn app_js_keeps_adversary_row_and_card_click_handlers_complete() {
        assert!(APP_JS.contains(
            "const row = target.closest(\"#adversaries-table tbody tr[data-adversary-row-id]\")"
        ));
        assert!(APP_JS
            .contains("const card = target.closest(\".adversary-card[data-adversary-card-id]\")"));
        assert!(APP_JS.contains("await openAdversaryDetail(adversaryId);"));
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
    fn index_html_includes_settings_api_tokens_and_opencti_fields_container() {
        assert!(INDEX_HTML.contains("id=\"settings-storage-opencti-accordion\""));
        assert!(INDEX_HTML.contains("id=\"settings-api-translation-accordion\""));
        assert!(INDEX_HTML.contains("id=\"settings-opencti-config-fields\""));
        assert!(INDEX_HTML.contains("id=\"settings-opencti-bundle-curl-example\""));
        assert!(INDEX_HTML.contains("id=\"settings-opencti-summary-curl-example\""));
        assert!(INDEX_HTML.contains("data-action=\"settings-code-copy\""));
        assert!(INDEX_HTML.contains("id=\"settings-opencti-curl-endpoint\""));
        assert!(INDEX_HTML.contains("id=\"settings-opencti-curl-token\""));
        assert!(INDEX_HTML.contains("id=\"settings-api-token-form\""));
        assert!(INDEX_HTML.contains("id=\"settings-api-token-name\""));
        assert!(INDEX_HTML.contains("id=\"settings-api-tokens-list\""));
        assert!(INDEX_HTML.contains("id=\"settings-api-token-secret\""));
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
                .matches("getElementById(\"adversaries-select-all-header\")")
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
        assert!(APP_JS.contains("<input\n        class=\"about-donation-address\""));
        assert!(APP_JS.contains("function renderAboutDialog(section = \"\")"));
        assert!(APP_JS.contains("function copyDonationAddress(method)"));
        assert!(APP_JS.contains("action === \"about-donation-method\""));
        assert!(APP_JS.contains("action === \"about-copy-donation\""));
        assert!(APP_CSS.contains(".about-card {"));
        assert!(APP_CSS.contains(".about-donation-card {"));
        assert!(APP_CSS.contains(".about-github-sponsors-link {"));
        assert!(APP_CSS.contains("grid-template-columns: minmax(0, 1fr) 220px;"));
        assert!(APP_CSS.contains("min-height: 42px;"));
        assert!(APP_CSS.contains("white-space: nowrap;"));
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
        assert!(
            INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-ghost rulelab-save-button\"")
        );
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-ghost rulelab-save-button\" data-i18n=\"rulelab.save\""));
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-ghost rulelab-save-button\" data-i18n=\"rulelab.save\" aria-label=\"Save Rule\" title=\"Save Rule\" disabled"));
        assert!(APP_CSS.contains(".rulelab-head-actions {"));
        assert!(APP_CSS.contains(".rulelab-save-button {"));
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
        assert!(APP_CSS.contains(".adversaries-empty-state {"));
        assert!(APP_CSS.contains(".adversary-create-modal {"));
        assert!(APP_JS.contains("if (route === \"adversaries-catalog\") route = \"adversaries\";"));
        assert!(APP_JS.contains("mountAdversaryEditorSurface();"));
        assert!(APP_JS.contains("state.adversaries.workspaceMode = \"editor\";"));
        assert!(APP_JS.contains(
            "const showEmptyState = showCatalog && state.adversaries.loaded && !hasEntries;"
        ));
        assert!(APP_JS.contains("action === \"adversaries-help-open\""));
        assert!(APP_JS.contains("action === \"adversaries-empty-create\""));
        assert!(TRANSLATIONS_JSON.contains("\"adversaries.editor.editing_title\""));
    }

    #[test]
    fn empty_states_use_localized_copy_and_uniform_ctas() {
        assert!(INDEX_HTML.contains("data-i18n=\"rules.empty.title\""));
        assert!(INDEX_HTML.contains("data-i18n=\"rules.empty.body\""));
        assert!(APP_JS.contains("const visibleTotal = Number(state.rules.total || 0);"));
        assert!(APP_JS.contains(
            "const showEmptyState = mode === \"explore\" && (visibleTotal === 0 || !hasEntries);"
        ));
        assert!(INDEX_HTML.contains("data-i18n=\"stix_objects.empty.title\""));
        assert!(INDEX_HTML.contains("data-i18n=\"stix_objects.empty.body\""));
        assert!(TRANSLATIONS_JSON.contains("\"rules.empty.title\": \"Aún no hay reglas creadas\""));
        assert!(TRANSLATIONS_JSON
            .contains("\"stix_objects.empty.title\": \"Aún no hay objetos creados\""));
        assert!(APP_CSS.contains("width: min(92%, 860px);"));
        assert!(APP_CSS.contains("max-width: 620px;"));
        assert!(APP_CSS.contains("min-height: 64px;"));
        assert!(APP_CSS.contains("white-space: normal;"));
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
        assert!(APP_CSS.contains("background: linear-gradient(140deg, var(--success), #2b9d64);"));
        assert!(APP_CSS.contains("color: #fff;"));
    }

    #[test]
    fn button_icons_keep_white_contrast_and_light_theme_icons_are_darker() {
        assert!(APP_CSS.contains(".btn-primary i,"));
        assert!(APP_CSS.contains(".btn-primary svg,"));
        assert!(APP_CSS.contains("color: currentColor;"));
        assert!(APP_CSS.contains("fill: currentColor;"));
        assert!(APP_CSS.contains("body.theme-light .nav-icon,"));
        assert!(APP_CSS.contains("body.theme-light .route-title-icon,"));
        assert!(APP_CSS.contains("body.theme-light .welcome-icon,"));
        assert!(APP_CSS.contains("color: rgba(32, 49, 82, 0.9);"));
    }

    #[test]
    fn selects_use_compact_shared_combobox_styling() {
        assert!(APP_CSS.contains("select {"));
        assert!(APP_CSS.contains("min-height: 42px;"));
        assert!(APP_CSS.contains("padding: 9px 38px 9px 12px;"));
        assert!(APP_CSS.contains("appearance: none;"));
        assert!(APP_CSS.contains("background-position: right 12px center;"));
        assert!(APP_CSS.contains("color-scheme: dark;"));
        assert!(APP_CSS.contains("select[multiple],"));
        assert!(APP_CSS.contains("background-image: none;"));
        assert!(APP_CSS.contains(".spuc-combobox {"));
        assert!(APP_CSS.contains(".spuc-combobox-trigger {"));
        assert!(APP_CSS.contains(".spuc-combobox-menu {"));
        assert!(APP_CSS.contains(".spuc-combobox-option.is-selected {"));
        assert!(APP_JS.contains("function isCustomComboboxCandidate(select) {"));
        assert!(APP_JS.contains("function syncCustomCombobox(select) {"));
        assert!(APP_JS.contains("function refreshCustomComboboxes(root = document) {"));
        assert!(APP_CSS.contains(".flow-picker-filters select {"));
        assert!(APP_CSS.contains(".rule-export-select {"));
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
        assert!(
            INDEX_HTML.contains("class=\"btn btn-primary btn-import icon-only stix-import-label\"")
        );
        assert!(INDEX_HTML.contains("id=\"stix-bulk-toggle\" class=\"btn btn-ghost icon-only\""));
        assert!(
            INDEX_HTML.contains("id=\"stix-export-selected\" class=\"btn btn-success icon-only\"")
        );
        assert!(INDEX_HTML
            .contains("id=\"stix-export-selected-stix\" class=\"btn btn-warning icon-only\""));
        assert!(
            INDEX_HTML.contains("id=\"stix-delete-selected\" class=\"btn btn-danger icon-only\"")
        );
        assert!(!INDEX_HTML.contains("id=\"stix-columns-toggle\""));
        assert!(APP_JS.contains("action === \"stix-bulk-toggle\""));
        assert!(!APP_JS.contains("action === \"stix-columns-toggle\""));
        assert!(APP_JS.contains("function stixObjectMatchesSearch("));
        assert!(APP_JS.contains("data-stix-row-id"));
        assert!(APP_JS.contains("toggleStixObjectDetails("));
        assert!(APP_JS.contains("action === \"stix-toggle-details\""));
        assert!(APP_JS.contains("action === \"stix-edit-object\""));
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
