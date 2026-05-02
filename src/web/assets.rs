pub(crate) const INDEX_HTML: &str = include_str!("static/index.html");
pub(crate) const APP_CSS: &str = include_str!("static/app.css");
pub(crate) const APP_JS: &str = include_str!("static/app.js");
pub(crate) const LOGO_SPUTNIK_PNG: &[u8] = include_bytes!("../../kb/assets/logo-sputnik.png");

#[cfg(test)]
mod tests {
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
        assert!(APP_JS.contains("await openRuleDetail(entry, { tab: \"detection\""));
        assert!(APP_JS.contains("await openRuleDetail(entry, { tab: \"emulation\""));
        assert!(APP_JS.contains("detail?.notes"));
        assert!(APP_JS.contains("detail.converter.comments"));
        assert!(APP_JS.contains("selectAllButton.innerHTML"));
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
        assert!(INDEX_HTML.contains("fa-square"));
        assert!(INDEX_HTML.contains("fa-pen-to-square"));
        assert!(INDEX_HTML.contains("fa-table-columns"));
        assert!(INDEX_HTML.contains("fa-file-csv"));
        assert!(INDEX_HTML.contains("fa-file-code"));
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
        assert_eq!(
            INDEX_HTML.matches("id=\"adversaries-view-cards\"").count(),
            1
        );
        assert_eq!(
            INDEX_HTML.matches("id=\"adversaries-view-table\"").count(),
            1
        );
        assert_eq!(
            INDEX_HTML
                .matches("id=\"adversaries-select-all-toggle\"")
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
    fn index_html_keeps_rulelab_save_button_visible() {
        assert!(INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-success\""));
        assert!(!INDEX_HTML.contains("id=\"rulelab-save\" class=\"btn btn-success hidden\""));
    }

    #[test]
    fn app_js_allows_admin_route_in_no_login_mode() {
        assert!(APP_JS.contains("if (route === \"admin\" && state.principal?.role !== \"admin\")"));
        assert!(!APP_JS.contains("if (route === \"admin\" && (state.bootstrap?.auth?.no_login || state.principal?.role !== \"admin\"))"));
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
    fn app_css_keeps_sidebar_footer_visible_and_brand_aligned() {
        assert!(APP_CSS.contains("height: calc(100vh - 36px);"));
        assert!(APP_CSS.contains("grid-template-rows: auto minmax(0, 1fr) auto;"));
        assert!(APP_CSS.contains(".sidebar-brand-line {"));
        assert!(APP_CSS.contains("align-items: center;"));
        assert!(APP_CSS.contains("overflow-y: auto;"));
        assert!(APP_CSS.contains("align-self: end;"));
    }

    #[test]
    fn app_css_expands_home_workspace_card() {
        assert!(APP_CSS.contains("max-width: 1160px;"));
        assert!(APP_CSS.contains("width: min(1140px, 100%);"));
        assert!(APP_CSS.contains("min-height: max(62vh, 520px);"));
        assert!(APP_CSS.contains("width: min(284px, 58vw);"));
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
    fn adversary_export_uses_single_operational_flow() {
        assert!(!INDEX_HTML.contains("id=\"adversary-export-operational-button\""));
        assert!(!APP_JS.contains("function exportAdversaryOperationalFromDialog()"));
        assert!(APP_JS.contains("function exportAdversaryFromDialog()"));
        assert!(APP_JS.contains("pickOperationalDownload(response.downloads, target)"));
    }
}
