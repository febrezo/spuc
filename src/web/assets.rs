pub(crate) const INDEX_HTML: &str = include_str!("static/index.html");
pub(crate) const APP_CSS: &str = include_str!("static/app.css");
pub(crate) const APP_JS: &str = include_str!("static/app.js");
pub(crate) const LOGO_SPUTNIK_PNG: &[u8] = include_bytes!("../../kb/assets/logo-sputnik.png");

#[cfg(test)]
mod tests {
    use super::{APP_CSS, APP_JS};

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
        assert!(APP_JS.contains("t(\"detail.rule.available_emulations\")"));
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
        assert!(APP_JS.contains("data-action=\"rule-copy-llm-prompt\""));
        assert!(APP_JS.contains("data-action=\"rulelab-copy-llm-prompt\""));
        assert!(APP_JS.contains("copyRuleLabPrompt(task = \"\")"));
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
}
