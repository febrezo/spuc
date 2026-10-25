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
    use super::APP_ENTRY_JS;

    #[test]
    fn app_entry_module_imports_boot_module() {
        assert!(APP_ENTRY_JS.contains("import \"./boot.js\";"));
    }
}
