use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::services::translation::{evaluate_rule, TranslationRequest};
use crate::catalog::{
    delete_rule_entry, edit_rule_entry, filter_adversary_entries, filter_rule_entries,
    load_catalog_data, resolve_adversary_selector, resolve_rule_selector, CatalogAdversaryEntry,
    CatalogRuleEntry,
};
use crate::cli::{AbilityTarget, BuildOutput, ConversionMode, ExportFormat};
use crate::commands::common::{
    available_detection_target_labels, build_ability_from_rule, parse_ability_target,
};
use crate::commands::sigma_runtime::{refresh_sigma_runtime_cache, sigma_runtime_info};
use crate::commands::sigma_targets::dynamic_sigma_targets;
use crate::commands::{emulate, learn, plan, translate, verify};
use crate::paths::spuc_config_root;
use crate::web::auth::{
    build_oauth_authorize_url, change_password, create_user, delete_user, exchange_oauth_code,
    list_users, load_or_init_oauth_policy, load_or_init_users, save_oauth_policy, save_users,
    set_oauth_provider_authorized, update_user as update_store_user, verify_credentials,
    OAuthConfig, OAuthIdentity, OAuthPolicyStore, Principal, ProviderBootstrap, PublicUserView,
    Role, UserStore,
};
use crate::web::{assets, i18n};
use spuc::emulation::ability as emu_ability;
use spuc::emulation::campaign as emu_campaign;
use spuc::emulation::catalog::AbilityCatalog;
use spuc::emulation::export as emu_export;

const OAUTH_STATE_TTL_SECONDS: i64 = 600;
const WEB_ADMIN_SETTINGS_SCHEMA_VERSION: &str = "1.0";
const WEB_USER_PREFERENCES_SCHEMA_VERSION: &str = "1.0";
const WEB_USER_OPENCTI_SETTINGS_SCHEMA_VERSION: &str = "1.0";
const WEB_USER_API_TOKENS_SCHEMA_VERSION: &str = "1.0";
const ENV_SIGMA_RPC_URL: &str = "SIGMA_RPC_URL";
const ENV_SIGMA_RPC_TOKEN: &str = "SPUC_SIGMA_RPC_TOKEN";
const ENV_ADMIN_API_TOKEN: &str = "SPUC_ADMIN_API_TOKEN";
const ENV_ADMIN_API_TOKEN_NAME: &str = "SPUC_ADMIN_API_TOKEN_NAME";
const ENV_ADMIN_API_TOKEN_EXPIRES_AT: &str = "SPUC_ADMIN_API_TOKEN_EXPIRES_AT";
const BOOTSTRAP_ADMIN_API_TOKEN_ID: &str = "tok-bootstrap-admin-env";
const OPENCTI_GRAPHQL_TIMEOUT_SECONDS: u64 = 8;
const OPENCTI_DEFAULT_LIMIT: usize = 25;
const OPENCTI_MAX_LIMIT: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminRuntimeSettingsStore {
    schema_version: String,
    no_login: bool,
    #[serde(default)]
    sigma_rpc_url: Option<String>,
    #[serde(default)]
    sigma_rpc_token: Option<String>,
    #[serde(default)]
    default_locale: Option<String>,
    #[serde(default)]
    default_theme: Option<String>,
    #[serde(default)]
    default_totp_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminRuntimeSettingsView {
    no_login: bool,
    sigma_rpc_url: Option<String>,
    sigma_rpc_token_set: bool,
    default_locale: String,
    default_theme: String,
    default_totp_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AdminRuntimeSettingsUpdateRequest {
    #[serde(default)]
    no_login: Option<bool>,
    #[serde(default)]
    sigma_rpc_url: Option<String>,
    #[serde(default)]
    sigma_rpc_token: Option<String>,
    #[serde(default)]
    default_locale: Option<String>,
    #[serde(default)]
    default_theme: Option<String>,
    #[serde(default)]
    default_totp_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserPreferencesStore {
    schema_version: String,
    #[serde(default)]
    entries: Vec<UserPreferencesEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserPreferencesEntry {
    user_id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    theme: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum StixCatalogSource {
    #[default]
    Local,
    OpenCti,
}

impl StixCatalogSource {
    fn as_str(self) -> &'static str {
        match self {
            StixCatalogSource::Local => "local",
            StixCatalogSource::OpenCti => "opencti",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserOpenCtiSettingsStore {
    schema_version: String,
    #[serde(default)]
    entries: Vec<UserOpenCtiSettingsEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserOpenCtiSettingsEntry {
    user_id: String,
    #[serde(default)]
    opencti_enabled: bool,
    #[serde(default)]
    opencti_endpoint: Option<String>,
    #[serde(default)]
    opencti_api_key: Option<String>,
    #[serde(default)]
    stix_catalog_source: StixCatalogSource,
}

#[derive(Debug, Clone, Serialize)]
struct UserOpenCtiSettingsView {
    opencti_enabled: bool,
    opencti_endpoint: Option<String>,
    opencti_api_key_set: bool,
    stix_catalog_source: &'static str,
    effective_source: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
struct UserOpenCtiSettingsUpdateRequest {
    #[serde(default)]
    opencti_enabled: Option<bool>,
    #[serde(default)]
    opencti_endpoint: Option<String>,
    #[serde(default)]
    opencti_api_key: Option<String>,
    #[serde(default)]
    stix_catalog_source: Option<StixCatalogSource>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenCtiTestRequest {
    #[serde(default)]
    opencti_endpoint: Option<String>,
    #[serde(default)]
    opencti_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OpenCtiTestResponse {
    ok: bool,
    code: &'static str,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserApiTokenStore {
    schema_version: String,
    #[serde(default)]
    entries: Vec<UserApiTokenEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserApiTokenEntry {
    id: String,
    user_id: String,
    name: String,
    token_hash: String,
    created_at: String,
    #[serde(default)]
    revoked_at: Option<String>,
    #[serde(default)]
    last_used_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct UserApiTokenView {
    id: String,
    user_id: String,
    name: String,
    created_at: String,
    revoked_at: Option<String>,
    last_used_at: Option<String>,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UserApiTokenCreateRequest {
    name: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserApiTokenCreateResponse {
    token: UserApiTokenView,
    token_value: String,
}

#[derive(Debug, Deserialize)]
struct TranslateStixPatternRequest {
    #[serde(rename = "type")]
    object_type: String,
    pattern_type: String,
    pattern: String,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    sigma_targets: Vec<String>,
    #[serde(default)]
    rule_confidence: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct TranslateStixBundleRequest {
    indicator: serde_json::Value,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    sigma_targets: Vec<String>,
    #[serde(default)]
    rule_confidence: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct TranslatePatternSummaryRequest {
    pattern: String,
    target: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    rule_confidence: Option<u8>,
}

#[derive(Debug, Serialize)]
struct TranslateStixPatternResponse {
    status: &'static str,
    comments: Vec<String>,
    results: Vec<TranslateStixPatternResult>,
}

#[derive(Debug, Serialize)]
struct TranslatePatternSummaryResponse {
    status: &'static str,
    comments: Vec<String>,
    result: Option<TranslatePatternSummaryResult>,
}

#[derive(Debug, Serialize)]
struct TranslatePatternSummaryResult {
    description: String,
    pattern: String,
    confidence: u8,
    target: String,
}

#[derive(Debug, Serialize)]
struct TranslateStixPatternResult {
    #[serde(rename = "type")]
    object_type: &'static str,
    pattern_type: String,
    pattern: String,
    confidence: u8,
    target: String,
    stix: TranslateStixDetectionRule,
}

#[derive(Debug, Serialize)]
struct TranslateStixDetectionRule {
    #[serde(rename = "type")]
    object_type: &'static str,
    pattern_type: String,
    pattern: String,
    confidence: u8,
    description: String,
    comments: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DownloadEntry {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) content_type: String,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    principal: Principal,
    created_at_utc: String,
}

#[derive(Debug, Clone)]
struct OAuthStateEntry {
    provider_id: String,
    created_at_epoch: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct WebRuntimeConfig {
    pub(crate) admin_user: String,
    pub(crate) project_link: String,
    pub(crate) project_name: String,
    pub(crate) documentation_link: String,
    pub(crate) license_link: String,
    pub(crate) license_name: String,
    pub(crate) oauth: OAuthConfig,
}

pub(crate) struct WebState {
    users_path: PathBuf,
    users: Mutex<UserStore>,
    user_preferences_path: PathBuf,
    user_preferences: Mutex<UserPreferencesStore>,
    user_opencti_settings_path: PathBuf,
    user_opencti_settings: Mutex<UserOpenCtiSettingsStore>,
    user_api_tokens_path: PathBuf,
    user_api_tokens: Mutex<UserApiTokenStore>,
    oauth_policy_path: PathBuf,
    oauth_policy: Mutex<OAuthPolicyStore>,
    runtime_settings_path: PathBuf,
    runtime_settings: Mutex<AdminRuntimeSettingsStore>,
    no_login: AtomicBool,
    generated_password: bool,
    runtime: WebRuntimeConfig,
    bootstrap_admin: Principal,
    sessions: Mutex<HashMap<String, SessionEntry>>,
    downloads: Mutex<HashMap<String, DownloadEntry>>,
    oauth_states: Mutex<HashMap<String, OAuthStateEntry>>,
}

impl WebState {
    pub(crate) fn new(
        admin_user: &str,
        admin_password: &str,
        generated_password: bool,
        no_login: bool,
    ) -> Result<Self> {
        let (users_path, users) =
            load_or_init_users(admin_user, admin_password, !generated_password)?;
        let (user_preferences_path, user_preferences) = load_or_init_user_preferences()?;
        let (user_opencti_settings_path, user_opencti_settings) =
            load_or_init_user_opencti_settings()?;
        let (user_api_tokens_path, mut user_api_tokens) = load_or_init_user_api_tokens()?;
        let oauth = OAuthConfig::from_env();
        let (oauth_policy_path, oauth_policy) = load_or_init_oauth_policy(&oauth)?;
        let (runtime_settings_path, runtime_settings) = load_or_init_runtime_settings(no_login)?;
        apply_sigma_rpc_env(&runtime_settings);
        let bootstrap_admin = users
            .users
            .iter()
            .find(|user| user.username.eq_ignore_ascii_case(admin_user) && user.enabled)
            .map(|user| Principal {
                user_id: user.id.clone(),
                username: user.username.clone(),
                role: user.role,
            })
            .or_else(|| {
                users
                    .users
                    .iter()
                    .find(|user| user.role == Role::Admin && user.enabled)
                    .map(|user| Principal {
                        user_id: user.id.clone(),
                        username: user.username.clone(),
                        role: user.role,
                    })
            })
            .ok_or_else(|| anyhow!("cannot bootstrap admin user for web runtime"))?;
        upsert_bootstrap_admin_api_token(
            &user_api_tokens_path,
            &mut user_api_tokens,
            &bootstrap_admin,
        )?;

        Ok(Self {
            users_path,
            users: Mutex::new(users),
            user_preferences_path,
            user_preferences: Mutex::new(user_preferences),
            user_opencti_settings_path,
            user_opencti_settings: Mutex::new(user_opencti_settings),
            user_api_tokens_path,
            user_api_tokens: Mutex::new(user_api_tokens),
            oauth_policy_path,
            oauth_policy: Mutex::new(oauth_policy),
            runtime_settings_path,
            no_login: AtomicBool::new(runtime_settings.no_login),
            runtime_settings: Mutex::new(runtime_settings),
            generated_password,
            runtime: WebRuntimeConfig {
                admin_user: admin_user.to_string(),
                project_link: "https://github.com/febrezo/spuc".to_string(),
                project_name: "GitHub Project".to_string(),
                documentation_link: "https://github.com/febrezo/spuc#readme".to_string(),
                license_link: "https://github.com/febrezo/spuc/blob/main/LICENSE.md".to_string(),
                license_name: "Server Side Public License".to_string(),
                oauth,
            },
            bootstrap_admin,
            sessions: Mutex::new(HashMap::new()),
            downloads: Mutex::new(HashMap::new()),
            oauth_states: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn generated_password(&self) -> bool {
        self.generated_password
    }

    pub(crate) fn runtime(&self) -> &WebRuntimeConfig {
        &self.runtime
    }

    pub(crate) fn no_login_enabled(&self) -> bool {
        self.no_login.load(Ordering::Relaxed)
    }

    pub(crate) fn runtime_settings_view(&self) -> AdminRuntimeSettingsView {
        let settings = self
            .runtime_settings
            .lock()
            .expect("runtime settings mutex poisoned")
            .clone();
        settings_view(settings)
    }

    pub(crate) fn update_runtime_settings(
        &self,
        payload: AdminRuntimeSettingsUpdateRequest,
    ) -> Result<AdminRuntimeSettingsView> {
        let mut settings = self
            .runtime_settings
            .lock()
            .expect("runtime settings mutex poisoned");

        if let Some(no_login) = payload.no_login {
            settings.no_login = no_login;
            self.no_login.store(no_login, Ordering::Relaxed);
        }
        if let Some(url) = payload.sigma_rpc_url {
            settings.sigma_rpc_url = normalize_optional_setting(url);
        }
        if let Some(token) = payload.sigma_rpc_token {
            settings.sigma_rpc_token = normalize_optional_setting(token);
        }
        if let Some(locale) = payload.default_locale {
            settings.default_locale = normalize_locale_setting(locale);
        }
        if let Some(theme) = payload.default_theme {
            settings.default_theme = normalize_theme_setting(theme);
        }
        if let Some(default_totp_required) = payload.default_totp_required {
            settings.default_totp_required = Some(default_totp_required);
        }

        persist_runtime_settings(&self.runtime_settings_path, &settings)?;
        apply_sigma_rpc_env(&settings);
        let _ = refresh_sigma_runtime_cache();
        Ok(settings_view(settings.clone()))
    }

    fn user_preferences_for(&self, user_id: &str) -> UserPreferencesEntry {
        self.user_preferences
            .lock()
            .expect("user preferences mutex poisoned")
            .entries
            .iter()
            .find(|entry| entry.user_id == user_id)
            .cloned()
            .unwrap_or(UserPreferencesEntry {
                user_id: user_id.to_string(),
                display_name: None,
                locale: None,
                theme: None,
            })
    }

    pub(crate) fn effective_locale_for(&self, principal: Option<&Principal>) -> String {
        if let Some(principal) = principal {
            if let Some(locale) = self.user_preferences_for(principal.user_id.as_str()).locale {
                return locale;
            }
        }
        self.runtime_settings
            .lock()
            .expect("runtime settings mutex poisoned")
            .default_locale
            .clone()
            .unwrap_or_else(|| "en".to_string())
    }

    pub(crate) fn effective_theme_for(&self, principal: Option<&Principal>) -> String {
        if let Some(principal) = principal {
            if let Some(theme) = self.user_preferences_for(principal.user_id.as_str()).theme {
                return theme;
            }
        }
        self.runtime_settings
            .lock()
            .expect("runtime settings mutex poisoned")
            .default_theme
            .clone()
            .unwrap_or_else(|| "dark".to_string())
    }

    pub(crate) fn effective_display_name_for(&self, principal: &Principal) -> String {
        self.user_preferences_for(principal.user_id.as_str())
            .display_name
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| principal.username.clone())
    }

    pub(crate) fn is_local_user(&self, user_id: &str) -> bool {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .users
            .iter()
            .any(|user| user.id == user_id)
    }

    pub(crate) fn is_bootstrap_admin_user(&self, user_id: &str) -> bool {
        self.bootstrap_admin.user_id == user_id
    }

    pub(crate) fn can_change_password(&self, principal: &Principal) -> bool {
        !self.no_login_enabled()
            && self.is_local_user(principal.user_id.as_str())
            && !self.is_bootstrap_admin_user(principal.user_id.as_str())
    }

    fn current_user_settings_view(&self, principal: &Principal) -> UserSettingsView {
        let locale = self.effective_locale_for(Some(principal));
        let theme = self.effective_theme_for(Some(principal));
        let display_name = self.effective_display_name_for(principal);
        UserSettingsView {
            account_id: principal.user_id.clone(),
            username: principal.username.clone(),
            display_name,
            locale,
            theme,
            can_change_password: self.can_change_password(principal),
            is_bootstrap_admin: self.is_bootstrap_admin_user(principal.user_id.as_str()),
            no_login: self.no_login_enabled(),
            local_auth: self.is_local_user(principal.user_id.as_str()),
        }
    }

    fn opencti_settings_for(&self, user_id: &str) -> UserOpenCtiSettingsEntry {
        self.user_opencti_settings
            .lock()
            .expect("OpenCTI settings mutex poisoned")
            .entries
            .iter()
            .find(|entry| entry.user_id == user_id)
            .cloned()
            .unwrap_or_else(|| default_opencti_settings_entry(user_id))
    }

    fn current_opencti_settings_view(&self, principal: &Principal) -> UserOpenCtiSettingsView {
        opencti_settings_view(self.opencti_settings_for(principal.user_id.as_str()))
    }

    fn update_current_opencti_settings(
        &self,
        principal: &Principal,
        payload: UserOpenCtiSettingsUpdateRequest,
    ) -> Result<UserOpenCtiSettingsView> {
        let mut store = self
            .user_opencti_settings
            .lock()
            .expect("OpenCTI settings mutex poisoned");
        let updated_entry = {
            let entry = user_opencti_settings_entry_mut(&mut store, principal.user_id.as_str());
            if let Some(enabled) = payload.opencti_enabled {
                entry.opencti_enabled = enabled;
            }
            if let Some(endpoint) = payload.opencti_endpoint {
                entry.opencti_endpoint = normalize_opencti_endpoint(endpoint);
            }
            if let Some(api_key) = payload.opencti_api_key {
                entry.opencti_api_key = normalize_optional_setting(api_key);
            }
            if let Some(source) = payload.stix_catalog_source {
                entry.stix_catalog_source = source;
            }
            normalize_opencti_settings_entry(entry);
            entry.clone()
        };
        persist_user_opencti_settings(&self.user_opencti_settings_path, &store)?;
        Ok(opencti_settings_view(updated_entry))
    }

    fn create_user_api_token(
        &self,
        principal: &Principal,
        name: &str,
        expires_at: Option<String>,
    ) -> Result<(UserApiTokenView, String)> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(anyhow!("token_name_required"));
        }
        let token_value = format!("spuc_pat_{}", generate_secret(44));
        let token_hash = hash_api_token(&token_value);
        let now = Utc::now().to_rfc3339();
        let entry = UserApiTokenEntry {
            id: format!("tok-{}", generate_secret(14)),
            user_id: principal.user_id.clone(),
            name: trimmed_name.to_string(),
            token_hash,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
            expires_at: expires_at.and_then(normalize_optional_setting),
        };

        let mut store = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned");
        store.entries.push(entry.clone());
        persist_user_api_tokens(&self.user_api_tokens_path, &store)?;
        Ok((api_token_view(entry), token_value))
    }

    fn list_user_api_tokens(&self, principal: &Principal) -> Vec<UserApiTokenView> {
        let mut tokens = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned")
            .entries
            .iter()
            .filter(|entry| entry.user_id == principal.user_id)
            .cloned()
            .map(api_token_view)
            .collect::<Vec<_>>();
        tokens.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        tokens
    }

    fn revoke_user_api_token(
        &self,
        principal: &Principal,
        token_id: &str,
    ) -> Result<UserApiTokenView> {
        let mut store = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned");
        let updated = {
            let Some(entry) = store
                .entries
                .iter_mut()
                .find(|entry| entry.user_id == principal.user_id && entry.id == token_id)
            else {
                return Err(anyhow!("token_not_found"));
            };
            if entry.revoked_at.is_none() {
                entry.revoked_at = Some(Utc::now().to_rfc3339());
            }
            entry.clone()
        };
        persist_user_api_tokens(&self.user_api_tokens_path, &store)?;
        Ok(api_token_view(updated))
    }

    fn rotate_user_api_token(
        &self,
        principal: &Principal,
        token_id: &str,
    ) -> Result<(UserApiTokenView, String)> {
        let mut store = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned");
        let (name, expires_at) = {
            let Some(source) = store
                .entries
                .iter_mut()
                .find(|entry| entry.user_id == principal.user_id && entry.id == token_id)
            else {
                return Err(anyhow!("token_not_found"));
            };
            if source.revoked_at.is_some() {
                return Err(anyhow!("token_revoked"));
            }
            source.revoked_at = Some(Utc::now().to_rfc3339());
            (source.name.clone(), source.expires_at.clone())
        };

        let token_value = format!("spuc_pat_{}", generate_secret(44));
        let new_entry = UserApiTokenEntry {
            id: format!("tok-{}", generate_secret(14)),
            user_id: principal.user_id.clone(),
            name,
            token_hash: hash_api_token(&token_value),
            created_at: Utc::now().to_rfc3339(),
            revoked_at: None,
            last_used_at: None,
            expires_at,
        };
        store.entries.push(new_entry.clone());
        persist_user_api_tokens(&self.user_api_tokens_path, &store)?;
        Ok((api_token_view(new_entry), token_value))
    }

    fn delete_user_api_token(&self, principal: &Principal, token_id: &str) -> Result<bool> {
        let mut store = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned");
        let before = store.entries.len();
        store
            .entries
            .retain(|entry| !(entry.user_id == principal.user_id && entry.id == token_id));
        let deleted = store.entries.len() != before;
        if deleted {
            persist_user_api_tokens(&self.user_api_tokens_path, &store)?;
        }
        Ok(deleted)
    }

    fn resolve_principal_from_api_token(&self, token: &str) -> Option<Principal> {
        let token_hash = hash_api_token(token);
        let now = Utc::now();
        let mut store = self
            .user_api_tokens
            .lock()
            .expect("API tokens mutex poisoned");
        let entry = store.entries.iter_mut().find(|entry| {
            entry.token_hash == token_hash
                && entry.revoked_at.is_none()
                && !is_token_expired(entry.expires_at.as_deref(), now)
        })?;
        entry.last_used_at = Some(now.to_rfc3339());
        let principal = self
            .users
            .lock()
            .expect("users mutex poisoned")
            .users
            .iter()
            .find(|user| user.id == entry.user_id && user.enabled)
            .map(|user| Principal {
                user_id: user.id.clone(),
                username: user.username.clone(),
                role: user.role,
            });
        if principal.is_some() {
            let _ = persist_user_api_tokens(&self.user_api_tokens_path, &store);
        }
        principal
    }

    fn update_current_user_settings(
        &self,
        principal: &Principal,
        payload: UserSettingsUpdateRequest,
    ) -> Result<UserSettingsView> {
        let mut preferences = self
            .user_preferences
            .lock()
            .expect("user preferences mutex poisoned");
        let entry = user_preferences_entry_mut(&mut preferences, principal.user_id.as_str());
        if let Some(display_name) = payload.display_name {
            entry.display_name = normalize_display_name_setting(display_name);
        }
        if let Some(locale) = payload.locale {
            entry.locale = normalize_locale_setting(locale);
        }
        if let Some(theme) = payload.theme {
            entry.theme = normalize_theme_setting(theme);
        }
        persist_user_preferences(&self.user_preferences_path, &preferences)?;
        drop(preferences);
        Ok(self.current_user_settings_view(principal))
    }

    pub(crate) fn list_oauth_providers(&self) -> Vec<ProviderBootstrap> {
        let policy = self
            .oauth_policy
            .lock()
            .expect("oauth policy mutex poisoned");
        self.runtime.oauth.bootstrap_views_with_policy(&policy)
    }

    pub(crate) fn oauth_provider(&self, provider_id: &str) -> Option<ProviderBootstrap> {
        let policy = self
            .oauth_policy
            .lock()
            .expect("oauth policy mutex poisoned");
        self.runtime
            .oauth
            .provider_with_policy(provider_id, &policy)
    }

    pub(crate) fn update_oauth_provider_authorization(
        &self,
        provider_id: &str,
        authorized: bool,
    ) -> Result<ProviderBootstrap> {
        if self.runtime.oauth.provider(provider_id).is_none() {
            return Err(anyhow!("provider_not_found"));
        }
        let mut policy = self
            .oauth_policy
            .lock()
            .expect("oauth policy mutex poisoned");
        set_oauth_provider_authorized(&mut policy, provider_id, authorized);
        save_oauth_policy(&self.oauth_policy_path, &policy)?;
        self.runtime
            .oauth
            .provider_with_policy(provider_id, &policy)
            .ok_or_else(|| anyhow!("provider_not_found"))
    }

    pub(crate) fn create_session(&self, principal: Principal) -> String {
        let session = generate_secret(36);
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .insert(
                session.clone(),
                SessionEntry {
                    principal,
                    created_at_utc: Utc::now().to_rfc3339(),
                },
            );
        session
    }

    pub(crate) fn resolve_principal(&self, session_cookie: Option<&str>) -> Option<Principal> {
        if self.no_login_enabled() {
            return Some(self.bootstrap_admin.clone());
        }
        let session = session_cookie?;
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .get(session)
            .map(|entry| entry.principal.clone())
    }

    pub(crate) fn revoke_session(&self, session: &str) {
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .remove(session);
    }

    pub(crate) fn authenticate_local(&self, username: &str, password: &str) -> Option<Principal> {
        let users = self.users.lock().expect("users mutex poisoned");
        verify_credentials(&users, username, password)
    }

    pub(crate) fn list_users(&self) -> Vec<PublicUserView> {
        let users = self.users.lock().expect("users mutex poisoned");
        let preferences = self
            .user_preferences
            .lock()
            .expect("user preferences mutex poisoned");
        list_users(&users)
            .into_iter()
            .map(|mut user| {
                if let Some(entry) = preferences
                    .entries
                    .iter()
                    .find(|entry| entry.user_id == user.id)
                {
                    user.display_name = entry
                        .display_name
                        .clone()
                        .filter(|value| !value.trim().is_empty())
                        .unwrap_or_else(|| user.username.clone());
                }
                user
            })
            .collect()
    }

    pub(crate) fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Role,
        display_name: Option<String>,
    ) -> Result<PublicUserView> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let mut view = create_user(&mut users, username, password, role)?;
        save_users(&self.users_path, &users)?;
        if let Some(display_name) = normalize_display_name_setting(display_name.unwrap_or_default())
        {
            let mut preferences = self
                .user_preferences
                .lock()
                .expect("user preferences mutex poisoned");
            let entry = user_preferences_entry_mut(&mut preferences, view.id.as_str());
            entry.display_name = Some(display_name.clone());
            persist_user_preferences(&self.user_preferences_path, &preferences)?;
            view.display_name = display_name;
        }
        Ok(view)
    }

    pub(crate) fn delete_user(&self, user_id: &str) -> Result<bool> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let deleted = delete_user(&mut users, user_id)?;
        if deleted {
            save_users(&self.users_path, &users)?;
            let mut preferences = self
                .user_preferences
                .lock()
                .expect("user preferences mutex poisoned");
            preferences.entries.retain(|entry| entry.user_id != user_id);
            persist_user_preferences(&self.user_preferences_path, &preferences)?;
            let mut opencti_settings = self
                .user_opencti_settings
                .lock()
                .expect("OpenCTI settings mutex poisoned");
            opencti_settings
                .entries
                .retain(|entry| entry.user_id != user_id);
            persist_user_opencti_settings(&self.user_opencti_settings_path, &opencti_settings)?;
            let mut api_tokens = self
                .user_api_tokens
                .lock()
                .expect("API tokens mutex poisoned");
            api_tokens.entries.retain(|entry| entry.user_id != user_id);
            persist_user_api_tokens(&self.user_api_tokens_path, &api_tokens)?;
        }
        Ok(deleted)
    }

    pub(crate) fn update_user(
        &self,
        user_id: &str,
        role: Option<Role>,
        enabled: Option<bool>,
        totp_enabled: Option<bool>,
        display_name: Option<String>,
    ) -> Result<PublicUserView> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let mut view = update_store_user(&mut users, user_id, role, enabled, totp_enabled)?;
        save_users(&self.users_path, &users)?;
        if let Some(display_name) = display_name {
            let mut preferences = self
                .user_preferences
                .lock()
                .expect("user preferences mutex poisoned");
            let effective_display_name = {
                let entry = user_preferences_entry_mut(&mut preferences, user_id);
                entry.display_name = normalize_display_name_setting(display_name);
                entry
                    .display_name
                    .clone()
                    .unwrap_or_else(|| view.username.clone())
            };
            persist_user_preferences(&self.user_preferences_path, &preferences)?;
            view.display_name = effective_display_name;
        }
        Ok(view)
    }

    pub(crate) fn change_user_password(
        &self,
        principal: &Principal,
        target_user_id: &str,
        current_password: Option<&str>,
        new_password: &str,
    ) -> Result<()> {
        let is_self_update = principal.user_id == target_user_id;
        if is_self_update && !self.can_change_password(principal) {
            return Err(anyhow!("password_change_not_allowed"));
        }
        let mut users = self.users.lock().expect("users mutex poisoned");
        let bypass = principal.role.can_manage_users() && !is_self_update;
        change_password(
            &mut users,
            target_user_id,
            current_password,
            new_password,
            bypass,
        )?;
        save_users(&self.users_path, &users)?;
        Ok(())
    }

    pub(crate) fn session_count(&self) -> usize {
        self.sessions.lock().expect("session mutex poisoned").len()
    }

    pub(crate) fn newest_session_timestamp(&self) -> Option<String> {
        self.sessions
            .lock()
            .expect("session mutex poisoned")
            .values()
            .map(|entry| entry.created_at_utc.clone())
            .max()
    }

    pub(crate) fn register_download(&self, entry: DownloadEntry) -> String {
        let token = format!("dl-{}", generate_secret(20));
        self.downloads
            .lock()
            .expect("download mutex poisoned")
            .insert(token.clone(), entry);
        token
    }

    pub(crate) fn get_download(&self, token: &str) -> Option<DownloadEntry> {
        self.downloads
            .lock()
            .expect("download mutex poisoned")
            .get(token)
            .cloned()
    }

    pub(crate) fn register_oauth_state(&self, provider_id: &str) -> String {
        let token = format!("oa-{}", generate_secret(36));
        let now = Utc::now().timestamp();
        let mut states = self
            .oauth_states
            .lock()
            .expect("oauth state mutex poisoned");
        states.retain(|_, entry| {
            now.saturating_sub(entry.created_at_epoch) <= OAUTH_STATE_TTL_SECONDS
        });
        states.insert(
            token.clone(),
            OAuthStateEntry {
                provider_id: provider_id.trim().to_ascii_lowercase(),
                created_at_epoch: now,
            },
        );
        token
    }

    pub(crate) fn take_oauth_state(&self, provider_id: &str, state_token: &str) -> bool {
        let now = Utc::now().timestamp();
        let mut states = self
            .oauth_states
            .lock()
            .expect("oauth state mutex poisoned");
        states.retain(|_, entry| {
            now.saturating_sub(entry.created_at_epoch) <= OAUTH_STATE_TTL_SECONDS
        });
        let Some(entry) = states.remove(state_token) else {
            return false;
        };
        entry.provider_id == provider_id.trim().to_ascii_lowercase()
    }

    fn principal_from_oauth_identity(&self, identity: &OAuthIdentity) -> Principal {
        let mut candidates = vec![identity.username.trim().to_string()];
        if let Some(email) = identity
            .email
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .filter(|email| !email.eq_ignore_ascii_case(identity.username.trim()))
        {
            candidates.push(email.to_string());
        }

        let users = self.users.lock().expect("users mutex poisoned");
        if let Some(user) = users.users.iter().find(|user| {
            user.enabled
                && candidates
                    .iter()
                    .any(|candidate| user.username.eq_ignore_ascii_case(candidate))
        }) {
            return Principal {
                user_id: user.id.clone(),
                username: user.username.clone(),
                role: user.role,
            };
        }

        let subject = URL_SAFE_NO_PAD.encode(identity.subject.as_bytes());
        Principal {
            user_id: format!("oauth-{}-{subject}", identity.provider_id),
            username: identity.username.trim().to_string(),
            role: Role::Analyst,
        }
    }
}

fn runtime_settings_path() -> Result<PathBuf> {
    let root = spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("web_runtime_settings.json"))
}

fn user_preferences_path() -> Result<PathBuf> {
    let root = spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("web_user_preferences.json"))
}

fn user_opencti_settings_path() -> Result<PathBuf> {
    let root = spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("user_opencti_settings.json"))
}

fn user_api_tokens_path() -> Result<PathBuf> {
    let root = spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("web_user_api_tokens.json"))
}

fn load_or_init_runtime_settings(
    no_login_default: bool,
) -> Result<(PathBuf, AdminRuntimeSettingsStore)> {
    let path = runtime_settings_path()?;
    if !path.exists() {
        let settings = AdminRuntimeSettingsStore {
            schema_version: WEB_ADMIN_SETTINGS_SCHEMA_VERSION.to_string(),
            no_login: no_login_default,
            sigma_rpc_url: normalize_optional_setting(
                std::env::var(ENV_SIGMA_RPC_URL).unwrap_or_default(),
            ),
            sigma_rpc_token: normalize_optional_setting(
                std::env::var(ENV_SIGMA_RPC_TOKEN).unwrap_or_default(),
            ),
            default_locale: Some("en".to_string()),
            default_theme: Some("dark".to_string()),
            default_totp_required: Some(false),
        };
        persist_runtime_settings(&path, &settings)?;
        return Ok((path, settings));
    }

    let raw = fs::read_to_string(&path)?;
    let mut settings: AdminRuntimeSettingsStore = serde_json::from_str(&raw)?;
    if settings.schema_version.trim().is_empty() {
        settings.schema_version = WEB_ADMIN_SETTINGS_SCHEMA_VERSION.to_string();
    }
    settings.sigma_rpc_url = settings
        .sigma_rpc_url
        .take()
        .and_then(normalize_optional_setting);
    settings.sigma_rpc_token = settings
        .sigma_rpc_token
        .take()
        .and_then(normalize_optional_setting);
    settings.default_locale = settings
        .default_locale
        .take()
        .and_then(normalize_locale_setting)
        .or_else(|| Some("en".to_string()));
    settings.default_theme = settings
        .default_theme
        .take()
        .and_then(normalize_theme_setting)
        .or_else(|| Some("dark".to_string()));
    settings.default_totp_required = Some(settings.default_totp_required.unwrap_or(false));
    persist_runtime_settings(&path, &settings)?;
    Ok((path, settings))
}

fn load_or_init_user_preferences() -> Result<(PathBuf, UserPreferencesStore)> {
    let path = user_preferences_path()?;
    if !path.exists() {
        let store = UserPreferencesStore {
            schema_version: WEB_USER_PREFERENCES_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        };
        persist_user_preferences(&path, &store)?;
        return Ok((path, store));
    }

    let raw = fs::read_to_string(&path)?;
    let mut store: UserPreferencesStore = serde_json::from_str(&raw)?;
    if store.schema_version.trim().is_empty() {
        store.schema_version = WEB_USER_PREFERENCES_SCHEMA_VERSION.to_string();
    }
    for entry in &mut store.entries {
        entry.display_name = entry
            .display_name
            .take()
            .and_then(normalize_display_name_setting);
        entry.locale = entry.locale.take().and_then(normalize_locale_setting);
        entry.theme = entry.theme.take().and_then(normalize_theme_setting);
    }
    store
        .entries
        .retain(|entry| !entry.user_id.trim().is_empty());
    persist_user_preferences(&path, &store)?;
    Ok((path, store))
}

fn load_or_init_user_opencti_settings() -> Result<(PathBuf, UserOpenCtiSettingsStore)> {
    let path = user_opencti_settings_path()?;
    if !path.exists() {
        let store = UserOpenCtiSettingsStore {
            schema_version: WEB_USER_OPENCTI_SETTINGS_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        };
        persist_user_opencti_settings(&path, &store)?;
        return Ok((path, store));
    }

    let raw = fs::read_to_string(&path)?;
    let mut store: UserOpenCtiSettingsStore = serde_json::from_str(&raw)?;
    if store.schema_version.trim().is_empty() {
        store.schema_version = WEB_USER_OPENCTI_SETTINGS_SCHEMA_VERSION.to_string();
    }
    store
        .entries
        .retain(|entry| !entry.user_id.trim().is_empty());
    for entry in &mut store.entries {
        normalize_opencti_settings_entry(entry);
    }
    persist_user_opencti_settings(&path, &store)?;
    Ok((path, store))
}

fn load_or_init_user_api_tokens() -> Result<(PathBuf, UserApiTokenStore)> {
    let path = user_api_tokens_path()?;
    if !path.exists() {
        let store = UserApiTokenStore {
            schema_version: WEB_USER_API_TOKENS_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        };
        persist_user_api_tokens(&path, &store)?;
        return Ok((path, store));
    }

    let raw = fs::read_to_string(&path)?;
    let mut store: UserApiTokenStore = serde_json::from_str(&raw)?;
    if store.schema_version.trim().is_empty() {
        store.schema_version = WEB_USER_API_TOKENS_SCHEMA_VERSION.to_string();
    }
    store
        .entries
        .retain(|entry| !entry.id.trim().is_empty() && !entry.user_id.trim().is_empty());
    persist_user_api_tokens(&path, &store)?;
    Ok((path, store))
}

fn upsert_bootstrap_admin_api_token(
    path: &Path,
    store: &mut UserApiTokenStore,
    admin: &Principal,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    let Some(token_value) = env_setting(ENV_ADMIN_API_TOKEN) else {
        if let Some(entry) = store
            .entries
            .iter_mut()
            .find(|entry| entry.id == BOOTSTRAP_ADMIN_API_TOKEN_ID && entry.revoked_at.is_none())
        {
            entry.revoked_at = Some(now);
            persist_user_api_tokens(path, store)?;
        }
        return Ok(());
    };
    let name = env_setting(ENV_ADMIN_API_TOKEN_NAME)
        .unwrap_or_else(|| "Bootstrap admin API token".to_string());
    let expires_at = env_setting(ENV_ADMIN_API_TOKEN_EXPIRES_AT);
    let token_hash = hash_api_token(&token_value);
    if let Some(entry) = store
        .entries
        .iter_mut()
        .find(|entry| entry.id == BOOTSTRAP_ADMIN_API_TOKEN_ID)
    {
        entry.user_id = admin.user_id.clone();
        entry.name = name;
        entry.token_hash = token_hash;
        entry.revoked_at = None;
        entry.expires_at = expires_at;
    } else {
        store.entries.push(UserApiTokenEntry {
            id: BOOTSTRAP_ADMIN_API_TOKEN_ID.to_string(),
            user_id: admin.user_id.clone(),
            name,
            token_hash,
            created_at: now,
            revoked_at: None,
            last_used_at: None,
            expires_at,
        });
    }
    persist_user_api_tokens(path, store)?;
    Ok(())
}

fn env_setting(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_runtime_settings(path: &Path, settings: &AdminRuntimeSettingsStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(settings)?;
    fs::write(path, raw)?;
    Ok(())
}

fn persist_user_preferences(path: &Path, settings: &UserPreferencesStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(settings)?;
    fs::write(path, raw)?;
    Ok(())
}

fn persist_user_opencti_settings(path: &Path, settings: &UserOpenCtiSettingsStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(settings)?;
    fs::write(path, raw)?;
    restrict_file_to_owner(path)?;
    Ok(())
}

fn persist_user_api_tokens(path: &Path, store: &UserApiTokenStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(store)?;
    fs::write(path, raw)?;
    restrict_file_to_owner(path)?;
    Ok(())
}

fn hash_api_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn is_token_expired(expires_at: Option<&str>, now: chrono::DateTime<Utc>) -> bool {
    let Some(value) = expires_at else {
        return false;
    };
    let Ok(expires) = chrono::DateTime::parse_from_rfc3339(value) else {
        return false;
    };
    expires.with_timezone(&Utc) <= now
}

fn api_token_view(entry: UserApiTokenEntry) -> UserApiTokenView {
    UserApiTokenView {
        id: entry.id,
        user_id: entry.user_id,
        name: entry.name,
        created_at: entry.created_at,
        revoked_at: entry.revoked_at,
        last_used_at: entry.last_used_at,
        expires_at: entry.expires_at,
    }
}

#[cfg(unix)]
fn restrict_file_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

fn normalize_optional_setting(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_opencti_endpoint(value: String) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn normalize_opencti_settings_entry(entry: &mut UserOpenCtiSettingsEntry) {
    entry.opencti_endpoint = entry
        .opencti_endpoint
        .take()
        .and_then(normalize_opencti_endpoint);
    entry.opencti_api_key = entry
        .opencti_api_key
        .take()
        .and_then(normalize_optional_setting);
    if !opencti_settings_configured(entry) {
        entry.opencti_enabled = false;
        entry.stix_catalog_source = StixCatalogSource::Local;
    }
}

fn opencti_settings_configured(entry: &UserOpenCtiSettingsEntry) -> bool {
    entry
        .opencti_endpoint
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && entry
            .opencti_api_key
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
}

fn opencti_effective_source(entry: &UserOpenCtiSettingsEntry) -> StixCatalogSource {
    if entry.opencti_enabled
        && entry.stix_catalog_source == StixCatalogSource::OpenCti
        && opencti_settings_configured(entry)
    {
        StixCatalogSource::OpenCti
    } else {
        StixCatalogSource::Local
    }
}

fn default_opencti_settings_entry(user_id: &str) -> UserOpenCtiSettingsEntry {
    UserOpenCtiSettingsEntry {
        user_id: user_id.to_string(),
        opencti_enabled: false,
        opencti_endpoint: None,
        opencti_api_key: None,
        stix_catalog_source: StixCatalogSource::Local,
    }
}

fn user_opencti_settings_entry_mut<'a>(
    store: &'a mut UserOpenCtiSettingsStore,
    user_id: &str,
) -> &'a mut UserOpenCtiSettingsEntry {
    if let Some(index) = store
        .entries
        .iter()
        .position(|entry| entry.user_id == user_id)
    {
        return &mut store.entries[index];
    }
    store.entries.push(default_opencti_settings_entry(user_id));
    store
        .entries
        .last_mut()
        .expect("OpenCTI settings entry inserted")
}

fn opencti_settings_view(entry: UserOpenCtiSettingsEntry) -> UserOpenCtiSettingsView {
    let effective_source = opencti_effective_source(&entry);
    UserOpenCtiSettingsView {
        opencti_enabled: entry.opencti_enabled,
        opencti_endpoint: entry.opencti_endpoint,
        opencti_api_key_set: entry
            .opencti_api_key
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        stix_catalog_source: entry.stix_catalog_source.as_str(),
        effective_source: effective_source.as_str(),
    }
}

fn normalize_display_name_setting(value: String) -> Option<String> {
    normalize_optional_setting(value)
}

fn normalize_locale_setting(value: String) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "es" => Some("es".to_string()),
        "en" => Some("en".to_string()),
        _ => None,
    }
}

fn normalize_theme_setting(value: String) -> Option<String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "light" => Some("light".to_string()),
        "dark" => Some("dark".to_string()),
        _ => None,
    }
}

fn user_preferences_entry_mut<'a>(
    store: &'a mut UserPreferencesStore,
    user_id: &str,
) -> &'a mut UserPreferencesEntry {
    if let Some(index) = store
        .entries
        .iter()
        .position(|entry| entry.user_id == user_id)
    {
        return &mut store.entries[index];
    }
    store.entries.push(UserPreferencesEntry {
        user_id: user_id.to_string(),
        display_name: None,
        locale: None,
        theme: None,
    });
    store
        .entries
        .last_mut()
        .expect("user preferences entry inserted")
}

fn settings_view(settings: AdminRuntimeSettingsStore) -> AdminRuntimeSettingsView {
    AdminRuntimeSettingsView {
        no_login: settings.no_login,
        sigma_rpc_url: settings.sigma_rpc_url,
        sigma_rpc_token_set: settings
            .sigma_rpc_token
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty()),
        default_locale: settings.default_locale.unwrap_or_else(|| "en".to_string()),
        default_theme: settings.default_theme.unwrap_or_else(|| "dark".to_string()),
        default_totp_required: settings.default_totp_required.unwrap_or(false),
    }
}

fn apply_sigma_rpc_env(settings: &AdminRuntimeSettingsStore) {
    unsafe {
        if let Some(url) = settings.sigma_rpc_url.as_deref() {
            std::env::set_var(ENV_SIGMA_RPC_URL, url);
        } else {
            std::env::remove_var(ENV_SIGMA_RPC_URL);
        }
        if let Some(token) = settings.sigma_rpc_token.as_deref() {
            std::env::set_var(ENV_SIGMA_RPC_TOKEN, token);
        } else {
            std::env::remove_var(ENV_SIGMA_RPC_TOKEN);
        }
    }
}

pub(crate) fn generate_secret(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = vec![0u8; len.max(1)];
    let filled = fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .is_ok();
    if !filled {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ u128::from(std::process::id());
        for (idx, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_shr(((idx % 8) * 8) as u32) as u8;
        }
    }
    bytes
        .into_iter()
        .take(len)
        .map(|value| ALPHABET[(value as usize) % ALPHABET.len()] as char)
        .collect()
}

#[derive(Debug)]
pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: HashMap<String, String>,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: Vec<u8>,
}

impl HttpRequest {
    fn json<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(Into::into)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        let header = self.headers.get("cookie")?;
        for item in header.split(';') {
            let trimmed = item.trim();
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == name {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }

    fn bearer_token(&self) -> Option<String> {
        let raw = self.headers.get("authorization")?.trim();
        let value = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))?;
        let token = value.trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    }
}

pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) content_type: String,
    pub(crate) body: Vec<u8>,
    pub(crate) headers: Vec<(String, String)>,
}

impl HttpResponse {
    pub(crate) fn text(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub(crate) fn html(body: &str) -> Self {
        Self::text(200, "text/html; charset=utf-8", body.as_bytes().to_vec())
    }

    pub(crate) fn css(body: &str) -> Self {
        Self::text(200, "text/css; charset=utf-8", body.as_bytes().to_vec())
    }

    pub(crate) fn javascript(body: &str) -> Self {
        Self::text(
            200,
            "application/javascript; charset=utf-8",
            body.as_bytes().to_vec(),
        )
    }

    pub(crate) fn json<T: Serialize>(status: u16, payload: &T) -> Result<Self> {
        Ok(Self::text(
            status,
            "application/json; charset=utf-8",
            serde_json::to_vec_pretty(payload)?,
        ))
    }

    pub(crate) fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    app: AppBootstrap,
    auth: AuthBootstrap,
    user: Option<UserSettingsView>,
    translation: TranslationBootstrap,
    counters: CounterBootstrap,
}

#[derive(Debug, Serialize)]
struct AppBootstrap {
    name: &'static str,
    version: &'static str,
    year: i32,
    project_url: String,
    project_name: String,
    documentation_url: String,
    license_url: String,
    license_name: String,
}

#[derive(Debug, Serialize)]
struct AuthBootstrap {
    no_login: bool,
    authenticated: bool,
    show_logout: bool,
    generated_password: bool,
    default_locale: String,
    default_theme: String,
    principal: Option<PrincipalView>,
    providers: Vec<ProviderBootstrap>,
}

#[derive(Debug, Serialize)]
struct PrincipalView {
    user_id: String,
    username: String,
    display_name: String,
    role: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct UserSettingsView {
    account_id: String,
    username: String,
    display_name: String,
    locale: String,
    theme: String,
    can_change_password: bool,
    is_bootstrap_admin: bool,
    no_login: bool,
    local_auth: bool,
}

#[derive(Debug, Serialize)]
struct CounterBootstrap {
    rules: usize,
    abilities: usize,
    adversaries: usize,
}

#[derive(Debug, Serialize)]
struct TranslationBootstrap {
    available_targets: Vec<String>,
    sigma_cli_available: bool,
    sigma_dynamic_targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OAuthLoginRequest {
    provider: String,
}

#[derive(Debug, Deserialize)]
struct AdminOAuthProviderUpdateRequest {
    authorized: bool,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    ok: bool,
    principal: PrincipalView,
}

#[derive(Debug, Deserialize)]
struct RuleMutationRequest {
    rule: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    ttp: Option<String>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    pap: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    indicates: Option<RuleIndicatesRelation>,
    #[serde(default)]
    indicates_list: Option<Vec<RuleIndicatesRelation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuleIndicatesRelation {
    stix_id: String,
    object_name: String,
}

#[derive(Debug, Deserialize)]
struct RuleIndicatesRequest {
    stix_id: String,
    object_name: String,
}

#[derive(Debug, Deserialize)]
struct TutorialValidateRequest {
    challenge_id: String,
    rule: String,
}

#[derive(Debug, Serialize)]
struct TutorialValidateResponse {
    syntax_ok: bool,
    solved: bool,
    message: Option<String>,
    hint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateAdversaryRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    pap: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    target_platform: Option<String>,
    #[serde(default)]
    ability_ids: Vec<String>,
    #[serde(default)]
    order: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateAdversaryRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    pap: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    target_platform: Option<String>,
    #[serde(default)]
    ability_ids: Vec<String>,
    #[serde(default)]
    order: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleCatalogQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    min_confidence: Option<u8>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    observable: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AdversaryCatalogQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    min_confidence: Option<u8>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default)]
    page_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AdminUserCreateRequest {
    username: String,
    password: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminUserUpdateRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    totp_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AdminPasswordChangeRequest {
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    current_password: Option<String>,
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct UserSettingsUpdateRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    locale: Option<String>,
    #[serde(default)]
    theme: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuleCompatibilityRequest {
    rule: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    sigma_targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RuleBundleExportRequest {
    #[serde(default)]
    rule_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StixObjectsBundleExportRequest {
    #[serde(default)]
    stix_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PatternBundleExportRequest {
    rule: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    confidence: Option<u8>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    pap: Option<String>,
    #[serde(default)]
    indicates_list: Vec<RuleIndicatesRelation>,
}

#[derive(Debug, Deserialize)]
struct DummyAbilityCreateRequest {
    kind: String,
    seconds: Option<u64>,
    label: Option<String>,
    platform: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    runner: Option<String>,
    #[serde(default)]
    payload_language: Option<String>,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    safety_notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuleView {
    id: String,
    ability_id: Option<String>,
    name: String,
    description: Option<String>,
    ttp: Option<String>,
    confidence: u8,
    tlp: String,
    pap: String,
    indicates: Option<RuleIndicatesRelation>,
    indicates_list: Vec<RuleIndicatesRelation>,
    emulable: bool,
    rule: String,
    last_seen_utc: String,
    commands: Vec<String>,
    targets: Vec<String>,
    statuses: Vec<String>,
    observables: Vec<String>,
    target_statuses: BTreeMap<String, String>,
    emulation_statuses: BTreeMap<String, String>,
    activity_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StixCatalogEntry {
    stix_id: String,
    stix_type: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tlp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StixObjectView {
    stix_id: String,
    stix_type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tlp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    aliases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<String>,
}

#[derive(Debug, Clone)]
struct StixProviderSearch {
    query: Option<String>,
    types: Vec<String>,
    limit: usize,
}

#[derive(Debug, Clone, Serialize)]
struct StixProviderErrorView {
    code: &'static str,
    message: String,
    go_to_user_settings: bool,
}

#[derive(Debug, Clone)]
struct StixProviderError {
    code: &'static str,
    message: String,
}

type StixProviderResult<T> = std::result::Result<T, StixProviderError>;

impl StixProviderError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn view(&self) -> StixProviderErrorView {
        StixProviderErrorView {
            code: self.code,
            message: self.message.clone(),
            go_to_user_settings: true,
        }
    }
}

#[allow(dead_code)]
trait StixCatalogProvider {
    fn search_objects(
        &self,
        search: &StixProviderSearch,
    ) -> StixProviderResult<Vec<StixObjectView>>;
    fn get_object_by_id(&self, id: &str) -> StixProviderResult<Option<StixObjectView>>;
    fn create_object(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<StixObjectView>;
    fn find_similar_objects(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<Vec<StixObjectView>>;
}

struct LocalStixCatalogProvider;

struct OpenCtiStixCatalogProvider {
    endpoint: String,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct StixObjectsResponse {
    entries: Vec<StixObjectView>,
    source: &'static str,
    effective_source: &'static str,
    fallback_used: bool,
    message: Option<String>,
    error: Option<StixProviderErrorView>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleMetadataEnvelope {
    tlp: String,
    pap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_platform: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    observables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    indicates_list: Vec<RuleIndicatesRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    indicates: Option<RuleIndicatesRelation>,
}

#[derive(Debug)]
struct DecodedRuleMetadata {
    description: Option<String>,
    tlp: String,
    pap: String,
    ttp: Option<String>,
    target_platform: Option<String>,
    observables: Vec<String>,
    indicates: Option<RuleIndicatesRelation>,
    indicates_list: Vec<RuleIndicatesRelation>,
}

#[derive(Debug, Serialize)]
struct AbilityView {
    id: String,
    name: String,
    description: String,
    ttp: Option<String>,
    platforms: Vec<String>,
    classification: String,
    emulation_level: String,
    confidence: u8,
    export_targets: Vec<String>,
    export_files: BTreeMap<String, String>,
    export_artifacts: BTreeMap<String, String>,
    source_pattern: String,
    agent_capabilities: Vec<String>,
    actions: Vec<AbilityActionView>,
}

#[derive(Debug, Serialize)]
struct AbilityActionView {
    id: String,
    title: String,
    action_type: String,
    observable: String,
    operator: String,
    value: String,
    safe_instructions: String,
}

#[derive(Debug, Serialize)]
struct AdversaryView {
    id: String,
    source_intrusion_set_id: String,
    name: String,
    confidence: u8,
    tlp: String,
    pap: String,
    target_platform: Option<String>,
    steps: usize,
    platforms: Vec<String>,
    description: String,
    ability_refs: Vec<String>,
    path: String,
    compatible_exports: Vec<String>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    syntax_ok: bool,
    syntax_error: Option<String>,
    emulable: bool,
    ability_preview: Option<AbilityView>,
}

#[derive(Debug, Serialize)]
struct RuleCompatibilityRow {
    target: String,
    runtime_status: String,
    severity: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: Option<String>,
    summary: String,
    notes: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Serialize)]
struct DownloadLink {
    name: String,
    url: String,
}

#[derive(Debug, Serialize)]
struct ExportResponse {
    id: String,
    target: String,
    downloads: Vec<DownloadLink>,
}

#[derive(Debug, Serialize)]
struct AdversaryCompatibilityIssue {
    target: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct AdversaryCompatibilityResponse {
    id: String,
    compatible_targets: Vec<String>,
    incompatible_targets: Vec<AdversaryCompatibilityIssue>,
}

#[derive(Debug, Serialize)]
struct PagedResponse<T> {
    total: usize,
    page: usize,
    page_size: usize,
    entries: Vec<T>,
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    kpis: OverviewKpis,
    statuses: Vec<NameCount>,
    emulation_coverage: Vec<NameRatio>,
    top_targets: Vec<NameCount>,
    top_platforms: Vec<NameCount>,
    top_observables: Vec<NameCount>,
}

#[derive(Debug, Serialize)]
struct OverviewKpis {
    rules_total: usize,
    adversaries_total: usize,
    abilities_total: usize,
    supported_destinations: usize,
    engines_available: usize,
}

#[derive(Debug, Serialize)]
struct NameCount {
    name: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct NameRatio {
    name: String,
    count: usize,
    percent: f64,
}

#[derive(Debug, Serialize)]
struct LearningBlock {
    id: &'static str,
    title: &'static str,
    summary: &'static str,
    example: &'static str,
}

pub(crate) fn route(request: HttpRequest, state: &WebState) -> Result<HttpResponse> {
    let segments = path_segments(&request.path);
    let cookie_session = request.cookie("spuc_web_session");
    let principal = state.resolve_principal(cookie_session.as_deref());

    if request.method == "GET" && request.path == "/healthz" {
        return HttpResponse::json(
            200,
            &serde_json::json!({
                "ok": true,
                "service": "spuc-web"
            }),
        );
    }

    if request.method == "GET" && request.path == "/" {
        return Ok(HttpResponse::html(assets::INDEX_HTML));
    }
    if request.method == "GET" && request.path == "/styles.css" {
        return Ok(HttpResponse::css(assets::APP_CSS));
    }
    if request.method == "GET" && request.path == "/app.js" {
        return Ok(HttpResponse::javascript(assets::APP_ENTRY_JS));
    }
    if request.method == "GET" && request.path == "/boot.js" {
        return Ok(HttpResponse::javascript(assets::APP_JS));
    }
    if request.method == "GET" && request.path == "/api-client.js" {
        return Ok(HttpResponse::javascript(assets::API_CLIENT_JS));
    }
    if request.method == "GET" && request.path == "/store.js" {
        return Ok(HttpResponse::javascript(assets::STORE_JS));
    }
    if request.method == "GET" && request.path == "/action-registry.js" {
        return Ok(HttpResponse::javascript(assets::ACTION_REGISTRY_JS));
    }
    if request.method == "GET" && request.path == "/ui/dom.js" {
        return Ok(HttpResponse::javascript(assets::UI_DOM_JS));
    }
    if request.method == "GET" && request.path == "/ui/toast.js" {
        return Ok(HttpResponse::javascript(assets::UI_TOAST_JS));
    }
    if request.method == "GET" && request.path == "/ui/modal.js" {
        return Ok(HttpResponse::javascript(assets::UI_MODAL_JS));
    }
    if request.method == "GET" && request.path == "/features/rules/index.js" {
        return Ok(HttpResponse::javascript(assets::RULES_FEATURE_JS));
    }
    if request.method == "GET" && request.path == "/assets/logo-sputnik.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::LOGO_SPUTNIK_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/assets/donate-bitcoin.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::DONATE_BITCOIN_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/assets/donate-monero.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::DONATE_MONERO_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/assets/logo-bitcoin.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::LOGO_BITCOIN_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/assets/logo-monero.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::LOGO_MONERO_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/assets/logo-github.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::LOGO_GITHUB_PNG.to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/i18n.json" {
        return Ok(HttpResponse::text(
            200,
            "application/json; charset=utf-8",
            i18n::TRANSLATIONS_JSON.as_bytes().to_vec(),
        ));
    }
    if request.method == "GET" && request.path == "/api/bootstrap" {
        return bootstrap_response(state, principal.as_ref());
    }
    if request.method == "POST" && request.path == "/api/login" {
        return login_local(&request, state);
    }
    if request.method == "POST" && request.path == "/api/login/oauth" {
        return login_oauth_prepare(&request, state);
    }
    if request.method == "GET" {
        if let ["api", "login", "oauth", provider_id, "callback"] = segments.as_slice() {
            return login_oauth_callback(provider_id, &request, state);
        }
    }
    if request.method == "POST" && request.path == "/api/logout" {
        if let Some(session) = cookie_session {
            state.revoke_session(&session);
        }
        return HttpResponse::json(200, &serde_json::json!({ "ok": true })).map(|response| {
            response.with_header(
                "Set-Cookie",
                "spuc_web_session=deleted; Max-Age=0; Path=/; SameSite=Strict",
            )
        });
    }

    if request.method == "POST" && request.path == "/api/translate/stix-pattern" {
        return translate_stix_pattern_with_token(&request, state);
    }
    if request.method == "POST" && request.path == "/api/translate/stix-bundle" {
        return translate_stix_bundle_with_token(&request, state);
    }
    if request.method == "POST" && request.path == "/api/translate/stix-pattern-summary" {
        return translate_stix_pattern_summary_with_token(&request, state);
    }

    let Some(principal) = principal else {
        return HttpResponse::json(
            401,
            &serde_json::json!({
                "error": "unauthorized",
                "code": "unauthorized"
            }),
        );
    };

    match (request.method.as_str(), segments.as_slice()) {
        ("GET", ["api", "overview"]) => overview_response(),
        ("GET", ["api", "rules"]) => list_rules(&request),
        ("GET", ["api", "rules", selector]) => show_rule(selector),
        ("GET", ["api", "stix-objects"]) => list_stix_objects(&request, &principal, state),
        ("POST", ["api", "stix-objects"]) => create_stix_object(&request, &principal, state),
        ("DELETE", ["api", "stix-objects", stix_id]) => delete_stix_object(stix_id),
        ("POST", ["api", "stix-objects", "export", "bundle"]) => {
            export_stix_objects_bundle(&request)
        }
        ("GET", ["api", "mitre-attack"]) => Ok(HttpResponse::text(
            200,
            "application/json; charset=utf-8",
            assets::MITRE_ATTACK_COMPACT_JSON.as_bytes().to_vec(),
        )),
        ("DELETE", ["api", "rules", selector]) => delete_rule(selector),
        ("POST", ["api", "rules", "save"]) => save_rule(&request),
        ("POST", ["api", "rules", selector, "indicates"]) => set_rule_indicates(selector, &request),
        ("POST", ["api", "rules", "compatibility"]) => rule_compatibility(&request),
        ("POST", ["api", "rules", "export", "bundle"]) => export_rules_bundle(&request),
        ("POST", ["api", "rules", "export", "bundle-from-pattern"]) => {
            export_bundle_from_pattern(&request)
        }
        ("GET", ["api", "abilities"]) => list_abilities(&request),
        ("POST", ["api", "abilities", "dummy"]) => create_dummy_ability(&request),
        ("GET", ["api", "abilities", ability_id]) => show_ability(ability_id),
        ("GET", ["api", "abilities", ability_id, "export"]) => {
            export_ability(ability_id, request.query.get("to").map(String::as_str))
        }
        ("GET", ["api", "adversaries"]) => list_adversaries(&request),
        ("GET", ["api", "adversaries", selector]) => show_adversary(selector),
        ("DELETE", ["api", "adversaries", selector]) => delete_adversary(selector),
        ("GET", ["api", "adversaries", selector, "compatibility"]) => {
            adversary_compatibility(selector)
        }
        ("POST", ["api", "adversaries"]) => create_adversary(&request, state),
        ("POST", ["api", "adversaries", selector, "update"]) => {
            update_adversary(selector, &request)
        }
        ("GET", ["api", "adversaries", selector, "export"]) => {
            export_adversary(selector, request.query.get("to").map(String::as_str), state)
        }
        ("GET", ["api", "tutorial", "challenges"]) => {
            HttpResponse::json(200, &learn::challenge_catalog())
        }
        ("POST", ["api", "tutorial", "validate"]) => validate_tutorial_submission(&request),
        ("GET", ["api", "learning", "blocks"]) => HttpResponse::json(200, &learning_blocks()),
        ("POST", ["api", "verify"]) => verify_rule_request(&request),
        ("GET", ["api", "download", token]) => download_file(token, state),
        ("GET", ["api", "settings", "profile"]) => settings_get_profile(&principal, state),
        ("POST", ["api", "settings", "profile"]) => {
            settings_update_profile(&principal, &request, state)
        }
        ("GET", ["api", "user", "tokens"]) => user_list_tokens(&principal, state),
        ("POST", ["api", "user", "tokens"]) => user_create_token(&principal, &request, state),
        ("DELETE", ["api", "user", "tokens", token_id]) => {
            user_revoke_token(&principal, token_id, state)
        }
        ("DELETE", ["api", "user", "tokens", token_id, "purge"]) => {
            user_delete_token(&principal, token_id, state)
        }
        ("POST", ["api", "user", "tokens", token_id, "rotate"]) => {
            user_rotate_token(&principal, token_id, state)
        }
        ("GET", ["api", "user", "settings", "stix-source"]) => {
            user_get_stix_source_settings(&principal, state)
        }
        ("PUT", ["api", "user", "settings", "stix-source"]) => {
            user_update_stix_source_settings(&principal, &request, state)
        }
        ("POST", ["api", "user", "settings", "opencti", "test"]) => {
            user_test_opencti_settings(&principal, &request, state)
        }
        ("GET", ["api", "admin", "users"]) => admin_list_users(&principal, state),
        ("POST", ["api", "admin", "users"]) => admin_create_user(&principal, &request, state),
        ("POST", ["api", "admin", "users", user_id, "update"]) => {
            admin_update_user(&principal, user_id, &request, state)
        }
        ("DELETE", ["api", "admin", "users", user_id]) => {
            admin_delete_user(&principal, user_id, state)
        }
        ("POST", ["api", "admin", "change-password"]) => {
            admin_change_password(&principal, &request, state)
        }
        ("GET", ["api", "admin", "oauth", "providers"]) => {
            admin_list_oauth_providers(&principal, state)
        }
        ("POST", ["api", "admin", "oauth", "providers", provider_id, "update"]) => {
            admin_update_oauth_provider(&principal, provider_id, &request, state)
        }
        ("GET", ["api", "admin", "settings"]) => admin_get_runtime_settings(&principal, state),
        ("POST", ["api", "admin", "settings"]) => {
            admin_update_runtime_settings(&principal, &request, state)
        }
        _ => HttpResponse::json(
            404,
            &serde_json::json!({
                "error": "not_found",
                "code": "not_found"
            }),
        ),
    }
}

fn bootstrap_response(state: &WebState, principal: Option<&Principal>) -> Result<HttpResponse> {
    let (_, abilities, rules, adversaries) = load_catalog_data()?;
    let default_locale = state.effective_locale_for(None);
    let default_theme = state.effective_theme_for(None);
    HttpResponse::json(
        200,
        &BootstrapResponse {
            app: AppBootstrap {
                name: "SPUC",
                version: env!("CARGO_PKG_VERSION"),
                year: Utc::now().year(),
                project_url: state.runtime().project_link.clone(),
                project_name: state.runtime().project_name.clone(),
                documentation_url: state.runtime().documentation_link.clone(),
                license_url: state.runtime().license_link.clone(),
                license_name: state.runtime().license_name.clone(),
            },
            auth: AuthBootstrap {
                no_login: state.no_login_enabled(),
                authenticated: principal.is_some(),
                show_logout: !state.no_login_enabled(),
                generated_password: state.generated_password(),
                default_locale,
                default_theme,
                principal: principal.map(|principal| PrincipalView {
                    user_id: principal.user_id.clone(),
                    username: principal.username.clone(),
                    display_name: state.effective_display_name_for(principal),
                    role: principal.role.as_str(),
                }),
                providers: state.list_oauth_providers(),
            },
            user: principal.map(|principal| state.current_user_settings_view(principal)),
            translation: TranslationBootstrap {
                available_targets: available_detection_target_labels(),
                sigma_cli_available: sigma_runtime_info().operational,
                sigma_dynamic_targets: dynamic_sigma_targets(),
            },
            counters: CounterBootstrap {
                rules: rules.len(),
                abilities: abilities.len(),
                adversaries: adversaries.len(),
            },
        },
    )
}

fn login_local(request: &HttpRequest, state: &WebState) -> Result<HttpResponse> {
    if state.no_login_enabled() {
        return HttpResponse::json(
            409,
            &serde_json::json!({
                "error": "login_disabled",
                "code": "no_login_mode"
            }),
        );
    }

    let payload: LoginRequest = request.json()?;
    let username = payload
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(state.runtime().admin_user.as_str());
    let password = payload
        .password
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("password is required"))?;

    let Some(principal) = state.authenticate_local(username, password) else {
        return HttpResponse::json(
            401,
            &serde_json::json!({
                "error": "invalid_credentials",
                "code": "invalid_credentials"
            }),
        );
    };

    let session = state.create_session(principal.clone());
    HttpResponse::json(
        200,
        &LoginResponse {
            ok: true,
            principal: principal_view(&principal),
        },
    )
    .map(|response| {
        response.with_header(
            "Set-Cookie",
            format!("spuc_web_session={session}; HttpOnly; Path=/; SameSite=Strict"),
        )
    })
}

fn login_oauth_prepare(request: &HttpRequest, state: &WebState) -> Result<HttpResponse> {
    if state.no_login_enabled() {
        return HttpResponse::json(
            409,
            &serde_json::json!({
                "error": "login_disabled",
                "code": "no_login_mode"
            }),
        );
    }

    let payload: OAuthLoginRequest = request.json()?;
    let provider_id = payload.provider.trim().to_ascii_lowercase();
    let Some(provider) = state.oauth_provider(provider_id.as_str()) else {
        return HttpResponse::json(404, &serde_json::json!({ "error": "provider_not_found" }));
    };
    if !provider.configured {
        return HttpResponse::json(
            400,
            &serde_json::json!({
                "error": "provider_not_configured",
                "provider": provider.id,
                "hint": format!(
                    "configure SPUC_WEB_{}_CLIENT_ID, SPUC_WEB_{}_CLIENT_SECRET and redirect URI",
                    provider.id.to_ascii_uppercase(),
                    provider.id.to_ascii_uppercase()
                )
            }),
        );
    }
    if !provider.authorized {
        return HttpResponse::json(
            403,
            &serde_json::json!({
                "error": "provider_not_authorized",
                "provider": provider.id,
                "hint": "enable this OAuth provider from User management"
            }),
        );
    }

    let state_token = state.register_oauth_state(provider.id);
    let auth_url = build_oauth_authorize_url(&provider, state_token.as_str())
        .ok_or_else(|| anyhow!("cannot build provider auth url"))?;

    HttpResponse::json(
        200,
        &serde_json::json!({
            "ok": true,
            "provider": provider.id,
            "auth_url": auth_url,
        }),
    )
}

fn login_oauth_callback(
    provider_id: &str,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    if state.no_login_enabled() {
        return Ok(oauth_callback_error_response(
            409,
            "Login is disabled in --no-login mode.",
        ));
    }

    let provider_id = provider_id.trim().to_ascii_lowercase();
    let Some(provider) = state.oauth_provider(provider_id.as_str()) else {
        return Ok(oauth_callback_error_response(
            404,
            "OAuth provider not found.",
        ));
    };
    if !provider.configured {
        return Ok(oauth_callback_error_response(
            400,
            "OAuth provider is not configured on this server.",
        ));
    }
    if !provider.authorized {
        return Ok(oauth_callback_error_response(
            403,
            "OAuth provider is disabled by administrator policy.",
        ));
    }

    if let Some(error) = request.query.get("error").map(String::as_str) {
        let description = request
            .query
            .get("error_description")
            .map(String::as_str)
            .unwrap_or(error);
        return Ok(oauth_callback_error_response(
            400,
            &format!("OAuth provider returned an error: {description}"),
        ));
    }

    let oauth_code = request
        .query
        .get("code")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let state_token = request
        .query
        .get("state")
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(oauth_code) = oauth_code else {
        return Ok(oauth_callback_error_response(
            400,
            "OAuth callback did not provide authorization code.",
        ));
    };
    let Some(state_token) = state_token else {
        return Ok(oauth_callback_error_response(
            400,
            "OAuth callback is missing state token.",
        ));
    };

    if !state.take_oauth_state(provider_id.as_str(), state_token) {
        return Ok(oauth_callback_error_response(
            400,
            "OAuth state token is invalid or expired.",
        ));
    }

    let identity = match exchange_oauth_code(provider_id.as_str(), oauth_code, state_token) {
        Ok(identity) => identity,
        Err(error) => {
            return Ok(oauth_callback_error_response(
                401,
                &format!("OAuth token exchange failed: {error}"),
            ));
        }
    };
    let principal = state.principal_from_oauth_identity(&identity);
    let session = state.create_session(principal);
    Ok(HttpResponse::html(OAUTH_CALLBACK_SUCCESS_HTML).with_header(
        "Set-Cookie",
        format!("spuc_web_session={session}; HttpOnly; Path=/; SameSite=Strict"),
    ))
}

const OAUTH_CALLBACK_SUCCESS_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=/">
  <title>SPUC OAuth</title>
</head>
<body>
  <p>OAuth login completed. Returning to SPUC...</p>
  <p><a href="/">Continue</a></p>
</body>
</html>
"#;

fn oauth_callback_error_response(status: u16, message: &str) -> HttpResponse {
    let escaped = escape_html(message);
    HttpResponse::text(
        status,
        "text/html; charset=utf-8",
        format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>SPUC OAuth</title></head><body><p>{escaped}</p><p><a href=\"/\">Return to SPUC</a></p></body></html>"
        ),
    )
}

fn escape_html(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn settings_get_profile(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    HttpResponse::json(
        200,
        &serde_json::json!({ "entry": state.current_user_settings_view(principal) }),
    )
}

fn settings_update_profile(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: UserSettingsUpdateRequest = request.json()?;
    let entry = state.update_current_user_settings(principal, payload)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": entry }))
}

fn user_get_stix_source_settings(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    HttpResponse::json(
        200,
        &serde_json::json!({ "entry": state.current_opencti_settings_view(principal) }),
    )
}

fn user_update_stix_source_settings(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: UserOpenCtiSettingsUpdateRequest = request.json()?;
    let entry = state.update_current_opencti_settings(principal, payload)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": entry }))
}

fn user_test_opencti_settings(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: OpenCtiTestRequest = request.json().unwrap_or(OpenCtiTestRequest {
        opencti_endpoint: None,
        opencti_api_key: None,
    });
    let saved = state.opencti_settings_for(principal.user_id.as_str());
    let endpoint = payload
        .opencti_endpoint
        .and_then(normalize_opencti_endpoint)
        .or(saved.opencti_endpoint);
    let api_key = payload
        .opencti_api_key
        .and_then(normalize_optional_setting)
        .or(saved.opencti_api_key);
    let Some(endpoint) = endpoint else {
        return HttpResponse::json(
            400,
            &OpenCtiTestResponse {
                ok: false,
                code: "opencti_not_configured",
                message: "OpenCTI endpoint is not configured.".to_string(),
            },
        );
    };
    let Some(api_key) = api_key else {
        return HttpResponse::json(
            400,
            &OpenCtiTestResponse {
                ok: false,
                code: "opencti_not_configured",
                message: "OpenCTI API key is not configured.".to_string(),
            },
        );
    };

    let provider = OpenCtiStixCatalogProvider { endpoint, api_key };
    match provider.test_connection() {
        Ok(()) => HttpResponse::json(
            200,
            &OpenCtiTestResponse {
                ok: true,
                code: "ok",
                message: "OpenCTI connection test succeeded.".to_string(),
            },
        ),
        Err(error) => HttpResponse::json(
            502,
            &OpenCtiTestResponse {
                ok: false,
                code: error.code,
                message: error.message,
            },
        ),
    }
}

fn user_list_tokens(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    HttpResponse::json(
        200,
        &serde_json::json!({ "entries": state.list_user_api_tokens(principal) }),
    )
}

fn user_create_token(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: UserApiTokenCreateRequest = request.json()?;
    let (token, token_value) =
        state.create_user_api_token(principal, payload.name.as_str(), payload.expires_at)?;
    HttpResponse::json(
        200,
        &serde_json::json!({
            "ok": true,
            "entry": UserApiTokenCreateResponse { token, token_value }
        }),
    )
}

fn user_revoke_token(
    principal: &Principal,
    token_id: &str,
    state: &WebState,
) -> Result<HttpResponse> {
    match state.revoke_user_api_token(principal, token_id) {
        Ok(entry) => HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": entry })),
        Err(error) if error.to_string().contains("token_not_found") => {
            HttpResponse::json(404, &serde_json::json!({ "error": "token_not_found" }))
        }
        Err(error) => Err(error),
    }
}

fn user_rotate_token(
    principal: &Principal,
    token_id: &str,
    state: &WebState,
) -> Result<HttpResponse> {
    match state.rotate_user_api_token(principal, token_id) {
        Ok((token, token_value)) => HttpResponse::json(
            200,
            &serde_json::json!({
                "ok": true,
                "entry": UserApiTokenCreateResponse { token, token_value }
            }),
        ),
        Err(error) if error.to_string().contains("token_not_found") => {
            HttpResponse::json(404, &serde_json::json!({ "error": "token_not_found" }))
        }
        Err(error) if error.to_string().contains("token_revoked") => {
            HttpResponse::json(409, &serde_json::json!({ "error": "token_revoked" }))
        }
        Err(error) => Err(error),
    }
}

fn user_delete_token(
    principal: &Principal,
    token_id: &str,
    state: &WebState,
) -> Result<HttpResponse> {
    match state.delete_user_api_token(principal, token_id) {
        Ok(true) => HttpResponse::json(200, &serde_json::json!({ "ok": true })),
        Ok(false) => HttpResponse::json(404, &serde_json::json!({ "error": "token_not_found" })),
        Err(error) => Err(error),
    }
}

fn translate_stix_pattern_with_token(
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    if let Err(response) = ensure_api_token_auth(request, state) {
        return Ok(response);
    }

    let payload: TranslateStixPatternRequest = match request.json() {
        Ok(payload) => payload,
        Err(error) => {
            return HttpResponse::json(
                400,
                &serde_json::json!({
                    "error": "invalid_request_payload",
                    "message": error.to_string()
                }),
            )
        }
    };
    if !payload.object_type.eq_ignore_ascii_case("indicator") {
        return HttpResponse::json(
            400,
            &TranslateStixPatternResponse {
                status: "error",
                comments: vec!["Only STIX indicator input is supported".to_string()],
                results: vec![],
            },
        );
    }
    if !payload.pattern_type.eq_ignore_ascii_case("stix") {
        return HttpResponse::json(
            400,
            &TranslateStixPatternResponse {
                status: "error",
                comments: vec!["pattern_type must be 'stix'".to_string()],
                results: vec![],
            },
        );
    }
    if payload.pattern.trim().is_empty() {
        return HttpResponse::json(
            400,
            &TranslateStixPatternResponse {
                status: "error",
                comments: vec!["pattern is required".to_string()],
                results: vec![],
            },
        );
    }

    let targets = if payload.targets.is_empty() {
        available_detection_target_labels()
    } else {
        payload.targets
    };

    let rows = match evaluate_rule(TranslationRequest {
        rule: payload.pattern.as_str(),
        targets: &targets,
        description: None,
        sigma_targets: &payload.sigma_targets,
        mode: ConversionMode::Strict,
        rule_confidence: payload.rule_confidence,
    }) {
        Ok(rows) => rows,
        Err(error) => {
            return HttpResponse::json(
                200,
                &TranslateStixPatternResponse {
                    status: "error",
                    comments: vec![error.to_string()],
                    results: vec![],
                },
            )
        }
    };

    let results = rows
        .into_iter()
        .filter_map(|row| {
            let output = row.output.clone()?;
            if output.trim().is_empty() || row.runtime_status.eq_ignore_ascii_case("unsupported") {
                return None;
            }
            let pattern_type = if row.target.starts_with("sigma") {
                "sigma".to_string()
            } else {
                row.target.clone()
            };
            Some(TranslateStixPatternResult {
                object_type: "indicator",
                pattern_type: pattern_type.clone(),
                pattern: output.clone(),
                confidence: row.conversion_confidence,
                target: row.target,
                stix: TranslateStixDetectionRule {
                    object_type: "indicator",
                    pattern_type: pattern_type.clone(),
                    pattern: output.clone(),
                    confidence: row.conversion_confidence,
                    description: row.summary,
                    comments: row.notes,
                },
            })
        })
        .collect::<Vec<_>>();

    if results.is_empty() {
        return HttpResponse::json(
            200,
            &TranslateStixPatternResponse {
                status: "error",
                comments: vec!["No translation results for the provided STIX pattern".to_string()],
                results,
            },
        );
    }

    HttpResponse::json(
        200,
        &TranslateStixPatternResponse {
            status: "success",
            comments: vec![],
            results,
        },
    )
}

fn translate_stix_bundle_with_token(
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    if let Err(response) = ensure_api_token_auth(request, state) {
        return Ok(response);
    }
    let payload: TranslateStixBundleRequest = match request.json() {
        Ok(payload) => payload,
        Err(error) => {
            return HttpResponse::json(
                400,
                &serde_json::json!({
                    "error": "invalid_request_payload",
                    "message": error.to_string()
                }),
            )
        }
    };
    let indicator =
        match normalize_input_indicator_for_bundle(&payload.indicator, payload.rule_confidence) {
            Ok(indicator) => indicator,
            Err(error) => return HttpResponse::json(400, &serde_json::json!({ "error": error })),
        };
    let translations = evaluate_stix_translations(
        indicator.pattern.as_str(),
        payload.targets,
        payload.sigma_targets,
        Some(indicator.confidence),
        indicator.description.as_deref(),
    )?;
    if translations.is_empty() {
        return HttpResponse::json(
            200,
            &serde_json::json!({ "status": "error", "comments": ["No translation results for the provided STIX pattern"], "objects": [] }),
        );
    }
    let bundle = build_stix_translation_bundle(indicator, translations);
    HttpResponse::json(200, &bundle)
}

fn translate_stix_pattern_summary_with_token(
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    if let Err(response) = ensure_api_token_auth(request, state) {
        return Ok(response);
    }
    let payload: TranslatePatternSummaryRequest = match request.json() {
        Ok(payload) => payload,
        Err(error) => {
            return HttpResponse::json(
                400,
                &serde_json::json!({
                    "error": "invalid_request_payload",
                    "message": error.to_string()
                }),
            )
        }
    };
    if payload.pattern.trim().is_empty() {
        return HttpResponse::json(
            400,
            &TranslatePatternSummaryResponse {
                status: "error",
                comments: vec!["pattern is required".to_string()],
                result: None,
            },
        );
    }
    if payload.target.trim().is_empty() {
        return HttpResponse::json(
            400,
            &TranslatePatternSummaryResponse {
                status: "error",
                comments: vec!["target is required".to_string()],
                result: None,
            },
        );
    }
    let rows = evaluate_stix_translations(
        payload.pattern.as_str(),
        vec![payload.target.clone()],
        vec![],
        payload.rule_confidence,
        payload.description.as_deref(),
    )?;
    let Some(row) = rows.into_iter().next() else {
        return HttpResponse::json(
            200,
            &TranslatePatternSummaryResponse {
                status: "error",
                comments: vec!["No translation results for the provided STIX pattern".to_string()],
                result: None,
            },
        );
    };
    HttpResponse::json(
        200,
        &TranslatePatternSummaryResponse {
            status: "success",
            comments: row.notes,
            result: Some(TranslatePatternSummaryResult {
                description: row.summary,
                pattern: row.output.unwrap_or_default(),
                confidence: row.conversion_confidence,
                target: row.target,
            }),
        },
    )
}

fn ensure_api_token_auth(
    request: &HttpRequest,
    state: &WebState,
) -> std::result::Result<(), HttpResponse> {
    let Some(token) = request.bearer_token() else {
        return Err(
            HttpResponse::json(401, &serde_json::json!({ "error": "missing_api_token" }))
                .expect("json response"),
        );
    };
    if state
        .resolve_principal_from_api_token(token.as_str())
        .is_none()
    {
        return Err(HttpResponse::json(
            401,
            &serde_json::json!({ "error": "invalid_or_revoked_api_token" }),
        )
        .expect("json response"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct InputIndicator {
    id: String,
    name: String,
    description: Option<String>,
    pattern_type: String,
    pattern: String,
    confidence: u8,
}

fn normalize_input_indicator_for_bundle(
    indicator: &serde_json::Value,
    fallback_confidence: Option<u8>,
) -> std::result::Result<InputIndicator, &'static str> {
    let object_type = indicator
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("indicator");
    if !object_type.eq_ignore_ascii_case("indicator") {
        return Err("only_indicator_object_supported");
    }
    let pattern_type = indicator
        .get("pattern_type")
        .and_then(|value| value.as_str())
        .unwrap_or("stix")
        .to_string();
    if !pattern_type.eq_ignore_ascii_case("stix") {
        return Err("pattern_type_must_be_stix");
    }
    let pattern = indicator
        .get("pattern")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if pattern.is_empty() {
        return Err("pattern_required");
    }
    let id = indicator
        .get("id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| new_stix_id("indicator"));
    let name = indicator
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "Source indicator".to_string());
    let description = indicator
        .get("description")
        .and_then(|value| value.as_str())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let confidence = fallback_confidence
        .or_else(|| {
            indicator
                .get("confidence")
                .and_then(|value| value.as_u64())
                .map(|value| value as u8)
        })
        .unwrap_or(70)
        .min(100);
    Ok(InputIndicator {
        id,
        name,
        description,
        pattern_type: "stix".to_string(),
        pattern,
        confidence,
    })
}

fn evaluate_stix_translations(
    pattern: &str,
    targets: Vec<String>,
    sigma_targets: Vec<String>,
    rule_confidence: Option<u8>,
    description: Option<&str>,
) -> Result<Vec<crate::app::services::translation::TranslationEvaluation>> {
    let targets = if targets.is_empty() {
        available_detection_target_labels()
    } else {
        targets
    };
    let rows = evaluate_rule(TranslationRequest {
        rule: pattern,
        targets: &targets,
        description,
        sigma_targets: &sigma_targets,
        mode: ConversionMode::Strict,
        rule_confidence,
    })?;
    Ok(rows
        .into_iter()
        .filter(|row| !row.runtime_status.eq_ignore_ascii_case("unsupported"))
        .filter(|row| {
            row.output
                .as_deref()
                .map(str::trim)
                .is_some_and(|output| !output.is_empty())
        })
        .collect())
}

fn build_stix_translation_bundle(
    source: InputIndicator,
    rows: Vec<crate::app::services::translation::TranslationEvaluation>,
) -> serde_json::Value {
    let now = Utc::now().to_rfc3339();
    let mut objects = Vec::new();
    objects.push(json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": source.id.clone(),
        "created": now,
        "modified": now,
        "name": source.name,
        "pattern_type": source.pattern_type,
        "pattern": source.pattern,
        "description": source.description.clone().unwrap_or_default(),
        "valid_from": now,
        "confidence": source.confidence,
    }));
    for row in rows {
        let output = row.output.unwrap_or_default();
        let target = row.target.clone();
        let derived_indicator_id = new_stix_id("indicator");
        let source_description = source
            .description
            .clone()
            .unwrap_or_else(|| row.summary.clone());
        let derived_description = format_derived_indicator_description(&source_description);
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": derived_indicator_id,
            "created": now,
            "modified": now,
            "name": format!("{} [{}]", source.name, target),
            "pattern_type": if target.starts_with("sigma") { "sigma" } else { target.as_str() },
            "pattern": output,
            "description": derived_description,
            "valid_from": now,
            "confidence": row.conversion_confidence,
            "labels": ["spuc", "auto-generated", target.as_str()],
            "x_spuc_translation_comments": row.notes,
        }));
        objects.push(json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": new_stix_id("relationship"),
            "created": now,
            "modified": now,
            "relationship_type": "derived-from",
            "source_ref": derived_indicator_id,
            "target_ref": source.id.clone(),
            "confidence": row.conversion_confidence,
        }));
    }
    json!({
        "type": "bundle",
        "id": new_stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    })
}

fn format_derived_indicator_description(source_description: &str) -> String {
    const GENERATED_NOTE: &str =
        "STIX Indicator automatically generated from the original STIX Pattern.";
    let trimmed = source_description.trim_end();
    if trimmed.is_empty() {
        GENERATED_NOTE.to_string()
    } else {
        format!("{trimmed}\n\n{GENERATED_NOTE}")
    }
}

fn admin_list_users(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    HttpResponse::json(
        200,
        &serde_json::json!({
            "entries": state.list_users(),
            "active_sessions": state.session_count(),
            "latest_session_utc": state.newest_session_timestamp(),
        }),
    )
}

fn admin_create_user(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    let payload: AdminUserCreateRequest = request.json()?;
    let role = match payload
        .role
        .as_deref()
        .unwrap_or("analyst")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "admin" => Role::Admin,
        _ => Role::Analyst,
    };
    let created = state.create_user(
        &payload.username,
        &payload.password,
        role,
        payload.display_name,
    )?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": created }))
}

fn admin_delete_user(
    principal: &Principal,
    user_id: &str,
    state: &WebState,
) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    if principal.user_id == user_id {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "self_delete_not_allowed" }),
        );
    }
    let deleted = state.delete_user(user_id)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "deleted": deleted }))
}

fn admin_update_user(
    principal: &Principal,
    user_id: &str,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    if principal.user_id == user_id {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "self_update_not_allowed" }),
        );
    }

    let payload: AdminUserUpdateRequest = request.json()?;
    let role = payload.role.as_deref().map(|value| {
        if value.trim().eq_ignore_ascii_case("admin") {
            Role::Admin
        } else {
            Role::Analyst
        }
    });
    let updated = state.update_user(
        user_id,
        role,
        payload.enabled,
        payload.totp_enabled,
        payload.display_name,
    )?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": updated }))
}

fn admin_change_password(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: AdminPasswordChangeRequest = request.json()?;
    let target_user_id = payload
        .user_id
        .as_deref()
        .unwrap_or(principal.user_id.as_str());
    if target_user_id != principal.user_id && !principal.role.can_manage_users() {
        return HttpResponse::json(403, &serde_json::json!({ "error": "forbidden" }));
    }

    state.change_user_password(
        principal,
        target_user_id,
        payload.current_password.as_deref(),
        payload.new_password.as_str(),
    )?;

    HttpResponse::json(200, &serde_json::json!({ "ok": true }))
}

fn admin_list_oauth_providers(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    HttpResponse::json(
        200,
        &serde_json::json!({ "entries": state.list_oauth_providers() }),
    )
}

fn admin_update_oauth_provider(
    principal: &Principal,
    provider_id: &str,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    let payload: AdminOAuthProviderUpdateRequest = request.json()?;
    let provider_id = provider_id.trim().to_ascii_lowercase();
    if state
        .runtime()
        .oauth
        .provider(provider_id.as_str())
        .is_none()
    {
        return HttpResponse::json(404, &serde_json::json!({ "error": "provider_not_found" }));
    }
    let updated =
        state.update_oauth_provider_authorization(provider_id.as_str(), payload.authorized)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": updated }))
}

fn admin_get_runtime_settings(principal: &Principal, state: &WebState) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    HttpResponse::json(
        200,
        &serde_json::json!({ "entry": state.runtime_settings_view() }),
    )
}

fn admin_update_runtime_settings(
    principal: &Principal,
    request: &HttpRequest,
    state: &WebState,
) -> Result<HttpResponse> {
    ensure_admin(principal)?;
    let payload: AdminRuntimeSettingsUpdateRequest = request.json()?;
    let updated = state.update_runtime_settings(payload)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "entry": updated }))
}

fn ensure_admin(principal: &Principal) -> Result<()> {
    if !principal.role.can_manage_users() {
        return Err(anyhow!("forbidden"));
    }
    Ok(())
}

fn overview_response() -> Result<HttpResponse> {
    let (_, abilities, rules, adversaries) = load_catalog_data()?;

    let mut status_counts = BTreeMap::<String, usize>::new();
    let mut target_counts = BTreeMap::<String, usize>::new();
    let mut observable_counts = BTreeMap::<String, usize>::new();
    for rule in &rules {
        *status_counts
            .entry(rule_status_bucket(rule).to_string())
            .or_insert(0) += 1;
        for target in &rule.targets {
            *target_counts.entry(target.to_string()).or_insert(0) += 1;
        }
        for observable in rule_observables(rule) {
            *observable_counts.entry(observable).or_insert(0) += 1;
        }
    }

    let mut platform_counts = BTreeMap::<String, usize>::new();
    for ability in &abilities {
        for platform in &ability.supported_platforms {
            *platform_counts.entry(platform.to_string()).or_insert(0) += 1;
        }
    }

    let statuses = status_counts
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect::<Vec<_>>();
    let emulation_targets = [
        "spuc-agent",
        "bash",
        "powershell",
        "atomic-red-team",
        "mitre-caldera",
    ];
    let total_rules = rules.len();
    let emulation_coverage = emulation_targets
        .iter()
        .map(|target| {
            let count = rules
                .iter()
                .filter(|entry| {
                    status_bucket(entry.emulation_statuses.get(*target).map(String::as_str))
                        != "unsupported"
                })
                .count();
            let percent = if total_rules == 0 {
                0.0
            } else {
                ((count as f64) * 1000.0 / (total_rules as f64)).round() / 10.0
            };
            NameRatio {
                name: (*target).to_string(),
                count,
                percent,
            }
        })
        .collect::<Vec<_>>();
    let top_targets = top_counts(target_counts, 8);
    let top_platforms = top_counts(platform_counts, 8);
    let top_observables = top_counts(observable_counts, 8);

    let destinations = rules
        .iter()
        .flat_map(|entry| entry.targets.iter())
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    HttpResponse::json(
        200,
        &OverviewResponse {
            kpis: OverviewKpis {
                rules_total: rules.len(),
                adversaries_total: adversaries.len(),
                abilities_total: abilities.len(),
                supported_destinations: destinations,
                engines_available: 9,
            },
            statuses,
            emulation_coverage,
            top_targets,
            top_platforms,
            top_observables,
        },
    )
}

fn list_rules(request: &HttpRequest) -> Result<HttpResponse> {
    let (_, _, rules, _) = load_catalog_data()?;
    let query = RuleCatalogQuery {
        q: request.query.get("q").cloned(),
        min_confidence: request
            .query
            .get("min_confidence")
            .and_then(|value| value.parse::<u8>().ok()),
        status: request.query.get("status").cloned(),
        target: request.query.get("target").cloned(),
        observable: request.query.get("observable").cloned(),
        sort: request.query.get("sort").cloned(),
        page: request
            .query
            .get("page")
            .and_then(|value| value.parse::<usize>().ok()),
        page_size: request
            .query
            .get("page_size")
            .and_then(|value| value.parse::<usize>().ok()),
    };

    let mut entries = filter_rule_entries(&rules, query.q.as_deref(), None);
    if let Some(min_confidence) = query.min_confidence {
        entries.retain(|entry| entry.confidence >= min_confidence);
    }
    if let Some(status) = query.status.as_deref() {
        let needle = status.trim().to_ascii_lowercase();
        entries.retain(|entry| rule_status_bucket(entry).eq_ignore_ascii_case(&needle));
    }
    if let Some(target) = query.target.as_deref() {
        let needle = target.trim().to_ascii_lowercase();
        entries.retain(|entry| {
            entry
                .targets
                .iter()
                .any(|value| value.to_ascii_lowercase().contains(&needle))
        });
    }
    if let Some(observable) = query.observable.as_deref() {
        let needle = observable.trim().to_ascii_lowercase();
        entries.retain(|entry| {
            rule_observables(entry)
                .iter()
                .any(|value| value.to_ascii_lowercase() == needle)
        });
    }

    sort_rules(&mut entries, query.sort.as_deref());

    let total = entries.len();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(25).clamp(5, 200);
    let start = (page - 1) * page_size;
    let paged = entries
        .into_iter()
        .skip(start)
        .take(page_size)
        .map(rule_view)
        .collect::<Vec<_>>();

    HttpResponse::json(
        200,
        &PagedResponse {
            total,
            page,
            page_size,
            entries: paged,
        },
    )
}

fn show_rule(selector: &str) -> Result<HttpResponse> {
    let (_, _, rules, _) = load_catalog_data()?;
    let entry = resolve_rule_selector(selector, &rules, None)?;
    HttpResponse::json(200, &rule_view(entry))
}

fn stix_catalog_path() -> Option<PathBuf> {
    spuc_config_root().map(|root| root.join("stix-objects.json"))
}

fn load_stix_catalog() -> Vec<StixCatalogEntry> {
    let Some(path) = stix_catalog_path() else {
        return Vec::new();
    };
    if !path.exists() {
        return Vec::new();
    }
    let Ok(data) = fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<StixCatalogEntry>>(&data).unwrap_or_default()
}

fn save_stix_catalog(entries: &[StixCatalogEntry]) -> Result<()> {
    let Some(path) = stix_catalog_path() else {
        return Err(anyhow!("stix catalog path unavailable"));
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(entries)?;
    Ok(fs::write(&path, data)?)
}

fn local_stix_catalog_views() -> Result<Vec<StixObjectView>> {
    let catalog_entries = load_stix_catalog();
    let (_, _, rules, _) = load_catalog_data()?;
    let mut from_rules = collect_stix_objects_from_rules(&rules);
    // Merge: catalog entries take priority; supplement with rule-derived entries.
    let catalog_ids: BTreeSet<String> = catalog_entries
        .iter()
        .map(|e| e.stix_id.to_ascii_lowercase())
        .collect();
    from_rules.retain(|e| !catalog_ids.contains(&e.stix_id.to_ascii_lowercase()));
    let mut catalog_views: Vec<StixObjectView> = catalog_entries
        .into_iter()
        .map(|e| StixObjectView {
            stix_id: e.stix_id,
            stix_type: e.stix_type,
            name: e.name,
            description: e.description,
            tlp: e.tlp,
            pap: e.pap,
            created_at: e.created_at,
            first_seen: e.first_seen,
            source: Some("local".to_string()),
            aliases: Vec::new(),
            external_references: Vec::new(),
        })
        .collect();
    catalog_views.append(&mut from_rules);
    catalog_views.sort_by(|a, b| {
        a.stix_type
            .cmp(&b.stix_type)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.stix_id.cmp(&b.stix_id))
    });
    Ok(catalog_views)
}

fn parse_stix_object_query(request: &HttpRequest) -> StixProviderSearch {
    let types = request
        .query
        .get("types")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_ascii_lowercase)
                .filter(|value| is_valid_stix_object_name(value))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let limit = request
        .query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(OPENCTI_DEFAULT_LIMIT)
        .clamp(1, OPENCTI_MAX_LIMIT);
    StixProviderSearch {
        query: request.query.get("q").cloned(),
        types,
        limit,
    }
}

fn stix_provider_for_settings(
    settings: &UserOpenCtiSettingsEntry,
) -> Option<OpenCtiStixCatalogProvider> {
    if opencti_effective_source(settings) != StixCatalogSource::OpenCti {
        return None;
    }
    Some(OpenCtiStixCatalogProvider {
        endpoint: settings.opencti_endpoint.clone()?,
        api_key: settings.opencti_api_key.clone()?,
    })
}

fn list_stix_objects(
    request: &HttpRequest,
    principal: &Principal,
    state: &WebState,
) -> Result<HttpResponse> {
    let search = parse_stix_object_query(request);
    let settings = state.opencti_settings_for(principal.user_id.as_str());
    if let Some(provider) = stix_provider_for_settings(&settings) {
        if search
            .query
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            return HttpResponse::json(
                200,
                &StixObjectsResponse {
                    entries: Vec::new(),
                    source: "opencti",
                    effective_source: "opencti",
                    fallback_used: false,
                    message: Some(
                        "Search OpenCTI objects by name, alias, type or external reference."
                            .to_string(),
                    ),
                    error: None,
                },
            );
        }
        match provider.search_objects(&search) {
            Ok(entries) => {
                return HttpResponse::json(
                    200,
                    &StixObjectsResponse {
                        entries,
                        source: "opencti",
                        effective_source: "opencti",
                        fallback_used: false,
                        message: None,
                        error: None,
                    },
                );
            }
            Err(error) => {
                let local_entries = LocalStixCatalogProvider
                    .search_objects(&search)
                    .map_err(|err| anyhow!(err.message))?;
                return HttpResponse::json(
                    200,
                    &StixObjectsResponse {
                        entries: local_entries,
                        source: "opencti",
                        effective_source: "local",
                        fallback_used: true,
                        message: Some(
                            "OpenCTI is unavailable. Showing local catalog results.".to_string(),
                        ),
                        error: Some(error.view()),
                    },
                );
            }
        }
    }

    let entries = LocalStixCatalogProvider
        .search_objects(&search)
        .map_err(|err| anyhow!(err.message))?;
    HttpResponse::json(
        200,
        &StixObjectsResponse {
            entries,
            source: "local",
            effective_source: "local",
            fallback_used: false,
            message: None,
            error: None,
        },
    )
}

#[derive(Debug, Deserialize)]
struct CreateStixObjectRequest {
    stix_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tlp: Option<String>,
    #[serde(default)]
    pap: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    force_create: bool,
}

fn create_stix_object(
    request: &HttpRequest,
    principal: &Principal,
    state: &WebState,
) -> Result<HttpResponse> {
    let payload: CreateStixObjectRequest = request.json()?;
    let settings = state.opencti_settings_for(principal.user_id.as_str());
    if let Some(provider) = stix_provider_for_settings(&settings) {
        if !payload.force_create {
            let similar = provider
                .find_similar_objects(&payload)
                .map_err(|err| anyhow!(err.message))?;
            if !similar.is_empty() {
                return HttpResponse::json(
                    409,
                    &serde_json::json!({
                        "error": "similar_objects_found",
                        "message": "Possible similar STIX objects were found. Review them before creating a new object.",
                        "candidates": similar
                    }),
                );
            }
        }
        return match provider.create_object(&payload) {
            Ok(created) => HttpResponse::json(
                200,
                &serde_json::json!({ "ok": true, "stix_id": created.stix_id, "entry": created }),
            ),
            Err(error) => HttpResponse::json(
                502,
                &serde_json::json!({
                    "error": error.code,
                    "message": error.message,
                    "go_to_user_settings": true
                }),
            ),
        };
    }
    create_local_stix_object(payload)
}

fn create_local_stix_object(payload: CreateStixObjectRequest) -> Result<HttpResponse> {
    let stix_id = payload.stix_id.trim().to_string();
    let name = payload.name.trim().to_string();
    if stix_id.is_empty() || name.is_empty() {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "stix_id_and_name_required" }),
        );
    }
    if !is_valid_stix_id(&stix_id) {
        return HttpResponse::json(400, &serde_json::json!({ "error": "invalid_stix_id" }));
    }
    let stix_type = stix_object_type_from_id(&stix_id);
    let now = Utc::now().to_rfc3339();
    let mut catalog = load_stix_catalog();
    // Upsert by stix_id
    if let Some(existing) = catalog
        .iter_mut()
        .find(|e| e.stix_id.eq_ignore_ascii_case(&stix_id))
    {
        existing.name = name;
        if let Some(desc) = payload
            .description
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            existing.description = Some(desc.to_string());
        }
        if payload.tlp.is_some() {
            existing.tlp = payload.tlp.map(|v| normalize_tlp(Some(&v)).to_string());
        }
        if payload.pap.is_some() {
            existing.pap = payload.pap.map(|v| normalize_pap(Some(&v)).to_string());
        }
        if payload.first_seen.is_some() {
            existing.first_seen = payload.first_seen;
        }
    } else {
        catalog.push(StixCatalogEntry {
            stix_id: stix_id.clone(),
            stix_type,
            name,
            description: payload.description.and_then(|v| {
                let trimmed = v.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            }),
            tlp: Some(normalize_tlp(payload.tlp.as_deref()).to_string()),
            pap: Some(normalize_pap(payload.pap.as_deref()).to_string()),
            created_at: Some(payload.created_at.unwrap_or_else(|| now.clone())),
            first_seen: Some(payload.first_seen.unwrap_or(now)),
        });
    }
    save_stix_catalog(&catalog)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true, "stix_id": stix_id }))
}

impl StixCatalogProvider for LocalStixCatalogProvider {
    fn search_objects(
        &self,
        search: &StixProviderSearch,
    ) -> StixProviderResult<Vec<StixObjectView>> {
        let query = search.query.as_deref().map(str::trim).unwrap_or("");
        let query_lower = query.to_ascii_lowercase();
        let type_filter = search
            .types
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let mut entries = local_stix_catalog_views()
            .map_err(|error| StixProviderError::new("local_catalog_error", error.to_string()))?;
        entries.retain(|entry| {
            let type_matches = type_filter.is_empty()
                || type_filter.contains(&entry.stix_type.to_ascii_lowercase());
            if !type_matches {
                return false;
            }
            if query_lower.is_empty() {
                return true;
            }
            stix_object_matches_query(entry, &query_lower)
        });
        entries.truncate(search.limit);
        Ok(entries)
    }

    fn get_object_by_id(&self, id: &str) -> StixProviderResult<Option<StixObjectView>> {
        let id_lower = id.trim().to_ascii_lowercase();
        Ok(local_stix_catalog_views()
            .map_err(|error| StixProviderError::new("local_catalog_error", error.to_string()))?
            .into_iter()
            .find(|entry| entry.stix_id.to_ascii_lowercase() == id_lower))
    }

    fn create_object(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<StixObjectView> {
        let request_payload = CreateStixObjectRequest {
            stix_id: payload.stix_id.clone(),
            name: payload.name.clone(),
            description: payload.description.clone(),
            tlp: payload.tlp.clone(),
            pap: payload.pap.clone(),
            created_at: payload.created_at.clone(),
            first_seen: payload.first_seen.clone(),
            force_create: payload.force_create,
        };
        create_local_stix_object(request_payload)
            .map_err(|error| StixProviderError::new("local_catalog_error", error.to_string()))?;
        self.get_object_by_id(payload.stix_id.as_str())?
            .ok_or_else(|| {
                StixProviderError::new("local_catalog_error", "created object not found")
            })
    }

    fn find_similar_objects(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<Vec<StixObjectView>> {
        let search = StixProviderSearch {
            query: Some(payload.name.clone()),
            types: vec![stix_object_type_from_id(&payload.stix_id)],
            limit: 10,
        };
        self.search_objects(&search)
    }
}

impl OpenCtiStixCatalogProvider {
    fn test_connection(&self) -> StixProviderResult<()> {
        match self.graphql(
            "query SpucOpenCtiHealth { me { id name } }",
            serde_json::json!({}),
        ) {
            Ok(_) => Ok(()),
            Err(error) if error.code == "unexpected_graphql_response" => self
                .graphql(
                    "query SpucOpenCtiHealth { __typename }",
                    serde_json::json!({}),
                )
                .map(|_| ()),
            Err(error) => Err(error),
        }
    }

    fn graphql(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> StixProviderResult<serde_json::Value> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(
                OPENCTI_GRAPHQL_TIMEOUT_SECONDS,
            ))
            .build();
        let auth_header = format!("Bearer {}", self.api_key);
        let response = agent
            .post(self.endpoint.as_str())
            .set("Authorization", auth_header.as_str())
            .set("Accept", "application/json")
            .send_json(serde_json::json!({
                "query": query,
                "variables": variables
            }))
            .map_err(map_opencti_ureq_error)?;
        let payload = response.into_json::<serde_json::Value>().map_err(|error| {
            StixProviderError::new("unexpected_graphql_response", error.to_string())
        })?;
        if let Some(errors) = payload.get("errors").and_then(|value| value.as_array()) {
            if !errors.is_empty() {
                let message = errors
                    .first()
                    .and_then(|error| error.get("message"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("OpenCTI returned a GraphQL error.");
                return Err(classify_opencti_graphql_error(message));
            }
        }
        if payload.get("data").is_none() {
            return Err(StixProviderError::new(
                "unexpected_graphql_response",
                "OpenCTI response did not include a data object.",
            ));
        }
        Ok(payload)
    }
}

impl StixCatalogProvider for OpenCtiStixCatalogProvider {
    fn search_objects(
        &self,
        search: &StixProviderSearch,
    ) -> StixProviderResult<Vec<StixObjectView>> {
        let query_text = search.query.as_deref().map(str::trim).unwrap_or("");
        let payload = self.graphql(
            r#"
            query SpucSearchStix($search: String, $types: [String], $first: Int) {
              stixCoreObjects(search: $search, types: $types, first: $first) {
                edges {
                  node {
                    id
                    standard_id
                    entity_type
                    parent_types
                    representative
                    main_value
                    name
                    description
                    aliases
                    x_opencti_aliases
                    created
                    first_seen
                    externalReferences {
                      edges {
                        node {
                          source_name
                          external_id
                          url
                        }
                      }
                    }
                  }
                }
              }
            }
            "#,
            serde_json::json!({
                "search": query_text,
                "types": if search.types.is_empty() { serde_json::Value::Null } else { serde_json::json!(search.types) },
                "first": search.limit
            }),
        )?;
        let entries = payload
            .pointer("/data/stixCoreObjects/edges")
            .and_then(|value| value.as_array())
            .ok_or_else(|| {
                StixProviderError::new(
                    "unexpected_graphql_response",
                    "OpenCTI search response did not include stixCoreObjects edges.",
                )
            })?
            .iter()
            .filter_map(|edge| edge.get("node"))
            .filter_map(opencti_node_to_stix_view)
            .collect::<Vec<_>>();
        Ok(entries)
    }

    fn get_object_by_id(&self, id: &str) -> StixProviderResult<Option<StixObjectView>> {
        let payload = self.graphql(
            r#"
            query SpucGetStix($id: String!) {
              stixCoreObject(id: $id) {
                id
                standard_id
                entity_type
                parent_types
                representative
                main_value
                name
                description
                aliases
                x_opencti_aliases
                created
                first_seen
              }
            }
            "#,
            serde_json::json!({ "id": id }),
        )?;
        Ok(payload
            .pointer("/data/stixCoreObject")
            .and_then(opencti_node_to_stix_view))
    }

    fn create_object(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<StixObjectView> {
        let stix_type = stix_object_type_from_id(payload.stix_id.as_str());
        let (mutation_name, input_type) = opencti_create_mutation_for_type(stix_type.as_str())?;
        let description = payload
            .description
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("");
        let mutation = format!(
            "mutation SpucCreateStix($input: {input_type}!) {{ {mutation_name}(input: $input) {{ id standard_id entity_type name description }} }}"
        );
        let response = self.graphql(
            mutation.as_str(),
            serde_json::json!({
                "input": {
                    "name": payload.name.trim(),
                    "description": description
                }
            }),
        )?;
        response
            .pointer(&format!("/data/{mutation_name}"))
            .and_then(opencti_node_to_stix_view)
            .ok_or_else(|| {
                StixProviderError::new(
                    "unexpected_graphql_response",
                    "OpenCTI create response did not include the created STIX object.",
                )
            })
    }

    fn find_similar_objects(
        &self,
        payload: &CreateStixObjectRequest,
    ) -> StixProviderResult<Vec<StixObjectView>> {
        let search = StixProviderSearch {
            query: Some(payload.name.clone()),
            types: vec![stix_object_type_from_id(payload.stix_id.as_str())],
            limit: 10,
        };
        self.search_objects(&search)
    }
}

fn stix_object_matches_query(entry: &StixObjectView, query_lower: &str) -> bool {
    [
        entry.name.as_str(),
        entry.stix_id.as_str(),
        entry.stix_type.as_str(),
        entry.description.as_deref().unwrap_or(""),
    ]
    .iter()
    .any(|value| value.to_ascii_lowercase().contains(query_lower))
        || entry
            .aliases
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(query_lower))
        || entry
            .external_references
            .iter()
            .any(|value| value.to_ascii_lowercase().contains(query_lower))
}

fn map_opencti_ureq_error(error: ureq::Error) -> StixProviderError {
    match error {
        ureq::Error::Status(401, _) => StixProviderError::new(
            "invalid_api_key",
            "OpenCTI rejected the configured API key.",
        ),
        ureq::Error::Status(403, _) => StixProviderError::new(
            "permissions_insufficient",
            "The OpenCTI API key does not have permission for this operation.",
        ),
        ureq::Error::Status(429, _) => StixProviderError::new(
            "rate_limited",
            "OpenCTI rate-limited the request. SPUC kept the local catalog available.",
        ),
        ureq::Error::Status(status, response) => StixProviderError::new(
            "endpoint_unavailable",
            format!(
                "OpenCTI endpoint returned HTTP {} {}.",
                status,
                response.status_text()
            ),
        ),
        ureq::Error::Transport(error) => {
            let message = error.to_string();
            if message.to_ascii_lowercase().contains("timeout") {
                StixProviderError::new(
                    "timeout",
                    "OpenCTI request timed out. SPUC kept the local catalog available.",
                )
            } else {
                StixProviderError::new(
                    "endpoint_unavailable",
                    format!("OpenCTI endpoint is unavailable: {message}"),
                )
            }
        }
    }
}

fn classify_opencti_graphql_error(message: &str) -> StixProviderError {
    let lower = message.to_ascii_lowercase();
    if lower.contains("unauthorized") || lower.contains("authentication") {
        StixProviderError::new(
            "invalid_api_key",
            "OpenCTI rejected the configured API key.",
        )
    } else if lower.contains("forbidden") || lower.contains("permission") {
        StixProviderError::new(
            "permissions_insufficient",
            "The OpenCTI API key does not have permission for this operation.",
        )
    } else if lower.contains("rate") && lower.contains("limit") {
        StixProviderError::new(
            "rate_limited",
            "OpenCTI rate-limited the request. SPUC kept the local catalog available.",
        )
    } else {
        StixProviderError::new("unexpected_graphql_response", message.to_string())
    }
}

fn opencti_node_to_stix_view(node: &serde_json::Value) -> Option<StixObjectView> {
    let stix_id = node
        .get("standard_id")
        .and_then(|value| value.as_str())
        .or_else(|| node.get("id").and_then(|value| value.as_str()))
        .unwrap_or("")
        .trim()
        .to_string();
    if stix_id.is_empty() {
        return None;
    }
    let stix_type = node
        .get("entity_type")
        .and_then(|value| value.as_str())
        .map(str::to_ascii_lowercase)
        .or_else(|| Some(stix_object_type_from_id(stix_id.as_str())))
        .unwrap_or_default();
    let name = node
        .get("name")
        .and_then(|value| value.as_str())
        .or_else(|| node.get("representative").and_then(|value| value.as_str()))
        .or_else(|| node.get("main_value").and_then(|value| value.as_str()))
        .unwrap_or(stix_id.as_str())
        .to_string();
    Some(StixObjectView {
        stix_id,
        stix_type,
        name,
        description: node
            .get("description")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        tlp: None,
        pap: None,
        created_at: node
            .get("created")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        first_seen: node
            .get("first_seen")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        source: Some("opencti".to_string()),
        aliases: opencti_aliases(node),
        external_references: opencti_external_references(node),
    })
}

fn opencti_aliases(node: &serde_json::Value) -> Vec<String> {
    node.get("aliases")
        .or_else(|| node.get("x_opencti_aliases"))
        .and_then(|value| value.as_array())
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn opencti_external_references(node: &serde_json::Value) -> Vec<String> {
    node.pointer("/externalReferences/edges")
        .and_then(|value| value.as_array())
        .map(|edges| {
            edges
                .iter()
                .filter_map(|edge| edge.get("node"))
                .filter_map(|reference| {
                    let source = reference
                        .get("source_name")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let external_id = reference
                        .get("external_id")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let url = reference
                        .get("url")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let label = [source, external_id, url]
                        .into_iter()
                        .filter(|value| !value.trim().is_empty())
                        .collect::<Vec<_>>()
                        .join(" ");
                    if label.is_empty() {
                        None
                    } else {
                        Some(label)
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn opencti_create_mutation_for_type(
    stix_type: &str,
) -> StixProviderResult<(&'static str, &'static str)> {
    match stix_type {
        "intrusion-set" => Ok(("intrusionSetAdd", "IntrusionSetAddInput")),
        "malware" => Ok(("malwareAdd", "MalwareAddInput")),
        "tool" => Ok(("toolAdd", "ToolAddInput")),
        "campaign" => Ok(("campaignAdd", "CampaignAddInput")),
        "attack-pattern" => Ok(("attackPatternAdd", "AttackPatternAddInput")),
        "vulnerability" => Ok(("vulnerabilityAdd", "VulnerabilityAddInput")),
        "identity" => Ok(("identityAdd", "IdentityAddInput")),
        // TODO(opencti-integration): indicator creation needs a real STIX pattern from the
        // translation/auth API branch; do not invent indicator semantics from name-only UI input.
        "indicator" => Err(StixProviderError::new(
            "unsupported_object_creation",
            "Creating OpenCTI indicators requires a STIX pattern payload.",
        )),
        _ => Err(StixProviderError::new(
            "unsupported_object_creation",
            format!("Creating '{stix_type}' objects in OpenCTI is not supported yet."),
        )),
    }
}

fn delete_stix_object(stix_id: &str) -> Result<HttpResponse> {
    let mut catalog = load_stix_catalog();
    let before = catalog.len();
    catalog.retain(|e| !e.stix_id.eq_ignore_ascii_case(stix_id));
    if catalog.len() == before {
        return HttpResponse::json(404, &serde_json::json!({ "error": "not_found" }));
    }
    save_stix_catalog(&catalog)?;
    HttpResponse::json(200, &serde_json::json!({ "ok": true }))
}

fn delete_rule(selector: &str) -> Result<HttpResponse> {
    let (_, _, rules, _) = load_catalog_data()?;
    let entry = resolve_rule_selector(selector, &rules, None)?;
    let catalog = AbilityCatalog::from_default_root()?;
    let confirmation = format!("DELETE {}", entry.rule_id);
    delete_rule_entry(&catalog, &entry, Some(&confirmation))?;
    HttpResponse::json(
        200,
        &serde_json::json!({ "ok": true, "rule_id": entry.rule_id }),
    )
}

fn save_rule(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: RuleMutationRequest = request.json()?;
    let confidence = payload.confidence.unwrap_or(70);
    if confidence > 100 {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "confidence_out_of_range" }),
        );
    }

    let (catalog, _, rules, _) = load_catalog_data()?;
    let existing_indicates = rules
        .iter()
        .find(|entry| entry.rule.trim() == payload.rule.trim())
        .map(|entry| decode_rule_metadata_description(entry.description.clone()).indicates_list)
        .unwrap_or_default();

    // If indicates_list is explicitly provided, use it (with normalization and validation)
    // overriding existing stored ones. Otherwise, fall back to the legacy single `indicates`.
    let effective_indicates = if let Some(list) = payload.indicates_list.as_ref() {
        let normalized = normalize_indicates_relations(list.clone());
        for rel in &normalized {
            if !is_valid_stix_id(&rel.stix_id) {
                return HttpResponse::json(
                    400,
                    &serde_json::json!({ "error": "invalid_stix_id", "stix_id": rel.stix_id }),
                );
            }
        }
        normalized
    } else {
        let requested_indicates = normalize_indicates_relation(payload.indicates.clone());
        if payload.indicates.is_some() && requested_indicates.is_none() {
            return HttpResponse::json(
                400,
                &serde_json::json!({ "error": "indicates_requires_stix_id_and_object_name" }),
            );
        }
        if let Some(indicates) = requested_indicates.as_ref() {
            if !is_valid_stix_id(&indicates.stix_id) {
                return HttpResponse::json(400, &serde_json::json!({ "error": "invalid_stix_id" }));
            }
        }
        let mut merged = existing_indicates;
        if let Some(indicates) = requested_indicates {
            push_unique_indicates(&mut merged, indicates);
        }
        merged
    };

    let observables = extract_rule_observable_types(&payload.rule);
    let storage_description = encode_rule_metadata_description(
        payload.description.as_deref(),
        payload.tlp.as_deref(),
        payload.pap.as_deref(),
        payload.ttp.as_deref(),
        None,
        Some(observables.as_slice()),
        Some(effective_indicates.as_slice()),
    );
    let (effective_saved, saved_as_emulation) = persist_rule_entry(
        &payload.rule,
        payload.name.as_deref(),
        storage_description.as_deref(),
        payload.ttp.as_deref(),
        confidence,
    )?;

    let mut response = serde_json::to_value(rule_view(effective_saved))?;
    response["saved_as_emulation"] = serde_json::Value::Bool(saved_as_emulation);
    response["catalog_root"] = serde_json::Value::String(catalog.root().display().to_string());
    HttpResponse::json(200, &response)
}

fn set_rule_indicates(selector: &str, request: &HttpRequest) -> Result<HttpResponse> {
    let payload: RuleIndicatesRequest = request.json()?;
    let Some(indicates) = normalize_indicates_relation(Some(RuleIndicatesRelation {
        stix_id: payload.stix_id,
        object_name: payload.object_name,
    })) else {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "indicates_requires_stix_id_and_object_name" }),
        );
    };
    if !is_valid_stix_id(&indicates.stix_id) {
        return HttpResponse::json(400, &serde_json::json!({ "error": "invalid_stix_id" }));
    }

    let (_, _, rules, _) = load_catalog_data()?;
    let entry = resolve_rule_selector(selector, &rules, None)?;
    let metadata = decode_rule_metadata_description(entry.description.clone());
    let mut indicates_list = metadata.indicates_list.clone();
    push_unique_indicates(&mut indicates_list, indicates);
    let observables = if metadata.observables.is_empty() {
        extract_rule_observable_types(&entry.rule)
    } else {
        metadata.observables.clone()
    };
    let storage_description = encode_rule_metadata_description(
        metadata.description.as_deref(),
        Some(&metadata.tlp),
        Some(&metadata.pap),
        metadata.ttp.as_deref(),
        None,
        Some(observables.as_slice()),
        Some(indicates_list.as_slice()),
    );

    let (saved, _) = persist_rule_entry(
        &entry.rule,
        Some(&entry.name),
        storage_description.as_deref(),
        metadata.ttp.as_deref(),
        entry.confidence,
    )?;
    HttpResponse::json(200, &rule_view(saved))
}

fn persist_rule_entry(
    rule: &str,
    name: Option<&str>,
    description: Option<&str>,
    ttp: Option<&str>,
    confidence: u8,
) -> Result<(CatalogRuleEntry, bool)> {
    let rules = vec![rule.to_string()];
    let empty_ability_targets: [AbilityTarget; 0] = [];
    let empty_output_targets: [String; 0] = [];
    let empty_export_formats: [ExportFormat; 0] = [];
    let empty_sigma_targets: [String; 0] = [];

    let saved_as_emulation = emulate::run(emulate::options(
        &empty_ability_targets,
        &rules,
        None,
        None,
        description,
        ttp,
        Some(confidence),
        ConversionMode::Strict,
        &empty_export_formats,
        false,
    ))
    .is_ok();

    if !saved_as_emulation {
        translate::run(translate::options(
            &empty_output_targets,
            &rules,
            None,
            None,
            description,
            ttp,
            Some(confidence),
            &empty_sigma_targets,
            ConversionMode::Strict,
            &empty_export_formats,
            false,
        ))?;
    }

    let (_, _, rules, _) = load_catalog_data()?;
    let saved = rules
        .iter()
        .find(|entry| entry.rule.trim() == rule.trim())
        .cloned()
        .ok_or_else(|| anyhow!("rule was processed but not found in catalog"))?;

    let mut effective_saved = saved;
    if let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) {
        if effective_saved.ability_id.is_some() {
            let ability_catalog = AbilityCatalog::from_default_root()?;
            edit_rule_entry(&ability_catalog, &effective_saved, Some(name), None, None)?;
            let (_, _, rules_after_edit, _) = load_catalog_data()?;
            if let Some(found) = rules_after_edit
                .into_iter()
                .find(|entry| entry.rule.trim() == rule.trim())
            {
                effective_saved = found;
            }
        }
    }

    let persisted_as_emulation = saved_as_emulation && effective_saved.ability_id.is_some();
    Ok((effective_saved, persisted_as_emulation))
}

fn rule_compatibility(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: RuleCompatibilityRequest = request.json()?;
    let confidence = payload.confidence.unwrap_or(70);
    let targets = available_detection_target_labels();
    let rows = evaluate_rule(TranslationRequest {
        rule: &payload.rule,
        targets: &targets,
        description: payload.description.as_deref(),
        sigma_targets: &payload.sigma_targets,
        mode: ConversionMode::Strict,
        rule_confidence: Some(confidence),
    })?
    .into_iter()
    .map(|row| RuleCompatibilityRow {
        severity: status_severity(row.runtime_status.as_str()).to_string(),
        target: row.target,
        runtime_status: row.runtime_status,
        conversion_confidence: row.conversion_confidence,
        rule_confidence: row.rule_confidence,
        cause: row.cause,
        summary: row.summary,
        notes: row.notes,
        output: row.output,
    })
    .collect::<Vec<_>>();

    HttpResponse::json(200, &serde_json::json!({ "entries": rows }))
}

fn export_rules_bundle(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: RuleBundleExportRequest = request.json()?;
    if payload.rule_ids.is_empty() {
        return HttpResponse::json(400, &json!({ "error": "rule_ids_required" }));
    }
    let (_, _, rules, _) = load_catalog_data()?;
    let mut selected = Vec::new();
    for selector in &payload.rule_ids {
        selected.push(resolve_rule_selector(selector, &rules, None)?);
    }
    let bundle = build_stix_bundle_from_rules(&selected)?;
    let pretty = serde_json::to_vec_pretty(&bundle)?;
    Ok(
        HttpResponse::text(200, "application/json; charset=utf-8", pretty).with_header(
            "Content-Disposition",
            "attachment; filename=\"spuc-rules-bundle.json\"",
        ),
    )
}

fn export_bundle_from_pattern(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: PatternBundleExportRequest = request.json()?;
    let rule = payload.rule.trim().to_string();
    if rule.is_empty() {
        return HttpResponse::json(400, &json!({ "error": "rule_required" }));
    }
    let description = encode_rule_metadata_description(
        payload.description.as_deref(),
        payload.tlp.as_deref(),
        payload.pap.as_deref(),
        None,
        None,
        None,
        Some(&payload.indicates_list),
    );
    let entry = CatalogRuleEntry {
        rule_id: new_stix_id("x-spuc-lab-rule"),
        ability_id: None,
        name: payload.name.unwrap_or_else(|| "Lab Rule".to_string()),
        description,
        ttp: None,
        confidence: payload.confidence.unwrap_or(70),
        emulable: false,
        rule,
        last_seen_utc: Utc::now().to_rfc3339(),
        commands: vec![],
        targets: vec![],
        statuses: vec![],
        target_statuses: BTreeMap::new(),
        emulation_statuses: BTreeMap::new(),
        activity_count: 0,
    };
    let bundle = build_stix_bundle_from_rules(&[entry])?;
    let pretty = serde_json::to_vec_pretty(&bundle)?;
    Ok(
        HttpResponse::text(200, "application/json; charset=utf-8", pretty).with_header(
            "Content-Disposition",
            "attachment; filename=\"spuc-lab-bundle.json\"",
        ),
    )
}

fn export_stix_objects_bundle(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: StixObjectsBundleExportRequest = request.json()?;
    if payload.stix_ids.is_empty() {
        return HttpResponse::json(400, &json!({ "error": "stix_ids_required" }));
    }
    let catalog_entries = load_stix_catalog();
    let selected: Vec<StixCatalogEntry> = payload
        .stix_ids
        .iter()
        .filter_map(|id| {
            catalog_entries
                .iter()
                .find(|e| e.stix_id.eq_ignore_ascii_case(id))
                .cloned()
        })
        .collect();
    if selected.is_empty() {
        return HttpResponse::json(400, &json!({ "error": "stix_objects_not_found" }));
    }
    let bundle = build_stix_bundle_from_objects(&selected)?;
    let pretty = serde_json::to_vec_pretty(&bundle)?;
    Ok(
        HttpResponse::text(200, "application/json; charset=utf-8", pretty).with_header(
            "Content-Disposition",
            "attachment; filename=\"spuc-stix-objects-bundle.json\"",
        ),
    )
}

fn build_stix_bundle_from_objects(selected: &[StixCatalogEntry]) -> Result<serde_json::Value> {
    let now = Utc::now().to_rfc3339();
    let mut objects = Vec::new();

    for entry in selected {
        let mut obj = json!({
            "type": entry.stix_type,
            "spec_version": "2.1",
            "id": entry.stix_id,
            "created": entry.created_at.as_deref().unwrap_or(&now),
            "modified": now,
            "name": entry.name,
        });
        if let Some(desc) = &entry.description {
            obj["description"] = json!(desc);
        }
        if let Some(tlp) = &entry.tlp {
            obj["tlp"] = json!(tlp);
        }
        if let Some(pap) = &entry.pap {
            obj["pap"] = json!(pap);
        }
        objects.push(obj);
    }

    let bundle = json!({
        "type": "bundle",
        "spec_version": "2.1",
        "id": new_stix_id("bundle"),
        "objects": objects,
        "created": now,
        "modified": now,
    });

    Ok(bundle)
}

fn build_stix_bundle_from_rules(selected: &[CatalogRuleEntry]) -> Result<serde_json::Value> {
    let now = Utc::now().to_rfc3339();
    let mut objects = Vec::new();
    let mut included_object_ids = HashSet::new();
    let targets = available_detection_target_labels();

    for entry in selected {
        let rule = rule_view(entry.clone());
        let source_indicator_id = new_stix_id("indicator");
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": source_indicator_id.clone(),
            "created": now,
            "modified": now,
            "name": rule.name,
            "description": rule.description,
            "pattern": rule.rule,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": rule.confidence,
            "labels": ["spuc", "source-rule"],
            "x_spuc_rule_id": rule.id,
        }));

        let evaluations = evaluate_rule(TranslationRequest {
            rule: &rule.rule,
            targets: &targets,
            description: rule.description.as_deref(),
            sigma_targets: &[],
            mode: ConversionMode::Strict,
            rule_confidence: Some(rule.confidence),
        })?;

        for row in evaluations {
            if row.runtime_status.eq_ignore_ascii_case("unsupported") {
                continue;
            }
            let Some(output) = row
                .output
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let coefficient = (row.conversion_confidence as f64 / 100.0).clamp(0.0, 1.0);
            let derived_confidence = ((rule.confidence as f64) * coefficient).round() as u8;
            let derived_id = new_stix_id("x-spuc-derived-rule");
            objects.push(json!({
                "type": "x-spuc-derived-rule",
                "spec_version": "2.1",
                "id": derived_id,
                "created": now,
                "modified": now,
                "name": format!("{} [{}]", rule.name, row.target),
                "confidence": derived_confidence,
                "x_spuc_target": row.target,
                "x_spuc_runtime_status": row.runtime_status,
                "x_spuc_conversion_confidence": row.conversion_confidence,
                "x_spuc_rule_text": output,
                "x_spuc_source_rule_id": rule.id,
            }));
            objects.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": new_stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "related-to",
                "source_ref": derived_id,
                "target_ref": source_indicator_id.clone(),
                "confidence": derived_confidence,
            }));
        }

        let mut indicates = rule.indicates_list.clone();
        if let Some(single) = rule.indicates.clone() {
            push_unique_indicates(&mut indicates, single);
        }
        for relation in indicates {
            let stix_id = relation.stix_id.trim().to_string();
            if stix_id.is_empty() {
                continue;
            }
            let key = stix_id.to_ascii_lowercase();
            if !included_object_ids.contains(&key) {
                if let Some(stub) = build_stix_stub_object(&stix_id, &relation.object_name, &now) {
                    objects.push(stub);
                    included_object_ids.insert(key.clone());
                }
            }
            objects.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": new_stix_id("relationship"),
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": source_indicator_id.clone(),
                "target_ref": stix_id,
                "confidence": rule.confidence,
            }));
        }
    }

    Ok(json!({
        "type": "bundle",
        "id": new_stix_id("bundle"),
        "objects": objects,
    }))
}

fn build_stix_stub_object(
    stix_id: &str,
    object_name: &str,
    now: &str,
) -> Option<serde_json::Value> {
    let stix_type = stix_id.split_once("--")?.0.trim().to_ascii_lowercase();
    if stix_type.is_empty() {
        return None;
    }
    let mut base = json!({
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "name": if object_name.trim().is_empty() { "unknown" } else { object_name.trim() },
    });
    if stix_type == "malware" {
        base["is_family"] = json!(false);
    }
    Some(base)
}

fn new_stix_id(object_type: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);

    let mut left = DefaultHasher::new();
    object_type.hash(&mut left);
    nanos.hash(&mut left);
    seq.hash(&mut left);
    let left = left.finish();

    let mut right = DefaultHasher::new();
    seq.hash(&mut right);
    object_type.hash(&mut right);
    (nanos as u64).hash(&mut right);
    let right = right.finish();

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&left.to_be_bytes());
    bytes[8..].copy_from_slice(&right.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{}--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        object_type,
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn list_abilities(request: &HttpRequest) -> Result<HttpResponse> {
    let catalog = AbilityCatalog::from_default_root()?;
    let query = request.query.get("q").map(String::as_str);
    let platform = request.query.get("platform").map(String::as_str);
    let classification = request
        .query
        .get("classification")
        .map(|value| value.to_ascii_lowercase());
    let destination = request
        .query
        .get("target")
        .map(|value| value.to_ascii_lowercase());
    let min_confidence = request
        .query
        .get("min_confidence")
        .and_then(|value| value.parse::<u8>().ok());

    let mut abilities = catalog.search_and_filter(query, platform)?;
    if let Some(classification) = classification.as_deref() {
        abilities.retain(|ability| {
            classification_label(&ability.classification)
                .to_ascii_lowercase()
                .eq(classification)
        });
    }
    if let Some(min_confidence) = min_confidence {
        abilities.retain(|ability| ability.confidence >= min_confidence);
    }
    if let Some(destination) = destination.as_deref() {
        abilities.retain(|ability| {
            infer_ability_export_targets(ability)
                .into_iter()
                .any(|target| target.eq_ignore_ascii_case(destination))
        });
    }

    let rows = abilities.into_iter().map(ability_view).collect::<Vec<_>>();
    HttpResponse::json(200, &rows)
}

fn create_dummy_ability(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: DummyAbilityCreateRequest = request.json()?;
    let platform = normalize_dummy_platform(payload.platform.as_deref());
    let kind = payload.kind.trim().to_ascii_lowercase();
    let ability = match kind.as_str() {
        "sleep" => {
            let seconds = payload.seconds.unwrap_or(5);
            if seconds == 0 {
                return HttpResponse::json(400, &json!({ "error": "dummy_seconds_invalid" }));
            }
            build_dummy_sleep_ability(seconds, &platform)
        }
        "label" => {
            let Some(label) = payload
                .label
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return HttpResponse::json(400, &json!({ "error": "dummy_label_required" }));
            };
            build_dummy_label_ability(label, &platform)
        }
        "custom_payload" => {
            let Some(name) = payload
                .name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return HttpResponse::json(
                    400,
                    &json!({ "error": "custom_payload_name_required" }),
                );
            };
            let Some(payload_body) = payload
                .payload
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                return HttpResponse::json(
                    400,
                    &json!({ "error": "custom_payload_body_required" }),
                );
            };
            let runner = normalize_custom_payload_runner(payload.runner.as_deref());
            let language = normalize_payload_language(payload.payload_language.as_deref(), &runner);
            build_custom_payload_ability(
                name,
                payload.description.as_deref(),
                &platform,
                &runner,
                &language,
                payload_body,
                payload.safety_notes.as_deref(),
            )
        }
        _ => {
            return HttpResponse::json(400, &json!({ "error": "dummy_kind_invalid" }));
        }
    };

    let catalog = AbilityCatalog::from_default_root()?;
    let (path, _) = catalog.upsert_by_source_pattern(&ability)?;
    let ability_id = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(&ability.id)
        .to_string();
    let created = catalog
        .get_by_id(&ability_id)?
        .ok_or_else(|| anyhow!("dummy_ability_persist_failed"))?;
    HttpResponse::json(200, &ability_view(created))
}

fn normalize_custom_payload_runner(raw: Option<&str>) -> String {
    let normalized = raw.unwrap_or("spuc-agent").trim().to_ascii_lowercase();
    match normalized.as_str() {
        "bash" | "powershell" | "python" | "javascript" | "rubber-ducky" | "hid" | "spuc-agent" => {
            if normalized == "hid" {
                "rubber-ducky".to_string()
            } else {
                normalized
            }
        }
        _ => "spuc-agent".to_string(),
    }
}

fn normalize_payload_language(raw: Option<&str>, runner: &str) -> String {
    let normalized = raw.unwrap_or(runner).trim().to_ascii_lowercase();
    match normalized.as_str() {
        "bash" | "powershell" | "python" | "javascript" | "rubber-ducky" | "hid" => {
            if normalized == "hid" {
                "rubber-ducky".to_string()
            } else {
                normalized
            }
        }
        _ => runner.to_string(),
    }
}

fn normalize_dummy_platform(raw: Option<&str>) -> String {
    let normalized = raw.unwrap_or("any").trim().to_ascii_lowercase();
    match normalized.as_str() {
        "linux" | "windows" | "macos" | "any" => normalized,
        _ => "any".to_string(),
    }
}

fn dummy_slug(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

fn custom_payload_hash(name: &str, platform: &str, runner: &str, payload: &str) -> String {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    platform.hash(&mut hasher);
    runner.hash(&mut hasher);
    payload.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn build_custom_payload_ability(
    name: &str,
    description: Option<&str>,
    platform: &str,
    runner: &str,
    payload_language: &str,
    payload: &str,
    safety_notes: Option<&str>,
) -> emu_ability::Ability {
    let trimmed_name = name.trim();
    let slug = dummy_slug(trimmed_name);
    let hash = custom_payload_hash(trimmed_name, platform, runner, payload);
    let payload_description = description
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("User-defined custom payload step for authorized defensive lab export.");
    let safety = safety_notes
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("SPUC does not execute this custom payload from the UI. Export and run only in controlled, authorized labs with telemetry enabled.");

    emu_ability::Ability {
        schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
        id: format!("abl-custom-payload-{platform}-{runner}-{slug}-{}", &hash[..8]),
        name: format!("Custom payload: {trimmed_name}"),
        description: payload_description.to_string(),
        ttp: None,
        supported_platforms: vec![platform.to_string()],
        requires: vec![emu_ability::AbilityRequirement {
            id: format!("cap.runner.{runner}"),
            description: format!("Authorized lab runner capable of handling {runner} payloads."),
        }],
        optional: vec![],
        agent_capabilities: vec![format!("cap.custom_payload.{runner}")],
        actions: vec![emu_ability::AbilityAction {
            id: "act-custom-payload-001".to_string(),
            title: format!("Custom {payload_language} payload"),
            action_type: "custom_payload".to_string(),
            observable: format!("x-spuc-custom-payload:{runner}"),
            operator: "CONTAINS".to_string(),
            value: payload.to_string(),
            safe_instructions: safety.to_string(),
        }],
        source_pattern: format!(
            "[x-spuc-custom-payload:name = '{}' AND x-spuc-custom-payload:runner = '{}' AND x-spuc-custom-payload:platform = '{}' AND x-spuc-custom-payload:hash = '{}']",
            trimmed_name.replace('\'', "\\'"),
            runner,
            platform,
            hash
        ),
        classification: emu_ability::AbilityClassification::CommandLineTrace,
        emulation_level: emu_ability::EmulationLevel::TraceSimulation,
        confidence: 80,
    }
}

fn build_dummy_sleep_ability(seconds: u64, platform: &str) -> emu_ability::Ability {
    emu_ability::Ability {
        schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
        id: format!("abl-dummy-sleep-{platform}-{seconds}s"),
        name: format!("SPUC dummy sleep {}s", seconds),
        description: format!(
            "Dummy ability to delay execution flow by {} second(s) in a defensive simulation.",
            seconds
        ),
        ttp: None,
        supported_platforms: vec![platform.to_string()],
        requires: vec![],
        optional: vec![],
        agent_capabilities: vec![],
        actions: vec![emu_ability::AbilityAction {
            id: "act-dummy-sleep-001".to_string(),
            title: "Delay execution".to_string(),
            action_type: "sleep_seconds".to_string(),
            observable: "x-spuc-dummy:sleep_seconds".to_string(),
            operator: "EQUALS".to_string(),
            value: seconds.to_string(),
            safe_instructions: format!(
                "Wait {} second(s) before the next ability to simulate paced execution.",
                seconds
            ),
        }],
        source_pattern: format!(
            "[x-spuc-dummy:type = 'sleep' AND x-spuc-dummy:seconds = '{}' AND x-spuc-dummy:platform = '{}']",
            seconds, platform
        ),
        classification: emu_ability::AbilityClassification::CommandLineTrace,
        emulation_level: emu_ability::EmulationLevel::TraceSimulation,
        confidence: 100,
    }
}

fn build_dummy_label_ability(label: &str, platform: &str) -> emu_ability::Ability {
    let trimmed = label.trim();
    let tag = dummy_slug(trimmed);
    let label_literal = trimmed.replace('\'', "\\'");
    emu_ability::Ability {
        schema_version: emu_ability::ABILITY_SCHEMA_VERSION.to_string(),
        id: format!("abl-dummy-label-{platform}-{tag}"),
        name: format!("SPUC dummy label {}", trimmed),
        description: format!(
            "Dummy ability to inject a controlled execution label: {}.",
            trimmed
        ),
        ttp: None,
        supported_platforms: vec![platform.to_string()],
        requires: vec![],
        optional: vec![],
        agent_capabilities: vec![],
        actions: vec![emu_ability::AbilityAction {
            id: "act-dummy-label-001".to_string(),
            title: "Emit execution label".to_string(),
            action_type: "execution_label".to_string(),
            observable: "x-spuc-dummy:label".to_string(),
            operator: "EQUALS".to_string(),
            value: trimmed.to_string(),
            safe_instructions: format!(
                "Emit label '{}' in logs/telemetry to delimit execution phases.",
                trimmed
            ),
        }],
        source_pattern: format!(
            "[x-spuc-dummy:type = 'label' AND x-spuc-dummy:label = '{}' AND x-spuc-dummy:platform = '{}']",
            label_literal, platform
        ),
        classification: emu_ability::AbilityClassification::CommandLineTrace,
        emulation_level: emu_ability::EmulationLevel::TraceSimulation,
        confidence: 100,
    }
}

fn show_ability(ability_id: &str) -> Result<HttpResponse> {
    let catalog = AbilityCatalog::from_default_root()?;
    let ability = catalog
        .get_by_id(ability_id)?
        .ok_or_else(|| anyhow!("ability '{}' not found", ability_id))?;
    HttpResponse::json(200, &ability_view(ability))
}

fn export_ability(ability_id: &str, target: Option<&str>) -> Result<HttpResponse> {
    let catalog = AbilityCatalog::from_default_root()?;
    let ability = catalog
        .get_by_id(ability_id)?
        .ok_or_else(|| anyhow!("ability '{}' not found", ability_id))?;
    let target = target
        .and_then(parse_ability_target)
        .unwrap_or(AbilityTarget::SpucAgent);
    let artifact = emu_export::export_ability(
        crate::commands::common::ability_target_to_export(target),
        &ability,
    )?;
    let extension = crate::commands::common::ability_target_extension(target);
    let file_name = ability_export_filename(&ability.id, target);
    let content_type = match extension {
        "json" => "application/json; charset=utf-8",
        "yaml" | "yml" => "application/yaml; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };
    Ok(
        HttpResponse::text(200, content_type, artifact.into_bytes()).with_header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", file_name),
        ),
    )
}

fn list_adversaries(request: &HttpRequest) -> Result<HttpResponse> {
    let (_, _, _, adversaries) = load_catalog_data()?;
    let query = AdversaryCatalogQuery {
        q: request.query.get("q").cloned(),
        platform: request.query.get("platform").cloned(),
        min_confidence: request
            .query
            .get("min_confidence")
            .and_then(|value| value.parse::<u8>().ok()),
        sort: request.query.get("sort").cloned(),
        page: request
            .query
            .get("page")
            .and_then(|value| value.parse::<usize>().ok()),
        page_size: request
            .query
            .get("page_size")
            .and_then(|value| value.parse::<usize>().ok()),
    };

    let mut entries = filter_adversary_entries(&adversaries, query.q.as_deref(), None);
    let platform_filters = parse_platform_filters(query.platform.as_deref());
    if !platform_filters.is_empty() {
        entries.retain(|entry| {
            entry
                .platforms
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .any(|platform| {
                    platform_filters
                        .iter()
                        .any(|needle| platform == *needle || platform.contains(needle))
                })
        });
    }
    if let Some(min_confidence) = query.min_confidence {
        entries.retain(|entry| entry.confidence >= min_confidence);
    }

    sort_adversaries(&mut entries, query.sort.as_deref());

    let total = entries.len();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(5, 500);
    let start = (page - 1) * page_size;
    let paged = entries
        .into_iter()
        .skip(start)
        .take(page_size)
        .map(adversary_view)
        .collect::<Vec<_>>();

    HttpResponse::json(
        200,
        &PagedResponse {
            total,
            page,
            page_size,
            entries: paged,
        },
    )
}

fn parse_platform_filters(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default()
}

fn show_adversary(selector: &str) -> Result<HttpResponse> {
    let (_, _, _, adversaries) = load_catalog_data()?;
    let entry = resolve_adversary_selector(selector, &adversaries, None)?;
    HttpResponse::json(200, &adversary_view(entry))
}

fn delete_adversary(selector: &str) -> Result<HttpResponse> {
    let (_, _, _, adversaries) = load_catalog_data()?;
    let entry = resolve_adversary_selector(selector, &adversaries, None)?;
    fs::remove_file(&entry.path)?;
    HttpResponse::json(
        200,
        &serde_json::json!({
            "ok": true,
            "id": entry.adversary_id,
        }),
    )
}

fn adversary_compatibility(selector: &str) -> Result<HttpResponse> {
    let (_, _, _, adversaries) = load_catalog_data()?;
    let adversary = resolve_adversary_selector(selector, &adversaries, None)?;
    let targets = [
        AbilityTarget::SpucAgent,
        AbilityTarget::Bash,
        AbilityTarget::Powershell,
        AbilityTarget::AtomicRedTeam,
        AbilityTarget::MitreCaldera,
    ];
    let mut compatible = Vec::new();
    let mut incompatible = Vec::new();

    for target in targets {
        let export_root = unique_temp_export_dir(&adversary.adversary_id, target)?;
        let result = plan::export_saved_adversary(
            &adversary.path,
            target,
            Some(export_root.as_path()),
            &[BuildOutput::Manifest],
        );
        let _ = fs::remove_dir_all(&export_root);
        match result {
            Ok(()) => {
                compatible.push(crate::commands::common::ability_target_label(target).to_string())
            }
            Err(error) => incompatible.push(AdversaryCompatibilityIssue {
                target: crate::commands::common::ability_target_label(target).to_string(),
                reason: error.to_string(),
            }),
        }
    }

    HttpResponse::json(
        200,
        &AdversaryCompatibilityResponse {
            id: adversary.adversary_id,
            compatible_targets: compatible,
            incompatible_targets: incompatible,
        },
    )
}

fn create_adversary(request: &HttpRequest, state: &WebState) -> Result<HttpResponse> {
    let payload: CreateAdversaryRequest = request.json()?;
    if payload.name.trim().is_empty() {
        return HttpResponse::json(400, &serde_json::json!({ "error": "name_required" }));
    }
    let confidence = payload.confidence.unwrap_or(70);
    let requested_target_platform = payload
        .target_platform
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    if confidence > 100 {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "confidence_out_of_range" }),
        );
    }

    let catalog = AbilityCatalog::from_default_root()?;
    let abilities = catalog.select_by_ids(&payload.ability_ids)?;
    let target_platform = requested_target_platform
        .clone()
        .or_else(|| first_supported_platform_from_abilities(&abilities));
    let has_platform_mismatch =
        requested_target_platform
            .as_deref()
            .is_some_and(|target_platform| {
                abilities.iter().any(|ability| {
                    !ability
                        .supported_platforms
                        .iter()
                        .any(|platform| platform.eq_ignore_ascii_case(target_platform))
                })
            });
    if has_platform_mismatch {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "abilities_platform_mismatch" }),
        );
    }
    let order = if payload.order.is_empty() {
        payload.ability_ids.clone()
    } else {
        payload.order.clone()
    };
    let description_plain = payload
        .description
        .clone()
        .unwrap_or_else(|| plan::INTRUSION_SET_DEFAULT_DESCRIPTION.to_string());
    let description_encoded = encode_rule_metadata_description(
        Some(&description_plain),
        payload.tlp.as_deref(),
        payload.pap.as_deref(),
        None,
        target_platform.as_deref(),
        None,
        None,
    )
    .unwrap_or(description_plain);

    let campaign = emu_campaign::build_campaign_ordered_with_confidence(
        emu_campaign::generate_intrusion_set_stix_id(),
        payload.name.clone(),
        description_encoded,
        &abilities,
        &order,
        confidence,
    );
    let saved_path = emu_campaign::save_campaign_yaml(&campaign, None)?;

    let token = state.register_download(DownloadEntry {
        path: saved_path.clone(),
        name: saved_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("campaign.yaml")
            .to_string(),
        content_type: "application/yaml; charset=utf-8".to_string(),
    });

    HttpResponse::json(
        200,
        &serde_json::json!({
            "id": catalog_adversary_id(&campaign.intrusion_set_id),
            "source_intrusion_set_id": campaign.intrusion_set_id,
            "name": campaign.name,
            "confidence": campaign.confidence,
            "steps": campaign.steps.len(),
            "platforms": campaign.steps.iter().map(|step| step.platform.clone()).collect::<Vec<_>>(),
            "description": campaign.description,
            "downloads": [download_link(saved_path.file_name().and_then(|name| name.to_str()).unwrap_or("campaign.yaml"), &token)]
        }),
    )
}

fn update_adversary(selector: &str, request: &HttpRequest) -> Result<HttpResponse> {
    let payload: UpdateAdversaryRequest = request.json()?;
    if payload.name.trim().is_empty() {
        return HttpResponse::json(400, &serde_json::json!({ "error": "name_required" }));
    }
    let confidence = payload.confidence.unwrap_or(70);
    if confidence > 100 {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "confidence_out_of_range" }),
        );
    }

    let (catalog, _, _, adversaries) = load_catalog_data()?;
    let entry = resolve_adversary_selector(selector, &adversaries, None)?;
    let existing = emu_campaign::load_campaign_yaml(&entry.path)?;
    let existing_meta = decode_rule_metadata_description(Some(existing.description.clone()));
    let requested_target_platform = payload
        .target_platform
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());
    let inherited_target_platform = existing_meta
        .target_platform
        .clone()
        .or_else(|| updated_platform_from_steps(&existing.steps));
    let enforced_target_platform = requested_target_platform
        .clone()
        .or_else(|| inherited_target_platform.clone());
    let ordered_ids = normalize_ability_order(&payload.ability_ids, &payload.order);
    let abilities = catalog.select_by_ids(&ordered_ids)?;
    let target_platform = enforced_target_platform
        .clone()
        .or_else(|| first_supported_platform_from_abilities(&abilities));
    let has_platform_mismatch =
        enforced_target_platform
            .as_deref()
            .is_some_and(|target_platform| {
                abilities.iter().any(|ability| {
                    !ability
                        .supported_platforms
                        .iter()
                        .any(|platform| platform.eq_ignore_ascii_case(target_platform))
                })
            });
    if has_platform_mismatch {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "abilities_platform_mismatch" }),
        );
    }
    let plain_description = payload
        .description
        .unwrap_or_else(|| existing_meta.description.clone().unwrap_or_default())
        .trim()
        .to_string();
    let encoded_description = encode_rule_metadata_description(
        Some(&plain_description),
        payload.tlp.as_deref().or(Some(existing_meta.tlp.as_str())),
        payload.pap.as_deref().or(Some(existing_meta.pap.as_str())),
        None,
        target_platform.as_deref(),
        None,
        None,
    )
    .unwrap_or(plain_description);
    let updated = emu_campaign::build_campaign_ordered_with_confidence(
        existing.intrusion_set_id,
        payload.name.trim().to_string(),
        encoded_description,
        &abilities,
        &ordered_ids,
        confidence,
    );
    emu_campaign::save_campaign_yaml(&updated, Some(&entry.path))?;

    let refreshed_entry = CatalogAdversaryEntry {
        adversary_id: entry.adversary_id.clone(),
        source_intrusion_set_id: updated.intrusion_set_id,
        path: entry.path.clone(),
        name: updated.name,
        confidence: updated.confidence,
        steps: updated.steps.len(),
        platforms: updated
            .steps
            .iter()
            .map(|step| step.platform.clone())
            .collect::<Vec<_>>(),
        description: updated.description,
        ability_refs: updated
            .steps
            .iter()
            .map(|step| step.ability_ref.clone())
            .collect::<Vec<_>>(),
    };
    HttpResponse::json(200, &adversary_view(refreshed_entry))
}

fn export_adversary(
    selector: &str,
    target: Option<&str>,
    state: &WebState,
) -> Result<HttpResponse> {
    let (_, _, _, adversaries) = load_catalog_data()?;
    let adversary = resolve_adversary_selector(selector, &adversaries, None)?;
    let requested = target.and_then(parse_ability_target);
    let is_full_export = target.is_none()
        || matches!(
            target
                .map(|value| value.trim().to_ascii_lowercase())
                .as_deref(),
            Some("all") | Some("full")
        );

    let targets = if is_full_export {
        vec![
            AbilityTarget::SpucAgent,
            AbilityTarget::Bash,
            AbilityTarget::Powershell,
            AbilityTarget::AtomicRedTeam,
            AbilityTarget::MitreCaldera,
        ]
    } else {
        vec![requested.unwrap_or(AbilityTarget::SpucAgent)]
    };

    let export_root = unique_temp_export_dir(
        &adversary.adversary_id,
        targets.first().copied().unwrap_or(AbilityTarget::SpucAgent),
    )?;
    let mut exported_any = false;
    for executor in &targets {
        let target_label = crate::commands::common::ability_target_label(*executor);
        let target_root = export_root.join(target_label);
        fs::create_dir_all(&target_root)?;
        if plan::export_saved_adversary(
            &adversary.path,
            *executor,
            Some(target_root.as_path()),
            &[BuildOutput::Manifest, BuildOutput::Artifact],
        )
        .is_ok()
        {
            let _ = generate_operational_runner_artifacts(*executor, &target_root);
            exported_any = true;
        }
    }

    if !exported_any {
        return Err(anyhow!(
            "adversary '{}' could not be exported for any requested target",
            adversary.adversary_id
        ));
    }

    let mut downloads = Vec::new();
    for file in list_files_recursive(&export_root)? {
        let relative_path = file
            .strip_prefix(&export_root)
            .ok()
            .and_then(|p| p.to_str());

        // Remove the executor folder prefix (first component) from the relative path
        let relative = if let Some(path_str) = relative_path {
            let parts: Vec<&str> = path_str.split('/').collect();
            if parts.len() > 1 {
                // Skip the first component (executor folder) and rejoin
                parts[1..].join("-")
            } else if parts.len() == 1 {
                parts[0].to_string()
            } else {
                "artifact".to_string()
            }
        } else {
            "artifact".to_string()
        };

        let token = state.register_download(DownloadEntry {
            content_type: guess_content_type(&file).to_string(),
            name: relative.clone(),
            path: file,
        });
        downloads.push(download_link(&relative, &token));
    }

    HttpResponse::json(
        200,
        &ExportResponse {
            id: adversary.adversary_id,
            target: if is_full_export {
                "full".to_string()
            } else {
                crate::commands::common::ability_target_label(
                    requested.unwrap_or(AbilityTarget::SpucAgent),
                )
                .to_string()
            },
            downloads,
        },
    )
}

fn verify_rule_request(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: RuleMutationRequest = request.json()?;
    let confidence = payload.confidence.unwrap_or(70);
    let syntax = verify::verify_rule(&payload.rule);
    let ability_preview = build_ability_from_rule(
        &payload.rule,
        None,
        payload.name.as_deref().or(Some("web-preview")),
        payload.description.as_deref(),
        payload.ttp.as_deref(),
        confidence,
    )
    .ok()
    .map(ability_view);

    HttpResponse::json(
        200,
        &VerifyResponse {
            syntax_ok: syntax.is_ok(),
            syntax_error: syntax.err().map(|error| error.to_string()),
            emulable: ability_preview.is_some(),
            ability_preview,
        },
    )
}

fn validate_tutorial_submission(request: &HttpRequest) -> Result<HttpResponse> {
    let payload: TutorialValidateRequest = request.json()?;
    let syntax = verify::verify_rule(&payload.rule);
    if let Err(error) = syntax {
        return HttpResponse::json(
            200,
            &TutorialValidateResponse {
                syntax_ok: false,
                solved: false,
                message: Some(error.to_string()),
                hint: learn::challenge_hint(&payload.challenge_id).map(str::to_string),
            },
        );
    }

    match learn::evaluate_challenge_submission(&payload.challenge_id, &payload.rule) {
        Ok(()) => HttpResponse::json(
            200,
            &TutorialValidateResponse {
                syntax_ok: true,
                solved: true,
                message: Some("Challenge completed successfully.".to_string()),
                hint: None,
            },
        ),
        Err(message) => HttpResponse::json(
            200,
            &TutorialValidateResponse {
                syntax_ok: true,
                solved: false,
                message: Some(message),
                hint: learn::challenge_hint(&payload.challenge_id).map(str::to_string),
            },
        ),
    }
}

fn download_file(token: &str, state: &WebState) -> Result<HttpResponse> {
    let entry = state
        .get_download(token)
        .ok_or_else(|| anyhow!("download token '{}' not found", token))?;
    let body = fs::read(&entry.path)?;
    Ok(
        HttpResponse::text(200, &entry.content_type, body).with_header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", entry.name),
        ),
    )
}

fn rule_view(entry: CatalogRuleEntry) -> RuleView {
    let metadata = decode_rule_metadata_description(entry.description);
    let observables = if metadata.observables.is_empty() {
        extract_rule_observable_types(&entry.rule)
    } else {
        metadata.observables.clone()
    };
    RuleView {
        id: entry.rule_id,
        ability_id: entry.ability_id,
        name: entry.name,
        description: metadata.description,
        ttp: metadata.ttp.or(entry.ttp),
        confidence: entry.confidence,
        tlp: metadata.tlp,
        pap: metadata.pap,
        indicates: metadata.indicates,
        indicates_list: metadata.indicates_list,
        emulable: entry.emulable,
        rule: entry.rule,
        last_seen_utc: entry.last_seen_utc,
        commands: entry.commands,
        targets: entry.targets,
        statuses: entry.statuses,
        observables,
        target_statuses: entry.target_statuses,
        emulation_statuses: entry.emulation_statuses,
        activity_count: entry.activity_count,
    }
}

fn normalize_tlp(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
        "TLP:CLEAR" | "CLEAR" | "WHITE" | "TLP:WHITE" => "TLP:CLEAR",
        "TLP:GREEN" | "GREEN" => "TLP:GREEN",
        "TLP:AMBER" | "AMBER" => "TLP:AMBER",
        "TLP:AMBER+STRICT" | "AMBER+STRICT" => "TLP:AMBER+STRICT",
        "TLP:RED" | "RED" => "TLP:RED",
        _ => "TLP:GREEN",
    }
}

fn normalize_pap(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
        "PAP:CLEAR" | "CLEAR" | "WHITE" | "PAP:WHITE" => "PAP:CLEAR",
        "PAP:GREEN" | "GREEN" => "PAP:GREEN",
        "PAP:AMBER" | "AMBER" | "PAP:AMBER+STRICT" | "AMBER+STRICT" => "PAP:AMBER",
        "PAP:RED" | "RED" => "PAP:RED",
        _ => "PAP:GREEN",
    }
}

fn normalize_indicates_relation(
    relation: Option<RuleIndicatesRelation>,
) -> Option<RuleIndicatesRelation> {
    let relation = relation?;
    let stix_id = relation.stix_id.trim();
    let object_name = relation.object_name.trim();
    if stix_id.is_empty() || object_name.is_empty() {
        return None;
    }
    Some(RuleIndicatesRelation {
        stix_id: stix_id.to_string(),
        object_name: object_name.to_string(),
    })
}

fn normalize_indicates_relations(
    relations: Vec<RuleIndicatesRelation>,
) -> Vec<RuleIndicatesRelation> {
    let mut out = Vec::new();
    for relation in relations {
        if let Some(normalized) = normalize_indicates_relation(Some(relation)) {
            push_unique_indicates(&mut out, normalized);
        }
    }
    out
}

fn normalize_observables(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in values {
        let value = raw.trim().to_ascii_lowercase();
        if value.is_empty() || !is_valid_stix_object_name(&value) {
            continue;
        }
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out.sort();
    out
}

fn push_unique_indicates(
    relations: &mut Vec<RuleIndicatesRelation>,
    relation: RuleIndicatesRelation,
) {
    let exists = relations.iter().any(|current| {
        current.stix_id.eq_ignore_ascii_case(&relation.stix_id)
            && current
                .object_name
                .eq_ignore_ascii_case(&relation.object_name)
    });
    if !exists {
        relations.push(relation);
    }
}

fn encode_rule_metadata_description(
    description: Option<&str>,
    tlp: Option<&str>,
    pap: Option<&str>,
    ttp: Option<&str>,
    target_platform: Option<&str>,
    observables: Option<&[String]>,
    indicates: Option<&[RuleIndicatesRelation]>,
) -> Option<String> {
    let cleaned = description.unwrap_or("").trim();
    let observable_list = observables
        .map(|items| normalize_observables(items.to_vec()))
        .unwrap_or_default();
    let indicates_list = indicates
        .map(|items| normalize_indicates_relations(items.to_vec()))
        .unwrap_or_default();
    let envelope = RuleMetadataEnvelope {
        tlp: normalize_tlp(tlp).to_string(),
        pap: normalize_pap(pap).to_string(),
        ttp: normalize_ttp(ttp),
        target_platform: target_platform
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase()),
        observables: observable_list,
        indicates: indicates_list.first().cloned(),
        indicates_list,
    };

    let metadata_prefix = match serde_json::to_vec(&envelope) {
        Ok(json) => format!("[SPUC_META_B64:{}]", URL_SAFE_NO_PAD.encode(json)),
        Err(_) => format!(
            "[TLP:{}|PAP:{}]",
            normalize_tlp(Some(&envelope.tlp)),
            normalize_pap(Some(&envelope.pap))
        ),
    };
    if cleaned.is_empty() {
        return Some(metadata_prefix);
    }
    Some(format!("{metadata_prefix} {cleaned}"))
}

fn decode_rule_metadata_description(description: Option<String>) -> DecodedRuleMetadata {
    let Some(raw) = description else {
        return DecodedRuleMetadata {
            description: None,
            tlp: normalize_tlp(None).to_string(),
            pap: normalize_pap(None).to_string(),
            ttp: None,
            target_platform: None,
            observables: Vec::new(),
            indicates: None,
            indicates_list: Vec::new(),
        };
    };
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("[SPUC_META_B64:") {
        if let Some((meta_b64, remainder)) = rest.split_once(']') {
            if let Ok(decoded) = URL_SAFE_NO_PAD.decode(meta_b64.as_bytes()) {
                if let Ok(metadata) = serde_json::from_slice::<RuleMetadataEnvelope>(&decoded) {
                    let desc = remainder.trim();
                    let mut indicates_list = normalize_indicates_relations(metadata.indicates_list);
                    if let Some(single) = normalize_indicates_relation(metadata.indicates.clone()) {
                        push_unique_indicates(&mut indicates_list, single);
                    }
                    return DecodedRuleMetadata {
                        description: if desc.is_empty() {
                            None
                        } else {
                            Some(desc.to_string())
                        },
                        tlp: normalize_tlp(Some(&metadata.tlp)).to_string(),
                        pap: normalize_pap(Some(&metadata.pap)).to_string(),
                        ttp: normalize_ttp(metadata.ttp.as_deref()),
                        target_platform: metadata
                            .target_platform
                            .map(|value| value.trim().to_ascii_lowercase())
                            .filter(|value| !value.is_empty()),
                        observables: normalize_observables(metadata.observables),
                        indicates: indicates_list.first().cloned(),
                        indicates_list,
                    };
                }
            }
        }
    }
    if let Some(rest) = trimmed.strip_prefix("[TLP:") {
        if let Some((meta, remainder)) = rest.split_once(']') {
            if let Some((tlp, pap_raw)) = meta.split_once("|PAP:") {
                let tlp = normalize_tlp(Some(tlp)).to_string();
                let pap = normalize_pap(Some(pap_raw)).to_string();
                let body = remainder.trim();
                let desc = if body.is_empty() {
                    None
                } else {
                    Some(body.to_string())
                };
                return DecodedRuleMetadata {
                    description: desc,
                    tlp,
                    pap,
                    ttp: None,
                    target_platform: None,
                    observables: Vec::new(),
                    indicates: None,
                    indicates_list: Vec::new(),
                };
            }
        }
    }
    DecodedRuleMetadata {
        description: Some(raw),
        tlp: normalize_tlp(None).to_string(),
        pap: normalize_pap(None).to_string(),
        ttp: None,
        target_platform: None,
        observables: Vec::new(),
        indicates: None,
        indicates_list: Vec::new(),
    }
}

fn normalize_ttp(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

fn extract_rule_observable_types(rule: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for token in rule.split(|ch: char| {
        !(ch.is_ascii_alphanumeric()
            || ch == '-'
            || ch == ':'
            || ch == '.'
            || ch == '_'
            || ch == '*'
            || ch == '['
            || ch == ']')
    }) {
        let Some((object_type, _field)) = token.split_once(':') else {
            continue;
        };
        let normalized = object_type
            .trim_matches(|ch| ch == '[' || ch == ']')
            .trim()
            .to_ascii_lowercase();
        if normalized.is_empty() || !is_valid_stix_object_name(&normalized) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out.sort();
    out
}

fn is_valid_stix_object_name(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.ends_with('-') {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn rule_observables(entry: &CatalogRuleEntry) -> Vec<String> {
    let metadata = decode_rule_metadata_description(entry.description.clone());
    if metadata.observables.is_empty() {
        extract_rule_observable_types(&entry.rule)
    } else {
        metadata.observables
    }
}

fn stix_object_type_from_id(value: &str) -> String {
    value
        .trim()
        .split_once("--")
        .map(|(object_type, _)| object_type.trim().to_ascii_lowercase())
        .unwrap_or_default()
}

fn collect_stix_objects_from_rules(rules: &[CatalogRuleEntry]) -> Vec<StixObjectView> {
    let mut by_stix_id: BTreeMap<String, StixObjectView> = BTreeMap::new();
    for entry in rules {
        let metadata = decode_rule_metadata_description(entry.description.clone());
        let mut relations = metadata.indicates_list;
        if let Some(single) = metadata.indicates {
            push_unique_indicates(&mut relations, single);
        }
        for relation in relations {
            let stix_id = relation.stix_id.trim().to_string();
            if stix_id.is_empty() {
                continue;
            }
            let stix_type = stix_object_type_from_id(&stix_id);
            let name = relation.object_name.trim().to_string();
            let key = stix_id.to_ascii_lowercase();
            by_stix_id
                .entry(key)
                .and_modify(|existing| {
                    if existing.name.is_empty() && !name.is_empty() {
                        existing.name = name.clone();
                    }
                    if existing.stix_type.is_empty() && !stix_type.is_empty() {
                        existing.stix_type = stix_type.clone();
                    }
                })
                .or_insert(StixObjectView {
                    stix_id,
                    stix_type,
                    name,
                    description: None,
                    tlp: None,
                    pap: None,
                    created_at: None,
                    first_seen: None,
                    source: Some("local".to_string()),
                    aliases: Vec::new(),
                    external_references: Vec::new(),
                });
        }
    }
    let mut entries: Vec<StixObjectView> = by_stix_id.into_values().collect();
    entries.sort_by(|a, b| {
        a.stix_type
            .cmp(&b.stix_type)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.stix_id.cmp(&b.stix_id))
    });
    entries
}

fn is_valid_stix_id(value: &str) -> bool {
    let trimmed = value.trim();
    let Some((object_type, uuid)) = trimmed.split_once("--") else {
        return false;
    };
    if !is_valid_stix_object_name(object_type) {
        return false;
    }
    let bytes = uuid.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, byte) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    if bytes[14] != b'4' {
        return false;
    }
    matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

fn ability_view(ability: emu_ability::Ability) -> AbilityView {
    let export_targets = infer_ability_export_targets(&ability);
    let export_files = ability_export_files(&ability.id, &export_targets);
    let export_artifacts = ability_export_artifacts(&ability, &export_targets);
    AbilityView {
        id: ability.id,
        name: ability.name,
        description: ability.description,
        ttp: ability.ttp,
        platforms: ability.supported_platforms,
        classification: classification_label(&ability.classification).to_string(),
        emulation_level: emulation_level_label(&ability.emulation_level).to_string(),
        confidence: ability.confidence,
        export_targets,
        export_files,
        export_artifacts,
        source_pattern: ability.source_pattern,
        agent_capabilities: ability.agent_capabilities,
        actions: ability
            .actions
            .into_iter()
            .map(|action| AbilityActionView {
                id: action.id,
                title: action.title,
                action_type: action.action_type,
                observable: action.observable,
                operator: action.operator,
                value: action.value,
                safe_instructions: action.safe_instructions,
            })
            .collect(),
    }
}

fn infer_ability_export_targets(ability: &emu_ability::Ability) -> Vec<String> {
    let candidates = [
        AbilityTarget::SpucAgent,
        AbilityTarget::Bash,
        AbilityTarget::Powershell,
        AbilityTarget::AtomicRedTeam,
        AbilityTarget::MitreCaldera,
    ];
    let mut targets = Vec::new();
    for target in candidates {
        let result = emu_export::export_ability(
            crate::commands::common::ability_target_to_export(target),
            ability,
        );
        if result.is_ok() {
            targets.push(crate::commands::common::ability_target_label(target).to_string());
        }
    }
    targets
}

fn ability_export_files(ability_id: &str, targets: &[String]) -> BTreeMap<String, String> {
    targets
        .iter()
        .filter_map(|target| {
            let parsed = parse_ability_target(target.as_str())?;
            Some((target.clone(), ability_export_filename(ability_id, parsed)))
        })
        .collect()
}

fn ability_export_artifacts(
    ability: &emu_ability::Ability,
    targets: &[String],
) -> BTreeMap<String, String> {
    targets
        .iter()
        .filter_map(|target| {
            let parsed = parse_ability_target(target.as_str())?;
            let content = emu_export::export_ability(
                crate::commands::common::ability_target_to_export(parsed),
                ability,
            )
            .ok()?;
            Some((target.clone(), content))
        })
        .collect()
}

fn ability_export_filename(ability_id: &str, target: AbilityTarget) -> String {
    format!(
        "{}-{}.{}",
        ability_id,
        crate::commands::common::ability_target_label(target).replace('-', "_"),
        crate::commands::common::ability_target_extension(target)
    )
}

fn infer_adversary_export_targets(entry: &CatalogAdversaryEntry) -> Vec<String> {
    let targets = [
        AbilityTarget::SpucAgent,
        AbilityTarget::Bash,
        AbilityTarget::Powershell,
        AbilityTarget::AtomicRedTeam,
        AbilityTarget::MitreCaldera,
    ];
    let mut compatible = Vec::new();
    for target in targets {
        let Ok(export_root) = unique_temp_export_dir(&entry.adversary_id, target) else {
            continue;
        };
        let result = plan::export_saved_adversary(
            &entry.path,
            target,
            Some(export_root.as_path()),
            &[BuildOutput::Manifest],
        );
        let _ = fs::remove_dir_all(&export_root);
        if result.is_ok() {
            compatible.push(crate::commands::common::ability_target_label(target).to_string());
        }
    }
    compatible
}

fn adversary_view(entry: CatalogAdversaryEntry) -> AdversaryView {
    let compatible_exports = infer_adversary_export_targets(&entry);
    let metadata = decode_rule_metadata_description(Some(entry.description.clone()));
    AdversaryView {
        id: entry.adversary_id,
        source_intrusion_set_id: entry.source_intrusion_set_id,
        name: entry.name,
        confidence: entry.confidence,
        tlp: metadata.tlp,
        pap: metadata.pap,
        target_platform: metadata.target_platform,
        steps: entry.steps,
        platforms: entry.platforms,
        description: metadata.description.unwrap_or_default(),
        ability_refs: entry.ability_refs,
        path: entry.path.display().to_string(),
        compatible_exports,
    }
}

fn updated_platform_from_steps(
    steps: &[spuc::emulation::campaign::CampaignStep],
) -> Option<String> {
    steps
        .first()
        .map(|step| step.platform.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn first_supported_platform_from_abilities(
    abilities: &[spuc::emulation::ability::Ability],
) -> Option<String> {
    abilities
        .iter()
        .flat_map(|ability| ability.supported_platforms.iter())
        .map(|platform| platform.trim().to_ascii_lowercase())
        .find(|platform| !platform.is_empty())
}

fn normalize_ability_order(ability_ids: &[String], order: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let allowed = ability_ids
        .iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .collect::<HashSet<_>>();
    for id in order {
        let trimmed = id.trim();
        if trimmed.is_empty() || !allowed.contains(trimmed) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    for id in ability_ids {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            out.push(trimmed.to_string());
        }
    }
    out
}

fn principal_view(principal: &Principal) -> PrincipalView {
    PrincipalView {
        user_id: principal.user_id.clone(),
        username: principal.username.clone(),
        display_name: principal.username.clone(),
        role: principal.role.as_str(),
    }
}

fn sort_rules(entries: &mut [CatalogRuleEntry], sort: Option<&str>) {
    match sort.unwrap_or("confidence_desc") {
        "confidence_asc" => entries.sort_by_key(|entry| entry.confidence),
        "name_asc" => entries.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        }),
        "name_desc" => entries.sort_by(|a, b| {
            b.name
                .to_ascii_lowercase()
                .cmp(&a.name.to_ascii_lowercase())
                .then_with(|| b.rule_id.cmp(&a.rule_id))
        }),
        _ => entries.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        }),
    }
}

fn sort_adversaries(entries: &mut [CatalogAdversaryEntry], sort: Option<&str>) {
    match sort.unwrap_or("confidence_desc") {
        "confidence_asc" => entries.sort_by_key(|entry| entry.confidence),
        "name_asc" => entries.sort_by(|a, b| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
                .then_with(|| a.adversary_id.cmp(&b.adversary_id))
        }),
        "name_desc" => entries.sort_by(|a, b| {
            b.name
                .to_ascii_lowercase()
                .cmp(&a.name.to_ascii_lowercase())
                .then_with(|| b.adversary_id.cmp(&a.adversary_id))
        }),
        "steps_asc" => entries.sort_by(|a, b| {
            a.steps
                .cmp(&b.steps)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.adversary_id.cmp(&b.adversary_id))
        }),
        "steps_desc" => entries.sort_by(|a, b| {
            b.steps
                .cmp(&a.steps)
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| a.adversary_id.cmp(&b.adversary_id))
        }),
        _ => entries.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| b.steps.cmp(&a.steps))
                .then_with(|| a.adversary_id.cmp(&b.adversary_id))
        }),
    }
}

fn top_counts(map: BTreeMap<String, usize>, limit: usize) -> Vec<NameCount> {
    let mut items = map
        .into_iter()
        .map(|(name, count)| NameCount { name, count })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| {
        b.count.cmp(&a.count).then_with(|| {
            a.name
                .to_ascii_lowercase()
                .cmp(&b.name.to_ascii_lowercase())
        })
    });
    items.truncate(limit);
    items
}

fn classification_label(value: &emu_ability::AbilityClassification) -> &'static str {
    match value {
        emu_ability::AbilityClassification::CommandLineTrace => "command_line_trace",
        emu_ability::AbilityClassification::ProcessExecutionTrace => "process_execution_trace",
        emu_ability::AbilityClassification::FileDrop => "file_drop",
    }
}

fn emulation_level_label(value: &emu_ability::EmulationLevel) -> &'static str {
    match value {
        emu_ability::EmulationLevel::TraceSimulation => "trace_simulation",
    }
}

fn status_bucket(status: Option<&str>) -> &'static str {
    match status.unwrap_or("").to_ascii_lowercase().as_str() {
        "exact" => "exact",
        "schema-dependent" | "backend-dependent" | "lossy" | "partial" => "lossy",
        _ => "unsupported",
    }
}

fn rule_status_bucket(entry: &CatalogRuleEntry) -> &'static str {
    if entry
        .statuses
        .iter()
        .any(|status| status_bucket(Some(status.as_str())) == "exact")
    {
        "exact"
    } else if entry
        .statuses
        .iter()
        .any(|status| status_bucket(Some(status.as_str())) == "lossy")
    {
        "lossy"
    } else {
        "unsupported"
    }
}

fn status_severity(status: &str) -> &'static str {
    match status_bucket(Some(status)) {
        "exact" => "success",
        "lossy" => "warning",
        _ => "error",
    }
}

fn learning_blocks() -> Vec<LearningBlock> {
    vec![
        LearningBlock {
            id: "intro-stix",
            title: "STIX Patterns fundamentals",
            summary: "Model observable behavior with clear entities and operators before translating rules.",
            example: "[process:command_line MATCHES '^.*powershell.*$']",
        },
        LearningBlock {
            id: "rule-quality",
            title: "Write precise detection rules",
            summary: "Start with narrow observables and explicit operators to reduce unsupported conversions.",
            example: "[file:name = 'invoice.exe' AND file:size > 0]",
        },
        LearningBlock {
            id: "lab-flow",
            title: "Use the rule laboratory",
            summary: "Validate syntax first, then inspect per-target compatibility and generated output side-by-side.",
            example: "verify -> compatibility -> save",
        },
        LearningBlock {
            id: "compatibility",
            title: "Interpret compatibility states",
            summary: "Green means exact mapping, amber indicates semantics drift, red means unsupported conversion.",
            example: "exact / lossy / unsupported",
        },
        LearningBlock {
            id: "adversary-build",
            title: "Build adversary scenarios",
            summary: "Compose adversaries from validated abilities and export artifacts for your selected executor.",
            example: "select abilities -> compile -> export",
        },
    ]
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn unique_temp_export_dir(label: &str, executor: AbilityTarget) -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "spuc-web-{}-{}-{}",
        slugify(label),
        crate::commands::common::ability_target_label(executor),
        Utc::now().timestamp_millis()
    ));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn list_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort_by(|a, b| {
        let an = a.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let bn = b.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        an.cmp(bn)
    });
    Ok(files)
}

fn list_files_recursive(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort_by(|a, b| {
        let an = a.to_string_lossy();
        let bn = b.to_string_lossy();
        an.cmp(&bn)
    });
    Ok(files)
}

fn guess_content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
    {
        "json" => "application/json; charset=utf-8",
        "yaml" | "yml" => "application/yaml; charset=utf-8",
        "sh" | "ps1" | "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('-');
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed.to_string()
    }
}

fn slugify_token(value: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed.to_string()
    }
}

fn operational_extension(executor: AbilityTarget) -> &'static str {
    match executor {
        AbilityTarget::Bash => "sh",
        AbilityTarget::Powershell => "ps1",
        AbilityTarget::AtomicRedTeam => "yaml",
        AbilityTarget::SpucAgent | AbilityTarget::MitreCaldera => "json",
    }
}

fn render_operational_runner_content(
    executor: AbilityTarget,
    manifest_name: &str,
    artifact_contents: &[(String, String)],
) -> String {
    match executor {
        AbilityTarget::Bash => {
            let mut lines = vec![
                "#!/usr/bin/env bash".to_string(),
                "set -euo pipefail".to_string(),
                "".to_string(),
                "# ANSI color codes for output".to_string(),
                "RED='\\033[0;31m'".to_string(),
                "GREEN='\\033[0;32m'".to_string(),
                "YELLOW='\\033[1;33m'".to_string(),
                "BLUE='\\033[0;34m'".to_string(),
                "NC='\\033[0m' # No Color".to_string(),
                "".to_string(),
                format!(
                    "echo \"${{BLUE}}[spuc] operational adversary runner: {manifest_name}${{NC}}\""
                ),
                format!(
                    "echo \"${{YELLOW}}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${{NC}}\""
                ),
                "".to_string(),
            ];

            for (idx, (name, content)) in artifact_contents.iter().enumerate() {
                let step_num = idx + 1;
                let total = artifact_contents.len();
                lines.push(format!("echo \"${{GREEN}}[Step {}/{}]${{NC}} ${{YELLOW}}Ejecutando ability: {}${{NC}}\"", step_num, total, name));
                lines.push("echo \"\"".to_string());
                lines.push(format!("# ========== Ability: {} ==========", name));

                // Remove shebang and duplicate set -euo pipefail from nested scripts
                let content_lines: Vec<&str> = content.lines().collect();
                for (line_idx, line) in content_lines.iter().enumerate() {
                    let trimmed = line.trim();
                    // Skip shebang lines
                    if trimmed.starts_with("#!") {
                        continue;
                    }
                    // Skip duplicate shebang-like lines
                    if line_idx == 0 && trimmed.starts_with("#!") {
                        continue;
                    }
                    // Skip set -euo pipefail if it's already defined in outer script
                    if trimmed == "set -euo pipefail" && line_idx < 5 {
                        continue;
                    }
                    lines.push(line.to_string());
                }

                lines.push(format!("# ========== End: {} ==========", name));
                lines.push("echo \"\"".to_string());
                lines.push(format!(
                    "echo \"${{GREEN}}✓ Completado: {}${{NC}}\"",
                    name.replace(".sh", "")
                ));
                lines.push(
                    "echo \"${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\""
                        .to_string(),
                );
                lines.push("".to_string());
            }

            lines.push("echo \"\"".to_string());
            lines.push(
                "echo \"${GREEN}[spuc] operational run completed successfully${NC}\"".to_string(),
            );
            lines.push(format!(
                "echo \"${{BLUE}}All {} abilities executed${{NC}}\"",
                artifact_contents.len()
            ));
            lines.join("\n") + "\n"
        }
        AbilityTarget::Powershell => {
            let mut lines = vec![
                "$ErrorActionPreference = \"Stop\"".to_string(),
                "".to_string(),
                "# ANSI color codes for output".to_string(),
                "$RED = '\\033[0;31m'".to_string(),
                "$GREEN = '\\033[0;32m'".to_string(),
                "$YELLOW = '\\033[1;33m'".to_string(),
                "$BLUE = '\\033[0;34m'".to_string(),
                "$NC = '\\033[0m' # No Color".to_string(),
                "".to_string(),
                format!("Write-Host \"${{BLUE}}[spuc] operational adversary runner: {manifest_name}${{NC}}\""),
                "Write-Host \"${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\""
                    .to_string(),
                "".to_string(),
            ];

            for (idx, (name, content)) in artifact_contents.iter().enumerate() {
                let step_num = idx + 1;
                let total = artifact_contents.len();
                lines.push(format!("Write-Host \"${{GREEN}}[Step {}/{}]${{NC}} ${{YELLOW}}Ejecutando ability: {}${{NC}}\"", step_num, total, name));
                lines.push("".to_string());
                lines.push(format!("# ========== Ability: {} ==========", name));

                // Remove ErrorActionPreference duplicate from nested scripts if present at top
                let content_lines: Vec<&str> = content.lines().collect();
                for (line_idx, line) in content_lines.iter().enumerate() {
                    let trimmed = line.trim();
                    // Skip ErrorActionPreference if it's in first few lines
                    if line_idx < 5 && trimmed.starts_with("$ErrorActionPreference") {
                        continue;
                    }
                    lines.push(line.to_string());
                }

                lines.push(format!("# ========== End: {} ==========", name));
                lines.push("".to_string());
                lines.push(format!(
                    "Write-Host \"${{GREEN}}✓ Completado: {}${{NC}}\"",
                    name.replace(".ps1", "")
                ));
                lines.push(
                    "Write-Host \"${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\""
                        .to_string(),
                );
                lines.push("".to_string());
            }

            lines.push("".to_string());
            lines.push(
                "Write-Host \"${GREEN}[spuc] operational run completed successfully${NC}\""
                    .to_string(),
            );
            lines.push(format!(
                "Write-Host \"${{BLUE}}All {} abilities executed${{NC}}\"",
                artifact_contents.len()
            ));
            lines.join("\n") + "\n"
        }
        AbilityTarget::AtomicRedTeam => {
            let names: Vec<&str> = artifact_contents.iter().map(|(n, _)| n.as_str()).collect();
            #[derive(Serialize)]
            struct OperationalYaml<'a> {
                schema_version: &'a str,
                executor: &'a str,
                manifest: &'a str,
                artifacts: Vec<&'a str>,
            }
            serde_yaml::to_string(&OperationalYaml {
                schema_version: "1.0",
                executor: "atomic-red-team",
                manifest: manifest_name,
                artifacts: names,
            })
            .unwrap_or_else(|_| "schema_version: \"1.0\"\n".to_string())
        }
        AbilityTarget::SpucAgent => {
            let names: Vec<&str> = artifact_contents.iter().map(|(n, _)| n.as_str()).collect();
            json!({
                "schema_version": "1.0",
                "executor": "spuc-agent",
                "manifest": manifest_name,
                "artifacts": names,
                "run_hint": "spuc-agent validate/run using this ordered artifact list and manifest"
            })
            .to_string()
        }
        AbilityTarget::MitreCaldera => {
            let names: Vec<&str> = artifact_contents.iter().map(|(n, _)| n.as_str()).collect();
            json!({
                "schema_version": "1.0",
                "executor": "mitre-caldera",
                "manifest": manifest_name,
                "artifacts": names,
                "run_hint": "import artifacts in order and execute operation with linked abilities"
            })
            .to_string()
        }
    }
}

fn generate_operational_runner_artifacts(
    executor: AbilityTarget,
    target_root: &Path,
) -> Result<()> {
    let manifest_files = list_files(target_root)?
        .into_iter()
        .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("yaml"))
        .collect::<Vec<_>>();
    if manifest_files.is_empty() {
        return Ok(());
    }

    let artifact_ext = crate::commands::common::ability_target_extension(executor);
    let op_ext = operational_extension(executor);

    for manifest in manifest_files {
        let stem = manifest
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("spuc-intrusion-set")
            .to_string();
        let manifest_name = manifest
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("campaign.yaml")
            .to_string();

        let campaign = emu_campaign::load_campaign_yaml(&manifest)?;
        let mut ordered_names = Vec::new();
        for step in &campaign.steps {
            let candidate = format!(
                "{stem}-{}.{}",
                slugify_token(&step.ability_ref),
                artifact_ext
            );
            if target_root.join(&candidate).is_file() {
                ordered_names.push(candidate);
            }
        }
        if ordered_names.is_empty() {
            ordered_names = list_files(target_root)?
                .into_iter()
                .filter_map(|path| {
                    let name = path.file_name()?.to_str()?.to_string();
                    if name.starts_with(&(stem.clone() + "-"))
                        && name.ends_with(&format!(".{artifact_ext}"))
                    {
                        Some(name)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
        }
        let mut dedup = BTreeSet::new();
        ordered_names.retain(|name| dedup.insert(name.clone()));
        if ordered_names.is_empty() {
            continue;
        }

        // Read content of each artifact file (needed for bash/powershell to inline the code)
        let mut artifact_contents = Vec::new();
        for name in &ordered_names {
            let path = target_root.join(name);
            match fs::read_to_string(&path) {
                Ok(content) => {
                    artifact_contents.push((name.clone(), content));
                }
                Err(_) => {
                    // If we can't read, skip this artifact
                    continue;
                }
            }
        }

        if artifact_contents.is_empty() {
            continue;
        }

        let runner_name = format!("{stem}.{op_ext}");
        let runner_path = target_root.join(runner_name);
        let content =
            render_operational_runner_content(executor, &manifest_name, &artifact_contents);
        fs::write(runner_path, content)?;
    }

    Ok(())
}

fn catalog_adversary_id(intrusion_set_id: &str) -> String {
    emu_campaign::catalog_adversary_id(intrusion_set_id)
}

fn download_link(name: &str, token: &str) -> DownloadLink {
    DownloadLink {
        name: name.to_string(),
        url: format!("/api/download/{token}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    fn with_test_config_dir<T>(tag: &str, run: impl FnOnce() -> T) -> T {
        static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("test lock poisoned");
        let dir =
            std::env::temp_dir().join(format!("spuc_web_api_test_{}_{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test config dir");
        unsafe {
            std::env::set_var("SPUC_CONFIG_DIR", &dir);
        }
        let result = run();
        unsafe {
            std::env::remove_var("SPUC_CONFIG_DIR");
        }
        let _ = fs::remove_dir_all(&dir);
        result
    }

    #[test]
    fn save_rule_accepts_valid_payload() {
        with_test_config_dir("save_rule_ok", || {
            let request = HttpRequest {
                method: "POST".to_string(),
                path: "/api/rules/save".to_string(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::json!({
                    "rule": "[process:name = 'cmd.exe']",
                    "name": "Save test rule",
                    "description": "Rule saved from API test",
                    "confidence": 70,
                    "tlp": "TLP:GREEN",
                    "pap": "PAP:GREEN"
                })
                .to_string()
                .into_bytes(),
            };

            let response = save_rule(&request).expect("save rule response");
            assert_eq!(response.status, 200);
        });
    }

    #[test]
    fn save_rule_rejects_confidence_out_of_range() {
        with_test_config_dir("save_rule_invalid_confidence", || {
            let request = HttpRequest {
                method: "POST".to_string(),
                path: "/api/rules/save".to_string(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::json!({
                    "rule": "[process:name = 'cmd.exe']",
                    "name": "Invalid confidence rule",
                    "confidence": 101
                })
                .to_string()
                .into_bytes(),
            };

            let response = save_rule(&request).expect("save rule response");
            assert_eq!(response.status, 400);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
            assert_eq!(body["error"], "confidence_out_of_range");
        });
    }

    #[test]
    fn status_severity_maps_expected_values() {
        assert_eq!(status_severity("exact"), "success");
        assert_eq!(status_severity("schema-dependent"), "warning");
        assert_eq!(status_severity("unsupported"), "error");
    }

    #[test]
    fn rule_bucket_prefers_exact() {
        let entry = CatalogRuleEntry {
            rule_id: "rule-1".to_string(),
            ability_id: None,
            name: "R".to_string(),
            description: None,
            ttp: None,
            confidence: 80,
            emulable: false,
            rule: "[process:name = 'cmd.exe']".to_string(),
            last_seen_utc: "2026-01-01T00:00:00Z".to_string(),
            commands: vec![],
            targets: vec![],
            statuses: vec!["unsupported".to_string(), "exact".to_string()],
            target_statuses: std::collections::BTreeMap::new(),
            emulation_statuses: std::collections::BTreeMap::new(),
            activity_count: 1,
        };
        assert_eq!(rule_status_bucket(&entry), "exact");
    }

    #[test]
    fn metadata_roundtrip_preserves_indicates() {
        let encoded = encode_rule_metadata_description(
            Some("Sample rule"),
            Some("TLP:AMBER+STRICT"),
            Some("PAP:RED"),
            None,
            None,
            Some(&["process".to_string(), "file".to_string()]),
            Some(&[RuleIndicatesRelation {
                stix_id: "indicator--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                object_name: "Suspicious object".to_string(),
            }]),
        );
        let decoded = decode_rule_metadata_description(encoded);
        assert_eq!(decoded.description, Some("Sample rule".to_string()));
        assert_eq!(decoded.tlp, "TLP:AMBER+STRICT");
        assert_eq!(decoded.pap, "PAP:RED");
        assert_eq!(
            decoded.observables,
            vec!["file".to_string(), "process".to_string()]
        );
        assert_eq!(
            decoded.indicates,
            Some(RuleIndicatesRelation {
                stix_id: "indicator--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                object_name: "Suspicious object".to_string(),
            })
        );
        assert_eq!(decoded.indicates_list.len(), 1);
    }

    #[test]
    fn ability_export_filename_matches_download_header_format() {
        assert_eq!(
            ability_export_filename("abl-123", AbilityTarget::SpucAgent),
            "abl-123-spuc_agent.json"
        );
        assert_eq!(
            ability_export_filename("abl-123", AbilityTarget::AtomicRedTeam),
            "abl-123-atomic_red_team.yaml"
        );
    }

    #[test]
    fn ability_export_files_includes_requested_targets() {
        let files =
            ability_export_files("abl-123", &["spuc-agent".to_string(), "bash".to_string()]);
        assert_eq!(
            files.get("spuc-agent"),
            Some(&"abl-123-spuc_agent.json".to_string())
        );
        assert_eq!(files.get("bash"), Some(&"abl-123-bash.sh".to_string()));
    }

    #[test]
    fn metadata_roundtrip_preserves_multiple_indicates() {
        let encoded = encode_rule_metadata_description(
            Some("Sample rule"),
            Some("TLP:GREEN"),
            Some("PAP:GREEN"),
            None,
            None,
            Some(&["artifact".to_string()]),
            Some(&[
                RuleIndicatesRelation {
                    stix_id: "indicator--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                    object_name: "Object A".to_string(),
                },
                RuleIndicatesRelation {
                    stix_id: "indicator--11111111-2222-4def-8abc-0123456789ab".to_string(),
                    object_name: "Object B".to_string(),
                },
            ]),
        );
        let decoded = decode_rule_metadata_description(encoded);
        assert_eq!(decoded.indicates_list.len(), 2);
        assert_eq!(decoded.observables, vec!["artifact".to_string()]);
        assert_eq!(
            decoded.indicates_list[0],
            RuleIndicatesRelation {
                stix_id: "indicator--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                object_name: "Object A".to_string(),
            }
        );
    }

    #[test]
    fn metadata_decoder_supports_legacy_prefix() {
        let decoded = decode_rule_metadata_description(Some(
            "[TLP:GREEN|PAP:AMBER] Legacy description".to_string(),
        ));
        assert_eq!(decoded.tlp, "TLP:GREEN");
        assert_eq!(decoded.pap, "PAP:AMBER");
        assert_eq!(decoded.description, Some("Legacy description".to_string()));
        assert!(decoded.observables.is_empty());
        assert_eq!(decoded.indicates, None);
    }

    #[test]
    fn stix_id_validation_accepts_and_rejects_expected_cases() {
        assert!(is_valid_stix_id(
            "indicator--01234567-89ab-4def-8abc-0123456789ab"
        ));
        assert!(!is_valid_stix_id(
            "indicator--01234567-89ab-5def-8abc-0123456789ab"
        ));
        assert!(!is_valid_stix_id(
            "indicator-01234567-89ab-4def-8abc-0123456789ab"
        ));
        assert!(!is_valid_stix_id(
            "Indicator--01234567-89ab-4def-8abc-0123456789ab"
        ));
    }

    #[test]
    fn stix_object_type_from_id_extracts_expected_value() {
        assert_eq!(
            stix_object_type_from_id("malware--01234567-89ab-4def-8abc-0123456789ab"),
            "malware"
        );
        assert_eq!(stix_object_type_from_id("invalid"), "");
    }

    #[test]
    fn collect_stix_objects_from_rules_merges_unique_relations() {
        let description = encode_rule_metadata_description(
            Some("Rule"),
            Some("TLP:GREEN"),
            Some("PAP:GREEN"),
            None,
            None,
            None,
            Some(&[
                RuleIndicatesRelation {
                    stix_id: "malware--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                    object_name: "Emotet".to_string(),
                },
                RuleIndicatesRelation {
                    stix_id: "indicator--11111111-2222-4def-8abc-0123456789ab".to_string(),
                    object_name: "IOC Alpha".to_string(),
                },
            ]),
        );
        let rules = vec![CatalogRuleEntry {
            rule_id: "rule-1".to_string(),
            ability_id: None,
            name: "Rule 1".to_string(),
            description,
            ttp: None,
            confidence: 70,
            emulable: false,
            rule: "[process:name = 'cmd.exe']".to_string(),
            last_seen_utc: "2026-01-01T00:00:00Z".to_string(),
            commands: vec![],
            targets: vec![],
            statuses: vec![],
            target_statuses: std::collections::BTreeMap::new(),
            emulation_statuses: std::collections::BTreeMap::new(),
            activity_count: 0,
        }];

        let objects = collect_stix_objects_from_rules(&rules);
        assert_eq!(objects.len(), 2);
        assert!(objects
            .iter()
            .any(|item| item.stix_id == "malware--01234567-89ab-4def-8abc-0123456789ab"));
        assert!(objects
            .iter()
            .any(|item| item.stix_id == "indicator--11111111-2222-4def-8abc-0123456789ab"));
    }

    #[test]
    fn normalize_ability_order_keeps_allowed_values_and_appends_missing() {
        let ability_ids = vec![
            "abl-1".to_string(),
            "abl-2".to_string(),
            "abl-3".to_string(),
        ];
        let order = vec![
            "abl-2".to_string(),
            "invalid".to_string(),
            "abl-2".to_string(),
            "abl-1".to_string(),
        ];
        let normalized = normalize_ability_order(&ability_ids, &order);
        assert_eq!(
            normalized,
            vec![
                "abl-2".to_string(),
                "abl-1".to_string(),
                "abl-3".to_string()
            ]
        );
    }

    #[test]
    fn extract_rule_observables_returns_unique_sorted_object_types() {
        let observables = extract_rule_observable_types(
            "[process:name = 'cmd.exe' AND file:name = 'a.exe' AND artifact:payload_bin = 'Zg==']",
        );
        assert_eq!(
            observables,
            vec![
                "artifact".to_string(),
                "file".to_string(),
                "process".to_string()
            ]
        );
    }

    #[test]
    fn extract_rule_observables_ignores_start_stop_timestamps() {
        let observables = extract_rule_observable_types(
            "[file:name = 'foo.dll'] START t'2016-06-01T00:00:00Z' STOP t'2016-07-01T00:00:00Z'",
        );
        assert_eq!(observables, vec!["file".to_string()]);
    }

    #[test]
    fn normalize_observables_deduplicates_and_rejects_invalid() {
        let values = vec![
            "Process".to_string(),
            "process".to_string(),
            "".to_string(),
            "bad/type".to_string(),
            "network-traffic".to_string(),
        ];
        let normalized = normalize_observables(values);
        assert_eq!(
            normalized,
            vec!["network-traffic".to_string(), "process".to_string()]
        );
    }

    #[test]
    fn push_unique_indicates_avoids_case_insensitive_duplicates() {
        let mut relations = vec![RuleIndicatesRelation {
            stix_id: "malware--01234567-89ab-4def-8abc-0123456789ab".to_string(),
            object_name: "Emotet".to_string(),
        }];
        push_unique_indicates(
            &mut relations,
            RuleIndicatesRelation {
                stix_id: "MALWARE--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                object_name: "emotet".to_string(),
            },
        );
        push_unique_indicates(
            &mut relations,
            RuleIndicatesRelation {
                stix_id: "malware--11111111-2222-4def-8abc-0123456789ab".to_string(),
                object_name: "Qakbot".to_string(),
            },
        );
        assert_eq!(relations.len(), 2);
    }

    #[test]
    fn parse_platform_filters_splits_csv_and_trims() {
        let parsed = parse_platform_filters(Some("linux, windows , macos,,"));
        assert_eq!(
            parsed,
            vec![
                "linux".to_string(),
                "windows".to_string(),
                "macos".to_string()
            ]
        );
        assert!(parse_platform_filters(None).is_empty());
    }

    #[test]
    fn adversary_view_decodes_tlp_pap_metadata() {
        let encoded = encode_rule_metadata_description(
            Some("Campaign description"),
            Some("TLP:AMBER"),
            Some("PAP:RED"),
            None,
            Some("linux"),
            None,
            None,
        )
        .expect("encoded adversary metadata");
        let entry = CatalogAdversaryEntry {
            adversary_id: "adversary-001".to_string(),
            source_intrusion_set_id: "intrusion-set-001".to_string(),
            path: std::env::temp_dir().join("spuc-adversary-test.yaml"),
            name: "Test adversary".to_string(),
            confidence: 73,
            steps: 2,
            platforms: vec!["linux".to_string()],
            description: encoded,
            ability_refs: vec!["ability-1".to_string()],
        };
        let view = adversary_view(entry);
        assert_eq!(view.tlp, "TLP:AMBER");
        assert_eq!(view.pap, "PAP:RED");
        assert_eq!(view.description, "Campaign description");
        assert_eq!(view.target_platform.as_deref(), Some("linux"));
    }

    #[test]
    fn metadata_roundtrip_normalizes_target_platform() {
        let encoded = encode_rule_metadata_description(
            Some("Campaign description"),
            Some("TLP:GREEN"),
            Some("PAP:GREEN"),
            None,
            Some(" Windows "),
            None,
            None,
        )
        .expect("encoded metadata");
        let decoded = decode_rule_metadata_description(Some(encoded));
        assert_eq!(decoded.target_platform.as_deref(), Some("windows"));
    }

    #[test]
    fn updated_platform_from_steps_uses_first_step_platform() {
        let steps = vec![spuc::emulation::campaign::CampaignStep {
            id: "step-1".to_string(),
            ability_ref: "ability-1".to_string(),
            platform: " Linux ".to_string(),
            after: None,
            delay_seconds: None,
            timeout_seconds: None,
        }];

        assert_eq!(
            updated_platform_from_steps(&steps).as_deref(),
            Some("linux")
        );
    }

    #[test]
    fn create_adversary_allows_initial_empty_plan_without_platform() {
        with_test_config_dir("adversary_empty_create", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let request = HttpRequest {
                method: "POST".to_string(),
                path: "/api/adversaries".to_string(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::json!({
                    "name": "Draft adversary",
                    "description": "Draft description",
                    "confidence": 70,
                    "target_platform": "",
                    "ability_ids": [],
                    "order": []
                })
                .to_string()
                .into_bytes(),
            };

            let response = create_adversary(&request, &state).expect("create adversary");
            assert_eq!(response.status, 200);
            let body: serde_json::Value =
                serde_json::from_slice(&response.body).expect("json response");
            assert!(body["id"].as_str().unwrap_or("").starts_with("adversary-"));
            assert_eq!(body["name"], "Draft adversary");
            assert_eq!(body["steps"], 0);
            assert_eq!(body["platforms"].as_array().expect("platforms").len(), 0);
        });
    }

    #[test]
    fn oauth_state_token_is_single_use_and_provider_bound() {
        with_test_config_dir("oauth_state", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let token = state.register_oauth_state("google");
            assert!(state.take_oauth_state("google", &token));
            assert!(!state.take_oauth_state("google", &token));

            let second = state.register_oauth_state("google");
            assert!(!state.take_oauth_state("github", &second));
        });
    }

    #[test]
    fn oauth_identity_maps_to_existing_user_or_falls_back_to_analyst() {
        with_test_config_dir("oauth_identity", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");

            let existing = OAuthIdentity {
                provider_id: "google",
                subject: "111".to_string(),
                username: "admin".to_string(),
                email: None,
            };
            let principal_existing = state.principal_from_oauth_identity(&existing);
            assert_eq!(principal_existing.role, Role::Admin);
            assert_eq!(principal_existing.username, "admin");

            let unknown = OAuthIdentity {
                provider_id: "github",
                subject: "abc-123".to_string(),
                username: "gh-user".to_string(),
                email: Some("gh-user@example.com".to_string()),
            };
            let principal_unknown = state.principal_from_oauth_identity(&unknown);
            assert_eq!(principal_unknown.role, Role::Analyst);
            assert!(principal_unknown.user_id.starts_with("oauth-github-"));
            assert_eq!(principal_unknown.username, "gh-user");
        });
    }

    #[test]
    fn user_settings_persist_display_name_and_preferences() {
        with_test_config_dir("user_settings", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            state
                .create_user(
                    "analyst",
                    "analyst-pass",
                    Role::Analyst,
                    Some("Blue Team".to_string()),
                )
                .expect("create analyst");
            let principal = state
                .authenticate_local("analyst", "analyst-pass")
                .expect("principal");

            assert!(state.can_change_password(&principal));

            let updated = state
                .update_current_user_settings(
                    &principal,
                    UserSettingsUpdateRequest {
                        display_name: Some("Blue Team Lead".to_string()),
                        locale: Some("es".to_string()),
                        theme: Some("light".to_string()),
                    },
                )
                .expect("update settings");

            assert_eq!(updated.display_name, "Blue Team Lead");
            assert_eq!(updated.locale, "es");
            assert_eq!(updated.theme, "light");

            let users = state.list_users();
            let analyst = users
                .iter()
                .find(|user| user.username == "analyst")
                .expect("analyst present");
            assert_eq!(analyst.display_name, "Blue Team Lead");
        });
    }

    #[test]
    fn opencti_settings_default_to_empty_local_source() {
        with_test_config_dir("opencti_empty_settings", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("admin principal");

            let view = state.current_opencti_settings_view(&principal);
            assert!(!view.opencti_enabled);
            assert_eq!(view.opencti_endpoint, None);
            assert!(!view.opencti_api_key_set);
            assert_eq!(view.stix_catalog_source, "local");
            assert_eq!(view.effective_source, "local");
        });
    }

    #[test]
    fn opencti_failure_falls_back_to_local_catalog() {
        with_test_config_dir("opencti_local_fallback", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("admin principal");
            save_stix_catalog(&[StixCatalogEntry {
                stix_id: "malware--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                stix_type: "malware".to_string(),
                name: "Emotet".to_string(),
                description: Some("Local fallback fixture".to_string()),
                tlp: Some("TLP:GREEN".to_string()),
                pap: Some("PAP:GREEN".to_string()),
                created_at: Some("2026-01-01".to_string()),
                first_seen: Some("2026-01-01".to_string()),
            }])
            .expect("save local stix object");
            state
                .update_current_opencti_settings(
                    &principal,
                    UserOpenCtiSettingsUpdateRequest {
                        opencti_enabled: Some(true),
                        opencti_endpoint: Some("http://127.0.0.1:9/graphql".to_string()),
                        opencti_api_key: Some("test-key".to_string()),
                        stix_catalog_source: Some(StixCatalogSource::OpenCti),
                    },
                )
                .expect("update OpenCTI settings");

            let mut query = HashMap::new();
            query.insert("q".to_string(), "emotet".to_string());
            let request = HttpRequest {
                method: "GET".to_string(),
                path: "/api/stix-objects".to_string(),
                query,
                headers: HashMap::new(),
                body: Vec::new(),
            };
            let response =
                list_stix_objects(&request, &principal, &state).expect("list stix objects");
            assert_eq!(response.status, 200);
            let body: serde_json::Value =
                serde_json::from_slice(&response.body).expect("json response");
            assert_eq!(body["source"], "opencti");
            assert_eq!(body["effective_source"], "local");
            assert_eq!(body["fallback_used"], true);
            assert_eq!(body["entries"][0]["name"], "Emotet");
        });
    }

    #[test]
    fn bootstrap_admin_and_no_login_disable_self_password_rotation() {
        with_test_config_dir("password_policy", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let admin = state
                .authenticate_local("admin", "secret-pass")
                .expect("admin principal");
            assert!(!state.can_change_password(&admin));
            assert!(state
                .change_user_password(&admin, &admin.user_id, Some("secret-pass"), "new-secret")
                .is_err());

            let no_login_state = WebState::new("admin", "secret-pass", false, true).expect("state");
            let local_admin = no_login_state.bootstrap_admin.clone();
            assert!(!no_login_state.can_change_password(&local_admin));
            assert!(no_login_state
                .change_user_password(&local_admin, &local_admin.user_id, None, "other-secret")
                .is_err());
        });
    }

    #[test]
    fn new_stix_id_generates_valid_v4_shape() {
        let id = new_stix_id("indicator");
        assert!(id.starts_with("indicator--"));
        assert!(is_valid_stix_id(&id));
    }

    #[test]
    fn bundle_builder_adds_related_and_indicates_relationships() {
        let description = encode_rule_metadata_description(
            Some("desc"),
            Some("TLP:GREEN"),
            Some("PAP:GREEN"),
            None,
            None,
            None,
            Some(&[RuleIndicatesRelation {
                stix_id: "malware--01234567-89ab-4def-8abc-0123456789ab".to_string(),
                object_name: "Test malware".to_string(),
            }]),
        );
        let entry = CatalogRuleEntry {
            rule_id: "rule-1".to_string(),
            ability_id: None,
            name: "Rule 1".to_string(),
            description,
            ttp: None,
            confidence: 80,
            emulable: false,
            rule: "[process:name = 'cmd.exe']".to_string(),
            last_seen_utc: "2026-01-01T00:00:00Z".to_string(),
            commands: vec![],
            targets: vec![],
            statuses: vec![],
            target_statuses: BTreeMap::new(),
            emulation_statuses: BTreeMap::new(),
            activity_count: 0,
        };
        let bundle = build_stix_bundle_from_rules(&[entry]).expect("bundle should build");
        let objects = bundle["objects"].as_array().expect("objects array");
        assert!(objects.iter().any(|obj| {
            obj["type"] == "relationship" && obj["relationship_type"] == "related-to"
        }));
        assert!(objects.iter().any(|obj| {
            obj["type"] == "relationship" && obj["relationship_type"] == "indicates"
        }));
    }

    #[test]
    fn dummy_sleep_builder_creates_expected_shape() {
        let ability = build_dummy_sleep_ability(7, "linux");
        assert_eq!(ability.id, "abl-dummy-sleep-linux-7s");
        assert_eq!(ability.actions.len(), 1);
        assert_eq!(ability.actions[0].action_type, "sleep_seconds");
        assert_eq!(ability.supported_platforms, vec!["linux".to_string()]);
    }

    #[test]
    fn dummy_label_builder_slugifies_and_escapes() {
        let ability = build_dummy_label_ability("Phase A's", "windows");
        assert_eq!(ability.id, "abl-dummy-label-windows-phase_a_s");
        assert!(ability.source_pattern.contains("Phase A\\'s"));
        assert_eq!(ability.actions[0].action_type, "execution_label");
    }

    #[test]
    fn custom_payload_builder_is_safe_metadata_only() {
        let ability = build_custom_payload_ability(
            "Telemetry probe",
            Some("Validate a runner payload"),
            "linux",
            "bash",
            "bash",
            "echo spuc",
            None,
        );
        assert!(ability
            .id
            .starts_with("abl-custom-payload-linux-bash-telemetry_probe-"));
        assert_eq!(ability.supported_platforms, vec!["linux".to_string()]);
        assert_eq!(ability.actions[0].action_type, "custom_payload");
        assert_eq!(ability.actions[0].observable, "x-spuc-custom-payload:bash");
        assert_eq!(ability.actions[0].value, "echo spuc");
        assert!(ability.actions[0]
            .safe_instructions
            .contains("SPUC does not execute"));
        assert!(ability
            .agent_capabilities
            .contains(&"cap.custom_payload.bash".to_string()));
    }

    #[test]
    fn normalize_dummy_platform_only_accepts_known_values() {
        assert_eq!(normalize_dummy_platform(Some("linux")), "linux");
        assert_eq!(normalize_dummy_platform(Some("windows")), "windows");
        assert_eq!(normalize_dummy_platform(Some("macos")), "macos");
        assert_eq!(normalize_dummy_platform(Some("bad-os")), "any");
        assert_eq!(normalize_dummy_platform(None), "any");
    }

    #[test]
    fn operational_runner_content_for_bash_sequences_artifacts() {
        let artifact_contents = vec![
            ("one.sh".to_string(), "echo 'Running one'\n".to_string()),
            ("two.sh".to_string(), "echo 'Running two'\n".to_string()),
        ];
        let content = render_operational_runner_content(
            AbilityTarget::Bash,
            "campaign.yaml",
            &artifact_contents,
        );
        assert!(content.contains("#!/usr/bin/env bash"));
        assert!(content.contains("Ejecutando ability: one.sh"));
        assert!(content.contains("Ejecutando ability: two.sh"));
        assert!(content.contains("echo 'Running one'"));
        assert!(content.contains("echo 'Running two'"));
    }

    #[test]
    fn operational_runner_content_for_spuc_agent_is_json() {
        let artifact_contents = vec![("a.json".to_string(), "{}".to_string())];
        let content = render_operational_runner_content(
            AbilityTarget::SpucAgent,
            "campaign.yaml",
            &artifact_contents,
        );
        let value: serde_json::Value = serde_json::from_str(&content).expect("json");
        assert_eq!(value["executor"], "spuc-agent");
        assert_eq!(value["manifest"], "campaign.yaml");
        assert!(value["artifacts"].is_array());
    }

    #[test]
    fn user_can_create_and_list_multiple_api_tokens() {
        with_test_config_dir("api_tokens_multi", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");

            state
                .create_user_api_token(&principal, "Token A", None)
                .expect("token a");
            state
                .create_user_api_token(&principal, "Token B", None)
                .expect("token b");

            let entries = state.list_user_api_tokens(&principal);
            assert_eq!(entries.len(), 2);
        });
    }

    #[test]
    fn invalid_and_revoked_tokens_are_rejected() {
        with_test_config_dir("api_tokens_reject", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");

            let (entry, token_value) = state
                .create_user_api_token(&principal, "Token", None)
                .expect("token create");
            assert!(state
                .resolve_principal_from_api_token(token_value.as_str())
                .is_some());
            assert!(state
                .resolve_principal_from_api_token("invalid-token")
                .is_none());

            state
                .revoke_user_api_token(&principal, entry.id.as_str())
                .expect("revoke token");
            assert!(state
                .resolve_principal_from_api_token(token_value.as_str())
                .is_none());
        });
    }

    #[test]
    fn token_auth_updates_last_used_at() {
        with_test_config_dir("api_tokens_last_used", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");

            let (created, token_value) = state
                .create_user_api_token(&principal, "Token", None)
                .expect("token create");
            let before = state
                .list_user_api_tokens(&principal)
                .into_iter()
                .find(|entry| entry.id == created.id)
                .expect("entry")
                .last_used_at;
            assert!(before.is_none());

            assert!(state
                .resolve_principal_from_api_token(token_value.as_str())
                .is_some());
            let after = state
                .list_user_api_tokens(&principal)
                .into_iter()
                .find(|entry| entry.id == created.id)
                .expect("entry")
                .last_used_at;
            assert!(after.is_some());
        });
    }

    #[test]
    fn user_can_delete_revoked_token_record() {
        with_test_config_dir("api_tokens_delete_revoked", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");

            let (created, _) = state
                .create_user_api_token(&principal, "Old token", None)
                .expect("token create");
            state
                .revoke_user_api_token(&principal, created.id.as_str())
                .expect("token revoke");

            let deleted = state
                .delete_user_api_token(&principal, created.id.as_str())
                .expect("token delete");
            assert!(deleted);

            let entries = state.list_user_api_tokens(&principal);
            assert!(entries.iter().all(|entry| entry.id != created.id));
        });
    }

    #[test]
    fn env_admin_api_token_bootstraps_admin_api_access() {
        with_test_config_dir("api_tokens_env_bootstrap", || {
            unsafe {
                std::env::set_var(ENV_ADMIN_API_TOKEN, "spuc_pat_env_test_token");
                std::env::set_var(ENV_ADMIN_API_TOKEN_NAME, "Container connector token");
            }
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .resolve_principal_from_api_token("spuc_pat_env_test_token")
                .expect("env token should resolve");
            assert_eq!(principal.username, "admin");

            let entries = state.list_user_api_tokens(&principal);
            let bootstrap = entries
                .iter()
                .find(|entry| entry.id == BOOTSTRAP_ADMIN_API_TOKEN_ID)
                .expect("bootstrap token entry");
            assert_eq!(bootstrap.name, "Container connector token");
            assert!(bootstrap.last_used_at.is_some());
            unsafe {
                std::env::remove_var(ENV_ADMIN_API_TOKEN);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_NAME);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_EXPIRES_AT);
            }
        });
    }

    #[test]
    fn env_admin_api_token_updates_existing_bootstrap_record() {
        with_test_config_dir("api_tokens_env_update", || {
            unsafe {
                std::env::set_var(ENV_ADMIN_API_TOKEN, "first-token");
            }
            let first = WebState::new("admin", "secret-pass", false, false).expect("state");
            assert!(first
                .resolve_principal_from_api_token("first-token")
                .is_some());

            unsafe {
                std::env::set_var(ENV_ADMIN_API_TOKEN, "second-token");
                std::env::set_var(ENV_ADMIN_API_TOKEN_NAME, "Rotated env token");
            }
            let second = WebState::new("admin", "secret-pass", false, false).expect("state");
            assert!(second
                .resolve_principal_from_api_token("first-token")
                .is_none());
            let principal = second
                .resolve_principal_from_api_token("second-token")
                .expect("rotated token should resolve");
            let entries = second.list_user_api_tokens(&principal);
            let bootstrap_entries = entries
                .iter()
                .filter(|entry| entry.id == BOOTSTRAP_ADMIN_API_TOKEN_ID)
                .count();
            assert_eq!(bootstrap_entries, 1);
            assert!(entries
                .iter()
                .any(|entry| entry.id == BOOTSTRAP_ADMIN_API_TOKEN_ID
                    && entry.name == "Rotated env token"));
            unsafe {
                std::env::remove_var(ENV_ADMIN_API_TOKEN);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_NAME);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_EXPIRES_AT);
            }
        });
    }

    #[test]
    fn missing_env_admin_api_token_revokes_bootstrap_record() {
        with_test_config_dir("api_tokens_env_revoke", || {
            unsafe {
                std::env::set_var(ENV_ADMIN_API_TOKEN, "temporary-token");
            }
            let first = WebState::new("admin", "secret-pass", false, false).expect("state");
            assert!(first
                .resolve_principal_from_api_token("temporary-token")
                .is_some());

            unsafe {
                std::env::remove_var(ENV_ADMIN_API_TOKEN);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_NAME);
                std::env::remove_var(ENV_ADMIN_API_TOKEN_EXPIRES_AT);
            }
            let second = WebState::new("admin", "secret-pass", false, false).expect("state");
            assert!(second
                .resolve_principal_from_api_token("temporary-token")
                .is_none());
        });
    }

    #[test]
    fn translate_endpoint_requires_and_honors_api_tokens() {
        with_test_config_dir("translate_token_auth", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");
            let (entry, token_value) = state
                .create_user_api_token(&principal, "Translate token", None)
                .expect("token create");

            let missing = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: HashMap::new(),
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe']"
                })
                .to_string()
                .into_bytes(),
            };
            let missing_resp = route(missing, &state).expect("missing token response");
            assert_eq!(missing_resp.status, 401);

            let mut ok_headers = HashMap::new();
            ok_headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", token_value),
            );
            let valid = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: ok_headers,
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe']",
                    "targets": ["sigma"]
                })
                .to_string()
                .into_bytes(),
            };
            let valid_resp = route(valid, &state).expect("valid translate response");
            assert_eq!(valid_resp.status, 200);
            let valid_body: serde_json::Value =
                serde_json::from_slice(&valid_resp.body).expect("json");
            assert_eq!(valid_body["status"], "success");
            let first = valid_body["results"][0].clone();
            assert!(first.get("stix").is_some());
            assert!(first["stix"]["confidence"].as_u64().is_some());
            assert!(first["stix"]["description"].is_string());
            assert!(first["stix"]["comments"].is_array());

            let default_targets = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert(
                        "authorization".to_string(),
                        format!("Bearer {}", token_value),
                    );
                    headers
                },
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe']"
                })
                .to_string()
                .into_bytes(),
            };
            let default_targets_resp =
                route(default_targets, &state).expect("default targets translate response");
            assert_eq!(default_targets_resp.status, 200);
            let default_targets_body: serde_json::Value =
                serde_json::from_slice(&default_targets_resp.body).expect("json");
            assert_eq!(default_targets_body["status"], "success");

            state
                .revoke_user_api_token(&principal, entry.id.as_str())
                .expect("revoke token");
            let mut revoked_headers = HashMap::new();
            revoked_headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", token_value),
            );
            let revoked = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: revoked_headers,
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe']"
                })
                .to_string()
                .into_bytes(),
            };
            let revoked_resp = route(revoked, &state).expect("revoked token response");
            assert_eq!(revoked_resp.status, 401);
        });
    }

    #[test]
    fn translate_endpoint_reports_invalid_pattern_and_empty_results() {
        with_test_config_dir("translate_endpoint_errors", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");
            let (_entry, token_value) = state
                .create_user_api_token(&principal, "Translate token", None)
                .expect("token create");

            let mut headers = HashMap::new();
            headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", token_value),
            );
            let invalid = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: headers.clone(),
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe'"
                })
                .to_string()
                .into_bytes(),
            };
            let invalid_resp = route(invalid, &state).expect("invalid pattern response");
            assert_eq!(invalid_resp.status, 200);
            let invalid_body: serde_json::Value =
                serde_json::from_slice(&invalid_resp.body).expect("json");
            assert_eq!(invalid_body["status"], "error");

            let empty = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers,
                body: serde_json::json!({
                    "type": "indicator",
                    "pattern_type": "stix",
                    "pattern": "[process:name = 'cmd.exe']",
                    "targets": ["unknown-only"]
                })
                .to_string()
                .into_bytes(),
            };
            let empty_resp = route(empty, &state).expect("empty result response");
            assert_eq!(empty_resp.status, 200);
            let empty_body: serde_json::Value =
                serde_json::from_slice(&empty_resp.body).expect("json");
            assert_eq!(empty_body["status"], "error");
            assert_eq!(empty_body["results"].as_array().map(|v| v.len()), Some(0));

            let malformed = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern".to_string(),
                query: HashMap::new(),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert(
                        "authorization".to_string(),
                        format!("Bearer {}", token_value),
                    );
                    headers
                },
                body: br#"{ \"type\": \"indicator\", \"pattern_type\": \"stix\" }"#.to_vec(),
            };
            let malformed_resp = route(malformed, &state).expect("malformed payload response");
            assert_eq!(malformed_resp.status, 400);
            let malformed_body: serde_json::Value =
                serde_json::from_slice(&malformed_resp.body).expect("json");
            assert_eq!(malformed_body["error"], "invalid_request_payload");
        });
    }

    #[test]
    fn translate_stix_bundle_endpoint_returns_indicators_and_derived_from_relationships() {
        with_test_config_dir("translate_bundle_endpoint", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");
            let (_entry, token_value) = state
                .create_user_api_token(&principal, "Translate bundle token", None)
                .expect("token create");
            let mut headers = HashMap::new();
            headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", token_value),
            );
            let request = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-bundle".to_string(),
                query: HashMap::new(),
                headers,
                body: serde_json::json!({
                    "indicator": {
                        "type": "indicator",
                        "id": "indicator--11111111-1111-4111-8111-111111111111",
                        "name": "Original indicator",
                        "description": "Base description",
                        "pattern_type": "stix",
                        "pattern": "[process:name = 'cmd.exe']",
                        "confidence": 77
                    },
                    "targets": ["sigma"]
                })
                .to_string()
                .into_bytes(),
            };
            let response = route(request, &state).expect("bundle response");
            assert_eq!(response.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
            assert_eq!(body["type"], "bundle");
            let objects = body["objects"].as_array().expect("objects array");
            assert!(objects.iter().any(|obj| obj["type"] == "indicator"
                && obj["id"] == "indicator--11111111-1111-4111-8111-111111111111"));
            let derived_indicators: Vec<&serde_json::Value> = objects
                .iter()
                .filter(|obj| {
                    obj["type"] == "indicator"
                        && obj["id"] != "indicator--11111111-1111-4111-8111-111111111111"
                })
                .collect();
            assert!(!derived_indicators.is_empty());
            assert!(derived_indicators.iter().all(|obj| {
                let description = obj["description"].as_str().unwrap_or_default();
                description.contains(
                    "\n\nSTIX Indicator automatically generated from the original STIX Pattern.",
                )
            }));
            let relationships: Vec<&serde_json::Value> = objects
                .iter()
                .filter(|obj| {
                    obj["type"] == "relationship" && obj["relationship_type"] == "derived-from"
                })
                .collect();
            assert!(!relationships.is_empty());
            assert!(relationships
                .iter()
                .all(|rel| rel["confidence"].as_u64().is_some()));
            let ids: Vec<String> = derived_indicators
                .iter()
                .filter_map(|obj| obj["id"].as_str().map(|value| value.to_string()))
                .collect();
            let unique: std::collections::HashSet<String> = ids.iter().cloned().collect();
            assert_eq!(ids.len(), unique.len());
        });
    }

    #[test]
    fn translate_stix_pattern_summary_endpoint_returns_description_and_confidence() {
        with_test_config_dir("translate_summary_endpoint", || {
            let state = WebState::new("admin", "secret-pass", false, false).expect("state");
            let principal = state
                .authenticate_local("admin", "secret-pass")
                .expect("principal");
            let (_entry, token_value) = state
                .create_user_api_token(&principal, "Translate summary token", None)
                .expect("token create");
            let mut headers = HashMap::new();
            headers.insert(
                "authorization".to_string(),
                format!("Bearer {}", token_value),
            );
            let request = HttpRequest {
                method: "POST".to_string(),
                path: "/api/translate/stix-pattern-summary".to_string(),
                query: HashMap::new(),
                headers,
                body: serde_json::json!({
                    "pattern": "[process:name = 'cmd.exe']",
                    "target": "sigma",
                    "description": "Example source description"
                })
                .to_string()
                .into_bytes(),
            };
            let response = route(request, &state).expect("summary response");
            assert_eq!(response.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
            assert_eq!(body["status"], "success");
            assert!(body["result"]["description"].is_string());
            assert!(body["result"]["pattern"].is_string());
            assert!(body["result"]["confidence"].as_u64().is_some());
        });
    }
}
