use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Datelike, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::services::translation::{TranslationRequest, evaluate_rule};
use crate::catalog::{
    CatalogAdversaryEntry, CatalogRuleEntry, delete_rule_entry, edit_rule_entry,
    filter_adversary_entries, filter_rule_entries, load_catalog_data, resolve_adversary_selector,
    resolve_rule_selector,
};
use crate::cli::{AbilityTarget, BuildOutput, ConversionMode, ExportFormat};
use crate::commands::common::{
    available_detection_target_labels, build_ability_from_rule, parse_ability_target,
};
use crate::commands::sigma_runtime::sigma_runtime_info;
use crate::commands::sigma_targets::dynamic_sigma_targets;
use crate::commands::{emulate, learn, plan, translate, verify};
use crate::web::auth::{
    OAuthConfig, OAuthIdentity, OAuthPolicyStore, Principal, ProviderBootstrap, PublicUserView,
    Role, UserStore, build_oauth_authorize_url, change_password, create_user, delete_user,
    exchange_oauth_code, list_users, load_or_init_oauth_policy, load_or_init_users,
    save_oauth_policy, save_users, set_oauth_provider_authorized, update_user as update_store_user,
    verify_credentials,
};
use crate::web::{assets, i18n};
use spuc::emulation::ability as emu_ability;
use spuc::emulation::campaign as emu_campaign;
use spuc::emulation::catalog::AbilityCatalog;
use spuc::emulation::export as emu_export;

const OAUTH_STATE_TTL_SECONDS: i64 = 600;

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
    pub(crate) no_login: bool,
    pub(crate) admin_user: String,
    pub(crate) project_link: String,
    pub(crate) project_name: String,
    pub(crate) license_link: String,
    pub(crate) license_name: String,
    pub(crate) oauth: OAuthConfig,
}

pub(crate) struct WebState {
    users_path: PathBuf,
    users: Mutex<UserStore>,
    oauth_policy_path: PathBuf,
    oauth_policy: Mutex<OAuthPolicyStore>,
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
        let (users_path, users) = load_or_init_users(
            admin_user,
            admin_password,
            !generated_password,
        )?;
        let oauth = OAuthConfig::from_env();
        let (oauth_policy_path, oauth_policy) = load_or_init_oauth_policy(&oauth)?;
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

        Ok(Self {
            users_path,
            users: Mutex::new(users),
            oauth_policy_path,
            oauth_policy: Mutex::new(oauth_policy),
            generated_password,
            runtime: WebRuntimeConfig {
                no_login,
                admin_user: admin_user.to_string(),
                project_link: "https://github.com/febrezo/spuc".to_string(),
                project_name: "GitHub Project".to_string(),
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
        if self.runtime.no_login {
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
        list_users(&users)
    }

    pub(crate) fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<PublicUserView> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let view = create_user(&mut users, username, password, role)?;
        save_users(&self.users_path, &users)?;
        Ok(view)
    }

    pub(crate) fn delete_user(&self, user_id: &str) -> Result<bool> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let deleted = delete_user(&mut users, user_id)?;
        if deleted {
            save_users(&self.users_path, &users)?;
        }
        Ok(deleted)
    }

    pub(crate) fn update_user(
        &self,
        user_id: &str,
        role: Option<Role>,
        enabled: Option<bool>,
    ) -> Result<PublicUserView> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let view = update_store_user(&mut users, user_id, role, enabled)?;
        save_users(&self.users_path, &users)?;
        Ok(view)
    }

    pub(crate) fn change_user_password(
        &self,
        principal: &Principal,
        target_user_id: &str,
        current_password: Option<&str>,
        new_password: &str,
    ) -> Result<()> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        let is_self_update = principal.user_id == target_user_id;
        let bypass =
            self.runtime.no_login || (principal.role.can_manage_users() && !is_self_update);
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
    license_url: String,
    license_name: String,
}

#[derive(Debug, Serialize)]
struct AuthBootstrap {
    no_login: bool,
    authenticated: bool,
    show_logout: bool,
    generated_password: bool,
    principal: Option<PrincipalView>,
    providers: Vec<ProviderBootstrap>,
}

#[derive(Debug, Serialize)]
struct PrincipalView {
    user_id: String,
    username: String,
    role: &'static str,
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
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AdminUserUpdateRequest {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
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
struct DummyAbilityCreateRequest {
    kind: String,
    seconds: Option<u64>,
    label: Option<String>,
    platform: Option<String>,
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

#[derive(Debug, Clone, Serialize)]
struct StixObjectView {
    stix_id: String,
    stix_type: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RuleMetadataEnvelope {
    tlp: String,
    pap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttp: Option<String>,
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

    if request.method == "GET" && request.path == "/" {
        return Ok(HttpResponse::html(assets::INDEX_HTML));
    }
    if request.method == "GET" && request.path == "/styles.css" {
        return Ok(HttpResponse::css(assets::APP_CSS));
    }
    if request.method == "GET" && request.path == "/app.js" {
        return Ok(HttpResponse::javascript(assets::APP_JS));
    }
    if request.method == "GET" && request.path == "/assets/logo-sputnik.png" {
        return Ok(HttpResponse::text(
            200,
            "image/png",
            assets::LOGO_SPUTNIK_PNG.to_vec(),
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
        ("GET", ["api", "stix-objects"]) => list_stix_objects(),
        ("DELETE", ["api", "rules", selector]) => delete_rule(selector),
        ("POST", ["api", "rules", "save"]) => save_rule(&request),
        ("POST", ["api", "rules", selector, "indicates"]) => set_rule_indicates(selector, &request),
        ("POST", ["api", "rules", "compatibility"]) => rule_compatibility(&request),
        ("POST", ["api", "rules", "export", "bundle"]) => {
            export_rules_bundle(&request)
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
    HttpResponse::json(
        200,
        &BootstrapResponse {
            app: AppBootstrap {
                name: "SPUC",
                version: env!("CARGO_PKG_VERSION"),
                year: Utc::now().year(),
                project_url: state.runtime().project_link.clone(),
                project_name: state.runtime().project_name.clone(),
                license_url: state.runtime().license_link.clone(),
                license_name: state.runtime().license_name.clone(),
            },
            auth: AuthBootstrap {
                no_login: state.runtime().no_login,
                authenticated: principal.is_some(),
                show_logout: !state.runtime().no_login,
                generated_password: state.generated_password(),
                principal: principal.map(principal_view),
                providers: state.list_oauth_providers(),
            },
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
    if state.runtime().no_login {
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
    if state.runtime().no_login {
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
    if state.runtime().no_login {
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
    let created = state.create_user(&payload.username, &payload.password, role)?;
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
    let updated = state.update_user(user_id, role, payload.enabled)?;
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

fn list_stix_objects() -> Result<HttpResponse> {
    let (_, _, rules, _) = load_catalog_data()?;
    let entries = collect_stix_objects_from_rules(&rules);
    HttpResponse::json(
        200,
        &serde_json::json!({
            "entries": entries
        }),
    )
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

    let mut effective_indicates = existing_indicates;
    if let Some(indicates) = requested_indicates {
        push_unique_indicates(&mut effective_indicates, indicates);
    }
    let observables = extract_rule_observable_types(&payload.rule);
    let storage_description = encode_rule_metadata_description(
        payload.description.as_deref(),
        payload.tlp.as_deref(),
        payload.pap.as_deref(),
        payload.ttp.as_deref(),
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
    Ok(HttpResponse::text(200, "application/json; charset=utf-8", pretty).with_header(
        "Content-Disposition",
        "attachment; filename=\"spuc-rules-bundle.json\"",
    ))
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
            let Some(output) = row.output.as_deref().map(str::trim).filter(|value| !value.is_empty()) else {
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

fn build_stix_stub_object(stix_id: &str, object_name: &str, now: &str) -> Option<serde_json::Value> {
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
                .filter(|value| !value.is_empty()) else {
                return HttpResponse::json(400, &json!({ "error": "dummy_label_required" }));
            };
            build_dummy_label_ability(label, &platform)
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
    if payload.ability_ids.is_empty() {
        return HttpResponse::json(400, &serde_json::json!({ "error": "ability_ids_required" }));
    }
    let confidence = payload.confidence.unwrap_or(70);
    if confidence > 100 {
        return HttpResponse::json(
            400,
            &serde_json::json!({ "error": "confidence_out_of_range" }),
        );
    }

    let catalog = AbilityCatalog::from_default_root()?;
    let abilities = catalog.select_by_ids(&payload.ability_ids)?;
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
        None,
        None,
    )
    .unwrap_or(description_plain);

    let campaign = emu_campaign::build_campaign_ordered_with_confidence(
        format!("intrusion-set-{}", generate_secret(10).to_ascii_lowercase()),
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
    if payload.ability_ids.is_empty() {
        return HttpResponse::json(400, &serde_json::json!({ "error": "ability_ids_required" }));
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
    let ordered_ids = normalize_ability_order(&payload.ability_ids, &payload.order);
    let abilities = catalog.select_by_ids(&ordered_ids)?;
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
            target.map(|value| value.trim().to_ascii_lowercase()).as_deref(),
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
        targets
            .first()
            .copied()
            .unwrap_or(AbilityTarget::SpucAgent),
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
        let relative = file
            .strip_prefix(&export_root)
            .ok()
            .and_then(|value| value.to_str())
            .unwrap_or("artifact")
            .replace('/', "-");
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
        steps: entry.steps,
        platforms: entry.platforms,
        description: metadata.description.unwrap_or_default(),
        ability_refs: entry.ability_refs,
        path: entry.path.display().to_string(),
        compatible_exports,
    }
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
    artifact_names: &[String],
) -> String {
    match executor {
        AbilityTarget::Bash => {
            let mut lines = vec![
                "#!/usr/bin/env bash".to_string(),
                "set -euo pipefail".to_string(),
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"".to_string(),
                format!("echo \"[spuc] operational adversary runner: {manifest_name}\""),
            ];
            for name in artifact_names {
                lines.push(format!("bash \"$SCRIPT_DIR/{name}\""));
            }
            lines.push("echo \"[spuc] operational run completed\"".to_string());
            lines.join("\n") + "\n"
        }
        AbilityTarget::Powershell => {
            let mut lines = vec![
                "$ErrorActionPreference = \"Stop\"".to_string(),
                "$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path".to_string(),
                format!("Write-Host \"[spuc] operational adversary runner: {manifest_name}\""),
            ];
            for name in artifact_names {
                lines.push(format!("& \"$scriptDir\\{name}\""));
            }
            lines.push("Write-Host \"[spuc] operational run completed\"".to_string());
            lines.join("\n") + "\n"
        }
        AbilityTarget::AtomicRedTeam => {
            #[derive(Serialize)]
            struct OperationalYaml<'a> {
                schema_version: &'a str,
                executor: &'a str,
                manifest: &'a str,
                artifacts: &'a [String],
            }
            serde_yaml::to_string(&OperationalYaml {
                schema_version: "1.0",
                executor: "atomic-red-team",
                manifest: manifest_name,
                artifacts: artifact_names,
            })
            .unwrap_or_else(|_| "schema_version: \"1.0\"\n".to_string())
        }
        AbilityTarget::SpucAgent => json!({
            "schema_version": "1.0",
            "executor": "spuc-agent",
            "manifest": manifest_name,
            "artifacts": artifact_names,
            "run_hint": "spuc-agent validate/run using this ordered artifact list and manifest"
        })
        .to_string(),
        AbilityTarget::MitreCaldera => json!({
            "schema_version": "1.0",
            "executor": "mitre-caldera",
            "manifest": manifest_name,
            "artifacts": artifact_names,
            "run_hint": "import artifacts in order and execute operation with linked abilities"
        })
        .to_string(),
    }
}

fn generate_operational_runner_artifacts(executor: AbilityTarget, target_root: &Path) -> Result<()> {
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
            let candidate = format!("{stem}-{}.{}", slugify_token(&step.ability_ref), artifact_ext);
            if target_root.join(&candidate).is_file() {
                ordered_names.push(candidate);
            }
        }
        if ordered_names.is_empty() {
            ordered_names = list_files(target_root)?
                .into_iter()
                .filter_map(|path| {
                    let name = path.file_name()?.to_str()?.to_string();
                    if name.starts_with(&(stem.clone() + "-")) && name.ends_with(&format!(".{artifact_ext}")) {
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

        let runner_name = format!("{stem}-operational.{op_ext}");
        let runner_path = target_root.join(runner_name);
        let content = render_operational_runner_content(executor, &manifest_name, &ordered_names);
        fs::write(runner_path, content)?;
    }

    Ok(())
}

fn catalog_adversary_id(intrusion_set_id: &str) -> String {
    if intrusion_set_id.starts_with("adversary-") {
        intrusion_set_id.to_string()
    } else if let Some(suffix) = intrusion_set_id.strip_prefix("intrusion-set-") {
        format!("adversary-{suffix}")
    } else {
        format!("adversary-{intrusion_set_id}")
    }
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
        assert!(
            objects
                .iter()
                .any(|item| item.stix_id == "malware--01234567-89ab-4def-8abc-0123456789ab")
        );
        assert!(
            objects
                .iter()
                .any(|item| item.stix_id == "indicator--11111111-2222-4def-8abc-0123456789ab")
        );
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
    }

    #[test]
    fn oauth_state_token_is_single_use_and_provider_bound() {
        let state = WebState::new("admin", "secret-pass", false, false).expect("state");
        let token = state.register_oauth_state("google");
        assert!(state.take_oauth_state("google", &token));
        assert!(!state.take_oauth_state("google", &token));

        let second = state.register_oauth_state("google");
        assert!(!state.take_oauth_state("github", &second));
    }

    #[test]
    fn oauth_identity_maps_to_existing_user_or_falls_back_to_analyst() {
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
    fn normalize_dummy_platform_only_accepts_known_values() {
        assert_eq!(normalize_dummy_platform(Some("linux")), "linux");
        assert_eq!(normalize_dummy_platform(Some("windows")), "windows");
        assert_eq!(normalize_dummy_platform(Some("macos")), "macos");
        assert_eq!(normalize_dummy_platform(Some("bad-os")), "any");
        assert_eq!(normalize_dummy_platform(None), "any");
    }

    #[test]
    fn operational_runner_content_for_bash_sequences_artifacts() {
        let content = render_operational_runner_content(
            AbilityTarget::Bash,
            "campaign.yaml",
            &["one.sh".to_string(), "two.sh".to_string()],
        );
        assert!(content.contains("#!/usr/bin/env bash"));
        assert!(content.contains("bash \"$SCRIPT_DIR/one.sh\""));
        assert!(content.contains("bash \"$SCRIPT_DIR/two.sh\""));
    }

    #[test]
    fn operational_runner_content_for_spuc_agent_is_json() {
        let content = render_operational_runner_content(
            AbilityTarget::SpucAgent,
            "campaign.yaml",
            &["a.json".to_string()],
        );
        let value: serde_json::Value = serde_json::from_str(&content).expect("json");
        assert_eq!(value["executor"], "spuc-agent");
        assert_eq!(value["manifest"], "campaign.yaml");
        assert!(value["artifacts"].is_array());
    }
}
