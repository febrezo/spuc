use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use crate::paths;
use crate::web::api::generate_secret;

const USERS_SCHEMA_VERSION: &str = "1.0";
const OAUTH_POLICY_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Role {
    Admin,
    Analyst,
}

impl Role {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Analyst => "analyst",
        }
    }

    pub(crate) fn can_manage_users(self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WebUser {
    pub(crate) id: String,
    pub(crate) username: String,
    pub(crate) role: Role,
    pub(crate) password_salt: String,
    pub(crate) password_hash: String,
    pub(crate) created_at_utc: String,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct UserStore {
    pub(crate) schema_version: String,
    pub(crate) users: Vec<WebUser>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PublicUserView {
    pub(crate) id: String,
    pub(crate) username: String,
    pub(crate) role: &'static str,
    pub(crate) created_at_utc: String,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Principal {
    pub(crate) user_id: String,
    pub(crate) username: String,
    pub(crate) role: Role,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderBootstrap {
    pub(crate) id: &'static str,
    pub(crate) configured: bool,
    pub(crate) authorized: bool,
    pub(crate) enabled: bool,
    pub(crate) label: &'static str,
    pub(crate) auth_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthPolicyStore {
    pub(crate) schema_version: String,
    #[serde(default)]
    pub(crate) providers: BTreeMap<String, bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthConfig {
    pub(crate) providers: HashMap<&'static str, ProviderBootstrap>,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthIdentity {
    pub(crate) provider_id: &'static str,
    pub(crate) subject: String,
    pub(crate) username: String,
    pub(crate) email: Option<String>,
}

impl OAuthConfig {
    pub(crate) fn from_env() -> Self {
        let mut providers = HashMap::new();
        providers.insert("google", provider_google_from_env());
        providers.insert("github", provider_github_from_env());
        Self { providers }
    }

    pub(crate) fn bootstrap_views_with_policy(
        &self,
        policy: &OAuthPolicyStore,
    ) -> Vec<ProviderBootstrap> {
        let mut views = self
            .providers
            .values()
            .cloned()
            .map(|provider| provider_with_policy(provider, policy))
            .collect::<Vec<_>>();
        views.sort_by(|a, b| a.id.cmp(b.id));
        views
    }

    pub(crate) fn bootstrap_views(&self) -> Vec<ProviderBootstrap> {
        let mut views = self.providers.values().cloned().collect::<Vec<_>>();
        views.sort_by(|a, b| a.id.cmp(b.id));
        views
    }

    pub(crate) fn provider(&self, id: &str) -> Option<&ProviderBootstrap> {
        self.providers.get(id)
    }

    pub(crate) fn provider_with_policy(
        &self,
        id: &str,
        policy: &OAuthPolicyStore,
    ) -> Option<ProviderBootstrap> {
        let base = self.providers.get(id)?;
        Some(provider_with_policy(base.clone(), policy))
    }
}

pub(crate) fn users_store_path() -> Result<PathBuf> {
    let root = paths::spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("web_users.json"))
}

pub(crate) fn oauth_policy_store_path() -> Result<PathBuf> {
    let root = paths::spuc_config_root().ok_or_else(|| anyhow!("cannot resolve config root"))?;
    fs::create_dir_all(&root)?;
    Ok(root.join("web_oauth_policy.json"))
}

pub(crate) fn load_or_init_oauth_policy(
    config: &OAuthConfig,
) -> Result<(PathBuf, OAuthPolicyStore)> {
    let path = oauth_policy_store_path()?;
    if !path.exists() {
        let policy = default_oauth_policy(config);
        save_oauth_policy(&path, &policy)?;
        return Ok((path, policy));
    }

    let raw = fs::read_to_string(&path)?;
    let parsed: OAuthPolicyStore = serde_json::from_str(&raw)?;
    let normalized = normalize_oauth_policy(parsed.clone(), config);
    if normalized.schema_version != parsed.schema_version
        || normalized.providers != parsed.providers
    {
        save_oauth_policy(&path, &normalized)?;
    }
    Ok((path, normalized))
}

pub(crate) fn save_oauth_policy(path: &PathBuf, policy: &OAuthPolicyStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(policy)?;
    fs::write(path, raw)?;
    Ok(())
}

pub(crate) fn oauth_provider_authorized(policy: &OAuthPolicyStore, provider_id: &str) -> bool {
    let key = provider_id.trim().to_ascii_lowercase();
    policy.providers.get(&key).copied().unwrap_or(false)
}

pub(crate) fn set_oauth_provider_authorized(
    policy: &mut OAuthPolicyStore,
    provider_id: &str,
    authorized: bool,
) {
    let key = provider_id.trim().to_ascii_lowercase();
    policy.providers.insert(key, authorized);
}

fn default_oauth_policy(config: &OAuthConfig) -> OAuthPolicyStore {
    let mut providers = BTreeMap::new();
    for id in config.providers.keys() {
        providers.insert((*id).to_string(), false);
    }
    OAuthPolicyStore {
        schema_version: OAUTH_POLICY_SCHEMA_VERSION.to_string(),
        providers,
    }
}

fn normalize_oauth_policy(mut policy: OAuthPolicyStore, config: &OAuthConfig) -> OAuthPolicyStore {
    if policy.schema_version.trim().is_empty() {
        policy.schema_version = OAUTH_POLICY_SCHEMA_VERSION.to_string();
    }
    for id in config.providers.keys() {
        policy.providers.entry((*id).to_string()).or_insert(false);
    }
    policy
}

fn provider_with_policy(
    mut provider: ProviderBootstrap,
    policy: &OAuthPolicyStore,
) -> ProviderBootstrap {
    provider.authorized = oauth_provider_authorized(policy, provider.id);
    provider.enabled = provider.configured && provider.authorized;
    provider
}

pub(crate) fn load_or_init_users(
    admin_username: &str,
    admin_password: &str,
    enforce_admin_password: bool,
) -> Result<(PathBuf, UserStore)> {
    let path = users_store_path()?;
    let store = load_or_init_users_from_path(
        &path,
        admin_username,
        admin_password,
        enforce_admin_password,
    )?;
    Ok((path, store))
}

fn load_or_init_users_from_path(
    path: &PathBuf,
    admin_username: &str,
    admin_password: &str,
    enforce_admin_password: bool,
) -> Result<UserStore> {
    if !path.exists() {
        let admin = new_user(admin_username, admin_password, Role::Admin)?;
        let store = UserStore {
            schema_version: USERS_SCHEMA_VERSION.to_string(),
            users: vec![admin],
        };
        save_users(&path, &store)?;
        return Ok(store);
    }

    let raw = fs::read_to_string(&path)?;
    let mut store: UserStore = serde_json::from_str(&raw)?;
    let mut changed = false;
    if store.schema_version.trim().is_empty() {
        store.schema_version = USERS_SCHEMA_VERSION.to_string();
        changed = true;
    }

    if let Some(user) = store
        .users
        .iter_mut()
        .find(|user| user.username.eq_ignore_ascii_case(admin_username))
    {
        if user.role != Role::Admin {
            user.role = Role::Admin;
            changed = true;
        }
        if !user.enabled {
            user.enabled = true;
            changed = true;
        }
        if enforce_admin_password
            && !verify_password(admin_password, &user.password_salt, &user.password_hash)
        {
            let (salt, hash) = hash_password(admin_password)?;
            user.password_salt = salt;
            user.password_hash = hash;
            changed = true;
        }
    } else {
        store
            .users
            .push(new_user(admin_username, admin_password, Role::Admin)?);
        changed = true;
    }

    let has_admin = store
        .users
        .iter()
        .any(|user| user.role == Role::Admin && user.enabled);
    if !has_admin {
        store
            .users
            .push(new_user(admin_username, admin_password, Role::Admin)?);
        changed = true;
    }

    if changed {
        save_users(&path, &store)?;
    }

    Ok(store)
}

pub(crate) fn save_users(path: &PathBuf, store: &UserStore) -> Result<()> {
    let raw = serde_json::to_string_pretty(store)?;
    fs::write(path, raw)?;
    Ok(())
}

pub(crate) fn verify_credentials(
    store: &UserStore,
    username: &str,
    password: &str,
) -> Option<Principal> {
    let user = store
        .users
        .iter()
        .find(|user| user.enabled && user.username.eq_ignore_ascii_case(username))?;
    if verify_password(password, &user.password_salt, &user.password_hash) {
        Some(Principal {
            user_id: user.id.clone(),
            username: user.username.clone(),
            role: user.role,
        })
    } else {
        None
    }
}

pub(crate) fn list_users(store: &UserStore) -> Vec<PublicUserView> {
    let mut users = store
        .users
        .iter()
        .map(|user| PublicUserView {
            id: user.id.clone(),
            username: user.username.clone(),
            role: user.role.as_str(),
            created_at_utc: user.created_at_utc.clone(),
            enabled: user.enabled,
        })
        .collect::<Vec<_>>();
    users.sort_by(|a, b| {
        a.username
            .to_ascii_lowercase()
            .cmp(&b.username.to_ascii_lowercase())
    });
    users
}

pub(crate) fn create_user(
    store: &mut UserStore,
    username: &str,
    password: &str,
    role: Role,
) -> Result<PublicUserView> {
    if username.trim().is_empty() {
        return Err(anyhow!("username is required"));
    }
    if password.trim().len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    if store
        .users
        .iter()
        .any(|user| user.username.eq_ignore_ascii_case(username))
    {
        return Err(anyhow!("user '{}' already exists", username));
    }
    let user = new_user(username, password, role)?;
    let view = PublicUserView {
        id: user.id.clone(),
        username: user.username.clone(),
        role: user.role.as_str(),
        created_at_utc: user.created_at_utc.clone(),
        enabled: user.enabled,
    };
    store.users.push(user);
    Ok(view)
}

pub(crate) fn delete_user(store: &mut UserStore, user_id: &str) -> Result<bool> {
    let before = store.users.len();
    store.users.retain(|user| user.id != user_id);
    if store
        .users
        .iter()
        .filter(|user| user.role == Role::Admin && user.enabled)
        .count()
        == 0
    {
        return Err(anyhow!("cannot remove the last enabled admin user"));
    }
    Ok(store.users.len() != before)
}

pub(crate) fn update_user(
    store: &mut UserStore,
    user_id: &str,
    role: Option<Role>,
    enabled: Option<bool>,
) -> Result<PublicUserView> {
    let Some(index) = store.users.iter().position(|user| user.id == user_id) else {
        return Err(anyhow!("user '{}' not found", user_id));
    };
    let mut updated = store.users[index].clone();
    if let Some(role) = role {
        updated.role = role;
    }
    if let Some(enabled) = enabled {
        updated.enabled = enabled;
    }

    let enabled_admins = store
        .users
        .iter()
        .enumerate()
        .filter(|(current_index, user)| {
            if *current_index == index {
                updated.role == Role::Admin && updated.enabled
            } else {
                user.role == Role::Admin && user.enabled
            }
        })
        .count();
    if enabled_admins == 0 {
        return Err(anyhow!("cannot disable the last enabled admin user"));
    }

    store.users[index] = updated.clone();
    Ok(PublicUserView {
        id: updated.id,
        username: updated.username,
        role: updated.role.as_str(),
        created_at_utc: updated.created_at_utc,
        enabled: updated.enabled,
    })
}

pub(crate) fn change_password(
    store: &mut UserStore,
    user_id: &str,
    current_password: Option<&str>,
    new_password: &str,
    bypass_current_check: bool,
) -> Result<()> {
    if new_password.trim().len() < 8 {
        return Err(anyhow!("new_password must be at least 8 characters"));
    }
    let Some(user) = store.users.iter_mut().find(|user| user.id == user_id) else {
        return Err(anyhow!("user '{}' not found", user_id));
    };

    if !bypass_current_check {
        let Some(current_password) = current_password else {
            return Err(anyhow!("current_password is required"));
        };
        if !verify_password(current_password, &user.password_salt, &user.password_hash) {
            return Err(anyhow!("current password is not valid"));
        }
    }

    let (salt, hash) = hash_password(new_password)?;
    user.password_salt = salt;
    user.password_hash = hash;
    Ok(())
}

fn new_user(username: &str, password: &str, role: Role) -> Result<WebUser> {
    if password.trim().len() < 8 {
        return Err(anyhow!("password must be at least 8 characters"));
    }
    let (password_salt, password_hash) = hash_password(password)?;
    Ok(WebUser {
        id: format!("usr-{}", generate_secret(10).to_ascii_lowercase()),
        username: username.trim().to_string(),
        role,
        password_salt,
        password_hash,
        created_at_utc: Utc::now().to_rfc3339(),
        enabled: true,
    })
}

fn hash_password(password: &str) -> Result<(String, String)> {
    let salt = generate_secret(18);
    let hash = digest_password(password, &salt)?;
    Ok((salt, hash))
}

fn verify_password(password: &str, salt: &str, expected_hash: &str) -> bool {
    digest_password(password, salt)
        .map(|value| value == expected_hash)
        .unwrap_or(false)
}

fn digest_password(password: &str, salt: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    Ok(STANDARD.encode(digest))
}

fn provider_google_from_env() -> ProviderBootstrap {
    let client_id = std::env::var("SPUC_WEB_GOOGLE_CLIENT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let client_secret = std::env::var("SPUC_WEB_GOOGLE_CLIENT_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let redirect_uri = std::env::var("SPUC_WEB_GOOGLE_REDIRECT_URI")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let configured = client_id.is_some() && client_secret.is_some() && redirect_uri.is_some();
    let auth_url = if configured {
        Some(format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile",
            client_id.as_deref().unwrap_or_default(),
            redirect_uri.as_deref().unwrap_or_default(),
        ))
    } else {
        None
    };
    ProviderBootstrap {
        id: "google",
        configured,
        authorized: false,
        enabled: false,
        label: "Google",
        auth_url,
    }
}

fn provider_github_from_env() -> ProviderBootstrap {
    let client_id = std::env::var("SPUC_WEB_GITHUB_CLIENT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let client_secret = std::env::var("SPUC_WEB_GITHUB_CLIENT_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let redirect_uri = std::env::var("SPUC_WEB_GITHUB_REDIRECT_URI")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let configured = client_id.is_some() && client_secret.is_some() && redirect_uri.is_some();
    let auth_url = if configured {
        Some(format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email",
            client_id.as_deref().unwrap_or_default(),
            redirect_uri.as_deref().unwrap_or_default(),
        ))
    } else {
        None
    };
    ProviderBootstrap {
        id: "github",
        configured,
        authorized: false,
        enabled: false,
        label: "GitHub",
        auth_url,
    }
}

pub(crate) fn build_oauth_authorize_url(
    provider: &ProviderBootstrap,
    state: &str,
) -> Option<String> {
    if !provider.enabled {
        return None;
    }
    let auth_url = provider.auth_url.as_deref()?;
    let separator = if auth_url.contains('?') { "&" } else { "?" };
    Some(format!("{auth_url}{separator}state={state}"))
}

#[derive(Debug, Clone)]
struct OAuthRuntimeProvider {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfoResponse {
    sub: Option<String>,
    email: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserResponse {
    id: Option<u64>,
    login: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmailResponse {
    email: String,
    primary: bool,
    verified: bool,
}

pub(crate) fn exchange_oauth_code(
    provider_id: &str,
    code: &str,
    state: &str,
) -> Result<OAuthIdentity> {
    let normalized = provider_id.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "google" => exchange_google_code(code, state),
        "github" => exchange_github_code(code, state),
        _ => Err(anyhow!("provider_not_supported")),
    }
}

fn exchange_google_code(code: &str, state: &str) -> Result<OAuthIdentity> {
    let runtime = oauth_runtime_provider("google")?;
    let token: GoogleTokenResponse = post_form_json(
        "https://oauth2.googleapis.com/token",
        &[
            ("code", code),
            ("client_id", runtime.client_id.as_str()),
            ("client_secret", runtime.client_secret.as_str()),
            ("redirect_uri", runtime.redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
            ("state", state),
        ],
        &[("Accept", "application/json")],
    )?;
    let access_token = token
        .access_token
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "google token exchange failed: {}",
                token
                    .error_description
                    .or(token.error)
                    .unwrap_or_else(|| "missing access_token".to_string())
            )
        })?;

    let profile: GoogleUserInfoResponse = get_json(
        "https://openidconnect.googleapis.com/v1/userinfo",
        &[
            ("Authorization", format!("Bearer {access_token}")),
            ("Accept", "application/json".to_string()),
        ],
    )?;

    let subject = profile
        .sub
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("google userinfo did not include sub"))?;
    let username = profile
        .email
        .clone()
        .or(profile.name)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("google-{subject}"));

    Ok(OAuthIdentity {
        provider_id: "google",
        subject,
        username,
        email: profile.email.filter(|value| !value.trim().is_empty()),
    })
}

fn exchange_github_code(code: &str, state: &str) -> Result<OAuthIdentity> {
    let runtime = oauth_runtime_provider("github")?;
    let token: GitHubTokenResponse = post_form_json(
        "https://github.com/login/oauth/access_token",
        &[
            ("code", code),
            ("client_id", runtime.client_id.as_str()),
            ("client_secret", runtime.client_secret.as_str()),
            ("redirect_uri", runtime.redirect_uri.as_str()),
            ("state", state),
        ],
        &[("Accept", "application/json"), ("User-Agent", "spuc-web")],
    )?;
    let access_token = token
        .access_token
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "github token exchange failed: {}",
                token
                    .error_description
                    .or(token.error)
                    .unwrap_or_else(|| "missing access_token".to_string())
            )
        })?;

    let profile: GitHubUserResponse = get_json(
        "https://api.github.com/user",
        &[
            ("Authorization", format!("Bearer {access_token}")),
            ("Accept", "application/vnd.github+json".to_string()),
            ("User-Agent", "spuc-web".to_string()),
        ],
    )?;
    let subject = profile
        .id
        .map(|value| value.to_string())
        .or_else(|| profile.login.clone())
        .ok_or_else(|| anyhow!("github user profile missing id/login"))?;
    let fallback_email = github_primary_email(&access_token)?;
    let email = profile
        .email
        .filter(|value| !value.trim().is_empty())
        .or(fallback_email);
    let username = profile
        .login
        .clone()
        .or_else(|| email.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("github-{subject}"));

    Ok(OAuthIdentity {
        provider_id: "github",
        subject,
        username,
        email,
    })
}

fn github_primary_email(access_token: &str) -> Result<Option<String>> {
    let emails: Vec<GitHubEmailResponse> = get_json(
        "https://api.github.com/user/emails",
        &[
            ("Authorization", format!("Bearer {access_token}")),
            ("Accept", "application/vnd.github+json".to_string()),
            ("User-Agent", "spuc-web".to_string()),
        ],
    )?;
    let preferred = emails
        .iter()
        .find(|item| item.primary && item.verified)
        .or_else(|| emails.iter().find(|item| item.verified))
        .or_else(|| emails.first());
    Ok(preferred
        .map(|item| item.email.trim().to_string())
        .filter(|value| !value.is_empty()))
}

fn oauth_runtime_provider(provider_id: &str) -> Result<OAuthRuntimeProvider> {
    match provider_id.trim().to_ascii_lowercase().as_str() {
        "google" => runtime_provider_from_env(
            "SPUC_WEB_GOOGLE_CLIENT_ID",
            "SPUC_WEB_GOOGLE_CLIENT_SECRET",
            "SPUC_WEB_GOOGLE_REDIRECT_URI",
        ),
        "github" => runtime_provider_from_env(
            "SPUC_WEB_GITHUB_CLIENT_ID",
            "SPUC_WEB_GITHUB_CLIENT_SECRET",
            "SPUC_WEB_GITHUB_REDIRECT_URI",
        ),
        _ => Err(anyhow!("provider_not_supported")),
    }
}

fn runtime_provider_from_env(
    client_id_var: &str,
    client_secret_var: &str,
    redirect_uri_var: &str,
) -> Result<OAuthRuntimeProvider> {
    let client_id = std::env::var(client_id_var)
        .map_err(|_| anyhow!("{client_id_var} is required"))?
        .trim()
        .to_string();
    let client_secret = std::env::var(client_secret_var)
        .map_err(|_| anyhow!("{client_secret_var} is required"))?
        .trim()
        .to_string();
    let redirect_uri = std::env::var(redirect_uri_var)
        .map_err(|_| anyhow!("{redirect_uri_var} is required"))?
        .trim()
        .to_string();
    if client_id.is_empty() || client_secret.is_empty() || redirect_uri.is_empty() {
        return Err(anyhow!(
            "OAuth provider environment values must not be empty"
        ));
    }
    Ok(OAuthRuntimeProvider {
        client_id,
        client_secret,
        redirect_uri,
    })
}

fn post_form_json<T: DeserializeOwned>(
    url: &str,
    form: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Result<T> {
    let mut request = ureq::post(url);
    for (name, value) in headers {
        request = request.set(name, value);
    }
    decode_response(request.send_form(form))
}

fn get_json<T: DeserializeOwned>(url: &str, headers: &[(&str, String)]) -> Result<T> {
    let mut request = ureq::get(url);
    for (name, value) in headers {
        request = request.set(name, value.as_str());
    }
    decode_response(request.call())
}

fn decode_response<T: DeserializeOwned>(
    response: std::result::Result<ureq::Response, ureq::Error>,
) -> Result<T> {
    match response {
        Ok(response) => response.into_json().map_err(Into::into),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            if body.trim().is_empty() {
                Err(anyhow!("oauth provider returned HTTP {status}"))
            } else {
                Err(anyhow!("oauth provider returned HTTP {status}: {body}"))
            }
        }
        Err(error) => Err(anyhow!("oauth http request failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_store() -> UserStore {
        UserStore {
            schema_version: USERS_SCHEMA_VERSION.to_string(),
            users: vec![new_user("admin", "secret-pass", Role::Admin).expect("admin")],
        }
    }

    #[test]
    fn create_user_and_verify_credentials() {
        let mut store = sample_store();
        let created =
            create_user(&mut store, "hunter", "hunter-pass", Role::Analyst).expect("create");
        assert_eq!(created.role, "analyst");

        let principal = verify_credentials(&store, "hunter", "hunter-pass").expect("principal");
        assert_eq!(principal.username, "hunter");
        assert_eq!(principal.role, Role::Analyst);
    }

    #[test]
    fn delete_last_admin_is_rejected() {
        let mut store = sample_store();
        let admin_id = store.users[0].id.clone();
        let result = delete_user(&mut store, &admin_id);
        assert!(result.is_err());
    }

    #[test]
    fn change_password_requires_current_unless_bypassed() {
        let mut store = sample_store();
        let admin_id = store.users[0].id.clone();

        let missing_current = change_password(&mut store, &admin_id, None, "new-secret", false);
        assert!(missing_current.is_err());

        change_password(
            &mut store,
            &admin_id,
            Some("secret-pass"),
            "new-secret",
            false,
        )
        .expect("changed");

        assert!(verify_credentials(&store, "admin", "secret-pass").is_none());
        assert!(verify_credentials(&store, "admin", "new-secret").is_some());
    }

    #[test]
    fn update_user_cannot_disable_last_admin() {
        let mut store = sample_store();
        let admin_id = store.users[0].id.clone();
        let result = update_user(&mut store, &admin_id, None, Some(false));
        assert!(result.is_err());
    }

    #[test]
    fn oauth_policy_defaults_to_disabled_for_known_providers() {
        let config = OAuthConfig {
            providers: HashMap::from([
                (
                    "google",
                    ProviderBootstrap {
                        id: "google",
                        configured: true,
                        authorized: false,
                        enabled: false,
                        label: "Google",
                        auth_url: Some("https://example.com/google".to_string()),
                    },
                ),
                (
                    "github",
                    ProviderBootstrap {
                        id: "github",
                        configured: true,
                        authorized: false,
                        enabled: false,
                        label: "GitHub",
                        auth_url: Some("https://example.com/github".to_string()),
                    },
                ),
            ]),
        };
        let policy = default_oauth_policy(&config);
        assert_eq!(policy.providers.get("google"), Some(&false));
        assert_eq!(policy.providers.get("github"), Some(&false));
    }

    #[test]
    fn provider_bootstrap_with_policy_computes_enabled_flag() {
        let config = OAuthConfig {
            providers: HashMap::from([(
                "google",
                ProviderBootstrap {
                    id: "google",
                    configured: true,
                    authorized: false,
                    enabled: false,
                    label: "Google",
                    auth_url: Some("https://example.com/google".to_string()),
                },
            )]),
        };
        let mut policy = default_oauth_policy(&config);
        let before = config
            .provider_with_policy("google", &policy)
            .expect("provider");
        assert!(!before.enabled);
        assert!(!before.authorized);

        set_oauth_provider_authorized(&mut policy, "google", true);
        let after = config
            .provider_with_policy("google", &policy)
            .expect("provider");
        assert!(after.enabled);
        assert!(after.authorized);
        assert!(after.configured);
    }

    #[test]
    fn oauth_authorize_url_appends_state_parameter() {
        let provider = ProviderBootstrap {
            id: "google",
            configured: true,
            authorized: true,
            enabled: true,
            label: "Google",
            auth_url: Some("https://example.com/oauth?client_id=abc".to_string()),
        };
        let url = build_oauth_authorize_url(&provider, "state-token").expect("auth url");
        assert!(url.contains("state=state-token"));
        assert!(url.contains("client_id=abc"));
    }

    #[test]
    fn load_or_init_users_enforces_explicit_admin_password() {
        let path = temp_users_store_path("enforce_admin_password");
        let first = load_or_init_users_from_path(&path, "admin", "old-secret", true)
            .expect("initialize users");
        assert!(verify_credentials(&first, "admin", "old-secret").is_some());

        let second = load_or_init_users_from_path(&path, "admin", "new-secret", true)
            .expect("refresh users");
        assert!(verify_credentials(&second, "admin", "old-secret").is_none());
        assert!(verify_credentials(&second, "admin", "new-secret").is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_or_init_users_keeps_existing_password_when_not_enforced() {
        let path = temp_users_store_path("skip_enforce_admin_password");
        let first = load_or_init_users_from_path(&path, "admin", "old-secret", true)
            .expect("initialize users");
        assert!(verify_credentials(&first, "admin", "old-secret").is_some());

        let second = load_or_init_users_from_path(&path, "admin", "new-secret", false)
            .expect("reload users");
        assert!(verify_credentials(&second, "admin", "old-secret").is_some());
        assert!(verify_credentials(&second, "admin", "new-secret").is_none());

        let _ = fs::remove_file(path);
    }

    fn temp_users_store_path(tag: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("spuc_web_users_{tag}_{ts}.json"))
    }
}
