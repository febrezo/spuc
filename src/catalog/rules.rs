//! Translation-owned rules store.
//!
//! Source of truth for cataloged rules after the emulation removal: a single
//! JSON file at `<config_root>/catalog/rules.json`, keyed by synthetic STIX
//! indicator ids minted deterministically from the source pattern. The rule
//! metadata codec (the `SPUC_META_B64` envelope) moves here from the web API:
//! the persisted file carries decoded first-class fields instead of an
//! encoded ability description.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub(crate) fn rules_path(config_root: &Path) -> PathBuf {
    config_root.join("catalog").join("rules.json")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RuleIndicatesRelation {
    pub(crate) stix_id: String,
    pub(crate) object_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RuleMetadataEnvelope {
    pub(crate) tlp: String,
    pub(crate) pap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target_platform: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) observables: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) indicates_list: Vec<RuleIndicatesRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) indicates: Option<RuleIndicatesRelation>,
}

#[derive(Debug)]
pub(crate) struct DecodedRuleMetadata {
    pub(crate) description: Option<String>,
    pub(crate) tlp: String,
    pub(crate) pap: String,
    pub(crate) ttp: Option<String>,
    pub(crate) target_platform: Option<String>,
    pub(crate) observables: Vec<String>,
    pub(crate) indicates: Option<RuleIndicatesRelation>,
    pub(crate) indicates_list: Vec<RuleIndicatesRelation>,
}

/// One persisted catalog rule. The field set mirrors exactly what the rule
/// metadata codec carries (plus the save-request name/confidence), so no
/// invented metadata exists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PersistedRule {
    pub(crate) indicator_id: String,
    pub(crate) source_pattern: String,
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default = "default_persisted_tlp")]
    pub(crate) tlp: String,
    #[serde(default = "default_persisted_pap")]
    pub(crate) pap: String,
    #[serde(default)]
    pub(crate) ttp: Option<String>,
    #[serde(default)]
    pub(crate) target_platform: Option<String>,
    #[serde(default)]
    pub(crate) observables: Vec<String>,
    #[serde(default)]
    pub(crate) indicates: Option<RuleIndicatesRelation>,
    #[serde(default)]
    pub(crate) indicates_list: Vec<RuleIndicatesRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) rule_confidence: Option<u8>,
}

fn default_persisted_tlp() -> String {
    normalize_tlp(None).to_string()
}

fn default_persisted_pap() -> String {
    normalize_pap(None).to_string()
}

/// Canonical, toolchain-independent FNV-1a over `salt` merged into the byte
/// stream. Used to build both halves of the minted indicator id.
fn fnv1a64(bytes: impl IntoIterator<Item = u8>, initial: u64) -> u64 {
    let mut hash = initial;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

const FNV1A64_OFFSET_BASIS: u64 = 0xcbf29ce484222325;

/// Deterministically mint a synthetic STIX indicator id from the source
/// pattern. The FNV-1a scheme is fixed by construction (salt + bytes), so the
/// same pattern always yields the same id, independent of the Rust toolchain.
pub(crate) fn mint_rule_indicator_id(source_pattern: &str) -> String {
    let pattern = source_pattern.trim();
    let left = fnv1a64(
        b"indicator"
            .iter()
            .copied()
            .chain(pattern.as_bytes().iter().copied()),
        FNV1A64_OFFSET_BASIS,
    );
    let right = fnv1a64(
        pattern
            .as_bytes()
            .iter()
            .copied()
            .chain(b"spuc-catalog-rule".iter().copied()),
        FNV1A64_OFFSET_BASIS,
    );

    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&left.to_be_bytes());
    bytes[8..].copy_from_slice(&right.to_be_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "indicator--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
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

/// Read the store strictly. A malformed existing file must never masquerade as
/// an empty catalog: callers must stop instead of overwriting user data.
pub(crate) fn load_persisted_rules(config_root: &Path) -> Result<Vec<PersistedRule>> {
    let path = rules_path(config_root);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// The lock file is separate from rules.json: replacing the JSON via rename
/// does not replace the inode whose exclusive lock coordinates writers.
fn with_rules_write_lock<T>(
    config_root: &Path,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let catalog_dir = config_root.join("catalog");
    fs::create_dir_all(&catalog_dir)?;
    let lock_path = catalog_dir.join("rules.json.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("locking {}", lock_path.display()))?;
    let result = operation();
    drop(lock); // Closing releases the advisory OS lock, including on errors.
    result
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let file_name = path.file_name().context("output path has no filename")?;
    let temp_name = format!(
        ".{}.tmp-{}-{}",
        file_name.to_string_lossy(),
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let temporary = parent.join(temp_name);
    let outcome = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if outcome.is_err() {
        // Never remove or truncate the previously committed rules.json.
        let _ = fs::remove_file(&temporary);
    }
    outcome.with_context(|| format!("atomically writing {}", path.display()))
}

fn save_persisted_rules_locked(config_root: &Path, rules: &[PersistedRule]) -> Result<()> {
    let raw = serde_json::to_vec_pretty(rules)?;
    atomic_write(&rules_path(config_root), &raw)
}

pub(crate) fn save_persisted_rules(config_root: &Path, rules: &[PersistedRule]) -> Result<()> {
    with_rules_write_lock(config_root, || {
        save_persisted_rules_locked(config_root, rules)
    })
}

/// Insert or replace by `indicator_id`. An exclusive file lock covers the
/// complete read/modify/commit cycle, across processes on local filesystems.
pub(crate) fn upsert_persisted_rule(config_root: &Path, rule: PersistedRule) -> Result<bool> {
    with_rules_write_lock(config_root, || {
        let mut rules = load_persisted_rules(config_root)?;
        let created = if let Some(existing) = rules
            .iter_mut()
            .find(|current| current.indicator_id == rule.indicator_id)
        {
            *existing = rule;
            false
        } else {
            rules.push(rule);
            true
        };
        save_persisted_rules_locked(config_root, &rules)?;
        Ok(created)
    })
}

pub(crate) fn delete_persisted_rule(config_root: &Path, indicator_id: &str) -> Result<bool> {
    with_rules_write_lock(config_root, || {
        let mut rules = load_persisted_rules(config_root)?;
        let before = rules.len();
        rules.retain(|current| current.indicator_id != indicator_id);
        if rules.len() == before {
            return Ok(false);
        }
        save_persisted_rules_locked(config_root, &rules)?;
        Ok(true)
    })
}

pub(crate) fn seed_marker_path(config_root: &Path) -> PathBuf {
    config_root.join("catalog").join("rules.json.seeded")
}

/// True when the description carries a decodable web-save metadata envelope;
/// this is the discriminator that separates user-saved rules from the
/// dual-flow's default derivation ability descriptions.
fn ability_description_is_web_save(description: &str) -> bool {
    let trimmed = description.trim();
    let Some(rest) = trimmed.strip_prefix("[SPUC_META_B64:") else {
        return false;
    };
    let Some((meta_b64, _remainder)) = rest.split_once(']') else {
        return false;
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(meta_b64.as_bytes()) else {
        return false;
    };
    serde_json::from_slice::<RuleMetadataEnvelope>(&decoded).is_ok()
}

/// One-time scan of the legacy `abilities/*.json` directory: every file whose
/// description carries an encoded web-save metadata envelope becomes a rule
/// in the translation-owned store. Legacy files are read-only; dummy and
/// corrupt files are skipped. Returns the number of rules seeded.
fn seed_rules_from_legacy_abilities_locked(config_root: &Path) -> Result<usize> {
    let abilities_dir = config_root.join("abilities");
    if !abilities_dir.is_dir() {
        return Ok(0);
    }
    let mut seeded = load_persisted_rules(config_root)?;
    let before = seeded.len();

    let mut files: Vec<PathBuf> = fs::read_dir(&abilities_dir)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    files.sort();

    for path in files {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        // Legacy abilities were written as single pretty JSON objects; a few
        // real-world files ended with concatenated objects (write bug), so
        // any parse failure skips the file entirely.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
            continue;
        };
        let id = value
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if id.starts_with("abl-dummy-") {
            continue;
        }
        let description = value
            .get("description")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !ability_description_is_web_save(description) {
            continue;
        }
        let Some(pattern) = value
            .get("source_pattern")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
        else {
            continue;
        };
        let name = value
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| pattern.clone());
        let metadata = decode_rule_metadata_description(Some(description.to_string()));
        let rule = PersistedRule {
            indicator_id: mint_rule_indicator_id(&pattern),
            source_pattern: pattern,
            name,
            description: metadata.description,
            tlp: metadata.tlp,
            pap: metadata.pap,
            ttp: metadata.ttp,
            target_platform: metadata.target_platform,
            observables: metadata.observables,
            indicates: metadata.indicates,
            indicates_list: metadata.indicates_list,
            rule_confidence: value
                .get("confidence")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u8::try_from(value).ok()),
        };
        if let Some(existing) = seeded
            .iter_mut()
            .find(|current| current.source_pattern.trim() == rule.source_pattern.trim())
        {
            *existing = rule;
        } else {
            seeded.push(rule);
        }
    }

    save_persisted_rules_locked(config_root, &seeded)?;
    Ok(seeded.len() - before)
}

/// Ensures the one-shot legacy seeding has run: guarded by a durable marker
/// written AFTER a successful persist, so deleting `rules.json` afterwards
/// never resurrects dropped rules.
pub(crate) fn ensure_rules_seeded(config_root: &Path) -> Result<()> {
    with_rules_write_lock(config_root, || {
        if seed_marker_path(config_root).exists() {
            return Ok(());
        }
        seed_rules_from_legacy_abilities_locked(config_root)?;
        let marker = serde_json::json!({
            "seeded_from_abilities": true,
            "utc": chrono::Utc::now().to_rfc3339()
        });
        atomic_write(
            &seed_marker_path(config_root),
            &serde_json::to_vec_pretty(&marker)?,
        )
    })
}

pub(crate) fn normalize_tlp(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
        "TLP:CLEAR" | "CLEAR" | "WHITE" | "TLP:WHITE" => "TLP:CLEAR",
        "TLP:GREEN" | "GREEN" => "TLP:GREEN",
        "TLP:AMBER" | "AMBER" => "TLP:AMBER",
        "TLP:AMBER+STRICT" | "AMBER+STRICT" => "TLP:AMBER+STRICT",
        "TLP:RED" | "RED" => "TLP:RED",
        _ => "TLP:GREEN",
    }
}

pub(crate) fn normalize_pap(raw: Option<&str>) -> &'static str {
    match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
        "PAP:CLEAR" | "CLEAR" | "WHITE" | "PAP:WHITE" => "PAP:CLEAR",
        "PAP:GREEN" | "GREEN" => "PAP:GREEN",
        "PAP:AMBER" | "AMBER" | "PAP:AMBER+STRICT" | "AMBER+STRICT" => "PAP:AMBER",
        "PAP:RED" | "RED" => "PAP:RED",
        _ => "PAP:GREEN",
    }
}

pub(crate) fn normalize_ttp(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_uppercase())
}

pub(crate) fn is_valid_stix_object_name(value: &str) -> bool {
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

pub(crate) fn normalize_indicates_relation(
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

pub(crate) fn normalize_indicates_relations(
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

pub(crate) fn normalize_observables(values: Vec<String>) -> Vec<String> {
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

pub(crate) fn push_unique_indicates(
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

pub(crate) fn encode_rule_metadata_description(
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

pub(crate) fn decode_rule_metadata_description(description: Option<String>) -> DecodedRuleMetadata {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "spuc_rules_test_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn sample_rule(pattern: &str, name: &str) -> PersistedRule {
        PersistedRule {
            indicator_id: mint_rule_indicator_id(pattern),
            source_pattern: pattern.to_string(),
            name: name.to_string(),
            description: Some("Phishing beacon".to_string()),
            tlp: "TLP:AMBER".to_string(),
            pap: "PAP:AMBER".to_string(),
            ttp: Some("T1111".to_string()),
            target_platform: Some("windows".to_string()),
            observables: vec!["process:command_line".to_string()],
            indicates: Some(RuleIndicatesRelation {
                stix_id: "malware--abc".to_string(),
                object_name: "Beaconer".to_string(),
            }),
            indicates_list: vec![RuleIndicatesRelation {
                stix_id: "malware--abc".to_string(),
                object_name: "Beaconer".to_string(),
            }],
            rule_confidence: Some(90),
        }
    }

    #[test]
    fn mint_rule_indicator_id_is_deterministic() {
        let pattern = "[process:name = 'cmd.exe']";
        assert!(mint_rule_indicator_id(pattern).starts_with("indicator--"));
        assert_eq!(
            mint_rule_indicator_id(pattern),
            mint_rule_indicator_id(" [process:name = 'cmd.exe'] ")
        );
        assert_ne!(
            mint_rule_indicator_id(pattern),
            mint_rule_indicator_id("[process:name = 'notepad.exe']")
        );
    }

    #[test]
    fn rules_store_roundtrips_upsert_update_delete() {
        let root = test_root("roundtrip");
        let rule = sample_rule("[process:name = 'cmd.exe']", "one");
        let created = upsert_persisted_rule(&root, rule.clone()).expect("upsert");
        assert!(created);
        let loaded = load_persisted_rules(&root).expect("load rules");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], rule);

        let mut updated = rule.clone();
        updated.name = "renamed".to_string();
        let created_again = upsert_persisted_rule(&root, updated.clone()).expect("upsert");
        assert!(!created_again);
        assert_eq!(
            load_persisted_rules(&root).expect("load rules"),
            vec![updated]
        );

        assert!(delete_persisted_rule(&root, &rule.indicator_id).expect("delete"));
        assert!(!delete_persisted_rule(&root, &rule.indicator_id).expect("delete again"));
        assert!(load_persisted_rules(&root).expect("load rules").is_empty());
    }

    #[test]
    fn rules_store_rejects_invalid_entries() {
        let root = test_root("skip-invalid");

        // A corrupt or non-array file must fail closed rather than appear empty.
        let corrupt = test_root("corrupt-file");
        fs::create_dir_all(rules_path(&corrupt).parent().unwrap()).expect("mkdir");
        fs::write(rules_path(&corrupt), "not an array at all\n").expect("write corrupt");
        assert!(load_persisted_rules(&corrupt).is_err());

        // Even a syntactically valid array with malformed entries must fail closed.
        let rule = sample_rule("[process:name = 'cmd.exe']", "one");
        upsert_persisted_rule(&root, rule.clone()).expect("upsert");
        fs::write(
            rules_path(&root),
            r#"[{"indicator_id":42},{"indicator_id":"indicator--00000000-0000-4000-8000-000000000000","source_pattern":"[file:name = 'x']","name":"valid"}]"#,
        )
        .expect("overwrite with invalid elements");

        assert!(load_persisted_rules(&root).is_err());
    }

    #[test]
    fn rules_store_tolerates_missing_optional_fields() {
        let root = test_root("missing-fields");
        let path = rules_path(&root);
        fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        fs::write(
            path,
            r#"[{"indicator_id":"indicator--00000000-0000-4000-8000-000000000000","source_pattern":"[file:name = 'a']","name":"min"}]"#,
        )
        .expect("write");
        let rules = load_persisted_rules(&root).expect("load rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "min");
        assert!(rules[0].observables.is_empty());
        assert_eq!(rules[0].tlp, "TLP:GREEN");
        assert_eq!(rules[0].pap, "PAP:GREEN");
    }

    #[test]
    fn metadata_codec_roundtrips_b64_envelope() {
        let description = "Phishing beacon";
        let encoded = encode_rule_metadata_description(
            Some(description),
            Some("amber"),
            Some("RED"),
            Some(" t1111 "),
            Some("Windows"),
            Some(&[
                " process ".to_string(),
                " file ".to_string(),
                "Process".to_string(),
            ]),
            Some(&[
                RuleIndicatesRelation {
                    stix_id: "malware--abc".to_string(),
                    object_name: "Beaconer".to_string(),
                },
                RuleIndicatesRelation {
                    stix_id: "malware--def".to_string(),
                    object_name: "Loader".to_string(),
                },
            ]),
        )
        .expect("encode");
        let decoded = decode_rule_metadata_description(Some(encoded));
        assert_eq!(decoded.description.as_deref(), Some(description));
        assert_eq!(decoded.tlp, "TLP:AMBER");
        assert_eq!(decoded.pap, "PAP:RED");
        assert_eq!(decoded.ttp.as_deref(), Some("T1111"));
        assert_eq!(decoded.target_platform.as_deref(), Some("windows"));
        assert_eq!(decoded.observables, vec!["file", "process"]);
        assert_eq!(decoded.indicates_list.len(), 2);
        assert_eq!(
            decoded.indicates.as_ref().map(|r| r.stix_id.as_str()),
            Some("malware--abc")
        );
    }

    #[test]
    fn metadata_codec_falls_back_to_tlp_pap_prefix() {
        let encoded = encode_rule_metadata_description(None, None, None, None, None, None, None)
            .expect("encode");
        // The JSON envelope path succeeds for simple payloads; the legacy
        // [TLP:|PAP:] prefix only appears when JSON serialization fails.
        assert!(encoded.starts_with("[SPUC_META_B64:"));
        let decoded = decode_rule_metadata_description(Some(encoded));
        assert_eq!(decoded.description, None);
        assert_eq!(decoded.tlp, "TLP:GREEN");
        assert_eq!(decoded.pap, "PAP:GREEN");
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

    // ---- Legacy seeding ----

    fn legacy_ability_fixture(
        id: &str,
        pattern: &str,
        name: &str,
        description: &str,
        confidence: u8,
    ) -> String {
        let ability = serde_json::json!({
            "schema_version": "1.0",
            "id": id,
            "name": name,
            "description": description,
            "ttp": null,
            "supported_platforms": ["windows"],
            "requires": [],
            "optional": [],
            "agent_capabilities": [],
            "actions": [{
                "id": "act-001",
                "title": "title",
                "action_type": "emit_process_command_line",
                "observable": "process",
                "operator": "MATCHES",
                "value": "^.*$",
                "safe_instructions": "safe"
            }],
            "source_pattern": pattern,
            "classification": "command-line-trace",
            "emulation_level": "trace-simulation",
            "confidence": confidence
        });
        serde_json::to_string_pretty(&ability).expect("fixture")
    }

    fn write_legacy_ability(root: &Path, file_name: &str, body: &str) -> PathBuf {
        let dir = root.join("abilities");
        fs::create_dir_all(&dir).expect("abilities dir");
        let path = dir.join(file_name);
        fs::write(&path, body).expect("write ability");
        path
    }

    fn seeded_web_save_ability(id: &str, pattern: &str) -> String {
        let description = encode_rule_metadata_description(
            Some("Beacon desc"),
            Some("amber"),
            Some("RED"),
            Some("t1111"),
            Some("windows"),
            Some(&["process".to_string()]),
            Some(&[RuleIndicatesRelation {
                stix_id: "malware--abc".to_string(),
                object_name: "Beaconer".to_string(),
            }]),
        )
        .expect("encoded description");
        legacy_ability_fixture(id, pattern, "Saved rule", &description, 88)
    }

    #[test]
    fn seed_recovers_only_encoded_web_save_abilities() {
        let root = test_root("seed");

        let saved_path = write_legacy_ability(
            &root,
            "abl-1.json",
            &seeded_web_save_ability("abl-1", "[process:name = 'cmd.exe']"),
        );
        let plain_path = write_legacy_ability(
            &root,
            "abl-2.json",
            &legacy_ability_fixture(
                "abl-2",
                "[file:name = 'evil.exe']",
                "Dual-flow default",
                "Defensive and controlled execution sample.",
                70,
            ),
        );
        let dummy_path = write_legacy_ability(
            &root,
            "abl-dummy-x.json",
            &seeded_web_save_ability("abl-dummy-x", "[process:name = 'dummy.exe']"),
        );
        let corrupt_path = write_legacy_ability(
            &root,
            "abl-3.json",
            &(legacy_ability_fixture("abl-3", "[file:name = 'x'] ", "bad", "plain", 70)
                + legacy_ability_fixture("abl-4", "[file:name = 'y']", "bad", "plain", 70)
                    .as_str()),
        );
        let before: [String; 4] = [
            fs::read_to_string(&saved_path).expect("saved"),
            fs::read_to_string(&plain_path).expect("plain"),
            fs::read_to_string(&dummy_path).expect("dummy"),
            fs::read_to_string(&corrupt_path).expect("corrupt"),
        ];

        ensure_rules_seeded(&root).expect("seed");

        let rules = load_persisted_rules(&root).expect("load rules");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.source_pattern, "[process:name = 'cmd.exe']");
        assert_eq!(rule.name, "Saved rule");
        assert_eq!(rule.description.as_deref(), Some("Beacon desc"));
        assert_eq!(rule.tlp, "TLP:AMBER");
        assert_eq!(rule.pap, "PAP:RED");
        assert_eq!(rule.ttp.as_deref(), Some("T1111"));
        assert_eq!(rule.target_platform.as_deref(), Some("windows"));
        assert_eq!(rule.observables, vec!["process".to_string()]);
        assert_eq!(
            rule.indicates.as_ref().map(|r| r.object_name.clone()),
            Some("Beaconer".to_string())
        );
        assert_eq!(rule.rule_confidence, Some(88));
        assert_eq!(
            rule.indicator_id,
            mint_rule_indicator_id(rule.source_pattern.trim())
        );

        // Legacy files must be untouched.
        let after: [String; 4] = [
            fs::read_to_string(&saved_path).expect("saved"),
            fs::read_to_string(&plain_path).expect("plain"),
            fs::read_to_string(&dummy_path).expect("dummy"),
            fs::read_to_string(&corrupt_path).expect("corrupt"),
        ];
        assert_eq!(before, after);

        // Marker durability.
        assert!(seed_marker_path(&root).exists());
    }

    #[test]
    fn ensure_rules_seeded_is_idempotent_and_deletions_are_durable() {
        let root = test_root("idempotent");
        write_legacy_ability(
            &root,
            "abl-1.json",
            &seeded_web_save_ability("abl-1", "[process:name = 'cmd.exe']"),
        );

        ensure_rules_seeded(&root).expect("seed");
        assert_eq!(load_persisted_rules(&root).expect("load rules").len(), 1);

        let id = mint_rule_indicator_id("[process:name = 'cmd.exe']");
        assert!(delete_persisted_rule(&root, &id).expect("delete"));

        // A dropped rule must NOT resurrect from the legacy abilities scan.
        ensure_rules_seeded(&root).expect("second pass");
        assert!(load_persisted_rules(&root).expect("load rules").is_empty());
    }

    #[test]
    fn ensure_rules_seeded_works_without_abilities_dir() {
        let root = test_root("fresh-machine");
        ensure_rules_seeded(&root).expect("seed without abilities");
        assert!(load_persisted_rules(&root).expect("load rules").is_empty());
        assert!(seed_marker_path(&root).exists());
    }

    #[test]
    fn corrupt_store_must_not_be_overwritten_by_upsert_or_delete() {
        let root = test_root("corruption-preservation");
        let path = rules_path(&root);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        let corrupt = b"[{invalid persisted JSON";
        fs::write(&path, corrupt).expect("seed corruption");
        let rule = sample_rule("[process:name = 'cmd.exe']", "one");
        assert!(upsert_persisted_rule(&root, rule.clone()).is_err());
        assert!(delete_persisted_rule(&root, &rule.indicator_id).is_err());
        assert_eq!(
            fs::read(&path).expect("read").as_slice(),
            corrupt.as_slice()
        );
    }

    #[test]
    fn concurrent_upserts_preserve_all_distinct_rules() {
        use std::sync::{Arc, Barrier};
        let root = test_root("parallel-upserts");
        let count = 20;
        let barrier = Arc::new(Barrier::new(count));
        let mut workers = Vec::new();
        for index in 0..count {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let pattern = format!("[process:pid = {index}]");
                barrier.wait();
                upsert_persisted_rule(&root, sample_rule(&pattern, "parallel"))
                    .expect("concurrent upsert");
            }));
        }
        for worker in workers {
            worker.join().expect("worker");
        }
        assert_eq!(
            load_persisted_rules(&root).expect("load rules").len(),
            count
        );
        let catalog_dir = root.join("catalog");
        let left_over_temps = fs::read_dir(&catalog_dir)
            .expect("catalog directory")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(left_over_temps, 0);
    }
}
