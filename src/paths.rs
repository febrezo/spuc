use std::env;
use std::path::PathBuf;

pub fn spuc_config_root() -> Option<PathBuf> {
    if let Ok(custom) = env::var("SPUC_CONFIG_DIR") {
        if !custom.trim().is_empty() {
            return Some(PathBuf::from(custom));
        }
    }

    #[cfg(target_os = "windows")]
    {
        return env::var("APPDATA")
            .ok()
            .map(|base| PathBuf::from(base).join("spuc"));
    }

    #[cfg(target_os = "macos")]
    {
        return env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join("Library/Application Support/spuc"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join("spuc"));
            }
        }
        return env::var("HOME")
            .ok()
            .map(|home| PathBuf::from(home).join(".config/spuc"));
    }
}

#[allow(dead_code)]
pub fn abilities_dir() -> Option<PathBuf> {
    spuc_config_root().map(|p| p.join("abilities"))
}

pub fn campaigns_dir() -> Option<PathBuf> {
    spuc_config_root().map(|p| p.join("intrusion_sets"))
}
