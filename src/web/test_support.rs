//! Test-only shared helpers for web module tests.
//!
//! Multiple test helpers in this crate swap `SPUC_CONFIG_DIR` in and out for
//! isolated config roots. Test threads run in parallel, so every swapper must
//! serialize behind ONE shared lock that also guards the process-global env
//! access; otherwise concurrent readers (and other swappers) observe the
//! wrong directory and fail nondeterministically.

#![cfg(test)]

use std::fs;
use std::sync::{Mutex, OnceLock};

pub(crate) fn with_shared_test_env_lock<T>(run: impl FnOnce() -> T) -> T {
    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = TEST_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("shared test-env lock poisoned");
    run()
}

pub(crate) fn with_test_config_dir<T>(tag: &str, run: impl FnOnce() -> T) -> T {
    with_shared_test_env_lock(move || {
        let dir =
            std::env::temp_dir().join(format!("spuc_web_test_{}_{}", tag, std::process::id()));
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
    })
}
