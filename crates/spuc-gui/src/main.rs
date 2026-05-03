use anyhow::{anyhow, Context, Result};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

const WINDOW_LABEL: &str = "main";
const WINDOW_TITLE_EN: &str = "SPUC: A behavioural IOC mapping lab";
const WINDOW_TITLE_ES: &str = "SPUC: un laboratorio de mapeo de IOC conductuales";
const SERVER_HOST: &str = "127.0.0.1";
const READY_TIMEOUT: Duration = Duration::from_secs(15);

struct AppState {
    sidecar: Mutex<Option<Child>>,
}

fn main() -> Result<()> {
    let server_port = choose_available_port()?;
    let sidecar = spawn_server_sidecar(server_port)?;
    let target_url = format!("http://{SERVER_HOST}:{server_port}/");

    tauri::Builder::default()
        .manage(AppState {
            sidecar: Mutex::new(Some(sidecar)),
        })
        .setup(move |app| {
            let window = WebviewWindowBuilder::new(
                app,
                WINDOW_LABEL,
                WebviewUrl::App("loading.html".into()),
            )
            .title(localized_window_title())
            .inner_size(1560.0, 980.0)
            .min_inner_size(1280.0, 820.0)
            .resizable(true)
            .build()?;
            thread::spawn(move || {
                if let Err(error) = wait_for_server_ready(SERVER_HOST, server_port, READY_TIMEOUT)
                    .and_then(|_| {
                        let external = tauri::Url::parse(&target_url)
                            .context("cannot parse desktop web URL")?;
                        window
                            .navigate(external)
                            .map_err(|error| anyhow!("cannot navigate desktop window: {error}"))
                    })
                {
                    eprintln!("desktop web startup error: {error}");
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .map_err(|error| anyhow!("desktop runtime init error: {error}"))?
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    shutdown_sidecar(state);
                }
            }
        });

    Ok(())
}

fn spawn_server_sidecar(port: u16) -> Result<Child> {
    let server_bin = resolve_server_binary()?;
    Command::new(&server_bin)
        .arg("web")
        .arg("--port")
        .arg(port.to_string())
        .arg("--no-login")
        .arg("--no-open")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| {
            format!(
                "cannot start sidecar '{}'; build it with 'cargo build -p spuc-cli --bin spuc' or set SPUC_SERVER_BIN to the spuc binary path",
                server_bin.display()
            )
        })
}

fn choose_available_port() -> Result<u16> {
    let listener =
        TcpListener::bind((SERVER_HOST, 0)).context("cannot reserve local desktop port")?;
    let port = listener
        .local_addr()
        .context("cannot resolve reserved local desktop port")?
        .port();
    Ok(port)
}

fn wait_for_server_ready(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let health_url = format!("http://{host}:{port}/healthz");
    while start.elapsed() < timeout {
        match ureq::get(&health_url).call() {
            Ok(response) if response.status() == 200 => return Ok(()),
            Ok(_) | Err(_) => thread::sleep(Duration::from_millis(120)),
        }
    }
    Err(anyhow!("health endpoint did not return 200 in time"))
}

fn resolve_server_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("SPUC_SERVER_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let current_exe = std::env::current_exe().context("cannot resolve desktop binary path")?;
    if let Some(dir) = current_exe.parent() {
        let local = dir.join(server_binary_name());
        if local.exists() {
            return Ok(local);
        }
    }

    Ok(Path::new(server_binary_name()).to_path_buf())
}

fn server_binary_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "spuc.exe"
    } else {
        "spuc"
    }
}

fn localized_window_title() -> &'static str {
    let locale = std::env::var("SPUC_LOCALE")
        .ok()
        .or_else(|| std::env::var("LC_ALL").ok())
        .or_else(|| std::env::var("LC_MESSAGES").ok())
        .or_else(|| std::env::var("LANG").ok())
        .unwrap_or_default()
        .to_lowercase();

    if locale.starts_with("es") {
        WINDOW_TITLE_ES
    } else {
        WINDOW_TITLE_EN
    }
}

fn shutdown_sidecar(state: tauri::State<'_, AppState>) {
    let mut guard = state.sidecar.lock().expect("sidecar mutex poisoned");
    let Some(mut child) = guard.take() else {
        return;
    };
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::{
        choose_available_port, localized_window_title, server_binary_name, SERVER_HOST,
        WINDOW_TITLE_EN, WINDOW_TITLE_ES,
    };
    use std::net::TcpListener;

    #[test]
    fn choose_available_port_returns_bindable_local_port() {
        let port = match choose_available_port() {
            Ok(port) => port,
            Err(error) => {
                let details = format!("{error:#}");
                if details.contains("Operation not permitted")
                    || details.contains("Permission denied")
                {
                    return;
                }
                panic!("available port: {details}");
            }
        };
        assert!(port > 0);

        let listener = TcpListener::bind((SERVER_HOST, port)).expect("port can be rebound");
        drop(listener);
    }

    #[test]
    fn server_binary_name_matches_platform() {
        if cfg!(target_os = "windows") {
            assert_eq!(server_binary_name(), "spuc.exe");
        } else {
            assert_eq!(server_binary_name(), "spuc");
        }
    }

    #[test]
    fn localized_window_title_follows_spanish_locale_override() {
        std::env::set_var("SPUC_LOCALE", "es_ES.UTF-8");
        assert_eq!(localized_window_title(), WINDOW_TITLE_ES);
        std::env::set_var("SPUC_LOCALE", "en_US.UTF-8");
        assert_eq!(localized_window_title(), WINDOW_TITLE_EN);
        std::env::remove_var("SPUC_LOCALE");
    }
}
