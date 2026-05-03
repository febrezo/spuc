use anyhow::{Context, Result, anyhow};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tauri::{WebviewUrl, WebviewWindowBuilder};

use crate::web::api::{WebState, generate_secret};

const WINDOW_LABEL: &str = "main";
const WINDOW_TITLE: &str = "SPUC: A behavioural IOC mapping lab";

pub(crate) fn run(preferred_port: u16) -> Result<()> {
    let web_url = start_local_web(preferred_port)?;

    tauri::Builder::default()
        .setup(move |app| {
            let external = url::Url::parse(&web_url)?;
            WebviewWindowBuilder::new(app, WINDOW_LABEL, WebviewUrl::External(external))
                .title(WINDOW_TITLE)
                .inner_size(1440.0, 900.0)
                .min_inner_size(1200.0, 760.0)
                .resizable(true)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|error| anyhow!("desktop runtime error: {error}"))
}

fn start_local_web(preferred_port: u16) -> Result<String> {
    let listener = TcpListener::bind(("127.0.0.1", preferred_port))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .context("cannot bind local desktop listener")?;
    let port = listener
        .local_addr()
        .context("cannot resolve local desktop listener address")?
        .port();

    let password = generate_secret(25);
    let state = Arc::new(WebState::new("admin", &password, true, true)?);
    thread::spawn(move || {
        if let Err(error) = crate::web::server::start(listener, state) {
            eprintln!("desktop web runtime error: {error}");
        }
    });

    wait_for_web_ready(port, Duration::from_secs(3))?;
    Ok(format!("http://127.0.0.1:{port}/"))
}

fn wait_for_web_ready(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(anyhow!("desktop web runtime did not become ready in time"))
}

#[cfg(test)]
mod tests {
    use super::wait_for_web_ready;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn wait_for_web_ready_detects_open_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            drop(listener);
        });
        let ready = wait_for_web_ready(port, Duration::from_millis(500));
        assert!(ready.is_ok(), "port should be detected as reachable");
    }
}
