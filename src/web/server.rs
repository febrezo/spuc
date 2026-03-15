use anyhow::Result;
use chrono::Utc;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use crate::ui::ansi::{BLUE, RED, RESET, YELLOW};
use crate::web::api::{HttpRequest, HttpResponse, WebState, generate_secret, route};

pub(crate) fn run(
    port: u16,
    admin_user: &str,
    admin_password: Option<&str>,
    no_login: bool,
) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let generated = admin_password.is_none();
    let password = admin_password
        .map(str::to_string)
        .unwrap_or_else(|| generate_secret(25));

    let state = Arc::new(WebState::new(admin_user, &password, generated, no_login)?);
    log_info(&format!(
        "Web interface listening on http://127.0.0.1:{port}/"
    ));

    if no_login {
        log_info("Login disabled by --no-login. Browser enters directly as administrator.");
    } else if generated {
        println!("{YELLOW}Generated administrator password: {password}{RESET}");
    } else {
        log_info("Administrator password provided by CLI.");
    }

    log_info(
        "OAuth providers are read from environment variables (Google/GitHub). If missing, local login is used.",
    );
    start(listener, state)
}

pub(crate) fn start(listener: TcpListener, state: Arc<WebState>) -> Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_client(stream, &state) {
                        log_error(&format!("web error: {error}"));
                    }
                });
            }
            Err(error) => log_error(&format!("accept error: {error}")),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, state: &WebState) -> Result<()> {
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }

    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return write_response(
            &mut stream,
            HttpResponse::text(400, "text/plain; charset=utf-8", b"bad request".to_vec()),
        );
    }

    let method = parts[0].to_string();
    let raw_path = parts[1];
    let (path, query) = split_path_and_query(raw_path);
    let mut headers = std::collections::HashMap::new();
    let mut content_length = 0usize;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if key == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
            }
            headers.insert(key, value);
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let request = HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    };

    let response = match route(request, state) {
        Ok(response) => response,
        Err(error) => HttpResponse::text(
            500,
            "application/json; charset=utf-8",
            serde_json::to_vec_pretty(&serde_json::json!({
                "error": error.to_string(),
                "code": "internal_error"
            }))?,
        ),
    };

    write_response(&mut stream, response)
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) -> Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "OK",
    };

    let mut header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    );
    for (key, value) in response.headers {
        header.push_str(&format!("{}: {}\r\n", key, value));
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    stream.write_all(&response.body)?;
    Ok(())
}

fn split_path_and_query(raw: &str) -> (String, std::collections::HashMap<String, String>) {
    let mut query = std::collections::HashMap::new();
    if let Some((path, raw_query)) = raw.split_once('?') {
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            query.insert(percent_decode(key), percent_decode(value));
        }
        (path.to_string(), query)
    } else {
        (raw.to_string(), query)
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        match bytes[idx] {
            b'+' => {
                out.push(b' ');
                idx += 1;
            }
            b'%' if idx + 2 < bytes.len() => {
                let hex = &value[idx + 1..idx + 3];
                if let Ok(parsed) = u8::from_str_radix(hex, 16) {
                    out.push(parsed);
                    idx += 3;
                } else {
                    out.push(bytes[idx]);
                    idx += 1;
                }
            }
            byte => {
                out.push(byte);
                idx += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn log_info(message: &str) {
    let ts = Utc::now().to_rfc3339();
    println!("{BLUE}[{ts} UTC+0]{RESET} {message}");
}

fn log_error(message: &str) {
    let ts = Utc::now().to_rfc3339();
    eprintln!("{RED}[{ts} UTC+0] {message}{RESET}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    fn send_raw(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        stream.write_all(request.as_bytes()).expect("write");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut idle_reads = 0u8;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    idle_reads = 0;
                    buffer.extend_from_slice(&chunk[..n]);
                    if response_complete(&buffer) {
                        break;
                    }
                }
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock
                        || err.kind() == ErrorKind::TimedOut =>
                {
                    idle_reads = idle_reads.saturating_add(1);
                    if idle_reads >= 3 {
                        break;
                    }
                }
                Err(err) => panic!("read: {err}"),
            }
        }
        let buffer = String::from_utf8_lossy(&buffer).into_owned();
        buffer
    }

    fn response_complete(raw: &[u8]) -> bool {
        let marker = b"\r\n\r\n";
        let Some(header_end) = raw.windows(marker.len()).position(|w| w == marker) else {
            return false;
        };
        let header_len = header_end + marker.len();
        let headers = String::from_utf8_lossy(&raw[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if !name.trim().eq_ignore_ascii_case("Content-Length") {
                    return None;
                }
                value.trim().parse::<usize>().ok()
            })
            .unwrap_or(0);
        raw.len() >= header_len + content_length
    }

    #[test]
    fn web_server_serves_i18n_and_protected_routes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(WebState::new("admin", "secret-pass", false, false).expect("state"));
        let state_for_thread = Arc::clone(&state);
        std::thread::spawn(move || {
            start(listener, state_for_thread).expect("server");
        });
        std::thread::sleep(Duration::from_millis(120));

        let i18n = send_raw(port, "GET /i18n.json HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert!(i18n.contains("\"es\""));
        assert!(i18n.contains("SPUC"));
        assert!(i18n.contains("Import rules from file"));
        assert!(i18n.contains("\"nav.rulelab\": \"Laboratory\""));
        assert!(i18n.contains("\"rules.import.progress.reading\": \"Reading rules file...\""));

        let unauthorized = send_raw(
            port,
            "GET /api/tutorial/challenges HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(unauthorized.contains("401 Unauthorized"));

        let login_body = r#"{"username":"admin","password":"secret-pass"}"#;
        let login = send_raw(
            port,
            &format!(
                "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                login_body.len(),
                login_body
            ),
        );
        assert!(login.contains("200 OK"));
        let cookie = login
            .lines()
            .find(|line| line.starts_with("Set-Cookie: spuc_web_session="))
            .and_then(|line| {
                line.split_once(':')
                    .map(|(_, value)| value.trim().to_string())
            })
            .expect("session cookie");

        let tutorial = send_raw(
            port,
            &format!(
                "GET /api/tutorial/challenges HTTP/1.1\r\nHost: localhost\r\nCookie: {}\r\n\r\n",
                cookie
            ),
        );
        assert!(tutorial.contains("200 OK"));
        assert!(tutorial.contains("core001"));
    }

    #[test]
    fn no_login_mode_allows_access_without_cookie() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(WebState::new("admin", "secret-pass", false, true).expect("state"));
        let state_for_thread = Arc::clone(&state);
        std::thread::spawn(move || {
            start(listener, state_for_thread).expect("server");
        });
        std::thread::sleep(Duration::from_millis(120));

        let tutorial = send_raw(
            port,
            "GET /api/tutorial/challenges HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        assert!(tutorial.contains("200 OK"));
    }

    #[test]
    fn admin_can_toggle_oauth_provider_authorization() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(WebState::new("admin", "secret-pass", false, false).expect("state"));
        let state_for_thread = Arc::clone(&state);
        std::thread::spawn(move || {
            start(listener, state_for_thread).expect("server");
        });
        std::thread::sleep(Duration::from_millis(120));

        let login_body = r#"{"username":"admin","password":"secret-pass"}"#;
        let login = send_raw(
            port,
            &format!(
                "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                login_body.len(),
                login_body
            ),
        );
        assert!(login.contains("200 OK"));
        let cookie = login
            .lines()
            .find(|line| line.starts_with("Set-Cookie: spuc_web_session="))
            .and_then(|line| {
                line.split_once(':')
                    .map(|(_, value)| value.trim().to_string())
            })
            .expect("session cookie");

        let oauth_update_body = r#"{"authorized":true}"#;
        let oauth_update = send_raw(
            port,
            &format!(
                "POST /api/admin/oauth/providers/google/update HTTP/1.1\r\nHost: localhost\r\nCookie: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                cookie,
                oauth_update_body.len(),
                oauth_update_body
            ),
        );
        assert!(oauth_update.contains("200 OK"));

        let bootstrap = send_raw(
            port,
            &format!(
                "GET /api/bootstrap HTTP/1.1\r\nHost: localhost\r\nCookie: {}\r\n\r\n",
                cookie
            ),
        );
        assert!(bootstrap.contains("\"id\": \"google\""));
        assert!(bootstrap.contains("\"authorized\": true"));
    }

    #[test]
    fn percent_decoder_handles_spaces_and_utf8() {
        assert_eq!(percent_decode("spuc+web"), "spuc web");
        assert_eq!(percent_decode("regla%20uno"), "regla uno");
        assert_eq!(percent_decode("%C3%A1rbol"), "árbol");
    }
}
