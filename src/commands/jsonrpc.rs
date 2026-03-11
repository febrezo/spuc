use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader as IoBufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::services::translation::evaluate_rule_from_labels;
use crate::cli::ConversionMode;
use crate::ui::ansi::{BLUE, RED, RESET};

#[derive(Debug, Deserialize)]
struct RpcRequest {
    rule: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    sigma_targets: Vec<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    rule_confidence: Option<u8>,
}

#[derive(Debug, Serialize)]
struct RpcResult {
    target: String,
    runtime_status: String,
    conversion_confidence: u8,
    rule_confidence: Option<u8>,
    cause: Option<String>,
    summary: String,
    notes: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    ok: bool,
    results: Vec<RpcResult>,
    error: Option<String>,
}

pub(crate) fn run(port: u16, token: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let token = Arc::new(token.unwrap_or_else(generate_token));
    service_log_info(&format!("Service listening on http://127.0.0.1:{port}/rpc"));
    service_log_info(&format!("Bearer token: {}", token));
    service_log_info(&format!(
        "Example curl: {}",
        example_curl_command(port, token.as_ref())
    ));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token = Arc::clone(&token);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, &token) {
                        service_log_error(&format!("service error: {e}"));
                    }
                });
            }
            Err(e) => service_log_error(&format!("accept error: {e}")),
        }
    }
    Ok(())
}

fn service_log_info(msg: &str) {
    let ts = Utc::now().to_rfc3339();
    println!("{BLUE}[{ts} UTC+0]{RESET} {msg}");
}

fn service_log_error(msg: &str) {
    let ts = Utc::now().to_rfc3339();
    eprintln!("{RED}[{ts} UTC+0] {msg}{RESET}");
}

fn generate_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("spuc-{now:x}-{:x}", std::process::id())
}

fn handle_client(mut stream: TcpStream, token: &str) -> Result<()> {
    let mut reader = IoBufReader::new(&mut stream);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line)? == 0 {
        return Ok(());
    }

    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_http_json(
            &mut stream,
            400,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("bad request".to_string()),
            },
        );
    }
    let method = parts[0];
    let path = parts[1];

    let mut auth_header = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 || line == "\r\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let value = v.trim().to_string();
            if key == "authorization" {
                auth_header = value;
            } else if key == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
            }
        }
    }

    if method != "POST" || path != "/rpc" {
        return write_http_json(
            &mut stream,
            404,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("not found".to_string()),
            },
        );
    }

    let expected = format!("Bearer {token}");
    if auth_header != expected {
        return write_http_json(
            &mut stream,
            401,
            RpcResponse {
                ok: false,
                results: vec![],
                error: Some("unauthorized".to_string()),
            },
        );
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let request: RpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return write_http_json(
                &mut stream,
                400,
                RpcResponse {
                    ok: false,
                    results: vec![],
                    error: Some(format!("invalid JSON: {e}")),
                },
            );
        }
    };

    let response = handle_rpc(request);
    write_http_json(&mut stream, 200, response)
}

fn handle_rpc(request: RpcRequest) -> RpcResponse {
    if let Some(conf) = request.rule_confidence {
        if conf > 100 {
            return RpcResponse {
                ok: false,
                results: vec![],
                error: Some("rule_confidence must be in range 0..100".to_string()),
            };
        }
    }
    let mode = match request
        .mode
        .as_deref()
        .unwrap_or("strict")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "partial" => ConversionMode::Partial,
        _ => ConversionMode::Strict,
    };
    let results = match evaluate_rule_from_labels(
        &request.rule,
        &request.to,
        request.description.as_deref(),
        &request.sigma_targets,
        mode,
        request.rule_confidence,
    ) {
        Ok(rows) => rows
            .into_iter()
            .map(|row| RpcResult {
                target: row.target,
                runtime_status: row.runtime_status,
                conversion_confidence: row.conversion_confidence,
                rule_confidence: row.rule_confidence,
                cause: row.cause,
                summary: row.summary,
                notes: row.notes,
                output: row.output,
            })
            .collect(),
        Err(error) => {
            return RpcResponse {
                ok: false,
                results: vec![],
                error: Some(error.to_string()),
            };
        }
    };

    RpcResponse {
        ok: true,
        results,
        error: None,
    }
}

fn write_http_json(stream: &mut TcpStream, code: u16, payload: RpcResponse) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let body = serde_json::to_string(&payload)?;
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    )?;
    stream.flush()?;
    Ok(())
}

fn example_curl_command(port: u16, token: &str) -> String {
    format!(
        "curl -X POST 'http://127.0.0.1:{port}/rpc' -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' --data-raw \"{{\\\"rule\\\":\\\"[ipv4-addr:value = '1.1.1.1']\\\",\\\"to\\\":[\\\"sigma\\\"]}}\""
    )
}

#[cfg(test)]
mod tests {
    use super::example_curl_command;

    #[test]
    fn jsonrpc_example_curl_uses_valid_json_payload_format() {
        let cmd = example_curl_command(8080, "spuc-test-token");
        assert!(cmd.contains("--data-raw"));
        assert!(cmd.contains("\\\"rule\\\":\\\"[ipv4-addr:value = '1.1.1.1']\\\""));
        assert!(!cmd.contains("\\'"));
    }
}
