use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn spuc_bin() -> String {
    if let Ok(bin) = std::env::var("CARGO_BIN_EXE_spuc") {
        return bin;
    }
    let bin = "target/debug/spuc".to_string();
    let status = Command::new("cargo")
        .args(["build", "-q", "-p", "spuc-cli", "--bin", "spuc"])
        .status()
        .expect("failed to build spuc binary for tests");
    assert!(status.success(), "failed to build spuc binary for tests");
    assert!(Path::new(&bin).exists(), "spuc binary missing after build");
    bin
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("failed to reserve local port");
    listener.local_addr().expect("local addr").port()
}

fn wait_for_port(port: u16) {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("jsonrpc service did not start on port {port}");
}

fn start_jsonrpc_server(port: u16) -> Child {
    Command::new(spuc_bin())
        .args([
            "jsonrpc",
            "--port",
            &port.to_string(),
            "--token",
            "integration-test-token",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn jsonrpc server")
}

#[test]
fn jsonrpc_server_accepts_authenticated_requests() {
    let port = reserve_local_port();
    let mut child = start_jsonrpc_server(port);
    wait_for_port(port);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to jsonrpc");
    let payload = r#"{"rule":"[file:size = 25536]","to":["kql"]}"#;
    let request = format!(
        "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer integration-test-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );

    stream.write_all(request.as_bytes()).expect("send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );
    assert!(
        response.contains("\"ok\":true"),
        "response body did not report ok=true: {response}"
    );
    assert!(
        response.contains("\"target\":\"kql\""),
        "response body did not include kql target: {response}"
    );
}
