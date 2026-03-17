#![cfg_attr(target_os = "windows", allow(unused_imports, dead_code))]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use dumbvpn::{EndpointAddr, EndpointTicket, SecretKey};

fn dumbvpn_bin() -> &'static str {
    env!("CARGO_BIN_EXE_dumbvpn")
}

fn wait2() -> Arc<Barrier> {
    Arc::new(Barrier::new(2))
}

const TIMEOUT: Duration = Duration::from_secs(30);

/// Pre-generated secret for a test endpoint.
struct TestSecret {
    secret_hex: String,
    public: iroh::PublicKey,
}

fn test_secret() -> TestSecret {
    let secret = SecretKey::generate(&mut rand::rng());
    TestSecret {
        secret_hex: hex::encode(secret.to_bytes()),
        public: secret.public(),
    }
}

/// The shared network secret used for all tests.
const TEST_NETWORK_SECRET: &str = "test-network-secret";

/// Apply common test env vars to a duct command expression.
fn test_env(cmd: duct::Expression, secret: &TestSecret) -> duct::Expression {
    cmd.env_remove("RUST_LOG")
        .env("DUMBVPN_LOCAL_ONLY", "1")
        .env("IROH_SECRET", &secret.secret_hex)
        .env("DUMBVPN_NETWORK_SECRET", TEST_NETWORK_SECRET)
}

/// Get a free TCP port by briefly binding to port 0.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll until a file appears and contains a non-empty value, then return its
/// contents as a string.
fn wait_for_file(path: &Path, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = std::fs::read_to_string(path) {
            if !content.is_empty() {
                return content;
            }
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Read the port file written by `--port-path` and construct a ticket.
fn read_ticket(port_path: &Path, public: &iroh::PublicKey, timeout: Duration) -> String {
    let port_str = wait_for_file(port_path, timeout);
    let port: u16 = port_str.trim().parse().unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let endpoint_addr = EndpointAddr::new(*public).with_ip_addr(addr);
    EndpointTicket::new(endpoint_addr).to_string()
}

/// Poll until a TCP connection to `addr` succeeds, then return the stream.
fn wait_for_tcp_connect(addr: &str, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(stream) = TcpStream::connect(addr) {
            return stream;
        }
        if Instant::now() >= deadline {
            panic!("timeout waiting for TCP connection to {addr}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Verify that a wrong network secret causes the connection to fail.
#[test]
fn connect_listen_wrong_secret() {
    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let _listen = test_env(
        duct::cmd(dumbvpn_bin(), ["listen", "--port-path", &port_path]),
        &listen_secret,
    )
    .stdin_bytes(b"hello from listen")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    // Connect with a different network secret — should fail.
    let connect = duct::cmd(dumbvpn_bin(), ["connect", &ticket])
        .env_remove("RUST_LOG")
        .env("DUMBVPN_LOCAL_ONLY", "1")
        .env("IROH_SECRET", &connect_secret.secret_hex)
        .env("DUMBVPN_NETWORK_SECRET", "wrong-secret")
        .stdin_bytes(b"hello from connect")
        .stderr_null()
        .stdout_capture()
        .unchecked()
        .run()
        .unwrap();

    assert!(!connect.status.success());
}

/// Tests the basic functionality of the connect and listen pair
///
/// Connect and listen both write a limited amount of data and then EOF.
/// The interaction should stop when both sides have EOF'd.
#[test]
fn connect_listen_happy() {
    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let listen_to_connect = b"hello from listen";
    let connect_to_listen = b"hello from connect";

    let listen = test_env(
        duct::cmd(dumbvpn_bin(), ["listen", "--port-path", &port_path]),
        &listen_secret,
    )
    .stdin_bytes(listen_to_connect)
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let connect = test_env(
        duct::cmd(dumbvpn_bin(), ["connect", &ticket]),
        &connect_secret,
    )
    .stdin_bytes(connect_to_listen)
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    assert!(connect.status.success());
    assert_eq!(&connect.stdout, listen_to_connect);

    let listen_out = listen.wait().unwrap();
    assert_eq!(&listen_out.stdout, connect_to_listen);
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_connect() {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;

    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let listen = test_env(
        duct::cmd(dumbvpn_bin(), ["listen", "--port-path", &port_path]),
        &listen_secret,
    )
    .stdin_bytes(b"hello from listen\n")
    .stderr_null()
    .stdout_capture()
    .reader()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let mut connect = test_env(
        duct::cmd(dumbvpn_bin(), ["connect", &ticket]),
        &connect_secret,
    )
    .stderr_null()
    .stdout_capture()
    .reader()
    .unwrap();

    // wait until we get data from the listen process
    let mut buf = [0u8; 1];
    connect.read_exact(&mut buf).unwrap();

    for pid in connect.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    // we don't care about the results. This test is just to make sure that the
    // listen command stops when the connect command stops.
    drop(listen);
    connect.read_to_end(&mut tmp).ok();
}

#[cfg(unix)]
#[test]
fn connect_listen_ctrlc_listen() {
    use nix::sys::signal::{self, Signal};
    use nix::unistd::Pid;

    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let mut listen = test_env(
        duct::cmd(dumbvpn_bin(), ["listen", "--port-path", &port_path]),
        &listen_secret,
    )
    .stderr_null()
    .stdout_capture()
    .reader()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let mut connect = test_env(
        duct::cmd(dumbvpn_bin(), ["connect", &ticket]),
        &connect_secret,
    )
    .stderr_null()
    .stdout_capture()
    .reader()
    .unwrap();

    // Give the connection time to establish before sending SIGINT.
    // iroh handles retries internally, but we need the connection to be up
    // before killing the listener to test graceful shutdown.
    std::thread::sleep(Duration::from_secs(1));
    for pid in listen.pids() {
        signal::kill(Pid::from_raw(pid as i32), Signal::SIGINT).unwrap();
    }

    let mut tmp = Vec::new();
    listen.read_to_end(&mut tmp).ok();
    connect.read_to_end(&mut tmp).ok();
}

#[test]
#[cfg(unix)]
#[ignore = "flaky: race between TCP backend write and connect"]
fn listen_tcp_happy() {
    let b1 = wait2();
    let b2 = b1.clone();
    let tcp_port = free_port();
    let host_port = format!("localhost:{tcp_port}");
    let host_port_2 = host_port.clone();
    std::thread::spawn(move || {
        let server = TcpListener::bind(host_port_2).unwrap();
        b1.wait();
        let (mut stream, _addr) = server.accept().unwrap();
        stream.write_all(b"hello from tcp").unwrap();
        stream.flush().unwrap();
        drop(stream);
    });
    b2.wait();

    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let _listen_tcp = test_env(
        duct::cmd(
            dumbvpn_bin(),
            [
                "listen-tcp",
                "--host",
                &host_port,
                "--port-path",
                &port_path,
            ],
        ),
        &listen_secret,
    )
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let connect = test_env(
        duct::cmd(dumbvpn_bin(), ["connect", &ticket]),
        &connect_secret,
    )
    .stderr_null()
    .stdout_capture()
    .stdin_bytes(b"hello from connect")
    .unchecked()
    .run()
    .unwrap();

    assert_eq!(&connect.stdout, b"hello from tcp");
}

#[test]
fn connect_tcp_happy() {
    let tcp_port = free_port();
    let host_port = format!("localhost:{tcp_port}");

    let listen_secret = test_secret();
    let connect_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let _listen = test_env(
        duct::cmd(dumbvpn_bin(), ["listen", "--port-path", &port_path]),
        &listen_secret,
    )
    .stdin_bytes(b"hello from listen\n")
    .stderr_null()
    .stdout_capture()
    .start()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let _connect_tcp = test_env(
        duct::cmd(
            dumbvpn_bin(),
            ["connect-tcp", "--addr", &host_port, &ticket],
        ),
        &connect_secret,
    )
    .stderr_null()
    .stdout_null()
    .start()
    .unwrap();

    // Wait for connect-tcp to bind its TCP port.
    let mut conn = wait_for_tcp_connect(&host_port, Duration::from_secs(10));
    conn.write_all(b"hello from tcp").unwrap();
    conn.flush().unwrap();
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf, b"hello from listen\n");
}

/// Integration test for Unix-domain socket tunneling.
#[cfg(all(test, unix))]
mod unix_socket_tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::*;

    /// Polls until the condition returns true or timeout is reached.
    fn wait_until<F>(timeout: Duration, mut condition: F)
    where
        F: FnMut() -> bool,
    {
        let deadline = Instant::now() + timeout;
        while !condition() {
            if Instant::now() >= deadline {
                panic!("timeout waiting for condition");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Waits until a filesystem path exists.
    fn wait_for_path<P: AsRef<Path>>(path: P, timeout: Duration) {
        let p = path.as_ref().to_path_buf();
        wait_until(timeout, move || p.exists());
    }

    /// Generate a temp directory with a Unix socket path
    fn temp_socket_path() -> (TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let socket_path = temp_dir.path().join("test.sock");
        (temp_dir, socket_path)
    }

    /// Helper to drain stderr from a process in a background thread
    fn drain_stderr(
        stderr: std::process::ChildStderr,
        prefix: &'static str,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("[{prefix}] {line}");
            }
        })
    }

    /// A dummy unix server that accepts multiple connections and handles them
    /// properly.
    fn dummy_unix_server(
        socket_path: PathBuf,
        barrier: Arc<Barrier>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let _ = std::fs::remove_file(&socket_path);
            let listener = UnixListener::bind(&socket_path).unwrap();
            barrier.wait();
            for stream in listener.incoming() {
                if let Ok(mut stream) = stream {
                    std::thread::spawn(move || {
                        let mut buf = vec![0; 1024];
                        if let Ok(n) = stream.read(&mut buf) {
                            if 0 < n && stream.write_all(b"hello from unix").is_ok() {
                                stream.shutdown(Shutdown::Write).ok();
                            }
                        }
                        while 0 < stream.read(&mut buf).unwrap_or(0) {}
                    });
                } else {
                    break;
                }
            }
        })
    }

    #[test]
    fn unix_socket_roundtrip() {
        let (_tmp_dir, backend_sock) = temp_socket_path();
        let client_sock = backend_sock.with_extension("client");

        let barrier = Arc::new(Barrier::new(2));
        let _backend_thread = dummy_unix_server(backend_sock.clone(), barrier.clone());
        barrier.wait();

        // Actively probe the backend server to ensure it's accepting connections.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if UnixStream::connect(&backend_sock).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if UnixStream::connect(&backend_sock).is_err() {
            panic!("backend server not connectable after 5s");
        }

        let listen_secret = test_secret();
        let connect_secret = test_secret();
        let port_file = tempfile::NamedTempFile::new().unwrap();
        let port_path = port_file.path().to_str().unwrap().to_string();

        // Launch listen-unix targeting the backend.
        let mut listen_proc = std::process::Command::new(dumbvpn_bin())
            .args([
                "listen-unix",
                "--socket-path",
                backend_sock.to_str().unwrap(),
                "--port-path",
                &port_path,
            ])
            .env_remove("RUST_LOG")
            .env("DUMBVPN_LOCAL_ONLY", "1")
            .env("IROH_SECRET", &listen_secret.secret_hex)
            .env("DUMBVPN_NETWORK_SECRET", TEST_NETWORK_SECRET)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn listen-unix");

        let listen_stderr = listen_proc.stderr.take().unwrap();
        let listen_stderr_thread = drain_stderr(listen_stderr, "listen-unix-stderr");

        let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

        // Launch connect-unix, exposing the client socket.
        let mut connect_proc = std::process::Command::new(dumbvpn_bin())
            .args([
                "connect-unix",
                "--socket-path",
                client_sock.to_str().unwrap(),
                &ticket,
            ])
            .env_remove("RUST_LOG")
            .env("DUMBVPN_LOCAL_ONLY", "1")
            .env("IROH_SECRET", &connect_secret.secret_hex)
            .env("DUMBVPN_NETWORK_SECRET", TEST_NETWORK_SECRET)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn connect-unix");

        let connect_stderr = connect_proc.stderr.take().unwrap();
        let connect_stderr_thread = drain_stderr(connect_stderr, "connect-unix-stderr");

        // Wait for connect-unix to create its socket.
        wait_for_path(&client_sock, Duration::from_secs(5));

        // Perform the end-to-end exchange.
        let mut client = UnixStream::connect(&client_sock).expect("connect to client socket");
        client
            .write_all(b"hello from client")
            .expect("client write");

        let mut reply = Vec::new();
        client.read_to_end(&mut reply).expect("client read");
        assert_eq!(&reply, b"hello from unix");

        // Clean up child processes.
        listen_proc.kill().ok();
        listen_proc.wait().ok();
        connect_proc.kill().ok();
        connect_proc.wait().ok();
        listen_stderr_thread.join().ok();
        connect_stderr_thread.join().ok();
    }
}

/// Test that list-nodes returns at least the listener's own entry.
#[test]
fn list_nodes_returns_self() {
    let listen_secret = test_secret();
    let query_secret = test_secret();
    let port_file = tempfile::NamedTempFile::new().unwrap();
    let port_path = port_file.path().to_str().unwrap().to_string();

    let _listen = test_env(
        duct::cmd(
            dumbvpn_bin(),
            ["listen", "--port-path", &port_path, "--node-name", "mynode"],
        ),
        &listen_secret,
    )
    .stdin_bytes(b"")
    .stderr_null()
    .stdout_null()
    .start()
    .unwrap();

    let ticket = read_ticket(port_file.path(), &listen_secret.public, TIMEOUT);

    let output = test_env(
        duct::cmd(dumbvpn_bin(), ["list-nodes", &ticket]),
        &query_secret,
    )
    .stderr_null()
    .stdout_capture()
    .run()
    .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("mynode"),
        "expected 'mynode' in output, got: {stdout}"
    );
}
