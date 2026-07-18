#![cfg(any(windows, target_os = "macos"))]

use std::env;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use codeischeap_process_attribution::resolve_loopback_client_pid;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn resolves_an_independent_loopback_client_process() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener must bind");
    listener
        .set_nonblocking(true)
        .expect("listener must become nonblocking");
    let server = listener.local_addr().expect("server address must exist");
    let child = Command::new(env::current_exe().expect("test executable must resolve"))
        .args([
            "--exact",
            "loopback_client_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("CIC_PROCESS_ATTRIBUTION_TEST_SERVER", server.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("client helper must start");
    let expected_pid = child.id();
    let _child = ChildGuard(child);
    let (_stream, client) = accept_before(&listener, Duration::from_secs(10));

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if resolve_loopback_client_pid(client, server).expect("socket query must succeed")
            == Some(expected_pid)
        {
            break;
        }
        assert!(Instant::now() < deadline, "client PID was not attributed");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
#[ignore]
fn loopback_client_helper() {
    let Ok(server) = env::var("CIC_PROCESS_ATTRIBUTION_TEST_SERVER") else {
        return;
    };
    let _stream = TcpStream::connect(server).expect("helper must connect");
    thread::sleep(Duration::from_secs(15));
}

fn accept_before(listener: &TcpListener, timeout: Duration) -> (TcpStream, std::net::SocketAddr) {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok(connection) => return connection,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "client helper did not connect");
                thread::sleep(Duration::from_millis(25));
            }
            Err(error) => panic!("client accept failed: {error}"),
        }
    }
}
