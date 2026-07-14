//! Local TCP relay proxy.
//!
//! Instead of hooking the many Winsock read/write entry points (send, recv,
//! WSASend, WSARecv, IOCP completions, …) and fighting their async/race-prone
//! edge cases, Tihulu now only hooks the initial TCP `connect`/`WSAConnect`
//! calls. At connect time the debugger rewrites the destination `sockaddr` so
//! the target dials a loopback listener owned by this module instead of the
//! real server.
//!
//! For every redirected connection we:
//!   1. bind a fresh loopback listener on a random ephemeral port,
//!   2. accept the target's connection,
//!   3. open a matching connection to the *original* destination,
//!   4. relay every byte transparently in both directions, and
//!   5. tee a copy of every byte to the TLS parser (via [`ProxyEvent`]).
//!
//! Because the relay is a pure TCP byte pump (it never terminates TLS), the
//! end-to-end TLS session is still negotiated between the target and the real
//! server — the target derives the genuine session secrets in its own memory,
//! exactly where the CALL-probe / fallback memory scanners look for them.

#![cfg(windows)]

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::tls_types::Direction;

/// Per-pump read buffer size.
const RELAY_BUF: usize = 32 * 1024;
/// How long a listener waits for the target to actually connect before
/// giving up and tearing the relay down (avoids leaking idle threads).
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Connect timeout for the upstream (original-destination) socket.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// Events emitted by relay threads and consumed by the debug-tracker event
/// loop. Carrying owned byte buffers keeps the relay threads decoupled from
/// the (single-threaded) TLS parser living in the tracker.
pub enum ProxyEvent {
    /// A chunk of relayed payload for `conn_id` in direction `dir`.
    Data {
        conn_id: u64,
        dir: Direction,
        data: Vec<u8>,
    },
    /// The relayed connection has been fully torn down.
    Closed { conn_id: u64 },
}

/// Owns the channel sender handed to every relay thread. One per
/// `DebugTracker`; the matching [`Receiver`] is drained by the event loop.
pub struct ProxyManager {
    tx: Sender<ProxyEvent>,
    verbose: bool,
}

impl ProxyManager {
    /// Create a manager together with the receiver the event loop drains.
    pub fn new(verbose: bool) -> (Self, Receiver<ProxyEvent>) {
        let (tx, rx) = channel();
        (Self { tx, verbose }, rx)
    }

    /// Bind a loopback listener on a random ephemeral port, spawn the relay
    /// thread for `conn_id`, and return the chosen port. The caller rewrites
    /// the target's `connect` destination to `127.0.0.1:<port>` so the next
    /// inbound connection on this listener is the target itself.
    pub fn start_connection(&self, conn_id: u64, dest: SocketAddr) -> std::io::Result<u16> {
        let listener = bind_random_loopback()?;
        let port = listener.local_addr()?.port();
        let tx = self.tx.clone();
        let verbose = self.verbose;
        std::thread::Builder::new()
            .name(format!("tihulu-relay-{}", conn_id))
            .spawn(move || relay_connection(conn_id, listener, dest, tx, verbose))?;
        Ok(port)
    }
}

/// Try a handful of random ephemeral ports, then fall back to an OS-assigned
/// one. Always binds to the IPv4 loopback so the rewritten `sockaddr_in` the
/// target sees is well-formed regardless of the original address family.
fn bind_random_loopback() -> std::io::Result<TcpListener> {
    for _ in 0..16 {
        let port = random_ephemeral_port();
        if let Ok(l) = TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
            return Ok(l);
        }
    }
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
}

/// Cheap, dependency-free PRNG in the dynamic/ephemeral port range
/// (49152-65535). Seeded once from the wall clock and advanced via xorshift.
fn random_ephemeral_port() -> u16 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            ^ (std::process::id() as u64).rotate_left(32);
        x = seed | 1;
    }
    // xorshift64
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    49152 + (x % (65535 - 49152 + 1)) as u16
}

/// Relay-thread entry point: accept the target, dial the real destination,
/// then pump bytes both ways until either side closes.
fn relay_connection(
    conn_id: u64,
    listener: TcpListener,
    dest: SocketAddr,
    tx: Sender<ProxyEvent>,
    verbose: bool,
) {
    let inbound = match accept_with_timeout(&listener) {
        Some(s) => s,
        None => {
            if verbose {
                crate::logln!("[dbg] relay {}: target never connected", conn_id);
            }
            let _ = tx.send(ProxyEvent::Closed { conn_id });
            return;
        }
    };
    let _ = inbound.set_nodelay(true);

    let outbound = match TcpStream::connect_timeout(&dest, UPSTREAM_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            crate::logln!(
                "[!] relay {}: upstream connect to {} failed: {}",
                conn_id, dest, e
            );
            let _ = tx.send(ProxyEvent::Closed { conn_id });
            return;
        }
    };
    let _ = outbound.set_nodelay(true);

    // Two independent halves share each socket via try_clone: one handle
    // reads, the peer handle writes.
    let (in_read, in_write) = match split(inbound) {
        Some(p) => p,
        None => {
            let _ = tx.send(ProxyEvent::Closed { conn_id });
            return;
        }
    };
    let (out_read, out_write) = match split(outbound) {
        Some(p) => p,
        None => {
            let _ = tx.send(ProxyEvent::Closed { conn_id });
            return;
        }
    };

    // client -> server (Direction::Out)
    let tx_out = tx.clone();
    let up = std::thread::spawn(move || {
        pump(in_read, out_write, Direction::Out, conn_id, tx_out);
    });
    // server -> client (Direction::In)
    pump(out_read, in_write, Direction::In, conn_id, tx.clone());
    let _ = up.join();

    let _ = tx.send(ProxyEvent::Closed { conn_id });
}

/// Poll-accept a single connection, honouring [`ACCEPT_TIMEOUT`]. Returns the
/// accepted, blocking stream or `None` on timeout/error.
fn accept_with_timeout(listener: &TcpListener) -> Option<TcpStream> {
    if listener.set_nonblocking(true).is_err() {
        // Fall back to a plain blocking accept.
        return listener.accept().ok().map(|(s, _)| s);
    }
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    let stream = loop {
        match listener.accept() {
            Ok((s, _)) => break Some(s),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break None,
        }
    };
    if let Some(ref s) = stream {
        let _ = s.set_nonblocking(false);
    }
    stream
}

/// Clone a stream into a (read-half, write-half) pair.
fn split(stream: TcpStream) -> Option<(TcpStream, TcpStream)> {
    let clone = stream.try_clone().ok()?;
    Some((stream, clone))
}

/// Copy bytes from `from` to `to`, teeing a copy of every chunk to the TLS
/// parser via the channel. Half-closes the peer write side on EOF so the
/// opposite pump also drains and exits.
fn pump(mut from: TcpStream, mut to: TcpStream, dir: Direction, conn_id: u64, tx: Sender<ProxyEvent>) {
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                // Tee first so the parser still sees the bytes even if the
                // forward write fails on a half-open connection.
                let _ = tx.send(ProxyEvent::Data {
                    conn_id,
                    dir,
                    data: buf[..n].to_vec(),
                });
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    let _ = from.shutdown(Shutdown::Read);
}
