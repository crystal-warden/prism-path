// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The read only feed: a Unix socket (and, when asked, a loopback TCP port) that sends newline delimited
//! canon/2 records and takes in exactly one subscription line per connection.
//!
//! The drain loop never waits on a client. It offers each record to every client's bounded queue and a
//! full queue drops the record for that client alone, counting it, and the client is sent a `gap` record
//! with the count at the place in its stream where the records went missing, so a reader always knows
//! what it missed and can tell which leaves from the indexes. A writer whose socket accepts nothing for the write timeout is
//! disconnected. A client that sends anything after its subscription is disconnected too.

use crate::record::{self, Refusal, MAX_SUBSCRIPTION};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct FeedConfig {
    /// Records queued per client before the next is dropped for it.
    pub queue: usize,
    pub max_clients: usize,
    /// How long a client's socket may accept no bytes before the client is disconnected.
    pub write_timeout: Duration,
    /// How long a new connection has to send its subscription.
    pub subscribe_timeout: Duration,
    /// Unix peers allowed by user id (the collector's own is added by the caller when wanted).
    pub allowed_uids: Vec<u32>,
    /// Unix peers allowed by their primary group id.
    pub allowed_gids: Vec<u32>,
}

impl Default for FeedConfig {
    fn default() -> Self {
        FeedConfig {
            queue: 4096,
            max_clients: 16,
            write_timeout: Duration::from_secs(5),
            subscribe_timeout: Duration::from_secs(5),
            allowed_uids: Vec::new(),
            allowed_gids: Vec::new(),
        }
    }
}

/// What the feed has done, for `status` records and the tests.
#[derive(Debug, Default)]
pub struct Stats {
    pub accepted: AtomicU64,
    pub refused: AtomicU64,
    /// Disconnected because their socket took nothing for the write timeout.
    pub slow: AtomicU64,
    /// Disconnected because they sent bytes after the subscription.
    pub extra_input: AtomicU64,
    /// Records dropped from full client queues, summed over clients.
    pub dropped: AtomicU64,
}

/// A queued record, or the count of records dropped at this point in the stream.
enum Item {
    Line(Arc<Vec<u8>>),
    Gap(u64),
}

#[derive(Default)]
struct ClientState {
    queue: VecDeque<Item>,
    /// Lines in the queue; gaps do not count against the bound (consecutive drops share one).
    lines: usize,
    closed: bool,
}

struct Client {
    state: Mutex<ClientState>,
    ready: Condvar,
}

impl Client {
    fn new() -> Client {
        Client { state: Mutex::new(ClientState::default()), ready: Condvar::new() }
    }

    /// Queue a record unless the queue is full; true when it was dropped.
    fn offer(&self, line: &Arc<Vec<u8>>, cap: usize) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return false;
        }
        if state.lines >= cap {
            match state.queue.back_mut() {
                Some(Item::Gap(count)) => *count += 1,
                _ => state.queue.push_back(Item::Gap(1)),
            }
            return true;
        }
        state.queue.push_back(Item::Line(line.clone()));
        state.lines += 1;
        self.ready.notify_one();
        false
    }

    fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.ready.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
}

pub struct Hub {
    cfg: FeedConfig,
    source: String,
    hello: Arc<Vec<u8>>,
    clients: Mutex<Vec<Arc<Client>>>,
    pending: Mutex<Vec<Arc<Client>>>,
    pub stats: Stats,
}

impl Hub {
    /// A hub whose every client is first sent `hello` (a record value).
    pub fn new(cfg: FeedConfig, source: &str, hello: &Value) -> Arc<Hub> {
        let hello = Arc::new(record::frame(hello).expect("the hello record is canon/2 and short"));
        Arc::new(Hub { cfg, source: source.to_string(), hello, clients: Mutex::new(Vec::new()), pending: Mutex::new(Vec::new()), stats: Stats::default() })
    }

    pub fn config(&self) -> &FeedConfig {
        &self.cfg
    }

    /// Offer a framed record to every client. Never blocks on a client.
    pub fn publish(&self, line: Vec<u8>) {
        let line = Arc::new(line);
        let mut clients = self.clients.lock().unwrap();
        clients.retain(|client| !client.is_closed());
        for client in clients.iter() {
            if client.offer(&line, self.cfg.queue) {
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Start serving the clients that subscribed since the last call: each is sent `hello` and then the
    /// record `join` makes (the seal of the tree at this point), and from then on every record published.
    /// The drain loop calls this between records, so a client's first seal and its first leaf agree.
    pub fn admit(&self, join: impl FnOnce() -> Vec<u8>) {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            return;
        }
        let join = Arc::new(join());
        let mut clients = self.clients.lock().unwrap();
        for client in pending.drain(..) {
            {
                let mut state = client.state.lock().unwrap();
                state.queue.push_back(Item::Line(self.hello.clone()));
                state.queue.push_back(Item::Line(join.clone()));
                state.lines += 2;
            }
            client.ready.notify_one();
            clients.push(client);
        }
    }

    /// Clients being served or waiting to be admitted.
    pub fn client_count(&self) -> usize {
        let pending = self.pending.lock().unwrap().iter().filter(|client| !client.is_closed()).count();
        pending + self.clients.lock().unwrap().iter().filter(|client| !client.is_closed()).count()
    }

    /// Wait until every client's queue is empty, or `deadline`.
    pub fn flush(&self, deadline: Instant) {
        while Instant::now() < deadline {
            let busy = self.clients.lock().unwrap().iter().any(|client| {
                let state = client.state.lock().unwrap();
                !state.closed && !state.queue.is_empty()
            });
            if !busy {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stats_value(&self) -> Value {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        json!({
            "clients": self.client_count(),
            "accepted": get(&self.stats.accepted),
            "refused": get(&self.stats.refused),
            "slow": get(&self.stats.slow),
            "extra_input": get(&self.stats.extra_input),
            "dropped": get(&self.stats.dropped),
        })
    }

    fn peer_allowed(&self, uid: u32, gid: u32) -> bool {
        self.cfg.allowed_uids.contains(&uid) || self.cfg.allowed_gids.contains(&gid)
    }
}

/// A connected stream of either kind.
pub trait Conn: Read + Write + Send + Sized + 'static {
    fn try_clone_conn(&self) -> io::Result<Self>;
    fn set_read_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn shutdown_conn(&self);
    fn shutdown_write_conn(&self);
}

impl Conn for UnixStream {
    fn try_clone_conn(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn set_read_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn set_write_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
    fn shutdown_conn(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
    fn shutdown_write_conn(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

impl Conn for TcpStream {
    fn try_clone_conn(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn set_read_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn set_write_timeout_conn(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_write_timeout(timeout)
    }
    fn shutdown_conn(&self) {
        let _ = self.shutdown(Shutdown::Both);
    }
    fn shutdown_write_conn(&self) {
        let _ = self.shutdown(Shutdown::Write);
    }
}

/// The peer's (pid, uid, gid) as the kernel recorded them at connect (SO_PEERCRED).
pub fn peer_cred(stream: &UnixStream) -> io::Result<(i32, u32, u32)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`, a ucred.
    let result = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut libc::ucred as *mut libc::c_void, &mut len) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

fn refuse<S: Conn>(hub: &Hub, mut stream: S, reason: Refusal) {
    hub.stats.refused.fetch_add(1, Ordering::Relaxed);
    let _ = stream.set_write_timeout_conn(Some(Duration::from_millis(500)));
    if let Ok(line) = record::frame(&json!({"kind": "refused", "reason": reason.as_str()})) {
        let _ = stream.write_all(&line);
    }
    // End the stream, then read off (and discard) a bounded amount of what the client already sent, so
    // closing over unread input does not reset the connection before the client reads the refusal.
    stream.shutdown_write_conn();
    let _ = stream.set_read_timeout_conn(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 4096];
    let mut left = 64 * 1024;
    while left > 0 {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(count) => left -= count.min(left),
        }
    }
    stream.shutdown_conn();
}

/// Read the subscription within the configured time, byte bounded.
fn read_subscription<S: Conn>(hub: &Hub, stream: &mut S) -> Result<(), Option<Refusal>> {
    let deadline = Instant::now() + hub.cfg.subscribe_timeout;
    let mut received = Vec::with_capacity(MAX_SUBSCRIPTION);
    let mut chunk = [0u8; MAX_SUBSCRIPTION];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Some(Refusal::Timeout));
        }
        stream.set_read_timeout_conn(Some(left)).map_err(|_| None)?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err(None),
            Ok(count) => {
                received.extend_from_slice(&chunk[..count]);
                match record::check_subscription(&received) {
                    None => continue,
                    Some(Ok(())) => return Ok(()),
                    Some(Err(reason)) => return Err(Some(reason)),
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Err(Some(Refusal::Timeout)),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(None),
        }
    }
}

/// Serve one connection to its end. `peer` is the Unix peer's (uid, gid); TCP has none to check.
pub fn serve<S: Conn>(hub: Arc<Hub>, mut stream: S, peer: Option<(u32, u32)>) {
    if let Some((uid, gid)) = peer {
        if !hub.peer_allowed(uid, gid) {
            return refuse(&hub, stream, Refusal::Peer);
        }
    }
    if hub.client_count() >= hub.cfg.max_clients {
        return refuse(&hub, stream, Refusal::Busy);
    }
    match read_subscription(&hub, &mut stream) {
        Ok(()) => {}
        Err(Some(reason)) => return refuse(&hub, stream, reason),
        Err(None) => return stream.shutdown_conn(),
    }
    hub.stats.accepted.fetch_add(1, Ordering::Relaxed);
    let client = Arc::new(Client::new());
    hub.pending.lock().unwrap().push(client.clone());

    // Anything the client sends from now on is more than a subscription: the connection ends.
    if let Ok(mut reader) = stream.try_clone_conn() {
        let watched = client.clone();
        let watcher_hub = hub.clone();
        let _ = reader.set_read_timeout_conn(None);
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                match reader.read(&mut byte) {
                    Ok(0) => return, // the client closed its sending side; it may still read
                    Ok(_) => {
                        watcher_hub.stats.extra_input.fetch_add(1, Ordering::Relaxed);
                        watched.close();
                        reader.shutdown_conn();
                        return;
                    }
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        watched.close();
                        return;
                    }
                }
            }
        });
    } else {
        client.close();
    }

    let _ = stream.set_write_timeout_conn(Some(hub.cfg.write_timeout));
    loop {
        let item = {
            let mut state = client.state.lock().unwrap();
            while state.queue.is_empty() && !state.closed {
                state = client.ready.wait(state).unwrap();
            }
            if state.closed {
                break;
            }
            let item = state.queue.pop_front().unwrap();
            if matches!(item, Item::Line(_)) {
                state.lines -= 1;
            }
            item
        };
        let line = match item {
            Item::Line(line) => line,
            Item::Gap(dropped) => match record::frame(&json!({"kind": "gap", "source": hub.source, "dropped": dropped})) {
                Ok(gap) => Arc::new(gap),
                Err(_) => break,
            },
        };
        if let Err(error) = stream.write_all(&line) {
            if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                hub.stats.slow.fetch_add(1, Ordering::Relaxed);
            }
            break;
        }
    }
    client.close();
    stream.shutdown_conn();
}

/// Bind the Unix socket at `path` with mode 0660 and, when given, group `gid`, and serve it on a thread.
/// A socket left at the path by an earlier run is replaced; anything else there is refused.
pub fn listen_unix(hub: Arc<Hub>, path: &Path, gid: Option<u32>) -> io::Result<thread::JoinHandle<()>> {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(ErrorKind::AlreadyExists, format!("{} exists and is not a socket", path.display())));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let hub = hub.clone();
            thread::spawn(move || {
                let peer = peer_cred(&stream).ok().map(|(_pid, uid, gid)| (uid, gid));
                match peer {
                    Some(peer) => serve(hub, stream, Some(peer)),
                    None => refuse(&hub, stream, Refusal::Peer),
                }
            });
        }
    }))
}

/// True for the loopback addresses the TCP listener may bind.
pub fn is_loopback(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Serve the feed on a loopback TCP address. A non loopback address is refused.
pub fn listen_tcp(hub: Arc<Hub>, addr: SocketAddr) -> io::Result<(SocketAddr, thread::JoinHandle<()>)> {
    if !is_loopback(&addr) {
        return Err(io::Error::new(ErrorKind::InvalidInput, format!("{addr} is not a loopback address")));
    }
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    Ok((bound, thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let hub = hub.clone();
            thread::spawn(move || serve(hub, stream, None));
        }
    })))
}
