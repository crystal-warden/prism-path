// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! The collector's command line. README.md has every option and the systemd unit it is meant to run under.

use prismpath_collector::collector::{self, End, Run, Settings};
use prismpath_collector::decode::Kind;
use prismpath_collector::feed::{self, FeedConfig, Hub};
use prismpath_collector::privs;
use prismpath_collector::source::{KernelSource, RecordedSource, Source};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_signal: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

const USAGE: &str = "usage: prismpath-collector --source gnet|selector [--maps-dir DIR | --ring PIN | --recorded FILE]
       --socket PATH [--socket-group NAME|GID] [--tcp 127.0.0.1:PORT] [--allow-uid UID]... [--allow-gid GID]...
       [--seal-interval-ms N] [--seal-count N] [--proof-window N] [--queue N] [--max-clients N] [--write-timeout-ms N] [--exit-when-drained]";

#[derive(Debug)]
struct Args {
    kind: Kind,
    maps_dir: Option<PathBuf>,
    ring: Option<PathBuf>,
    recorded: Option<PathBuf>,
    socket: PathBuf,
    socket_group: Option<String>,
    tcp: Option<SocketAddr>,
    feed: FeedConfig,
    settings: Settings,
}

fn number<T: std::str::FromStr>(flag: &str, value: Option<String>) -> Result<T, String> {
    value.as_deref().and_then(|text| text.parse().ok()).ok_or_else(|| format!("{flag} takes a number"))
}

fn parse(mut argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let (mut kind, mut maps_dir, mut ring, mut recorded, mut socket, mut socket_group, mut tcp) = (None, None, None, None, None, None, None);
    let mut feed = FeedConfig::default();
    let mut settings = Settings::default();
    while let Some(flag) = argv.next() {
        let mut value = || argv.next();
        match flag.as_str() {
            "--source" => kind = Some(value().as_deref().and_then(Kind::parse).ok_or("--source is gnet or selector")?),
            "--maps-dir" => maps_dir = Some(PathBuf::from(value().ok_or("--maps-dir takes a directory")?)),
            "--ring" => ring = Some(PathBuf::from(value().ok_or("--ring takes a pin path")?)),
            "--recorded" => recorded = Some(PathBuf::from(value().ok_or("--recorded takes a file")?)),
            "--socket" => socket = Some(PathBuf::from(value().ok_or("--socket takes a path")?)),
            "--socket-group" => socket_group = Some(value().ok_or("--socket-group takes a group")?),
            "--tcp" => tcp = Some(value().as_deref().and_then(|text| text.parse::<SocketAddr>().ok()).ok_or("--tcp takes ADDRESS:PORT")?),
            "--allow-uid" => feed.allowed_uids.push(number(&flag, value())?),
            "--allow-gid" => feed.allowed_gids.push(number(&flag, value())?),
            "--seal-interval-ms" => settings.seal_interval = Duration::from_millis(number(&flag, value())?),
            "--seal-count" => settings.seal_count = number(&flag, value())?,
            "--proof-window" => settings.proof_window = number(&flag, value())?,
            "--queue" => feed.queue = number(&flag, value())?,
            "--max-clients" => feed.max_clients = number(&flag, value())?,
            "--write-timeout-ms" => feed.write_timeout = Duration::from_millis(number(&flag, value())?),
            "--exit-when-drained" => settings.exit_when_drained = true,
            "--help" | "-h" => return Err(String::new()),
            other => return Err(format!("unknown option {other}")),
        }
    }
    let kind = kind.ok_or("--source is required")?;
    if [maps_dir.is_some(), ring.is_some(), recorded.is_some()].iter().filter(|given| **given).count() > 1 {
        return Err("give one of --maps-dir, --ring and --recorded".into());
    }
    if maps_dir.is_some() && kind != Kind::Gnet {
        return Err("--maps-dir is the governed net edge's pin directory".into());
    }
    if let Some(addr) = tcp {
        if !feed::is_loopback(&addr) {
            return Err(format!("--tcp {addr} is not a loopback address; the feed is never served off the host"));
        }
    }
    if settings.seal_interval.is_zero() || settings.seal_count == 0 || feed.queue == 0 || feed.max_clients == 0 {
        return Err("the seal interval and count, the queue and the client limit must be positive".into());
    }
    if (settings.proof_window as u64) < settings.seal_count {
        return Err("--proof-window must hold at least --seal-count leaves, so a client is always proved from the last seal it was sent".into());
    }
    if settings.proof_window > 1 << 24 {
        return Err("--proof-window is at most 16777216 leaves (512 MiB)".into());
    }
    if recorded.is_none() && ring.is_none() && maps_dir.is_none() && kind == Kind::Gnet {
        maps_dir = Some(PathBuf::from("/sys/fs/bpf/tc/globals"));
    }
    Ok(Args { kind, maps_dir, ring, recorded, socket: socket.ok_or("--socket is required")?, socket_group, tcp, feed, settings })
}

/// A group given by number or by its name in /etc/group.
fn resolve_group(text: &str) -> Result<u32, String> {
    if let Ok(gid) = text.parse::<u32>() {
        return Ok(gid);
    }
    let groups = std::fs::read_to_string("/etc/group").map_err(|error| format!("/etc/group: {error}"))?;
    groups
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let gid = fields.nth(1)?.parse::<u32>().ok()?;
            (name == text).then_some(gid)
        })
        .next()
        .ok_or_else(|| format!("no group {text} in /etc/group"))
}

fn fail(message: &str, code: u8) -> ExitCode {
    eprintln!("prismpath-collector: {message}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let mut args = match parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(message) if message.is_empty() => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => return fail(&format!("{message}\n{USAGE}"), 2),
    };
    // SAFETY: umask, geteuid, getuid and signal have no preconditions; the handler only stores an atomic.
    let (euid, uid) = unsafe {
        libc::umask(0o077);
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        (libc::geteuid(), libc::getuid())
    };
    let caps = match privs::current() {
        Ok(caps) => caps,
        Err(error) => return fail(&error.to_string(), 2),
    };
    if let Err(message) = privs::check_start(euid, &caps) {
        return fail(&message, 2);
    }
    if let Err(error) = privs::lock_down() {
        return fail(&format!("cannot set no_new_privs: {error}"), 2);
    }

    let mut source: Box<dyn Source> = if let Some(path) = &args.recorded {
        match RecordedSource::load(path) {
            Ok(source) => Box::new(source),
            Err(error) => return fail(&format!("{}: {error}", path.display()), 2),
        }
    } else {
        let ring = args.ring.clone().unwrap_or_else(|| match (&args.maps_dir, args.kind) {
            (Some(dir), _) => dir.join("gn_events"),
            (None, Kind::Selector) => PathBuf::from("/sys/fs/bpf/ppt_sel_receipts"),
            (None, Kind::Gnet) => PathBuf::from("/sys/fs/bpf/tc/globals/gn_events"),
        });
        match KernelSource::open(&ring, args.maps_dir.clone()) {
            Ok(source) => Box::new(source),
            Err(error) => return fail(&format!("cannot open the enforcer's pins (CAP_BPF and read access to them are needed): {error}"), 2),
        }
    };
    // The pins are open. CAP_BPF stays only while the counter maps are read (each read is a bpf(2) call);
    // CAP_PERFMON, every inheritable capability and the ambient set go now.
    let keep = if args.maps_dir.is_some() && args.recorded.is_none() { 1u64 << privs::CAP_BPF } else { 0 };
    if let Err(error) = privs::keep_only(keep) {
        return fail(&format!("cannot drop capabilities: {error}"), 2);
    }

    if !args.feed.allowed_uids.contains(&uid) {
        args.feed.allowed_uids.push(uid);
    }
    let gid = match args.socket_group.as_deref().map(resolve_group).transpose() {
        Ok(gid) => gid,
        Err(message) => return fail(&message, 2),
    };
    let session = collector::session_id();
    let hello = collector::hello(args.kind, &source.describe(), &session, &args.settings, args.feed.queue);
    let write_timeout = args.feed.write_timeout;
    let hub = Hub::new(args.feed, args.kind.name(), &hello);
    if let Err(error) = feed::listen_unix(hub.clone(), &args.socket, gid) {
        return fail(&format!("{}: {error}", args.socket.display()), 2);
    }
    if let Some(addr) = args.tcp {
        if let Err(error) = feed::listen_tcp(hub.clone(), addr) {
            return fail(&format!("{addr}: {error}"), 2);
        }
    }
    eprintln!("prismpath-collector: {} from {}, session {session}, feed on {}", args.kind.name(), source.describe(), args.socket.display());
    let mut run = Run::new(args.kind, session, &hub, args.settings);
    let end = run.run(source.as_mut(), &STOP);
    hub.flush(Instant::now() + write_timeout);
    let _ = std::fs::remove_file(&args.socket);
    eprintln!("prismpath-collector: {end:?} after {} records", run.sealer.count());
    match end {
        End::Stopped | End::Drained => ExitCode::SUCCESS,
        End::Corrupt(_) => ExitCode::from(3),
        End::Full => ExitCode::from(4),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Result<Args, String> {
        parse(text.split_whitespace().map(String::from))
    }

    #[test]
    fn options() {
        let parsed = args("--source gnet --socket /tmp/s").unwrap();
        assert_eq!(parsed.maps_dir, Some(PathBuf::from("/sys/fs/bpf/tc/globals")));
        assert!(args("--source gnet --socket /tmp/s --tcp 0.0.0.0:7000").unwrap_err().contains("not a loopback"));
        assert!(args("--source gnet --socket /tmp/s --tcp 192.168.1.2:7000").is_err());
        assert!(args("--source gnet --socket /tmp/s --tcp [::1]:7000").is_ok());
        assert!(args("--source selector --socket /tmp/s --maps-dir /x").is_err());
        assert!(args("--source gnet --socket /tmp/s --ring /a --recorded /b").is_err());
        assert!(args("--source other --socket /tmp/s").is_err());
        assert!(args("--source gnet").is_err());
        assert!(args("--source gnet --socket /tmp/s --queue 0").is_err());
        assert!(args("--source gnet --socket /tmp/s --write").is_err());
        assert_eq!(args("--source gnet --socket /tmp/s --proof-window 4096").unwrap().settings.proof_window, 4096);
        assert!(args("--source gnet --socket /tmp/s --proof-window 100").unwrap_err().contains("--seal-count"));
        assert!(args("--source gnet --socket /tmp/s --proof-window 100 --seal-count 100").is_ok());
        assert!(args("--source gnet --socket /tmp/s --proof-window 99999999").is_err());
        assert_eq!(resolve_group("1234"), Ok(1234));
    }
}
