// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! Privilege: the collector starts with CAP_BPF and CAP_PERFMON at most, refuses to start with anything
//! more or as root, and after opening its pins keeps CAP_BPF alone (the counter reads are bpf(2) calls,
//! which a host with unprivileged BPF disabled refuses without it). No new privileges can be gained
//! afterwards, and nothing it starts could inherit a capability.

use std::io;

pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;
/// The capabilities the collector may hold at start.
pub const ALLOWED: u64 = (1 << CAP_BPF) | (1 << CAP_PERFMON);

/// The capability sets of `/proc/self/status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

/// Read the capability sets from the text of a `/proc/<pid>/status`.
pub fn parse_status(text: &str) -> Option<Caps> {
    let mut caps = Caps::default();
    let mut seen = 0;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let slot = match key {
            "CapInh" => &mut caps.inheritable,
            "CapPrm" => &mut caps.permitted,
            "CapEff" => &mut caps.effective,
            "CapBnd" => &mut caps.bounding,
            "CapAmb" => &mut caps.ambient,
            _ => continue,
        };
        *slot = u64::from_str_radix(value.trim(), 16).ok()?;
        seen += 1;
    }
    (seen == 5).then_some(caps)
}

pub fn current() -> io::Result<Caps> {
    let text = std::fs::read_to_string("/proc/self/status")?;
    parse_status(&text).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no capability sets in /proc/self/status"))
}

const NAMES: [&str; 41] = [
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap",
    "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
    "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
    "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
    "mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf",
    "checkpoint_restore",
];

pub fn names(set: u64) -> Vec<String> {
    (0..64u32).filter(|bit| set & (1u64 << bit) != 0).map(|bit| NAMES.get(bit as usize).map_or(format!("cap_{bit}"), |name| format!("cap_{name}"))).collect()
}

/// Refuse to run as root, or holding any capability but CAP_BPF and CAP_PERFMON.
pub fn check_start(euid: u32, caps: &Caps) -> Result<(), String> {
    if euid == 0 {
        return Err("the collector does not run as root: run it as its own account with CAP_BPF (README, the systemd unit)".into());
    }
    let extra = (caps.effective | caps.permitted | caps.ambient) & !ALLOWED;
    if extra != 0 {
        return Err(format!("the collector holds capabilities beyond cap_bpf and cap_perfmon: {}", names(extra).join(", ")));
    }
    Ok(())
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn prctl(option: i32, arg: libc::c_ulong) -> io::Result<()> {
    // SAFETY: prctl with integer arguments only.
    if unsafe { libc::prctl(option, arg, 0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// No new privileges from here on (a set-uid or file capability binary gains nothing), and no ambient set.
pub fn lock_down() -> io::Result<()> {
    prctl(libc::PR_SET_NO_NEW_PRIVS, 1)?;
    prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong)
}

/// Keep only `keep` of the permitted and effective sets, and nothing inheritable. Lowering is always allowed.
pub fn keep_only(keep: u64) -> io::Result<()> {
    let caps = current()?;
    let permitted = caps.permitted & keep;
    let effective = caps.effective & keep;
    let mut header = CapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [
        CapData { effective: effective as u32, permitted: permitted as u32, inheritable: 0 },
        CapData { effective: (effective >> 32) as u32, permitted: (permitted >> 32) as u32, inheritable: 0 },
    ];
    // SAFETY: capset(2) with a version 3 header and its two data words.
    if unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut CapHeader, data.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
