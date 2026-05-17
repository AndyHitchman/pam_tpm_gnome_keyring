//! gkd-unlock — GNOME keyring control socket unlock helper.
//!
//! Can be invoked in two contexts:
//!
//! 1. **Root context (PAM module):** Called by pam_tpm_gnome_keyring.so during
//!    session open. Drops root privileges to the target user via setuid(2)
//!    before accessing the keyring socket.
//!
//! 2. **User context (systemd ExecStartPost):** Called directly as the target
//!    user from the gnome-keyring-daemon.service ExecStartPost hook. No
//!    privilege drop is needed. This is the preferred path — it unlocks the
//!    keyring the instant the daemon socket appears, before any GNOME
//!    application can trigger a password prompt.
//!
//! Usage: gkd-unlock <username>
//! Passphrase is read from stdin when called from root context.
//! When called as the user, passphrase is obtained via clevis directly.

use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const LOG_AUTH: libc::c_int = 4 << 3;
const LOG_ERR: libc::c_int = 3;
const LOG_INFO: libc::c_int = 6;
const LOG_DEBUG: libc::c_int = 7;

fn syslog(priority: libc::c_int, msg: &str) {
    let tagged = format!("gkd-unlock: {msg}\0");
    unsafe {
        libc::syslog(
            LOG_AUTH | priority,
            b"%s\0".as_ptr() as *const libc::c_char,
            tagged.as_ptr() as *const libc::c_char,
        );
    }
}

macro_rules! log_err  { ($($a:tt)*) => { syslog(LOG_ERR,   &format!($($a)*)) } }
macro_rules! log_info { ($($a:tt)*) => { syslog(LOG_INFO,  &format!($($a)*)) } }
macro_rules! log_dbg  { ($($a:tt)*) => { syslog(LOG_DEBUG, &format!($($a)*)) } }

fn main() {
    let username = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: gkd-unlock <username>");
        std::process::exit(2);
    });

    let uid = match get_uid(&username) {
        Some(u) => u,
        None => {
            log_err!("user '{username}' not found in /etc/passwd");
            std::process::exit(2);
        }
    };

    let calling_uid = unsafe { libc::getuid() };

    let passphrase = if calling_uid == 0 {
        // ── Root context (PAM module) ─────────────────────────────────────
        // Passphrase is piped in on stdin by the PAM module.
        // Drop privileges to the target user before touching any user resources.
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).unwrap_or(0);
        if buf.last() == Some(&b'\n') { buf.pop(); }

        if buf.is_empty() {
            log_err!("received empty passphrase for '{username}'");
            std::process::exit(2);
        }

        unsafe {
            if libc::setuid(uid) != 0 {
                log_err!("setuid({uid}) failed: {}", std::io::Error::last_os_error());
                std::process::exit(2);
            }
        }
        log_dbg!("dropped to uid={uid} for '{username}'");
        buf

    } else if calling_uid == uid {
        // ── User context (systemd ExecStartPost) ─────────────────────────
        // Already running as the correct user. Decrypt the passphrase
        // directly via clevis (no runuser needed).
        log_dbg!("running as uid={uid}, decrypting secret directly");
        match decrypt_secret_as_user() {
            Some(b) => b,
            None => {
                log_dbg!("no secret file or decryption failed, exiting cleanly");
                std::process::exit(0); // Not an error — user may not be enrolled
            }
        }

    } else {
        log_err!("called as uid={calling_uid} but target user is uid={uid}");
        std::process::exit(2);
    };

    let socket_path = format!("/run/user/{uid}/keyring/control");
    let deadline = Instant::now() + Duration::from_secs(30);

    // Retry loop handles two scenarios:
    //   1. Socket not yet present — daemon still starting. Poll every 200ms.
    //   2. Daemon in broken state (e.g. pam_gnome_keyring started a --login
    //      instance) — retry every 2s until the real daemon takes over.
    loop {
        if Instant::now() > deadline {
            log_err!("timed out after 30s waiting for successful unlock");
            std::process::exit(1);
        }

        match std::fs::metadata(&socket_path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                if m.uid() != uid {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        }

        match try_unlock(&socket_path, &passphrase) {
            Ok(()) => {
                log_info!("login keyring unlocked for '{username}'");
                std::process::exit(0);
            }
            Err(e) => {
                log_dbg!("unlock attempt failed ({e}), retrying in 2s");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Decrypt the secret file directly when already running as the target user.
fn decrypt_secret_as_user() -> Option<Vec<u8>> {
    let home = std::env::var("HOME").ok()
        .or_else(|| {
            // Fallback: read from /etc/passwd using current uid
            let uid = unsafe { libc::getuid() };
            let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
            for line in passwd.lines() {
                let parts: Vec<&str> = line.splitn(7, ':').collect();
                if parts.len() >= 6 && parts[2].parse::<u32>().ok() == Some(uid) {
                    return Some(parts[5].to_owned());
                }
            }
            None
        })?;

    let secret_path = format!("{home}/.config/gnome-keyring-unlock/secret.jwe");
    if !std::path::Path::new(&secret_path).exists() {
        return None;
    }

    let output = std::process::Command::new("clevis")
        .arg("decrypt")
        .stdin(std::fs::File::open(&secret_path).ok()?)
        .output()
        .ok()?;

    if !output.status.success() || output.stdout.is_empty() {
        return None;
    }

    let mut bytes = output.stdout;
    if bytes.last() == Some(&b'\n') { bytes.pop(); }
    if bytes.contains(&0) { return None; }
    Some(bytes)
}

fn try_unlock(socket_path: &str, passphrase: &[u8]) -> Result<(), String> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect: {e}"))?;

    send_credentials(stream.as_raw_fd())?;

    // GKD_CONTROL_OP_UNLOCK message (big-endian egg_buffer format):
    //   [u32 total_len][u32 op=1][u32 pw_len][pw bytes]
    let pw_len = passphrase.len() as u32;
    let total_len: u32 = 4 + 4 + 4 + pw_len;
    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&1u32.to_be_bytes()); // GKD_CONTROL_OP_UNLOCK = 1
    msg.extend_from_slice(&pw_len.to_be_bytes());
    msg.extend_from_slice(passphrase);

    let mut stream = stream;
    stream.write_all(&msg).map_err(|e| format!("write: {e}"))?;

    let mut size_buf = [0u8; 4];
    stream.read_exact(&mut size_buf).map_err(|e| format!("read size: {e}"))?;
    let resp_size = u32::from_be_bytes(size_buf) as usize;
    if resp_size < 8 {
        return Err(format!("response too short ({resp_size} bytes)"));
    }

    let mut rest = vec![0u8; resp_size - 4];
    stream.read_exact(&mut rest).map_err(|e| format!("read body: {e}"))?;

    match u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) {
        0 => Ok(()),
        1 => Err("DENIED (wrong passphrase?)".into()),
        2 => Err("FAILED".into()),
        3 => Err("NO_DAEMON".into()),
        n => Err(format!("unknown result code {n}")),
    }
}

fn get_uid(username: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.splitn(7, ':');
        let name = fields.next()?;
        fields.next();
        let uid_str = fields.next()?;
        if name == username {
            return uid_str.parse().ok();
        }
    }
    None
}

fn send_credentials(fd: libc::c_int) -> Result<(), String> {
    unsafe {
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd, libc::SOL_SOCKET, libc::SO_PASSCRED,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let cred = libc::ucred {
            pid: libc::getpid(),
            uid: libc::getuid(),
            gid: libc::getgid(),
        };

        let cmsg_space = libc::CMSG_SPACE(mem::size_of::<libc::ucred>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut byte = [0u8; 1];

        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };

        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::ucred>() as u32) as usize;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_CREDENTIALS;
        *(libc::CMSG_DATA(cmsg) as *mut libc::ucred) = cred;

        if libc::sendmsg(fd, &msg, 0) < 0 {
            return Err(format!("sendmsg: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(())
}
