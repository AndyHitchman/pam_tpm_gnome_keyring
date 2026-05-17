//! gkd-unlock — GNOME keyring control socket unlock helper.
//!
//! Spawned by pam_tpm_gnome_keyring.so during session open. This binary:
//!   1. Reads the passphrase from stdin (provided by the PAM module).
//!   2. Drops root privileges to the target user via setuid(2).
//!   3. Polls for the GNOME keyring daemon's control socket to appear.
//!   4. Speaks the GKD control protocol to unlock the login keyring.
//!   5. Retries on failure to handle the brief window where the PAM-started
//!      daemon is replaced by the real systemd-managed daemon.
//!
//! This binary must be owned by root and executable by root only (mode 0700)
//! since it is only ever invoked by the PAM module running as root.
//!
//! # Protocol
//!
//! The GNOME keyring control socket speaks a simple big-endian binary protocol
//! derived from gnome-keyring's internal egg_buffer format.
//!
//! Unlock request:  [u32 total_len][u32 op=1][u32 pw_len][pw bytes]
//! Unlock response: [u32 total_len][u32 result]
//!   result: 0=OK, 1=DENIED, 2=FAILED, 3=NO_DAEMON
//!
//! Before the request, a single byte is sent with SCM_CREDENTIALS ancillary
//! data so the daemon can verify the caller's UID matches the socket owner.

use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

// syslog constants
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

    // Read passphrase from stdin before dropping privileges.
    // The PAM module closes stdin after writing, so read_to_end is safe.
    let mut passphrase = Vec::new();
    std::io::stdin().read_to_end(&mut passphrase).unwrap_or(0);
    if passphrase.last() == Some(&b'\n') {
        passphrase.pop();
    }

    if passphrase.is_empty() {
        log_err!("received empty passphrase for '{username}'");
        std::process::exit(2);
    }

    // Resolve the target user's UID
    let uid = match get_uid(&username) {
        Some(u) => u,
        None => {
            log_err!("user '{username}' not found in /etc/passwd");
            std::process::exit(2);
        }
    };

    // Drop privileges. After setuid(uid), geteuid() == uid which satisfies
    // the GNOME keyring control socket's ownership check:
    //   if (st.st_uid != geteuid()) { ... reject ... }
    unsafe {
        if libc::setuid(uid) != 0 {
            log_err!(
                "setuid({uid}) failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }

    log_dbg!("dropped to uid={uid} for '{username}'");

    let socket_path = format!("/run/user/{uid}/keyring/control");
    let deadline = Instant::now() + Duration::from_secs(30);

    // Retry loop. Two failure modes are handled:
    //
    //   1. Socket not yet present: the keyring daemon hasn't started.
    //      Poll every 200 ms until it appears.
    //
    //   2. Unlock returns non-OK: during login, pam_gnome_keyring.so may
    //      start a temporary --login daemon that fails to initialise PKCS11.
    //      The real systemd-managed daemon replaces it seconds later.
    //      Retry every 2 s until we get OK or the deadline passes.
    loop {
        if Instant::now() > deadline {
            log_err!("timed out after 30s waiting for successful unlock");
            std::process::exit(1);
        }

        // Check socket exists and is owned by our (dropped) uid
        match std::fs::metadata(&socket_path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                if m.uid() != uid {
                    log_dbg!("socket owner mismatch, waiting…");
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        }

        // Attempt the unlock
        match try_unlock(&socket_path, &passphrase) {
            Ok(()) => {
                log_info!("login keyring unlocked for '{username}'");
                std::process::exit(0);
            }
            Err(e) => {
                // The daemon may be transitioning — retry after a short delay
                log_dbg!("unlock attempt failed ({e}), retrying in 2s…");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Attempt a single unlock via the GKD control socket protocol.
fn try_unlock(socket_path: &str, passphrase: &[u8]) -> Result<(), String> {
    let stream =
        UnixStream::connect(socket_path).map_err(|e| format!("connect: {e}"))?;

    // Send SCM_CREDENTIALS so the daemon can verify our UID
    send_credentials(stream.as_raw_fd())?;

    // Build GKD_CONTROL_OP_UNLOCK message (big-endian egg_buffer format):
    //   [u32 total_len][u32 op=1][u32 pw_len][pw bytes]
    let pw_len = passphrase.len() as u32;
    let total_len: u32 = 4 + 4 + 4 + pw_len; // total + op + string_len + data
    let mut msg = Vec::with_capacity(total_len as usize);
    msg.extend_from_slice(&total_len.to_be_bytes());
    msg.extend_from_slice(&1u32.to_be_bytes()); // GKD_CONTROL_OP_UNLOCK = 1
    msg.extend_from_slice(&pw_len.to_be_bytes());
    msg.extend_from_slice(passphrase);

    let mut stream = stream;
    stream.write_all(&msg).map_err(|e| format!("write: {e}"))?;

    // Read response: [u32 total_len][u32 result_code]
    let mut size_buf = [0u8; 4];
    stream
        .read_exact(&mut size_buf)
        .map_err(|e| format!("read size: {e}"))?;
    let resp_size = u32::from_be_bytes(size_buf) as usize;
    if resp_size < 8 {
        return Err(format!("response too short ({resp_size} bytes)"));
    }

    let mut rest = vec![0u8; resp_size - 4];
    stream
        .read_exact(&mut rest)
        .map_err(|e| format!("read body: {e}"))?;

    match u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) {
        0 => Ok(()), // GKD_CONTROL_RESULT_OK
        1 => Err("daemon returned DENIED (wrong passphrase?)".into()),
        2 => Err("daemon returned FAILED".into()),
        3 => Err("daemon returned NO_DAEMON".into()),
        n => Err(format!("daemon returned unknown result code {n}")),
    }
}

/// Look up a user's UID from /etc/passwd.
fn get_uid(username: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.splitn(7, ':');
        let name = fields.next()?;
        fields.next(); // password placeholder
        let uid_str = fields.next()?;
        if name == username {
            return uid_str.parse().ok();
        }
    }
    None
}

/// Send SCM_CREDENTIALS ancillary data on a Unix socket.
///
/// The GNOME keyring daemon calls egg_unix_credentials_read() on the server
/// side and rejects connections where the credential UID doesn't match the
/// socket file owner. After setuid(uid) above, getuid() returns uid, so the
/// kernel will accept our credential message.
fn send_credentials(fd: libc::c_int) -> Result<(), String> {
    unsafe {
        // Enable SO_PASSCRED so the kernel processes our ancillary data
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        let cred = libc::ucred {
            pid: libc::getpid(),
            uid: libc::getuid(), // == target uid after setuid()
            gid: libc::getgid(),
        };

        let cmsg_space =
            libc::CMSG_SPACE(mem::size_of::<libc::ucred>() as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut byte = [0u8; 1]; // required iov payload

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
        (*cmsg).cmsg_len =
            libc::CMSG_LEN(mem::size_of::<libc::ucred>() as u32) as usize;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_CREDENTIALS;
        *(libc::CMSG_DATA(cmsg) as *mut libc::ucred) = cred;

        if libc::sendmsg(fd, &msg, 0) < 0 {
            return Err(format!(
                "sendmsg: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}
