//! pam_tpm_gnome_keyring — PAM module for unlocking the GNOME keyring at login
//! using a TPM2-protected passphrase.
//!
//! # How it works
//!
//! During session open, this module:
//! 1. Decrypts the user's TPM2-protected keyring passphrase via `clevis decrypt`.
//! 2. Double-forks a background helper process (`gkd-unlock`) that:
//!    - Drops root privileges to the target user.
//!    - Polls for the GNOME keyring daemon's control socket.
//!    - Unlocks the keyring by speaking the GKD control socket protocol directly.
//!
//! The double-fork ensures the helper outlives the PAM session worker process,
//! allowing it to wait for the GNOME keyring daemon to fully start before
//! sending the unlock request.
//!
//! # Security
//!
//! The keyring passphrase is never stored in plaintext on disk. It is stored as
//! a JOSE JWE file encrypted using the TPM2 chip, bound to PCR 7 (Secure Boot
//! state) by default. Without the machine's TPM2, decryption is impossible.
//!
//! See README.md for full setup instructions and security considerations.

#![allow(non_camel_case_types)]

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::raw::{c_char, c_int, c_void};
use std::process::{Command, Stdio};

// ── PAM constants ────────────────────────────────────────────────────────────

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_USER: c_int = 2;
const PAM_AUTHTOK: c_int = 6;

// Path to the helper binary installed alongside this module.
// Must be owned by root and not world-writable.
const HELPER: &str = "/usr/local/bin/gkd-unlock";

// syslog priority constants (LOG_AUTH | level)
const LOG_AUTH: c_int = 4 << 3;
const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_INFO: c_int = 6;
const LOG_DEBUG: c_int = 7;

pub enum pam_handle_t {}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_item(pamh: *mut pam_handle_t, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
}

// ── Logging ──────────────────────────────────────────────────────────────────

/// Log a message to syslog AUTH facility. Appears in journalctl as:
///   journalctl -t pam_tpm_gnome_keyring
fn syslog(priority: c_int, msg: &str) {
    // Format ident as a static C string. We call openlog implicitly by just
    // using syslog(); the process name is used as the ident automatically.
    // We prefix our tag so messages are filterable.
    let tagged = format!("pam_tpm_gnome_keyring: {msg}");
    if let Ok(c_msg) = CString::new(tagged) {
        unsafe {
            // %s format avoids interpreting msg as a format string
            libc::syslog(
                LOG_AUTH | priority,
                b"%s\0".as_ptr() as *const c_char,
                c_msg.as_ptr(),
            );
        }
    }
}

macro_rules! log_err  { ($($a:tt)*) => { syslog(LOG_ERR,     &format!($($a)*)) } }
macro_rules! log_warn { ($($a:tt)*) => { syslog(LOG_WARNING,  &format!($($a)*)) } }
macro_rules! log_info { ($($a:tt)*) => { syslog(LOG_INFO,     &format!($($a)*)) } }
macro_rules! log_dbg  { ($($a:tt)*) => { syslog(LOG_DEBUG,    &format!($($a)*)) } }

// ── PAM helpers ──────────────────────────────────────────────────────────────

fn get_username(pamh: *mut pam_handle_t) -> Option<String> {
    let mut user_ptr: *const c_void = std::ptr::null();
    if unsafe { pam_get_item(pamh, PAM_USER, &mut user_ptr) } != PAM_SUCCESS
        || user_ptr.is_null()
    {
        return None;
    }
    unsafe { CStr::from_ptr(user_ptr as *const c_char) }
        .to_str()
        .ok()
        .map(|s| s.to_owned())
}

// ── TPM decryption ───────────────────────────────────────────────────────────

/// Decrypt the user's TPM2-protected keyring passphrase using clevis.
///
/// This must run as the target user (via `runuser`) because:
///  - The JWE file lives in the user's home directory.
///  - The TPM2 credential is bound to the user's session context.
///
/// Returns None if the secret file doesn't exist, the user is not in the
/// `tss` group, or clevis decryption fails for any reason.
fn decrypt_tpm_secret(username: &str) -> Option<Vec<u8>> {
    log_dbg!("decrypting secret for '{username}' via clevis");

    let output = Command::new("runuser")
        .args([
            "-u",
            username,
            "--",
            "sh",
            "-c",
            // Silently exit 1 if secret file doesn't exist so we don't log
            // noise for users who haven't enrolled.
            "f=\"$HOME/.config/gnome-keyring-unlock/secret.jwe\"; \
             [ -f \"$f\" ] || exit 1; \
             clevis decrypt < \"$f\" 2>/dev/null",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        // Exit 1 means no secret file or decryption failed — not an error
        // worth logging at warning level unless there IS a file but it failed.
        log_dbg!("clevis runuser exited {}", output.status.code().unwrap_or(-1));
        return None;
    }

    if output.stdout.is_empty() {
        log_warn!("clevis produced empty output for '{username}'");
        return None;
    }

    let mut bytes = output.stdout;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }

    // Guard against null bytes — CString requires null-free data
    if bytes.contains(&0) {
        log_err!("decrypted secret contains null bytes — refusing");
        return None;
    }

    log_dbg!("decrypted {} bytes for '{username}'", bytes.len());
    Some(bytes)
}

// ── Auth phase ───────────────────────────────────────────────────────────────

/// Set PAM_AUTHTOK to the TPM-decrypted passphrase.
///
/// This runs during the auth phase, before pam_gnome_keyring.so, so that
/// pam_gnome_keyring.so can stash the passphrase for the session phase.
/// In practice, runuser usually fails here (PAM runs as root in xdm_t context
/// which can't access the TPM device), so this is belt-and-suspenders — the
/// real unlock happens via the gkd-unlock helper in the session phase.
fn set_authtok(pamh: *mut pam_handle_t) -> c_int {
    let username = match get_username(pamh) {
        Some(u) => u,
        None => return PAM_IGNORE,
    };

    // Don't override an authtok already set by a previous module
    let mut tok_ptr: *const c_void = std::ptr::null();
    unsafe { pam_get_item(pamh, PAM_AUTHTOK, &mut tok_ptr) };
    if !tok_ptr.is_null() {
        let existing = unsafe { CStr::from_ptr(tok_ptr as *const c_char) };
        if !existing.to_bytes().is_empty() {
            log_dbg!("PAM_AUTHTOK already set by earlier module, skipping");
            return PAM_IGNORE;
        }
    }

    let mut bytes = match decrypt_tpm_secret(&username) {
        Some(b) => b,
        None => return PAM_IGNORE,
    };

    let passphrase = match CString::new(bytes.as_slice()) {
        Ok(s) => s,
        Err(_) => {
            bytes.fill(0);
            log_err!("failed to convert passphrase to CString");
            return PAM_IGNORE;
        }
    };
    bytes.fill(0);

    let rc = unsafe { pam_set_item(pamh, PAM_AUTHTOK, passphrase.as_ptr() as *const c_void) };
    if rc == PAM_SUCCESS {
        log_info!("PAM_AUTHTOK set for '{username}'");
    } else {
        log_err!("pam_set_item failed with rc={rc}");
    }
    rc
}

// ── Session phase ─────────────────────────────────────────────────────────────

/// Unlock the GNOME keyring via the gkd-unlock helper.
///
/// Uses a double-fork so the helper process is reparented to PID 1 (init)
/// and survives the PAM session worker process exiting. This is necessary
/// because the GNOME keyring daemon starts several seconds after the PAM
/// session opens; the helper polls for the control socket in the background.
fn unlock_via_helper(pamh: *mut pam_handle_t) -> c_int {
    let username = match get_username(pamh) {
        Some(u) => u,
        None => {
            log_warn!("could not get PAM_USER in session phase");
            return PAM_IGNORE;
        }
    };

    let passphrase = match decrypt_tpm_secret(&username) {
        Some(b) => b,
        None => {
            log_dbg!("no secret available for '{username}', skipping unlock");
            return PAM_IGNORE;
        }
    };

    // Verify helper exists before forking
    if !std::path::Path::new(HELPER).exists() {
        log_err!("helper not found at {HELPER}");
        return PAM_IGNORE;
    }

    log_info!("launching {HELPER} for '{username}'");

    // Double-fork: grandchild is reparented to init, surviving PAM exit.
    match unsafe { libc::fork() } {
        -1 => {
            log_err!("fork() failed: {}", std::io::Error::last_os_error());
            return PAM_IGNORE;
        }
        0 => {
            // ── First child ──────────────────────────────────────────────────
            // Create a new session so we're detached from the PAM terminal,
            // then immediately fork again and exit, orphaning the grandchild.
            unsafe { libc::setsid() };

            match unsafe { libc::fork() } {
                0 => {
                    // ── Grandchild (daemon) ──────────────────────────────────
                    // This process is now owned by init. Spawn the helper with
                    // the passphrase on stdin, wait for it, then exit.
                    let mut child = match Command::new(HELPER)
                        .arg(&username)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                    {
                        Ok(c) => c,
                        Err(e) => {
                            // Can't log here (syslog is not async-signal-safe in
                            // a fork context), just exit.
                            eprintln!("pam_tpm_gnome_keyring: spawn failed: {e}");
                            unsafe { libc::_exit(1) };
                        }
                    };

                    // Write passphrase and close stdin (sends EOF to helper)
                    if let Some(mut stdin) = child.stdin.take() {
                        let _ = stdin.write_all(&passphrase);
                    }

                    let _ = child.wait();
                    unsafe { libc::_exit(0) };
                }
                _ => {
                    // First child exits immediately — grandchild is reparented
                    unsafe { libc::_exit(0) };
                }
            }
        }
        pid => {
            // ── Parent (PAM module) ──────────────────────────────────────────
            // Reap the first child to avoid a zombie, then return immediately.
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        }
    }

    log_dbg!("helper launched in background for '{username}'");
    PAM_SUCCESS
}

// ── PAM entry points ──────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // Set PAM_AUTHTOK so pam_gnome_keyring.so can stash it.
    // Returns PAM_IGNORE so this module never influences auth decisions.
    set_authtok(pamh);
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    unlock_via_helper(pamh)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}
