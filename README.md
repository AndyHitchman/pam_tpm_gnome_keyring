# pam-tpm-gnome-keyring

A PAM module that automatically unlocks the GNOME keyring at login using a
TPM2-protected passphrase, enabling fully passwordless login when combined
with a hardware security key (YubiKey or similar FIDO2 device).

## Overview

Standard GNOME keyring unlock works by passing your login password through
PAM to the keyring daemon. When you authenticate with a hardware security key
(no password), this mechanism has nothing to pass, so the keyring stays locked
and prompts you again after login.

This module solves that by:

1. Storing the keyring passphrase encrypted in a JOSE JWE file, protected by
   the machine's TPM2 chip.
2. During login, decrypting the passphrase via `clevis` and unlocking the
   keyring daemon directly via its control socket.

The keyring passphrase is **never stored in plaintext on disk**. Without the
machine's TPM2 chip, the JWE file is useless.

```
Login (YubiKey touch)
  └─ pam_u2f.so          — authenticates the user
  └─ pam_tpm_gnome_keyring.so  — decrypts passphrase via TPM2, spawns gkd-unlock
       └─ gkd-unlock (background)
            └─ clevis decrypt  ← TPM2
            └─ setuid(user)
            └─ polls for /run/user/<uid>/keyring/control
            └─ GKD control socket protocol → keyring unlocked
```

## Security model

| Threat | Mitigation |
|--------|-----------|
| Stolen disk | JWE file is TPM2-encrypted; cannot be decrypted without this machine's TPM |
| Physical access to running machine | Keyring is only unlocked after successful YubiKey authentication |
| Malicious user reading JWE file | File permissions (600); decryption requires TPM2 which is bound to this machine |
| Passphrase in memory | Zeroed after use in the PAM module; the helper receives it via a pipe, not argv |
| Privilege escalation via gkd-unlock | Binary is root-owned mode 0700; drops to target user immediately via setuid(2) before accessing any user resources |
| TPM PCR binding | By default bound to PCR 7 (Secure Boot state); if the boot chain is tampered with, decryption fails |

### What this does NOT protect against

- A compromised root account (root can read the TPM and the JWE file)
- Unencrypted disk at rest (consider enabling LUKS full-disk encryption for
  stronger guarantees; this module is complementary to LUKS, not a replacement)
- An attacker who can access the machine while it is running and unlocked

## Prerequisites

- Fedora 44 (or similar systemd+GNOME+PAM distribution)
- GNOME keyring daemon managed by systemd (`gnome-keyring-daemon.service`)
- YubiKey (or other FIDO2 device) configured for PAM login via `pam_u2f`
- TPM2 chip present (`/dev/tpmrm0`)
- `clevis` and `clevis-tpm2` installed
- User in the `tss` group (required for TPM access)
- Rust toolchain (for building)

```bash
sudo dnf install -y clevis clevis-tpm2 pam-devel
sudo usermod -aG tss $USER
# Log out and back in for group to take effect
```

## Building

```bash
git clone https://github.com/yourusername/pam-tpm-gnome-keyring
cd pam-tpm-gnome-keyring
cargo build --release
```

## Installation

```bash
# Install the PAM module
sudo cp target/release/libpam_tpm_gnome_keyring.so /lib64/security/pam_tpm_gnome_keyring.so
sudo chmod 644 /lib64/security/pam_tpm_gnome_keyring.so
sudo restorecon /lib64/security/pam_tpm_gnome_keyring.so

# Install the helper binary (root-owned, not world-executable)
sudo cp target/release/gkd-unlock /usr/local/bin/gkd-unlock
sudo chmod 700 /usr/local/bin/gkd-unlock
sudo chown root:root /usr/local/bin/gkd-unlock
sudo restorecon /usr/local/bin/gkd-unlock
```

## Enrolling your keyring passphrase

First, set a dedicated passphrase on the GNOME login keyring (decoupled from
your login password):

1. Open **Passwords and Keys** (Seahorse)
2. Right-click the **Login** keyring → **Change Password**
3. Enter your current login password, then set a new strong passphrase

Then encrypt that passphrase with the TPM:

```bash
mkdir -p ~/.config/gnome-keyring-unlock
chmod 700 ~/.config/gnome-keyring-unlock

# Verify TPM is accessible
clevis encrypt tpm2 '{"pcr_ids":"7"}' <<< "test" | clevis decrypt

# Encrypt your keyring passphrase
read -rs PASS && echo -n "$PASS" | \
    clevis encrypt tpm2 '{"pcr_ids":"7"}' \
    > ~/.config/gnome-keyring-unlock/secret.jwe

chmod 600 ~/.config/gnome-keyring-unlock/secret.jwe

# Verify round-trip
clevis decrypt < ~/.config/gnome-keyring-unlock/secret.jwe
```

The `pcr_ids: "7"` binds the secret to PCR 7 (Secure Boot state). If the
boot chain changes (e.g. new shim, kernel), you will need to re-enrol.

## PAM configuration

> ⚠️ Always keep a root terminal open while editing PAM configuration.
> A misconfigured PAM stack can lock you out of the system.

Identify which GDM PAM file your login uses. On Fedora with a hardware key,
this is typically `/etc/pam.d/gdm-password`. Check with:

```bash
sudo journalctl -b | grep "AUDIT1100" | grep gdm
```

Edit the identified file. The key changes are:

**Auth section** — add `pam_tpm_gnome_keyring.so` before `pam_gnome_keyring.so`
so PAM_AUTHTOK is available if needed:

```
auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        optional      pam_tpm_gnome_keyring.so    # ← add this line
auth        sufficient    pam_u2f.so cue [cue_prompt=Touch YubiKey]
auth        substack      password-auth
auth        optional      pam_gnome_keyring.so
auth        include       postlogin
```

**Session section** — add `pam_tpm_gnome_keyring.so` before `pam_gnome_keyring.so`,
and remove `auto_start` from `pam_gnome_keyring.so` to prevent it from starting
its own broken daemon (the real daemon is managed by systemd):

```
session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
session     include       postlogin
session     optional      pam_tpm_gnome_keyring.so    # ← add this line
session     optional      pam_gnome_keyring.so         # ← remove auto_start
```

The removal of `auto_start` is critical. With `auto_start`, `pam_gnome_keyring.so`
starts a `--login` mode daemon that fails to initialise properly (no D-Bus
session at PAM time), which blocks the real systemd-managed daemon from
starting.

## Verification

After a full reboot:

```bash
# Check keyring is unlocked (should return <false>)
gdbus call --session \
  --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets/collection/login \
  --method org.freedesktop.DBus.Properties.Get \
  org.freedesktop.Secret.Collection Locked

# Check logs
journalctl -b -t pam_tpm_gnome_keyring
journalctl -b -t gkd-unlock
```

## Troubleshooting

**Keyring still locked after login**

Check the logs:
```bash
journalctl -b -t pam_tpm_gnome_keyring
journalctl -b -t gkd-unlock
sudo journalctl -b | grep -i "keyring" | grep -v "kernel\|dbus-broker"
```

Common causes:
- `tss` group not applied — log out fully and back in, or reboot
- Wrong passphrase in JWE file — re-enrol (`read -rs PASS && ...`)
- PCR 7 changed (Secure Boot update) — re-enrol
- `auto_start` not removed from PAM config

**Login is slow**

The helper polls for the keyring socket with a 30-second deadline. This should
not cause login delays since it runs in a double-forked background process.
If login is slow, check for other PAM module issues with:
```bash
sudo journalctl -b | grep "gdm-password" | head -20
```

**Clevis fails with permission denied on TPM**

Ensure your user is in the `tss` group and has fully logged out and back in:
```bash
id | grep tss
grep tss /etc/group
```

**Re-enrolling after a Secure Boot update**

```bash
rm ~/.config/gnome-keyring-unlock/secret.jwe
read -rs PASS && echo -n "$PASS" | \
    clevis encrypt tpm2 '{"pcr_ids":"7"}' \
    > ~/.config/gnome-keyring-unlock/secret.jwe
```

## How the control socket protocol works

The GNOME keyring daemon exposes a Unix domain socket at
`/run/user/<uid>/keyring/control`. The protocol (from
`daemon/control/gkd-control-client.c` in the gnome-keyring source) is:

1. Connect to the socket.
2. Send a 1-byte message with `SCM_CREDENTIALS` ancillary data containing
   the process PID/UID/GID. The daemon verifies the UID matches the socket
   file owner and rejects connections from other users (including root).
3. Send the unlock request:
   ```
   [u32 BE: total_length]       = 12 + len(passphrase)
   [u32 BE: op_code]            = 1  (GKD_CONTROL_OP_UNLOCK)
   [u32 BE: passphrase_length]
   [bytes: passphrase]          (no null terminator)
   ```
4. Read the response:
   ```
   [u32 BE: total_length]
   [u32 BE: result_code]        = 0 (OK), 1 (DENIED), 2 (FAILED), 3 (NO_DAEMON)
   ```

Because the daemon rejects root connections, the `gkd-unlock` helper drops
privileges via `setuid(uid)` before connecting. This is the key reason a
separate helper binary is required — a PAM module always runs as root.

## License

MIT — see [LICENSE](LICENSE).
