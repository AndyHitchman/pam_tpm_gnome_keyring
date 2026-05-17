# pam-tpm-gnome-keyring

A PAM module and systemd user service that automatically unlock the GNOME
keyring at login using a TPM2-protected passphrase, enabling fully
passwordless login when combined with a hardware security key (YubiKey or
any FIDO2 device).

## The problem

GNOME keyring normally unlocks by receiving your login password via PAM. When
you authenticate with a hardware security key — no password typed — PAM has
nothing to pass along, so the keyring stays locked and prompts you again after
login.

## How this solves it

The keyring passphrase is stored in a JOSE JWE file in your home directory,
encrypted against the machine's TPM2 chip. At login:

1. A systemd user service (`gnome-keyring-tpm-unlock.service`) starts after
   the keyring daemon's control socket is ready.
2. `gkd-unlock` decrypts the passphrase via `clevis` and speaks the GNOME
   keyring daemon's internal control socket protocol to unlock the keyring
   directly — before any GNOME application has a chance to prompt for a
   password.
3. The PAM module (`pam_tpm_gnome_keyring.so`) provides a redundant unlock
   path via a double-forked background process, covering edge cases where the
   systemd service races with application startup.

```
YubiKey login
├── pam_tpm_gnome_keyring.so  (auth)    sets PAM_AUTHTOK if TPM accessible
├── pam_u2f.so sufficient               authenticates the user
├── pam_gnome_keyring.so               uses PAM_AUTHTOK if available
└── [session opens]
    ├── pam_tpm_gnome_keyring.so (session)  double-forks gkd-unlock as backup
    └── gnome-keyring-tpm-unlock.service    PRIMARY: unlocks via control socket
            └── gkd-unlock <username>
                    └── clevis decrypt  ←  TPM2
                    └── GKD control socket protocol
                    └── keyring unlocked ✓
```

## Security model

| Threat | Mitigation |
|--------|-----------|
| Stolen disk | JWE file is TPM2-encrypted; useless without this machine's TPM |
| Physical access to running machine | Unlock requires prior YubiKey authentication |
| User reads JWE file | `~/.config/gnome-keyring-unlock/` is mode 700, JWE is mode 600; decryption still requires the TPM |
| Null bytes / injection in passphrase | Rejected before use in both the PAM module and helper |
| Privilege escalation via gkd-unlock | When called from PAM (root context), drops to target user via `setuid(2)` immediately; socket ownership check rejects wrong-UID connections |
| Tampered boot chain | PCR 7 binding means Secure Boot state changes invalidate the TPM seal |
| Compromised root | Root can access the TPM — no mitigation at this layer. Use LUKS FDE for defence in depth |

### What this does NOT protect against

- An unencrypted disk at rest — this module is complementary to LUKS full-disk
  encryption, not a replacement. On a machine that doesn't travel, the risk is
  lower; on a laptop, enable LUKS.
- A machine that is running and unlocked with an active attacker present.

## Prerequisites

- Fedora 44+ (or any systemd + GNOME + PAM distribution with socket-activated
  `gnome-keyring-daemon.service`)
- YubiKey (or FIDO2 device) configured for PAM login via `pam_u2f`
- TPM2 chip (`/dev/tpmrm0`)
- `clevis` and `clevis-tpm2`
- User in the `tss` group
- Rust toolchain

```bash
sudo dnf install -y clevis clevis-tpm2 pam-devel gcc
sudo usermod -aG tss $USER
# Reboot for group change to take effect
```

## Building

```bash
git clone https://github.com/yourusername/pam-tpm-gnome-keyring
cd pam-tpm-gnome-keyring
cargo build --release
```

## Installation

### Binaries

```bash
# PAM module (system-wide, readable by PAM loader)
sudo cp target/release/libpam_tpm_gnome_keyring.so /lib64/security/pam_tpm_gnome_keyring.so
sudo chmod 644 /lib64/security/pam_tpm_gnome_keyring.so
sudo chown root:root /lib64/security/pam_tpm_gnome_keyring.so
sudo restorecon /lib64/security/pam_tpm_gnome_keyring.so

# Unlock helper (world-executable: PAM calls it as root, systemd calls it as user)
sudo cp target/release/gkd-unlock /usr/local/bin/gkd-unlock
sudo chmod 755 /usr/local/bin/gkd-unlock
sudo chown root:root /usr/local/bin/gkd-unlock
sudo restorecon /usr/local/bin/gkd-unlock
```

### Systemd user service (primary unlock path)

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/gnome-keyring-tpm-unlock.service << 'UNIT'
[Unit]
Description=Unlock GNOME keyring via TPM2
After=gnome-keyring-daemon.socket
Requires=gnome-keyring-daemon.socket

[Service]
Type=oneshot
ExecStart=/usr/local/bin/gkd-unlock %u
RemainAfterExit=yes

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable gnome-keyring-tpm-unlock.service
```

### PAM configuration

> ⚠️ Keep a root terminal open while editing PAM files. A mistake can lock
> you out.

First identify which GDM PAM service your login uses:

```bash
sudo journalctl -b | grep "AUDIT1100" | grep gdm
# Look for: exe="/usr/libexec/gdm-session-worker" — check the service name
# in the PAM stack log preceding it
```

On Fedora with a YubiKey, this is typically `/etc/pam.d/gdm-password`. Edit it
so the auth and session sections look like this:

**`/etc/pam.d/gdm-password`**

```
# Auth
auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth        optional      pam_tpm_gnome_keyring.so
auth        sufficient    pam_u2f.so cue [cue_prompt=Touch YubiKey]
auth        substack      password-auth
auth        optional      pam_gnome_keyring.so
auth        include       postlogin

# Account / password (unchanged)
account     required      pam_nologin.so
account     include       password-auth
password    substack       password-auth
-password   optional       pam_gnome_keyring.so use_authtok

# Session
session     required      pam_selinux.so close
session     required      pam_loginuid.so
session     required      pam_selinux.so open
session     optional      pam_keyinit.so force revoke
session     required      pam_namespace.so
session     include       password-auth
session     optional      pam_tpm_gnome_keyring.so
session     optional      pam_gnome_keyring.so
session     include       postlogin
```

Key points:
- `pam_tpm_gnome_keyring.so` appears in **both** auth and session sections.
- `pam_gnome_keyring.so` in the session section has **no `auto_start`**. With
  `auto_start`, it starts a `--login` mode daemon that fails to initialise
  PKCS11 and blocks the real socket-activated daemon from starting.

## Enrolment

Set a dedicated passphrase on the GNOME login keyring, decoupled from your
login password:

1. Open **Passwords and Keys** (Seahorse)
2. Right-click **Login** keyring → **Change Password**
3. Enter your current login password, set a new strong passphrase

Encrypt that passphrase with the TPM:

```bash
# Verify TPM round-trip works
clevis encrypt tpm2 '{"pcr_ids":"7"}' <<< "test" | clevis decrypt

# Encrypt your keyring passphrase
mkdir -p ~/.config/gnome-keyring-unlock
chmod 700 ~/.config/gnome-keyring-unlock
read -rs PASS && echo -n "$PASS" | \
    clevis encrypt tpm2 '{"pcr_ids":"7"}' \
    > ~/.config/gnome-keyring-unlock/secret.jwe
chmod 600 ~/.config/gnome-keyring-unlock/secret.jwe
unset PASS

# Verify
clevis decrypt < ~/.config/gnome-keyring-unlock/secret.jwe && echo OK
```

`pcr_ids: "7"` binds the secret to PCR 7 (Secure Boot state). Re-enrol after
Secure Boot component updates (shim, grub, kernel signing key changes).

## Verification

After a full reboot:

```bash
# Keyring should be unlocked immediately — no password prompt
gdbus call --session \
  --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets/collection/login \
  --method org.freedesktop.DBus.Properties.Get \
  org.freedesktop.Secret.Collection Locked
# Expected: (<false>,)

# Check service ran successfully
systemctl --user status gnome-keyring-tpm-unlock.service

# Check unlock log
journalctl -b -t gkd-unlock
```

## Troubleshooting

**Password prompt still appears**

Check timing — the unlock must happen before GNOME apps access the keyring:

```bash
journalctl -b --user -u gnome-keyring-tpm-unlock.service
journalctl -b -t gkd-unlock
```

If the service is slow (>5s), check:
- Is the user in the `tss` group? (`id | grep tss`)
- Is the TPM accessible? (`clevis decrypt < ~/.config/gnome-keyring-unlock/secret.jwe`)
- Did PCR 7 change? (Secure Boot update) → re-enrol

**`auto_start` causes broken daemon**

If you see these in the logs, `auto_start` is still set on `pam_gnome_keyring.so`:
```
lookup_login_keyring: assertion 'GCK_IS_SESSION (session)' failed
couldn't create login credential: (unknown)
```
Remove `auto_start` from the session entry in the PAM file.

**Re-enrolment after Secure Boot update**

```bash
rm ~/.config/gnome-keyring-unlock/secret.jwe
read -rs PASS && echo -n "$PASS" | \
    clevis encrypt tpm2 '{"pcr_ids":"7"}' \
    > ~/.config/gnome-keyring-unlock/secret.jwe
unset PASS
```

**Checking which PAM service GDM uses**

```bash
sudo ausearch -m user_auth -ts today | grep gdm | tail -3
# Look for: msg='op=PAM:authentication ... exe="/usr/libexec/gdm-session-worker"'
# The service name appears in the journal as gdm-password][PID] or similar
sudo journalctl -b | grep "gdm-password\]\|gdm-switchable" | head -5
```

## How the control socket protocol works

The GNOME keyring daemon exposes a Unix domain socket at
`/run/user/<uid>/keyring/control`. On Fedora, this socket is created by
systemd's socket activation (`gnome-keyring-daemon.socket`) before the daemon
process even starts.

The protocol (from `daemon/control/gkd-control-client.c` in gnome-keyring
source):

1. Connect to the socket.
2. Send a 1-byte message with `SCM_CREDENTIALS` ancillary data (PID/UID/GID).
   The daemon verifies the credential UID matches the socket file owner, so
   connections from root are rejected — this is why `gkd-unlock` drops
   privileges before connecting.
3. Send the unlock request (big-endian `egg_buffer` format):
   ```
   [u32: total_length = 12 + len(passphrase)]
   [u32: op_code = 1]   (GKD_CONTROL_OP_UNLOCK)
   [u32: passphrase_length]
   [bytes: passphrase]  (no null terminator)
   ```
4. Read the response:
   ```
   [u32: total_length]
   [u32: result_code]   (0=OK, 1=DENIED, 2=FAILED, 3=NO_DAEMON)
   ```

## Repository layout

```
src/
  lib.rs              PAM module (pam_tpm_gnome_keyring.so)
  bin/
    gkd-unlock.rs     Unlock helper binary
Cargo.toml
README.md
LICENSE
```

## License

MIT — see [LICENSE](LICENSE).
