# sshca — SSH certificate authority toolkit

Shell scripts (POSIX `sh`) for running your own SSH certificate authority and using it on
macOS, FreeBSD and Linux.

**What you get**

- **Host certificates.** A host presents a certificate signed by your host CA. Users who trust
  that CA are never asked "are you sure you want to continue connecting?".
- **User certificates.** A user presents a certificate signed by your user CA. Hosts that trust
  that CA let the user in with no password and no `authorized_keys` bookkeeping.
- **Renewal from one place.** The CA private keys never leave your secured machine. It reaches
  out over ssh, signs, and installs.

---

## 1. Concepts in one minute

| Term | Meaning |
|---|---|
| **CA** | A key pair whose only job is to sign other keys. Here there are two: a **host CA** and a **user CA**, so a compromise of one does not give away the other. |
| **Certificate** | A public key + a list of names + an expiry, signed by a CA. Stored next to the key as `<key>-cert.pub`. |
| **Principals** | The names inside a certificate. For a **host** cert: the names clients type (`web1.example.com`, `web1`, an IP). For a **user** cert: the login names it may log in *as* (`alice`, `root`). |
| **Trust** | Hosts trust a *user CA* via `TrustedUserCAKeys` in `sshd_config`. Users trust a *host CA* via an `@cert-authority` line in `known_hosts`. |
| **Generation** | A CA key is identified by a UTC timestamp. Rotating adds a new generation and keeps the old one trusted until you retire it. |

A user is accepted on a host when: the host trusts the user CA, the certificate is signed by
it and unexpired, **and one of its principals equals the account being logged in to**
(no `AuthorizedPrincipalsFile` is used).

```
                CA machine (secured)                         target host
   ┌───────────────────────────────────────┐        ┌──────────────────────────────┐
   │ ~/.sshca/host/<gen>   host CA key     │        │ ssh_host_ed25519_key         │
   │ ~/.sshca/user/<gen>   user CA key     │  ssh   │  + -cert.pub  (signed here)  │
   │ ca.sh hostcert.sh usercert.sh         │ ─────► │ TrustedUserCAKeys (user CA)  │
   │ deploy.sh newuser.sh                  │        │ ~/.ssh/id_ed25519-cert.pub   │
   └───────────────────────────────────────┘        └──────────────────────────────┘
        public key fetched ► signed locally ► certificate copied back and installed
```

## 2. The scripts

| Script | Runs on | Purpose |
|---|---|---|
| `ca.sh` | CA machine | Create the CAs; rotate, retire, list; install trust locally. |
| `hostcert.sh` | CA machine (for itself) | Create / sign / renew a **host** certificate and install it on this machine. |
| `usercert.sh` | CA machine (for your account) | Create / sign / renew a **user** certificate; install it under `~/.ssh`. |
| `deploy.sh` | CA machine | The same installs, but **on this machine or on remote hosts over ssh**. Used for renewals. |
| `rootlogin.sh` | **the target host** | One-time bootstrap: allow root to log in with certificates/keys only. |
| `newuser.sh` | CA machine | ssh in as root, create an account with a home directory, set up its keys, certs and trust. |
| `sshca-lib.sh` | (library) | Shared code. Must stay next to the scripts. |

Every script prints its full usage with `--help`.

**Requirements.** OpenSSH 8.2+ on all machines (`ssh`, `ssh-keygen`, `sshd`), `sudo` for
non-root use, and on remote hosts a login that is root or can `sudo`. Linux user creation uses
`useradd` (Debian and RHEL families).

**Install.** Copy the directory anywhere on the CA machine and `chmod +x *.sh`. The tarball
preserves the executable bits. The directory holds no secrets, so it is safe to copy to a target
host for `rootlogin.sh`.

## 3. Set up the CA (once)

On your secured machine:

```sh
cd sshca
./ca.sh init -p '*.example.com'
```

- Asks for a passphrase for each CA key (host, then user). **Use one**; use
  `--no-passphrase` only for throwaway testing.
- `-p` is the host-name pattern the host CA is trusted for in `known_hosts`
  (comma-separated, wildcards ok, e.g. `'*.example.com,*.lan'`). Default `*`. Narrower is better.
- Creates `~/.sshca` (override with `SSHCA_DIR`):

```
~/.sshca/host/<gen>[.pub]   host CA key(s)        ~/.sshca/trust/user_ca_keys.pub     -> hosts' TrustedUserCAKeys
~/.sshca/user/<gen>[.pub]   user CA key(s)        ~/.sshca/trust/host_ca_known_hosts  -> clients' known_hosts
~/.sshca/{host,user}/CURRENT   which gen signs    ~/.sshca/retired/                   old generations
```

- Installs trust on this machine: your `~/.ssh/known_hosts` gets the host-CA line, and if this
  machine runs sshd it starts trusting the user CA. Skip with `--no-install`.

**Back up `~/.sshca`** (offline, encrypted). Whoever holds the CA keys can mint certificates
every host and user will trust. Losing them means re-issuing everything.

Then give **yourself** a certificate. Include `root` as a principal if you will log in as root
(use case B):

```sh
./usercert.sh create -u "$(id -un),root" -e +12w -a
```

`create` makes `~/.ssh/id_ed25519` (asks for a key passphrase), signs it, installs the cert next
to it and the host-CA trust in `known_hosts`, and with `-a` adds it to ssh-agent (macOS: and the
keychain). ssh finds `id_ed25519-cert.pub` automatically.

## 4. Use cases

### A. One server, doing everything on that machine

```sh
./hostcert.sh create -n web1.example.com,web1 -e 2027-06-30     # new host key + cert + sshd config + reload
./hostcert.sh renew                                             # later: re-sign, same names
./hostcert.sh renew --rotate-key                                # also replace the host key itself
```

Use this when the CA machine *is* the server. It writes `/etc/ssh/ssh_host_ed25519_key-cert.pub`,
puts the user-CA trust in `/etc/ssh/sshca_user_ca_keys.pub`, and adds `HostKey`, `HostCertificate`
and `TrustedUserCAKeys` through an `sshd_config.d` drop-in (or, where `sshd_config` has no
`Include`, a marked block at the **top** of `sshd_config`, with a timestamped backup). The config
is checked with `sshd -t` first and reverted if sshd rejects it. Then sshd is reloaded; existing
sessions survive.

### B. Bootstrap root login on a new server, then manage it remotely

This is the intended flow for machines that are not yet set up.

**1. On the CA machine**, copy the toolkit and the user-CA public key to the server:

```sh
scp -r sshca ~/.sshca/trust/user_ca_keys.pub you@server:
```

**2. On the server**, logged in as yourself:

```sh
cd sshca && sudo ./rootlogin.sh enable --user-ca ../user_ca_keys.pub
# optional fallback: add  --authorized-key ~/my_key.pub  to that same command to also
# allow one plain public key for root (works even without a certificate)
```

It trusts your user CA, sets `PermitRootLogin prohibit-password` (root can use a key or
certificate; **passwords and keyboard-interactive are refused for root**, other accounts are
unchanged), validates, reloads, and prints the server's **host-key fingerprints**. Keep them.

**3. On the CA machine**, make the server's identity verifiable and remove the first-connection
prompt for good:

```sh
./deploy.sh host -r root@server -n server.example.com,server
```

This is the one time ssh asks "continue connecting?". Compare the fingerprint with step 2, answer
`yes`, and from then on the host has a certificate and nobody is prompted again.

`rootlogin.sh status` shows the effective settings. `rootlogin.sh disable` sets
`PermitRootLogin no` again. The CA trust stays, so ordinary user certificates keep working.

### C. Create users

```sh
# Account whose keys live on the server (service/automation accounts):
./newuser.sh -r root@server -u backup -G users -c "Backup service"

# A person with their own key. They send you the PUBLIC key; you send back the certificate:
./newuser.sh -r root@server -u alice -k alice_ed25519.pub --out ./issued/alice
```

Both create the account with a home directory and **no password** (access is by certificate
only), install the host-CA trust in the new user's `~/.ssh/known_hosts`, and sign a user
certificate whose principal is the account name (override with `-p`).

- **Generated on the host** (default): an ed25519 key is created in `~/.ssh` with **no
  passphrase**, signed, and installed as `id_ed25519-cert.pub`.
- **Own key** (`-k`): the person's key never leaves their machine. The cert is written to
  `--out`; they save it as `<their key>-cert.pub` and `ssh alice@server` works. Their public key
  is also added to `authorized_keys` unless you pass `--cert-only`.

Extras: `-s SHELL`, `-G groups` (`sudo`, `wheel`, `admin`), `-e EXPIRY`. An account that
already exists is kept and just (re)configured.

### D. A user's own workstation (including macOS)

```sh
./usercert.sh create -u alice -e +12w -a       # first time
./usercert.sh renew  -e +12w -a                # renewal: same key, new certificate
./usercert.sh sign -k bob.pub -u bob -o ./out  # sign a colleague's public key and send it back
```

### E. Renewals across many machines

Put targets in a file, one per line, with optional host-certificate names:

```
# hosts.txt
root@web1.example.com   web1.example.com,web1
root@db1.example.com    db1.example.com,db1
admin@legacy.example.com             # not root: needs sudo on the target
```

```sh
ssh-add ~/.sshca/host/$(cat ~/.sshca/host/CURRENT) ~/.sshca/user/$(cat ~/.sshca/user/CURRENT)
./deploy.sh host -F hosts.txt -A -e +52w                 # re-sign every host
./deploy.sh user -F hosts.txt -A -u alice,backup -e +12w # re-sign accounts whose key is on the host
```

- `-A` signs using the CA keys held in ssh-agent, so a batch does not prompt for the CA
  passphrase per host.
- A host that fails is reported and the run continues with the next; the exit status is
  non-zero if any failed.
- With no `-n`, a host's existing certificate names are reused.
- `deploy.sh user` renews accounts whose private key **is on that host**. For people who hold
  their own key (use case C with `-k`), re-sign their public key with `usercert.sh sign`.
- Renew well before expiry (about half-life). Certificates are time-bound, so keep clocks in sync
  (NTP). Validity starts 5 minutes in the past to tolerate small skew.
- `-e` takes `+52w`, `+30d`, `+8h` or `YYYY-MM-DD` (end of that day, local time). Defaults:
  hosts `+52w`, users `+12w` (`SSHCA_HOST_EXPIRY`, `SSHCA_USER_EXPIRY`).

### F. Rotate the CA

Rotation keeps the old CA trusted while certificates are re-issued, so nothing breaks.

```sh
./ca.sh rotate both                      # new generation; old one still trusted
./deploy.sh all -F hosts.txt -A -u alice,backup     # re-sign everything under the new CA, push trust
./usercert.sh renew -a                              # your own certificate
./ca.sh list                                        # shows generations; * = signs new certs
./ca.sh retire host <old-generation>
./ca.sh retire user <old-generation>
./deploy.sh trust -F hosts.txt -A -u alice,backup   # old CA no longer trusted anywhere
```

Before retiring a user CA, re-sign people who use their own key (`usercert.sh sign`).
Certificates signed by a retired CA stop working as soon as hosts get the new trust.

## 5. Reference

**`ca.sh`**: `init [-p PATTERN] [--no-passphrase] [--no-install]` ·
`rotate host|user|both` · `retire host|user GEN` · `list` · `install`

**`hostcert.sh`**: `create -n NAMES [-e EXP] [--force]` · `renew [-n NAMES] [-e EXP] [--rotate-key]` ·
`sign -k PUB -n NAMES [-o DIR]` · `--system-known-hosts` for host-to-host trust

**`usercert.sh`**: `create|renew [-u NAMES] [-e EXP] [-K KEYFILE] [-a] [--no-known-hosts]` ·
`sign -k PUB -u NAMES [-o DIR]`

**`deploy.sh`**: `host|user|trust|all` · `-r [USER@]HOST` (repeat) · `-F FILE` · `-n NAMES` ·
`-u ACCOUNTS` · `-p PRINCIPALS` · `-e`/`--host-expiry`/`--user-expiry` · `-k KEYNAME` ·
`--rotate-key` · `--create-keys` (passphrase-less!) · `-S` (system-wide known_hosts) ·
`-A` (CA key from agent) · `-o OPT` / `-i FILE` (ssh options)

**`rootlogin.sh`**: `enable --user-ca FILE|- [--authorized-key FILE]` · `disable` · `status`

**`newuser.sh`**: `-r TARGET -u NAME [-k PUB] [-p PRINCIPALS] [-e EXP] [-s SHELL] [-G GROUPS] [-c COMMENT] [--out DIR] [--cert-only] [-A] [-o OPT] [-i FILE]`

**Environment**: `SSHCA_DIR` (default `~/.sshca`) · `SSHCA_HOST_EXPIRY` · `SSHCA_USER_EXPIRY` ·
`SSHCA_AGENT=1` (same as `-A`) · `SSHD_DIR` (default `/etc/ssh`; honored locally only, remote
targets must use `/etc/ssh`).

### What gets installed where

| Item | Location |
|---|---|
| Host certificate | `/etc/ssh/ssh_host_ed25519_key-cert.pub` |
| User-CA trust for sshd | `/etc/ssh/sshca_user_ca_keys.pub` |
| sshd settings | `/etc/ssh/sshd_config.d/10-sshca.conf` (or marked block atop `sshd_config`; backup `sshd_config.sshca-bak.<time>`) |
| Root-login setting | `/etc/ssh/sshca_extra.conf` (included in the managed block, so host renewals keep it) |
| Host-CA trust, per user | `~/.ssh/known_hosts` (lines tagged `sshca-managed`; your other entries are untouched) |
| Host-CA trust, system-wide | `/etc/ssh/ssh_known_hosts` (with `-S` / `trust`) |
| User certificate | `~/.ssh/id_ed25519-cert.pub` (next to the key) |

Reload behavior: Linux `systemctl reload-or-restart ssh|sshd` (or `service`/OpenRC), FreeBSD
`service sshd reload`; macOS starts sshd per connection, so no reload is needed (Remote Login must be on).

## 6. Troubleshooting

Start with `ssh -v`, `ssh-keygen -L -f <cert>`, and the server log
(`journalctl -u ssh`, `/var/log/auth.log`, `/var/log/secure`, or `/var/log/messages`).
sshd logs the exact reason, e.g. *"Certificate invalid: name is not a listed principal"* or *"expired"*.

| Symptom | Likely cause and fix |
|---|---|
| Still asked "continue connecting?" | The host has no certificate, or the name you typed is not among its principals (add short names/IPs: `deploy.sh host -n a.example.com,a,10.0.0.5`), or the host-CA pattern does not match (`ca.sh list` shows it). Check with `ssh -v host 2>&1 \| grep -i cert`. |
| `Permission denied (publickey)` with a cert | The cert lacks the login name as a principal (`ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub`); it expired; the host does not trust the user CA (`sudo sshd -T \| grep trustedusercakeys`); or clocks differ. |
| Root login refused | Cert needs principal `root`; `rootlogin.sh status`; the host must have run `rootlogin.sh enable`. |
| Cert not being offered | Key has a non-default name: add `IdentityFile ~/.ssh/mykey` to `~/.ssh/config`. Check `ssh-add -L` shows the `-cert` line. |
| `deploy.sh` stalls at a sudo prompt | Non-root targets use `ssh -t` so sudo can ask for a password; unattended runs need passwordless sudo or a root login. |
| sshd was not reloaded | The script says so. Reload by hand, then check with `sshd -T`. |
| RHEL/SELinux denials | `restorecon -Rv /etc/ssh ~/.ssh`. The scripts try this automatically. |

## 7. Security notes and limits

- **The CA keys are the crown jewels.** Passphrase them, keep them on a locked-down machine, back
  them up offline. `-A` puts them in ssh-agent: convenient, but anyone who can use your agent
  socket can sign.
- **Root by certificate means the CA is root everywhere.** Consider a separate short-lived admin
  certificate that carries `root`, for example `usercert.sh create -K ~/.ssh/id_admin -u root -e +1d` (use it with
  `ssh -i ~/.ssh/id_admin root@host`), and keep your daily certificate free of the `root` principal.
- **No revocation list.** Expiry is the control: use short lifetimes for users. To cut someone off
  earlier, remove the account or retire the CA. Adding a KRL is a small extension if you need it.
- **Host keys have no passphrase** (sshd must read them unattended), and keys generated by
  `newuser.sh` / `--create-keys` have none either. Use `-k` when a person should hold their own
  passphrase-protected key.
- **Trust on first use happens once**, in use case B step 3. Verify the fingerprint.
- Narrow the host CA's `known_hosts` pattern (`ca.sh init -p`) to your own domains.

## 8. What has been tested

Tested on Ubuntu 24.04 (OpenSSH 9.6) against a live `sshd`, including real logins and strict host
checking: CA init, rotation and retirement with overlap; host, user and own-key certificates;
`rootlogin.sh` enable/disable (root password refused, certificates without the `root` principal
refused, other users' password logins unchanged); `deploy.sh` over ssh as root and as a sudo user,
multi-host runs with an unreachable host, trust pushes and the agent-signing path; `newuser.sh`
in both modes and `--cert-only`; the `sshd_config` edit path for configs without `Include` (with
a `Match` block present). The scripts pass `dash -n` and `shellcheck`.

**Not run on macOS or FreeBSD, nor on an SELinux-enforcing RHEL host.** Those paths follow each
platform's documented tools (`pw useradd`, `sysadminctl`/`dseditgroup`, `service sshd reload`,
`restorecon`, BSD userland differences) but are unverified. Try them on a throwaway machine
first, `newuser.sh` on macOS in particular. Passphrase prompts were exercised via stdin only,
not on an interactive terminal.
