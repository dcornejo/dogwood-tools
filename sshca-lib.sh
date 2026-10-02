# sshca-lib.sh -- shared helpers for the sshca scripts.
# POSIX sh; works on macOS, FreeBSD and Linux.  Source it; do not execute it.
#
#   common       logging, quoting, argument checks, expiry parsing
#   CA side      functions that need the CA keys ($SSHCA_DIR); run on the CA machine only
#   target side  t_* functions that install keys and edit sshd config.  They run as root on
#                the machine being configured (locally via sudo, or remotely via deploy.sh)
#   transport    x_* functions that run/copy things on "the target", which is either this
#                machine (TARGET empty) or an ssh host (TARGET=[user@]host)
#
# NOTE: functions share one variable namespace (plain POSIX sh).  Every function therefore uses
# its own underscore-prefixed names, and loop variables are never reused across functions that
# call each other (scripts use _a/_t/_v; the lib avoids those in anything they call).
#
# Callers must set SSHCA_LIB to the absolute path of this file before sourcing it
# (needed so privileged helpers can re-source it under sudo / over ssh).

SSHCA_DIR=${SSHCA_DIR:-${HOME:-/root}/.sshca}
SSHD_DIR=${SSHD_DIR:-/etc/ssh}
SSHCA_HOST_EXPIRY=${SSHCA_HOST_EXPIRY:-+52w}
SSHCA_USER_EXPIRY=${SSHCA_USER_EXPIRY:-+12w}
SSHCA_MARK=sshca-managed                       # tag on known_hosts lines this toolkit owns
SSHCA_BEGIN='# BEGIN sshca managed block'      # markers used when we must edit sshd_config itself
SSHCA_END='# END sshca managed block'
SSHCA_DROPIN=10-sshca.conf                     # sshd_config.d drop-in name (sorts early: first value wins)

# ---------------------------------------------------------------- common ---

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# shq STRING -- print STRING single-quoted so a POSIX shell reads it back verbatim
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

need_cmds() { for _c in "$@"; do command -v "$_c" >/dev/null 2>&1 || die "required command not found: $_c"; done; }

# need_val OPTION ARGC -- inside an option loop: fail if the option has no value
need_val() { [ "$2" -ge 2 ] || die "option $1 needs a value"; }

os_name() {
  case $(uname -s) in
    Darwin)  echo macos ;;
    FreeBSD) echo freebsd ;;
    Linux)   echo linux ;;
    *)       die "unsupported OS: $(uname -s)" ;;
  esac
}

now_stamp() { date -u +%Y%m%dT%H%M%SZ; }
first_of()  { printf '%s\n' "${1%%,*}"; }

# check_list LABEL LIST -- comma-separated names: letters digits . _ - : and * only
check_list() {
  case $2 in
    ''|*[!A-Za-z0-9._,:*-]*|,*|*,|*,,*) die "invalid $1: '$2'" ;;
  esac
}

# check_account NAME -- a plausible local account name
check_account() {
  case $1 in
    ''|-*|*[!A-Za-z0-9._-]*) die "invalid account name: '$1'" ;;
  esac
}

# validity SPEC -- turn an expiry into an ssh-keygen -V interval.
#   +52w, +30d, +12h, +1d12h   relative to now
#   2027-06-30 or 20270630     end of that day (23:59:59, local time)
# The start is backdated 5 minutes to tolerate clock skew.
validity() {
  case $1 in
    +[0-9]*[smhdw]) _end=$1 ;;
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) _end=$(printf '%s' "$1" | sed 's/-//g')235959 ;;
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])   _end=${1}235959 ;;
    *) die "bad expiry '$1' (use +52w, +30d or YYYY-MM-DD)" ;;
  esac
  printf '%s\n' "-5m:$_end"
}

# priv FUNCTION ARGS... -- run a lib function as root on THIS machine
priv() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    need_cmds sudo
    sudo sh -c '. "$0"; "$@"' "$SSHCA_LIB" "$@"
  fi
}

# ------------------------------------------------------------- CA side ---

ca_require() { [ -f "$SSHCA_DIR/$1/CURRENT" ] || die "no $1 CA in $SSHCA_DIR (run: ca.sh init)"; }

# ca_current KIND -- print the path of the private key that signs new KIND certs
ca_current() { ca_require "$1"; printf '%s/%s/%s\n' "$SSHCA_DIR" "$1" "$(cat "$SSHCA_DIR/$1/CURRENT")"; }

# ca_rebuild_trust -- regenerate the files that get distributed to hosts and users:
#   trust/user_ca_keys.pub      every trusted user CA   -> sshd TrustedUserCAKeys
#   trust/host_ca_known_hosts   every trusted host CA   -> @cert-authority lines for known_hosts
ca_rebuild_trust() {
  HOST_PATTERN='*'
  # shellcheck disable=SC1090,SC1091
  [ -f "$SSHCA_DIR/config" ] && . "$SSHCA_DIR/config"
  _t=$SSHCA_DIR/trust
  mkdir -p "$_t" || die "cannot create $_t"
  : > "$_t/user_ca_keys.pub.new"
  : > "$_t/host_ca_known_hosts.new"
  for _p in "$SSHCA_DIR"/user/*.pub; do
    [ -f "$_p" ] && cut -d' ' -f1,2 "$_p" >> "$_t/user_ca_keys.pub.new"
  done
  for _p in "$SSHCA_DIR"/host/*.pub; do
    [ -f "$_p" ] && printf '@cert-authority %s %s %s\n' "$HOST_PATTERN" "$(cut -d' ' -f1,2 "$_p")" "$SSHCA_MARK" >> "$_t/host_ca_known_hosts.new"
  done
  chmod 644 "$_t/user_ca_keys.pub.new" "$_t/host_ca_known_hosts.new"
  mv "$_t/user_ca_keys.pub.new" "$_t/user_ca_keys.pub"
  mv "$_t/host_ca_known_hosts.new" "$_t/host_ca_known_hosts"
}

# sign_cert KIND PUBFILE KEYID PRINCIPALS VALIDITY
# KIND is host or user.  Writes ${PUBFILE%.pub}-cert.pub next to PUBFILE.
# With SSHCA_AGENT=1 the CA key is taken from ssh-agent instead of prompting for its passphrase.
sign_cert() {
  _kind=$1; _pub=$2; _kid=$3; _princ=$4; _val=$5
  _ca=$(ca_current "$_kind") || return 1
  _hflag=
  [ "$_kind" = host ] && _hflag=-h
  if [ "${SSHCA_AGENT:-0}" = 1 ]; then
    # shellcheck disable=SC2086
    ssh-keygen -q -U -s "$_ca.pub" $_hflag -I "$_kid" -n "$_princ" -V "$_val" "$_pub"
  else
    # shellcheck disable=SC2086
    ssh-keygen -q -s "$_ca" $_hflag -I "$_kid" -n "$_princ" -V "$_val" "$_pub"
  fi
}

# cert_principals CERTFILE -- comma-separated principals of a certificate
cert_principals() {
  ssh-keygen -L -f "$1" | awk '
    /Principals:/ { p = 1; next }
    /^[ \t]*(Critical Options|Extensions):/ { p = 0 }
    p { gsub(/^[ \t]+|[ \t]+$/, ""); if ($0 != "" && $0 != "(none)") { printf "%s%s", (n++ ? "," : ""), $0 } }
    END { printf "\n" }'
}

# cert_valid CERTFILE -- "from ... to ..."
cert_valid() { ssh-keygen -L -f "$1" | sed -n 's/^ *Valid: *//p'; }

# agent_add KEYFILE -- add a key (and its certificate) to ssh-agent; macOS: also the keychain
agent_add() {
  if [ "$(os_name)" = macos ]; then
    ssh-add --apple-use-keychain "$1" 2>/dev/null || ssh-add -K "$1" 2>/dev/null || ssh-add "$1"
  else
    ssh-add "$1"
  fi
}

# --------------------------------------------------------- target side ---
# Everything below assumes it is running as root (or, for t_install_known_hosts and
# t_install_user_cert on your own account, as that user) on the machine being configured.

t_chown() {   # ACCOUNT PATH...
  _cw=$1; shift
  if [ "$(id -u)" -eq 0 ]; then chown "$_cw:$(id -gn "$_cw")" "$@"; fi
}

# t_relabel PATH... -- fix SELinux labels on files we created (RHEL family); a no-op elsewhere
t_relabel() {
  if command -v restorecon >/dev/null 2>&1; then restorecon -R "$@" >/dev/null 2>&1; fi
  return 0
}

t_home() {    # ACCOUNT -- print its home directory
  check_account "$1"
  _h=$(eval "printf '%s' ~$1")
  case $_h in ''|'~'*) die "no such account: $1" ;; esac
  printf '%s\n' "$_h"
}

t_fp() { ssh-keygen -l -f "$1" | awk '{print $2}'; }

# t_cert_matches CERT PUBKEY -- does the certificate belong to this public key?
t_cert_matches() { [ "$(t_fp "$1")" = "$(t_fp "$2")" ]; }

t_sshd_bin() {
  for _p in /usr/sbin/sshd /usr/local/sbin/sshd; do
    if [ -x "$_p" ]; then printf '%s\n' "$_p"; return 0; fi
  done
  command -v sshd
}

# t_sshd_test [FILE] -- validate an sshd configuration (default: the live one)
t_sshd_test() {
  _bin=$(t_sshd_bin) || { warn "sshd binary not found"; return 1; }
  # shellcheck disable=SC2174
  if [ "$(os_name)" = linux ] && [ ! -d /run/sshd ]; then mkdir -p -m 0755 /run/sshd; fi
  "$_bin" -t -f "${1:-$SSHD_DIR/sshd_config}"
}

# t_hostkey_explicit -- does the admin's own config already name HostKey files?
# (If so we must not widen the set of host keys sshd offers.)
t_hostkey_explicit() {
  {
    [ -f "$SSHD_DIR/sshd_config" ] &&
      awk -v b="$SSHCA_BEGIN" -v e="$SSHCA_END" '$0==b{s=1;next} $0==e{s=0;next} !s' "$SSHD_DIR/sshd_config"
    for _f in "$SSHD_DIR"/sshd_config.d/*; do
      [ -f "$_f" ] || continue
      [ "${_f##*/}" = "$SSHCA_DROPIN" ] && continue
      cat "$_f"
    done
  } 2>/dev/null | grep -Eq '^[[:space:]]*HostKey[[:space:]]'
}

# t_sshd_block -- the sshd_config lines this toolkit manages
t_sshd_block() {
  printf 'HostKey %s/ssh_host_ed25519_key\n' "$SSHD_DIR"
  if ! t_hostkey_explicit; then
    for _hk in ssh_host_ecdsa_key ssh_host_rsa_key; do
      [ -f "$SSHD_DIR/$_hk" ] && printf 'HostKey %s/%s\n' "$SSHD_DIR" "$_hk"
    done
  fi
  [ -f "$SSHD_DIR/ssh_host_ed25519_key-cert.pub" ] && printf 'HostCertificate %s/ssh_host_ed25519_key-cert.pub\n' "$SSHD_DIR"
  [ -f "$SSHD_DIR/sshca_user_ca_keys.pub" ] && printf 'TrustedUserCAKeys %s/sshca_user_ca_keys.pub\n' "$SSHD_DIR"
  # extra options persisted by rootlogin.sh, so later host renewals do not drop them
  [ -f "$SSHD_DIR/sshca_extra.conf" ] && cat "$SSHD_DIR/sshca_extra.conf"
  return 0
}

# t_sshd_configure -- make sshd use the managed block.
#   * If sshd_config has "Include .../sshd_config.d/...", write a drop-in (cleanest).
#   * Otherwise insert a marked block at the TOP of sshd_config (sshd uses the first value it
#     sees, and anything appended after a "Match" line would be swallowed by that Match).
# The new config is validated with "sshd -t" first; on failure nothing is left changed.
t_sshd_configure() {
  _cfg=$SSHD_DIR/sshd_config
  [ -f "$_cfg" ] || { warn "$_cfg not found; sshd not configured"; return 1; }
  _blk=$(mktemp) || return 1
  t_sshd_block > "$_blk"
  if grep -Eq '^[[:space:]]*Include[[:space:]]+.*sshd_config\.d' "$_cfg"; then
    _dir=$SSHD_DIR/sshd_config.d
    _dst=$_dir/$SSHCA_DROPIN
    mkdir -p "$_dir" || { rm -f "$_blk"; return 1; }
    _prev=$(mktemp); _had=0
    if [ -f "$_dst" ]; then cp "$_dst" "$_prev"; _had=1; fi
    { echo "# Managed by sshca -- changes here are overwritten"; cat "$_blk"; } > "$_dst"
    chmod 644 "$_dst"
    if t_sshd_test; then
      say "sshd: configuration in $_dst"
      _rc=0
    else
      if [ "$_had" -eq 1 ]; then cp "$_prev" "$_dst"; else rm -f "$_dst"; fi
      warn "sshd rejected the new configuration; change reverted"
      _rc=1
    fi
    rm -f "$_blk" "$_prev"
    return $_rc
  fi
  _new=$_cfg.sshca-new
  {
    echo "$SSHCA_BEGIN"; cat "$_blk"; echo "$SSHCA_END"
    awk -v b="$SSHCA_BEGIN" -v e="$SSHCA_END" '$0==b{s=1;next} $0==e{s=0;next} !s' "$_cfg"
  } > "$_new"
  rm -f "$_blk"
  chmod 644 "$_new"
  if cmp -s "$_new" "$_cfg"; then
    rm -f "$_new"; say "sshd: $_cfg already up to date"; return 0
  fi
  if t_sshd_test "$_new"; then
    _bak=$_cfg.sshca-bak.$(date +%Y%m%d%H%M%S)
    cp -p "$_cfg" "$_bak" && mv "$_new" "$_cfg" || { rm -f "$_new"; return 1; }
    say "sshd: updated $_cfg (backup: $_bak)"
  else
    rm -f "$_new"; warn "sshd rejected the new configuration; $_cfg left unchanged"; return 1
  fi
}

# t_sshd_reload -- make a running sshd re-read its config and host keys (existing sessions survive)
t_sshd_reload() {
  case $(os_name) in
    macos)
      say "sshd: macOS starts sshd per connection; no reload needed (Remote Login must be on)" ;;
    freebsd)
      if service sshd status >/dev/null 2>&1; then service sshd reload
      else warn "sshd is not running (enable: sysrc sshd_enable=YES; service sshd start)"; return 1; fi ;;
    linux)
      if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        for _u in ssh sshd; do
          if systemctl cat "$_u.service" >/dev/null 2>&1; then systemctl reload-or-restart "$_u"; return $?; fi
        done
        warn "no ssh/sshd systemd unit found"; return 1
      elif command -v rc-service >/dev/null 2>&1; then rc-service sshd reload
      elif command -v service >/dev/null 2>&1; then service ssh reload 2>/dev/null || service sshd reload
      else warn "do not know how to reload sshd here"; return 1; fi ;;
  esac
}

# t_ensure_host_key [rotate] -- make sure an ed25519 host key exists (rotate: replace it)
t_ensure_host_key() {
  _k=$SSHD_DIR/ssh_host_ed25519_key
  if [ "${1:-}" = rotate ] || [ ! -f "$_k" ]; then
    rm -f "$_k.new" "$_k.new.pub"
    ssh-keygen -q -t ed25519 -N '' -C "host key $(hostname)" -f "$_k.new" || return 1
    mv "$_k.new" "$_k" && mv "$_k.new.pub" "$_k.pub" || return 1
    say "host key: generated $_k"
  fi
}

# t_install_user_ca FILE -- trust these user CAs for logins (TrustedUserCAKeys)
t_install_user_ca() {
  [ -f "$SSHD_DIR/sshd_config" ] || { warn "no sshd_config here; skipping server-side trust"; return 0; }
  install -m 0644 "$1" "$SSHD_DIR/sshca_user_ca_keys.pub" || return 1
  t_relabel "$SSHD_DIR"
  t_sshd_configure || return 1
  t_sshd_reload || warn "sshd was NOT reloaded; reload it by hand"
}

# t_install_host_cert CERT [USER_CA_FILE] -- install a host certificate (and the user-CA trust)
t_install_host_cert() {
  _cert=$1; _uca=${2:-}
  _k=$SSHD_DIR/ssh_host_ed25519_key
  [ -f "$_k.pub" ] || { warn "no host key $_k"; return 1; }
  t_cert_matches "$_cert" "$_k.pub" || { warn "certificate does not match $_k.pub"; return 1; }
  install -m 0644 "$_cert" "$_k-cert.pub" || return 1
  if [ -n "$_uca" ]; then install -m 0644 "$_uca" "$SSHD_DIR/sshca_user_ca_keys.pub" || return 1; fi
  t_relabel "$SSHD_DIR"
  t_sshd_configure || return 1
  t_sshd_reload || warn "sshd was NOT reloaded; reload it by hand"
  say "host certificate installed: $_k-cert.pub"
}

# t_install_known_hosts FILE WHO -- install the host-CA trust lines for WHO ("system" or an account)
t_install_known_hosts() {
  _src=$1; _who=$2
  if [ "$_who" = system ]; then
    _dst=$SSHD_DIR/ssh_known_hosts
  else
    _home=$(t_home "$_who") || return 1
    _sd=$_home/.ssh
    if [ ! -d "$_sd" ]; then mkdir "$_sd" && chmod 700 "$_sd" && t_chown "$_who" "$_sd" || return 1; fi
    _dst=$_sd/known_hosts
  fi
  _tmp=$_dst.sshca-new
  {
    [ -f "$_dst" ] && grep -v " $SSHCA_MARK\$" "$_dst"
    cat "$_src"
  } > "$_tmp" || { rm -f "$_tmp"; return 1; }
  chmod 644 "$_tmp"
  [ "$_who" = system ] || t_chown "$_who" "$_tmp"
  mv "$_tmp" "$_dst" || return 1
  t_relabel "$_dst"
  say "known_hosts: host-CA trust installed in $_dst"
}

# t_user_prepare ACCOUNT KEYNAME OUTFILE CREATE -- make sure the account has a key; copy its .pub to OUTFILE
t_user_prepare() {
  _acct=$1; _key=$2; _out=$3; _create=$4
  _home=$(t_home "$_acct") || return 1
  _sd=$_home/.ssh
  if [ ! -f "$_sd/$_key.pub" ]; then
    [ "$_create" = 1 ] || { warn "$_acct has no $_sd/$_key.pub (use --create-keys to generate one)"; return 1; }
    if [ ! -d "$_sd" ]; then mkdir "$_sd" && chmod 700 "$_sd" && t_chown "$_acct" "$_sd" || return 1; fi
    ssh-keygen -q -t ed25519 -N '' -C "$_acct@$(hostname)" -f "$_sd/$_key" || return 1
    t_chown "$_acct" "$_sd/$_key" "$_sd/$_key.pub"
    say "key: generated $_sd/$_key (no passphrase)"
  fi
  t_relabel "$_sd"
  cp "$_sd/$_key.pub" "$_out" && chmod 644 "$_out"
}

# t_install_user_cert CERT ACCOUNT KEYNAME -- put the cert next to the account's key
t_install_user_cert() {
  _cert=$1; _acct=$2; _key=$3
  _home=$(t_home "$_acct") || return 1
  _sd=$_home/.ssh
  [ -f "$_sd/$_key.pub" ] || { warn "no $_sd/$_key.pub"; return 1; }
  t_cert_matches "$_cert" "$_sd/$_key.pub" || { warn "certificate does not match $_sd/$_key.pub"; return 1; }
  install -m 0644 "$_cert" "$_sd/$_key-cert.pub" || return 1
  t_chown "$_acct" "$_sd/$_key-cert.pub"
  t_relabel "$_sd"
  say "user certificate installed: $_sd/$_key-cert.pub"
}

# t_install_authorized_key PUBFILE ACCOUNT -- add a public key to authorized_keys (idempotent)
t_install_authorized_key() {
  _pub=$1; _acct=$2
  _home=$(t_home "$_acct") || return 1
  _sd=$_home/.ssh
  if [ ! -d "$_sd" ]; then mkdir "$_sd" && chmod 700 "$_sd" && t_chown "$_acct" "$_sd" || return 1; fi
  _ak=$_sd/authorized_keys
  [ -f "$_ak" ] || { : > "$_ak" && chmod 600 "$_ak" && t_chown "$_acct" "$_ak"; } || return 1
  _line=$(head -n 1 "$_pub")
  case $_line in ssh-*|ecdsa-*|sk-*) ;; *) warn "$_pub does not look like a public key"; return 1 ;; esac
  if grep -qxF "$_line" "$_ak"; then say "authorized_keys: key already present for $_acct"
  else printf '%s\n' "$_line" >> "$_ak" && say "authorized_keys: key added for $_acct"; fi
  t_relabel "$_sd"
}

# t_create_user ACCOUNT SHELL GROUPS COMMENT -- create a login-less-by-password account with a home dir
# (password logins stay impossible; access is by certificate/key only).  Existing accounts are left alone.
t_create_user() {
  _acct=$1; _shell=$2; _groups=$3; _comment=$4
  check_account "$_acct"
  if id "$_acct" >/dev/null 2>&1; then say "account $_acct already exists"; return 0; fi
  [ -x "$_shell" ] || { warn "shell $_shell not found"; return 1; }
  case $(os_name) in
    linux)
      if [ -n "$_groups" ]; then useradd -m -s "$_shell" -G "$_groups" -c "$_comment" "$_acct" || return 1
      else useradd -m -s "$_shell" -c "$_comment" "$_acct" || return 1; fi
      usermod -p '*' "$_acct" || return 1 ;;
    freebsd)
      if [ -n "$_groups" ]; then pw useradd -n "$_acct" -m -s "$_shell" -G "$_groups" -c "$_comment" -w no || return 1
      else pw useradd -n "$_acct" -m -s "$_shell" -c "$_comment" -w no || return 1; fi ;;
    macos)
      need_cmds sysadminctl dseditgroup createhomedir openssl
      # random password nobody ever sees: login is by certificate/key only
      sysadminctl -addUser "$_acct" -fullName "$_comment" -home "/Users/$_acct" -shell "$_shell" \
        -password "$(openssl rand -base64 24)" >/dev/null 2>&1 || return 1
      createhomedir -c -u "$_acct" >/dev/null 2>&1
      if dscl . -read /Groups/com.apple.access_ssh >/dev/null 2>&1; then
        dseditgroup -o edit -a "$_acct" -t user com.apple.access_ssh
      fi
      if [ -n "$_groups" ]; then
        _oifs=$IFS; IFS=,
        # shellcheck disable=SC2086
        for _g in $_groups; do dseditgroup -o edit -a "$_acct" -t user "$_g"; done
        IFS=$_oifs
      fi ;;
  esac
  say "account $_acct created (home $(t_home "$_acct"))"
}

# t_rootlogin enable|disable [USER_CA_FILE]
# enable : root may log in with keys/certificates only (PermitRootLogin prohibit-password:
#          passwords and keyboard-interactive are refused for root).
# disable: PermitRootLogin no.
t_rootlogin() {
  _mode=$1; _uca=${2:-}
  if [ -n "$_uca" ]; then install -m 0644 "$_uca" "$SSHD_DIR/sshca_user_ca_keys.pub" || return 1; fi
  case $_mode in
    enable)  printf 'PermitRootLogin prohibit-password\n' > "$SSHD_DIR/sshca_extra.conf" ;;
    disable) printf 'PermitRootLogin no\n' > "$SSHD_DIR/sshca_extra.conf" ;;
    *) warn "t_rootlogin: bad mode $_mode"; return 1 ;;
  esac
  chmod 644 "$SSHD_DIR/sshca_extra.conf"
  t_relabel "$SSHD_DIR"
  t_sshd_configure || return 1
  t_sshd_reload || warn "sshd was NOT reloaded; reload it by hand"
}

# t_status -- what sshd will actually do (effective config) plus host key fingerprints
t_status() {
  _bin=$(t_sshd_bin) || { warn "sshd binary not found"; return 1; }
  say "effective sshd settings (as seen for user root):"
  "$_bin" -T -f "$SSHD_DIR/sshd_config" -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null |
    grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|trustedusercakeys|hostcertificate|authorizedprincipalsfile) ' |
    sed 's/^/  /'
  say "note: for root, 'without-password' (= prohibit-password) refuses passwords and keyboard-interactive"
  say "      logins even where passwordauthentication is 'yes' for other accounts"
  say "host key fingerprints (check these on your first connection):"
  for _f in "$SSHD_DIR"/ssh_host_*_key.pub; do
    [ -f "$_f" ] && ssh-keygen -l -f "$_f" | sed 's/^/  /'
  done
  return 0
}

# ----------------------------------------------------------- transport ---
# Globals: TARGET ("" = this machine, else [user@]host)  SSH_OPTS (extra ssh options, space separated)
# x_open sets STAGE (a private scratch dir on the target), RUID/RUSER (login uid/name on the target)
# and WORK (scratch dir on this machine).  Call x_close from a trap.

x_open() {
  WORK=$(mktemp -d) || die "mktemp failed"
  if [ -z "$TARGET" ]; then
    STAGE=$(mktemp -d) || die "mktemp failed"
    RUID=$(id -u); RUSER=$(id -un)
    return 0
  fi
  need_cmds ssh
  CTL_DIR=$(mktemp -d /tmp/sshca-cm.XXXXXX) || die "mktemp failed"
  # shellcheck disable=SC2089
  X_SSH="ssh -o ControlMaster=auto -o ControlPath=$CTL_DIR/c-%C -o ControlPersist=120 $SSH_OPTS"
  STAGE=$(x_run 'mktemp -d /tmp/sshca.XXXXXX') || die "cannot log in to $TARGET"
  RUID=$(x_run 'id -u') || die "cannot run commands on $TARGET"
  # shellcheck disable=SC2034  # used by the calling scripts
  RUSER=$(x_run 'id -un')
  x_put "$SSHCA_LIB" sshca-lib.sh || die "cannot copy files to $TARGET"
}

x_close() {
  if [ -n "${STAGE:-}" ]; then
    if [ -z "$TARGET" ]; then rm -rf "$STAGE"; else x_run "rm -rf $(shq "$STAGE")" >/dev/null 2>&1; fi
  fi
  if [ -n "${CTL_DIR:-}" ]; then
    # shellcheck disable=SC2086
    $X_SSH -O exit "$TARGET" >/dev/null 2>&1
    rm -rf "$CTL_DIR"
  fi
  [ -n "${WORK:-}" ] && rm -rf "$WORK"
  return 0
}

# x_run 'shell command' -- run on the target as the login user; stdout is returned
x_run() {
  if [ -z "$TARGET" ]; then sh -c "$1"
  else
    # shellcheck disable=SC2086
    $X_SSH -n "$TARGET" "exec sh -c $(shq "$1")"
  fi
}

# x_put LOCALFILE NAME -- copy a file into the target's stage dir
x_put() {
  if [ -z "$TARGET" ]; then cp "$1" "$STAGE/$2"
  else
    # shellcheck disable=SC2086
    $X_SSH "$TARGET" "exec sh -c $(shq "cat > $(shq "$STAGE/$2")")" < "$1"
  fi
}

# x_cat REMOTEPATH LOCALFILE -- copy a (readable) file from the target to this machine
x_cat() {
  if [ -z "$TARGET" ]; then cat "$1" > "$2"
  else
    # shellcheck disable=SC2086
    $X_SSH -n "$TARGET" "exec sh -c $(shq "cat $(shq "$1")")" > "$2"
  fi
}

# x_priv FUNCTION ARGS... -- run a lib t_* function as root on the target.
# Remote: via "ssh -t ... sudo" (so a sudo password prompt works); no sudo if we log in as root.
x_priv() {
  if [ -z "$TARGET" ]; then priv "$@"; return $?; fi
  _cmd=
  [ "$RUID" = 0 ] || _cmd='sudo '
  _cmd="${_cmd}sh -c $(shq '. "$0"; "$@"') $(shq "$STAGE/sshca-lib.sh")"
  for _xa in "$@"; do _cmd="$_cmd $(shq "$_xa")"; done
  # shellcheck disable=SC2086
  $X_SSH -t "$TARGET" "exec sh -c $(shq "$_cmd")"
}
