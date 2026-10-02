#!/bin/sh
# deploy.sh -- configure or renew SSH certificates on this machine or on remote hosts.
# Run it on the CA machine.  The CA private keys never leave it: for a remote target the script
# fetches the public key over ssh, signs it HERE, copies the certificate back, and installs it.
#
#   deploy.sh ACTION [options] [-r [USER@]HOST ...] [-F HOSTSFILE]
#
# ACTION
#   host    sign/renew the host certificate and install it, plus user-CA trust for sshd
#   user    sign/renew user certificates for accounts on the target, plus host-CA trust for them
#   trust   push the current CA trust (after ca.sh rotate/retire) to sshd, system known_hosts, accounts
#   all     host + user
#
# TARGETS (default: this machine)
#   -r [USER@]HOST   operate on that host over ssh (repeatable).  Log in as root, or as a user
#                    with sudo (sudo may ask for a password; that is why ssh -t is used)
#   -F FILE          file of targets, one per line:  [USER@]HOST [HOSTNAMES]   (# comments ok)
#                    HOSTNAMES = comma-separated principals for that host's certificate
#   -o OPT           extra ssh option, e.g. -o Port=2222 (repeatable);  -i FILE  ssh identity
#
# OPTIONS
#   -n NAMES         host-cert principals (default: those on the host's current cert, else the
#                    hostname you gave to -r)
#   -u ACCOUNTS      accounts on the target to configure (default: the account you log in as)
#   -p PRINCIPALS    user-cert principals (default: the account name itself)
#   -e EXPIRY        expiry for both kinds of cert: +52w, +30d, +8h or YYYY-MM-DD
#   --host-expiry E  / --user-expiry E   set them separately   (defaults +52w / +12w)
#   -k KEYNAME       user key file name under ~/.ssh (default id_ed25519)
#   --rotate-key     (host) replace the host key instead of re-signing it
#   --create-keys    (user) generate a missing key for the account -- no passphrase!
#   -S               also install host-CA trust system-wide (/etc/ssh/ssh_known_hosts)
#   -A               take the CA key from ssh-agent (ssh-add the CA key first) so a batch of
#                    hosts does not ask for its passphrase every time
#
# Typical renewal run:   deploy.sh all -F hosts.txt -u alice,bob -A
# What gets installed is the same as in hostcert.sh / usercert.sh; see README.md.

set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
SSHCA_LIB=$HERE/sshca-lib.sh
# shellcheck disable=SC1090
. "$SSHCA_LIB"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

[ $# -ge 1 ] || { usage; exit 1; }
case $1 in -h|--help|help) usage; exit 0 ;; esac
ACTION=$1; shift
case $ACTION in host|user|trust|all) ;; *) usage; exit 1 ;; esac

TLIST=$(mktemp) || die "mktemp failed"
trap 'rm -f "$TLIST"' EXIT
NAMES=; USERS=; PRINC=; HEXP=$SSHCA_HOST_EXPIRY; UEXP=$SSHCA_USER_EXPIRY
KEYNAME=id_ed25519; ROTATE=0; CREATE=0; SYSKH=0; SSH_OPTS=
HAVE_T=0

add_target() { printf '%s|%s\n' "$1" "$2" >> "$TLIST"; HAVE_T=1; }

while [ $# -gt 0 ]; do
  case $1 in
    -r|--remote)   need_val "$1" $#; add_target "$2" ""; shift 2 ;;
    -F|--file)     need_val "$1" $#; [ -f "$2" ] || die "no such file: $2"
                   while read -r _t _n _rest; do
                     case $_t in ''|'#'*) continue ;; esac
                     case $_n in '#'*) _n= ;; esac        # a trailing comment is not a name list
                     add_target "$_t" "$_n"
                   done < "$2"
                   shift 2 ;;
    -o)            need_val "$1" $#; SSH_OPTS="$SSH_OPTS -o $2"; shift 2 ;;
    -i)            need_val "$1" $#; SSH_OPTS="$SSH_OPTS -i $2"; shift 2 ;;
    -n|--names)    need_val "$1" $#; NAMES=$2; shift 2 ;;
    -u|--users)    need_val "$1" $#; USERS=$2; shift 2 ;;
    -p|--principals) need_val "$1" $#; PRINC=$2; shift 2 ;;
    -e|--expiry)   need_val "$1" $#; HEXP=$2; UEXP=$2; shift 2 ;;
    --host-expiry) need_val "$1" $#; HEXP=$2; shift 2 ;;
    --user-expiry) need_val "$1" $#; UEXP=$2; shift 2 ;;
    -k|--keyname)  need_val "$1" $#; KEYNAME=$2; shift 2 ;;
    --rotate-key)  ROTATE=1; shift ;;
    --create-keys) CREATE=1; shift ;;
    -S|--system-known-hosts) SYSKH=1; shift ;;
    -A|--agent)    SSHCA_AGENT=1; export SSHCA_AGENT; shift ;;
    -h|--help)     usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[ "$HAVE_T" = 1 ] || add_target "" "$NAMES"       # no targets given: this machine

need_cmds ssh-keygen
ca_require host; ca_require user
ca_rebuild_trust
case $KEYNAME in */*|'') die "-k takes a file NAME (no slashes), e.g. id_ed25519" ;; esac
[ -z "$NAMES" ] || check_list "host names" "$NAMES"
[ -z "$PRINC" ] || check_list "user principals" "$PRINC"

HK=$SSHD_DIR/ssh_host_ed25519_key

do_host() {
  if [ "$ROTATE" = 1 ]; then
    x_priv t_ensure_host_key rotate || die "host key rotation failed"
  else
    x_priv t_ensure_host_key || die "could not create a host key"
  fi
  x_cat "$HK.pub" "$WORK/ssh_host_ed25519_key.pub" 2>/dev/null && [ -s "$WORK/ssh_host_ed25519_key.pub" ] ||
    die "cannot read $HK.pub on the target"
  _names=$HNAMES
  if [ -z "$_names" ] && x_cat "$HK-cert.pub" "$WORK/old-cert.pub" 2>/dev/null && [ -s "$WORK/old-cert.pub" ]; then
    _names=$(cert_principals "$WORK/old-cert.pub")
  fi
  if [ -z "$_names" ]; then
    if [ -n "$TARGET" ]; then _names=${TARGET#*@}
    else _names=$(hostname -f 2>/dev/null || hostname); fi
    warn "no names given and no current cert: using '$_names' (override with -n)"
  fi
  check_list "host names" "$_names"
  _v=$(validity "$HEXP") || exit 1
  sign_cert host "$WORK/ssh_host_ed25519_key.pub" "host_$(first_of "$_names")_$(now_stamp)" "$_names" "$_v" ||
    die "signing failed"
  x_put "$WORK/ssh_host_ed25519_key-cert.pub" host-cert.pub || die "copy failed"
  x_put "$SSHCA_DIR/trust/user_ca_keys.pub" user_ca_keys.pub || die "copy failed"
  x_priv t_install_host_cert "$STAGE/host-cert.pub" "$STAGE/user_ca_keys.pub" || die "host certificate installation failed"
  if [ "$SYSKH" = 1 ]; then
    x_put "$SSHCA_DIR/trust/host_ca_known_hosts" known_hosts || die "copy failed"
    x_priv t_install_known_hosts "$STAGE/known_hosts" system || warn "system known_hosts install failed"
  fi
  say "host cert for: $_names"
  say "validity:      $(cert_valid "$WORK/ssh_host_ed25519_key-cert.pub")"
}

do_user() {
  _accts=${USERS:-$RUSER}
  x_put "$SSHCA_DIR/trust/host_ca_known_hosts" known_hosts || die "copy failed"
  _v=$(validity "$UEXP") || exit 1
  _oifs=$IFS; IFS=,; set -f
  # shellcheck disable=SC2086
  set -- $_accts
  set +f; IFS=$_oifs
  for _a; do
    check_account "$_a"
    _pr=${PRINC:-$_a}
    x_priv t_user_prepare "$_a" "$KEYNAME" "$STAGE/$_a.pub" "$CREATE" || die "no usable key for $_a"
    x_cat "$STAGE/$_a.pub" "$WORK/$_a.pub" || die "cannot fetch key for $_a"
    sign_cert user "$WORK/$_a.pub" "user_${_a}_$(now_stamp)" "$_pr" "$_v" || die "signing failed for $_a"
    x_put "$WORK/$_a-cert.pub" "$_a-cert.pub" || die "copy failed"
    x_priv t_install_user_cert "$STAGE/$_a-cert.pub" "$_a" "$KEYNAME" || die "certificate install failed for $_a"
    x_priv t_install_known_hosts "$STAGE/known_hosts" "$_a" || warn "known_hosts install failed for $_a"
    say "user cert for $_a (may log in as: $_pr)  validity: $(cert_valid "$WORK/$_a-cert.pub")"
  done
}

do_trust() {
  x_put "$SSHCA_DIR/trust/user_ca_keys.pub" user_ca_keys.pub || die "copy failed"
  x_put "$SSHCA_DIR/trust/host_ca_known_hosts" known_hosts || die "copy failed"
  x_priv t_install_user_ca "$STAGE/user_ca_keys.pub" || warn "could not update sshd trust"
  x_priv t_install_known_hosts "$STAGE/known_hosts" system || warn "could not update system known_hosts"
  if [ -n "$USERS" ]; then
    _oifs=$IFS; IFS=,; set -f
    # shellcheck disable=SC2086
    set -- $USERS
    set +f; IFS=$_oifs
    for _a; do
      check_account "$_a"
      x_priv t_install_known_hosts "$STAGE/known_hosts" "$_a" || warn "known_hosts install failed for $_a"
    done
  fi
}

deploy_one() {   # TARGET HOSTNAMES -- runs in a subshell; die only ends this target
  TARGET=$1; HNAMES=${2:-$NAMES}     # per-host names from -F win over the global -n
  trap 'x_close' EXIT
  trap 'x_close; exit 130' INT TERM HUP
  x_open
  say "=== ${TARGET:-this machine} (logged in as $RUSER) ==="
  case $ACTION in
    host)  do_host ;;
    user)  do_user ;;
    trust) do_trust ;;
    all)   do_host; do_user ;;
  esac
}

fails=
while IFS='|' read -r t n <&3; do
  if ( deploy_one "$t" "$n" ); then :
  else fails="$fails ${t:-local}"; warn "FAILED: ${t:-this machine}"
  fi
done 3< "$TLIST"

if [ -n "$fails" ]; then die "failed targets:$fails"; fi
say "done."
