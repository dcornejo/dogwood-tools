#!/bin/sh
# usercert.sh -- create, sign and renew SSH user certificates (run on the CA machine).
#
#   usercert.sh create [-u NAMES] [-e EXPIRY] [-K KEYFILE] [-a] [--no-known-hosts]
#   usercert.sh renew  [-u NAMES] [-e EXPIRY] [-K KEYFILE] [-a] [--no-known-hosts]
#   usercert.sh sign   -k PUBKEY -u NAMES [-e EXPIRY] [-o DIR]
#
#   create   generate an ed25519 key pair for YOUR account (ssh-keygen asks for a passphrase),
#            sign it, and install key, certificate and host-CA trust under ~/.ssh.
#   renew    re-sign your existing key and install the new certificate.
#   sign     sign a public key someone sent you.  Nothing is installed; the certificate is
#            written to DIR (default: current directory) as <key>-cert.pub, to send back.
#
#   -u NAMES   comma-separated principals = the login names the certificate may log in AS on
#              hosts.  Default for create/renew: your username.  Example: -u alice,root
#   -e EXPIRY  +12w  +30d  +8h  or  YYYY-MM-DD (end of that day).   Default: $SSHCA_USER_EXPIRY or +12w
#   -K FILE    private key to use (default ~/.ssh/id_ed25519).  The cert goes beside it as
#              FILE-cert.pub, which ssh finds automatically for default key names; for other
#              names add "IdentityFile FILE" to ~/.ssh/config.
#   -a         also add the key to ssh-agent (macOS: and the keychain)
#   --no-known-hosts   do not install the host-CA trust into ~/.ssh/known_hosts
#
# Hosts accept the certificate when (1) they trust the user CA (TrustedUserCAKeys) and
# (2) one of its principals equals the account being logged in to.
# To do this for accounts on a remote machine use deploy.sh user.
# Set SSHCA_AGENT=1 to take the CA key from ssh-agent instead of prompting for its passphrase.

set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
SSHCA_LIB=$HERE/sshca-lib.sh
# shellcheck disable=SC1090
. "$SSHCA_LIB"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

[ $# -ge 1 ] || { usage; exit 1; }
case $1 in -h|--help|help) usage; exit 0 ;; esac
cmd=$1; shift

me=$(id -un)
names=; exp=$SSHCA_USER_EXPIRY; pubin=; outdir=.; keyfile=$HOME/.ssh/id_ed25519; agent=0; knownhosts=1
while [ $# -gt 0 ]; do
  case $1 in
    -u|--users)  need_val "$1" $#; names=$2; shift 2 ;;
    -e|--expiry) need_val "$1" $#; exp=$2; shift 2 ;;
    -k|--key)    need_val "$1" $#; pubin=$2; shift 2 ;;
    -K|--keyfile) need_val "$1" $#; keyfile=$2; shift 2 ;;
    -o|--out)    need_val "$1" $#; outdir=$2; shift 2 ;;
    -a|--agent)  agent=1; shift ;;
    --no-known-hosts) knownhosts=0; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

need_cmds ssh-keygen
ca_require user
WORK=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT INT TERM HUP
v=$(validity "$exp") || exit 1

# sign_and_install -- sign $keyfile.pub for $names and put the certificate beside the key
sign_and_install() {
  check_list "user names" "$names"
  _b=$(basename "$keyfile")
  cp "$keyfile.pub" "$WORK/$_b.pub" || die "cannot read $keyfile.pub"
  sign_cert user "$WORK/$_b.pub" "user_$(first_of "$names")_$(now_stamp)" "$names" "$v" || die "signing failed"
  install -m 0644 "$WORK/$_b-cert.pub" "$keyfile-cert.pub" || die "cannot write $keyfile-cert.pub"
  say "user certificate installed: $keyfile-cert.pub"
  say "may log in as: $names"
  say "validity:      $(cert_valid "$keyfile-cert.pub")"
  if [ "$knownhosts" = 1 ]; then
    ca_rebuild_trust
    t_install_known_hosts "$SSHCA_DIR/trust/host_ca_known_hosts" "$me" || warn "could not update known_hosts"
  fi
  if [ "$agent" = 1 ]; then agent_add "$keyfile" || warn "ssh-add failed"; fi
}

case $cmd in
  create)
    [ ! -f "$keyfile" ] || die "$keyfile already exists; use 'renew' to re-sign it"
    [ -n "$names" ] || names=$me
    mkdir -p "$(dirname "$keyfile")" && chmod 700 "$(dirname "$keyfile")" || die "cannot create key directory"
    say "Generating $keyfile (choose a passphrase):"
    ssh-keygen -t ed25519 -C "$me@$(hostname)" -f "$keyfile" || die "ssh-keygen failed"
    sign_and_install
    ;;
  renew)
    [ -f "$keyfile.pub" ] || die "no $keyfile.pub; use 'create' (or -K to point at your key)"
    if [ -z "$names" ]; then
      if [ -f "$keyfile-cert.pub" ]; then names=$(cert_principals "$keyfile-cert.pub"); else names=$me; fi
    fi
    sign_and_install
    ;;
  sign)
    [ -n "$pubin" ] && [ -f "$pubin" ] || die "sign needs -k PUBKEY (an existing public key file)"
    [ -n "$names" ] || die "sign needs -u NAMES (the login names the certificate may use)"
    check_list "user names" "$names"
    _b=$(basename "$pubin" .pub)
    cp "$pubin" "$WORK/$_b.pub" || die "cannot read $pubin"
    sign_cert user "$WORK/$_b.pub" "user_$(first_of "$names")_$(now_stamp)" "$names" "$v" || die "signing failed"
    mkdir -p "$outdir" && cp "$WORK/$_b-cert.pub" "$outdir/" || die "cannot write to $outdir"
    say "wrote $outdir/$_b-cert.pub  (principals: $names)"
    say "validity: $(cert_valid "$outdir/$_b-cert.pub")"
    say "the owner puts it next to the private key as <key>-cert.pub"
    ;;
  *) usage; exit 1 ;;
esac
