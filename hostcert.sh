#!/bin/sh
# hostcert.sh -- create, sign and renew SSH host certificates (run on the CA machine).
#
#   hostcert.sh create -n NAMES [-e EXPIRY] [--force] [--system-known-hosts]
#   hostcert.sh renew  [-n NAMES] [-e EXPIRY] [--rotate-key] [--system-known-hosts]
#   hostcert.sh sign   -k PUBKEY -n NAMES [-e EXPIRY] [-o DIR]
#
#   create   generate an ed25519 host key on THIS machine, sign it, install it, reload sshd.
#            Refuses to replace an existing host key unless --force.
#   renew    re-sign THIS machine's existing host key and install the new certificate.
#            NAMES default to the principals on the current certificate.
#            --rotate-key also replaces the key (clients without the CA will see a changed-key warning).
#   sign     sign someone else's host public key.  Nothing is installed; the certificate is
#            written to DIR (default: current directory) as <key>-cert.pub.
#
#   -n NAMES   comma-separated principals the certificate is valid for: the FQDNs clients type
#              (add the short name and/or IP too if clients use them), e.g. web1.example.com,web1
#   -e EXPIRY  +52w  +30d  +12h  or  YYYY-MM-DD (end of that day).   Default: $SSHCA_HOST_EXPIRY or +52w
#   --system-known-hosts   also install the host-CA trust in /etc/ssh/ssh_known_hosts, so this
#                          host can ssh onward to other cert-bearing hosts without prompts
#
# Installing means: certificate -> /etc/ssh/ssh_host_ed25519_key-cert.pub, user-CA trust ->
# /etc/ssh/sshca_user_ca_keys.pub, and an sshd_config drop-in (or marked block) with HostKey,
# HostCertificate and TrustedUserCAKeys.  The config is validated with "sshd -t" before use.
# To do this on a remote machine use deploy.sh.  Uses sudo for the root-only steps.
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

names=; exp=$SSHCA_HOST_EXPIRY; pubin=; outdir=.; rotate=0; force=0; syskh=0
while [ $# -gt 0 ]; do
  case $1 in
    -n|--names)  need_val "$1" $#; names=$2; shift 2 ;;
    -e|--expiry) need_val "$1" $#; exp=$2; shift 2 ;;
    -k|--key)    need_val "$1" $#; pubin=$2; shift 2 ;;
    -o|--out)    need_val "$1" $#; outdir=$2; shift 2 ;;
    --rotate-key) rotate=1; shift ;;
    --force)     force=1; shift ;;
    --system-known-hosts) syskh=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

need_cmds ssh-keygen
ca_require host
WORK=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT INT TERM HUP
HOSTKEY=$SSHD_DIR/ssh_host_ed25519_key
HOSTCERT=$HOSTKEY-cert.pub
USERCA=$SSHCA_DIR/trust/user_ca_keys.pub

# sign_and_install NAMES -- sign this machine's host key and install the result
sign_and_install() {
  check_list "host names" "$1"
  _v=$(validity "$exp") || exit 1
  cp "$HOSTKEY.pub" "$WORK/ssh_host_ed25519_key.pub" || die "cannot read $HOSTKEY.pub"
  sign_cert host "$WORK/ssh_host_ed25519_key.pub" "host_$(first_of "$1")_$(now_stamp)" "$1" "$_v" ||
    die "signing failed"
  ca_rebuild_trust
  priv t_install_host_cert "$WORK/ssh_host_ed25519_key-cert.pub" "$USERCA" || die "installation failed"
  if [ "$syskh" = 1 ]; then
    priv t_install_known_hosts "$SSHCA_DIR/trust/host_ca_known_hosts" system || warn "known_hosts install failed"
  fi
  say "valid for: $1"
  say "validity:  $(cert_valid "$WORK/ssh_host_ed25519_key-cert.pub")"
}

case $cmd in
  create)
    [ -n "$names" ] || die "create needs -n NAMES (e.g. -n host.example.com,host)"
    if [ -f "$HOSTKEY" ] && [ "$force" -ne 1 ]; then
      die "$HOSTKEY already exists; use 'renew' to re-sign it (or --force to replace the key)"
    fi
    if [ "$force" -eq 1 ]; then priv t_ensure_host_key rotate; else priv t_ensure_host_key; fi || die "key generation failed"
    sign_and_install "$names"
    ;;
  renew)
    [ -f "$HOSTKEY.pub" ] || die "no host key at $HOSTKEY; use 'create'"
    if [ -z "$names" ] && [ -f "$HOSTCERT" ]; then names=$(cert_principals "$HOSTCERT"); fi
    [ -n "$names" ] || die "no existing certificate to take names from; give -n NAMES"
    if [ "$rotate" -eq 1 ]; then priv t_ensure_host_key rotate || die "key rotation failed"; fi
    sign_and_install "$names"
    ;;
  sign)
    [ -n "$pubin" ] && [ -f "$pubin" ] || die "sign needs -k PUBKEY (an existing public key file)"
    [ -n "$names" ] || die "sign needs -n NAMES"
    check_list "host names" "$names"
    _v=$(validity "$exp") || exit 1
    _base=$(basename "$pubin" .pub)
    cp "$pubin" "$WORK/$_base.pub" || die "cannot read $pubin"
    sign_cert host "$WORK/$_base.pub" "host_$(first_of "$names")_$(now_stamp)" "$names" "$_v" || die "signing failed"
    mkdir -p "$outdir" && cp "$WORK/$_base-cert.pub" "$outdir/" || die "cannot write to $outdir"
    say "wrote $outdir/$_base-cert.pub"
    say "validity: $(cert_valid "$outdir/$_base-cert.pub")"
    say "install it on the host as ${SSHD_DIR}/ssh_host_ed25519_key-cert.pub, or use deploy.sh host -r ..."
    ;;
  *) usage; exit 1 ;;
esac
