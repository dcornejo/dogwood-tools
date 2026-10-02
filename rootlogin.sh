#!/bin/sh
# rootlogin.sh -- allow root to log in over ssh with certificates/keys ONLY (no passwords).
# Run it ON THE TARGET HOST (macOS, FreeBSD or Linux), logged in as yourself, via sudo or as root.
# It is the one-time bootstrap that makes "newuser.sh" and "deploy.sh" possible from your CA machine.
#
#   rootlogin.sh enable  --user-ca FILE|-  [--authorized-key FILE]
#   rootlogin.sh disable
#   rootlogin.sh status
#
#   enable    1. trusts your user CA   (TrustedUserCAKeys), so a certificate whose principals
#                include "root" is accepted for root;
#             2. sets "PermitRootLogin prohibit-password": root may use a key or certificate, and
#                passwords / keyboard-interactive are refused for root;
#             3. optionally adds a plain public key to root's authorized_keys (a fallback that
#                works without the CA);
#             4. validates the config with "sshd -t", reloads sshd, and prints the host-key
#                fingerprints so you can verify them on your first connection.
#   disable   sets PermitRootLogin no again (the CA trust stays).
#   status    shows the effective sshd settings for root and the host-key fingerprints.
#
#   --user-ca FILE   the CA machine's  $SSHCA_DIR/trust/user_ca_keys.pub  ("-" = read it from stdin,
#                    so you can paste it).  Not needed again if already installed here.
#   --authorized-key FILE   one public key line to add to root's authorized_keys.
#
# Other users' login methods are NOT changed.  The setting is stored so later host-certificate
# renewals (deploy.sh host) keep it.  Test from a second terminal before closing this session.
# This script needs sshca-lib.sh next to it (copy the whole sshca directory, or just those two files).

set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
SSHCA_LIB=$HERE/sshca-lib.sh
# shellcheck disable=SC1090
. "$SSHCA_LIB"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

[ $# -ge 1 ] || { usage; exit 1; }
case $1 in -h|--help|help) usage; exit 0 ;; esac
cmd=$1; shift

uca=; akey=
while [ $# -gt 0 ]; do
  case $1 in
    --user-ca)         need_val "$1" $#; uca=$2; shift 2 ;;
    --authorized-key)  need_val "$1" $#; akey=$2; shift 2 ;;
    -h|--help)         usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

need_cmds ssh-keygen
WORK=$(mktemp -d) || die "mktemp failed"
trap 'rm -rf "$WORK"' EXIT INT TERM HUP

case $cmd in
  enable)
    ucafile=
    if [ -n "$uca" ]; then
      if [ "$uca" = - ]; then
        say "Paste the user CA public key line(s), then press Ctrl-D:"
        cat > "$WORK/uca.pub"
      else
        [ -f "$uca" ] || die "no such file: $uca"
        cp "$uca" "$WORK/uca.pub" || die "cannot read $uca"
      fi
      [ -s "$WORK/uca.pub" ] || die "the user CA file is empty"
      if grep -Evq '^(ssh-|ecdsa-|sk-|#|[[:space:]]*$)' "$WORK/uca.pub"; then
        die "$uca does not look like a list of public keys"
      fi
      ucafile=$WORK/uca.pub
    elif [ ! -f "$SSHD_DIR/sshca_user_ca_keys.pub" ]; then
      die "enable needs --user-ca FILE (the CA machine's trust/user_ca_keys.pub)"
    fi
    if [ -n "$akey" ]; then
      [ -f "$akey" ] || die "no such file: $akey"
      cp "$akey" "$WORK/akey.pub" || die "cannot read $akey"
    fi
    priv t_rootlogin enable "$ucafile" || die "could not enable root login"
    if [ -n "$akey" ]; then priv t_install_authorized_key "$WORK/akey.pub" root || warn "could not install the authorized key"; fi
    say
    priv t_status
    say
    say "Root can now log in with a key or certificate; passwords are refused for root."
    say "A certificate works for root only if its principals include 'root', e.g. on the CA machine:"
    say "    usercert.sh renew -u \$(id -un),root"
    say "From the CA machine, check the fingerprints above on your first connection:"
    say "    ssh root@<this host>"
    ;;
  disable)
    priv t_rootlogin disable || die "could not disable root login"
    priv t_status
    ;;
  status)
    priv t_status
    ;;
  *) usage; exit 1 ;;
esac
