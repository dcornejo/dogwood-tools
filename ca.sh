#!/bin/sh
# ca.sh -- create, rotate and retire the SSH certificate authorities (run on the CA machine).
#
#   ca.sh init   [-p HOST_PATTERN] [--no-passphrase] [--no-install]
#   ca.sh rotate host|user|both    [--no-passphrase] [--no-install]
#   ca.sh retire host|user GENERATION                [--no-install]
#   ca.sh list
#   ca.sh install                     (re-install the trust files on THIS machine)
#
# Two independent CAs are kept: a HOST CA (signs host keys) and a USER CA (signs user keys).
# Each CA is a numbered "generation" (a UTC timestamp).  Rotating adds a new generation and
# keeps trusting the old one until you retire it, so nothing breaks while certs are re-issued.
#
# "Install" on the CA machine means: put the host-CA trust lines in your ~/.ssh/known_hosts
# (so you can ssh to cert-bearing hosts without prompts) and, if this machine runs sshd,
# configure TrustedUserCAKeys so it accepts certificates from the user CA.
#
# Files live in $SSHCA_DIR (default ~/.sshca).  BACK IT UP and keep it private: whoever has the
# CA private keys can mint certificates that every host and user will trust.

set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
SSHCA_LIB=$HERE/sshca-lib.sh
# shellcheck disable=SC1090
. "$SSHCA_LIB"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

NOPASS=0
INSTALL=1

new_gen() {   # KIND
  _kind=$1
  _gen=$(now_stamp)
  _key=$SSHCA_DIR/$_kind/$_gen
  [ ! -e "$_key" ] || die "generation $_gen already exists; wait a second and retry"
  if [ "$NOPASS" = 1 ]; then
    ssh-keygen -q -t ed25519 -N '' -C "sshca $_kind CA $_gen" -f "$_key" || die "ssh-keygen failed"
  else
    say "Choose a passphrase for the $_kind CA key ($_gen):"
    ssh-keygen -q -t ed25519 -C "sshca $_kind CA $_gen" -f "$_key" || die "ssh-keygen failed"
  fi
  printf '%s\n' "$_gen" > "$SSHCA_DIR/$_kind/CURRENT"
  say "created $_kind CA generation $_gen"
}

install_local() {
  [ "$INSTALL" = 1 ] || return 0
  say "--- installing trust on this machine"
  t_install_known_hosts "$SSHCA_DIR/trust/host_ca_known_hosts" "$(id -un)" || warn "could not update known_hosts"
  if [ -f "$SSHD_DIR/sshd_config" ]; then
    priv t_install_user_ca "$SSHCA_DIR/trust/user_ca_keys.pub" || warn "could not configure sshd here"
  fi
}

parse_flags() {
  while [ $# -gt 0 ]; do
    case $1 in
      --no-passphrase) NOPASS=1; shift ;;
      --no-install)    INSTALL=0; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

cmd_init() {
  _pattern='*'
  while [ $# -gt 0 ]; do
    case $1 in
      -p|--host-pattern) need_val "$1" $#; _pattern=$2; shift 2 ;;
      --no-passphrase)   NOPASS=1; shift ;;
      --no-install)      INSTALL=0; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
  if [ -f "$SSHCA_DIR/host/CURRENT" ] || [ -f "$SSHCA_DIR/user/CURRENT" ]; then
    die "a CA already exists in $SSHCA_DIR; use 'rotate' to renew it"
  fi
  mkdir -p "$SSHCA_DIR/host" "$SSHCA_DIR/user" "$SSHCA_DIR/trust" "$SSHCA_DIR/retired/host" "$SSHCA_DIR/retired/user" ||
    die "cannot create $SSHCA_DIR"
  chmod 700 "$SSHCA_DIR" "$SSHCA_DIR/host" "$SSHCA_DIR/user" "$SSHCA_DIR/retired"
  printf 'HOST_PATTERN=%s\n' "$(shq "$_pattern")" > "$SSHCA_DIR/config"
  new_gen host
  new_gen user
  ca_rebuild_trust
  install_local
  say
  say "CA ready in $SSHCA_DIR (host pattern: $_pattern)"
  say "Next: hostcert.sh / usercert.sh / deploy.sh.  See README.md."
}

cmd_rotate() {
  [ $# -ge 1 ] || die "rotate needs host, user or both"
  _what=$1; shift
  parse_flags "$@"
  case $_what in host|user|both) ;; *) die "rotate needs host, user or both" ;; esac
  ca_require host; ca_require user
  case $_what in host|both) new_gen host ;; esac
  case $_what in user|both) new_gen user ;; esac
  ca_rebuild_trust
  install_local
  say
  say "The OLD generation is still trusted.  To finish the rotation:"
  say "  1. re-issue certificates:   deploy.sh all ...   (or hostcert.sh / usercert.sh renew)"
  say "  2. push the new trust:      deploy.sh trust ..."
  say "  3. retire the old CA:       ca.sh retire <host|user> <generation>   then   deploy.sh trust ..."
  say "Generations:"; cmd_list
}

cmd_retire() {
  [ $# -ge 2 ] || die "usage: ca.sh retire host|user GENERATION"
  _kind=$1; _gen=$2; shift 2
  parse_flags "$@"
  case $_kind in host|user) ;; *) die "kind must be host or user" ;; esac
  ca_require "$_kind"
  [ -f "$SSHCA_DIR/$_kind/$_gen.pub" ] || die "no such $_kind CA generation: $_gen (see: ca.sh list)"
  [ "$(cat "$SSHCA_DIR/$_kind/CURRENT")" != "$_gen" ] || die "$_gen is the current $_kind CA; rotate first"
  mv "$SSHCA_DIR/$_kind/$_gen" "$SSHCA_DIR/$_kind/$_gen.pub" "$SSHCA_DIR/retired/$_kind/" || die "move failed"
  ca_rebuild_trust
  say "retired $_kind CA $_gen (kept in $SSHCA_DIR/retired/$_kind)"
  say "Certificates signed by it stop being trusted once hosts/clients get the new trust (deploy.sh trust)."
  install_local
}

cmd_list() {
  [ -f "$SSHCA_DIR/config" ] && sed -n 's/^HOST_PATTERN=/host pattern: /p' "$SSHCA_DIR/config"
  for _kind in host user; do
    [ -f "$SSHCA_DIR/$_kind/CURRENT" ] || continue
    _cur=$(cat "$SSHCA_DIR/$_kind/CURRENT")
    say "$_kind CA:"
    for _p in "$SSHCA_DIR/$_kind"/*.pub; do
      [ -f "$_p" ] || continue
      _g=$(basename "$_p" .pub)
      _m=' '; [ "$_g" = "$_cur" ] && _m='*'
      printf '  %s %s  %s\n' "$_m" "$_g" "$(t_fp "$_p")"
    done
  done
  say "(* = signs new certificates; the others are still trusted until retired)"
}

[ $# -ge 1 ] || { usage; exit 1; }
need_cmds ssh-keygen
_cmd=$1; shift
case $_cmd in
  init)    cmd_init "$@" ;;
  rotate)  cmd_rotate "$@" ;;
  retire)  cmd_retire "$@" ;;
  list)    ca_require host; cmd_list ;;
  install) ca_require host; ca_rebuild_trust; INSTALL=1; install_local ;;
  -h|--help|help) usage ;;
  *) usage; exit 1 ;;
esac
