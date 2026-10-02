#!/bin/sh
# newuser.sh -- create a new user on a remote host and set up their keys and certificates.
# Run it on the CA machine.  It logs in to the target (normally as root, after rootlogin.sh has
# been run there), creates the account with a home directory, and configures ssh for it.
#
#   newuser.sh -r [root@]HOST -u NAME [options]
#
# Two ways to give the new account its credentials:
#
#   (default)  GENERATE ON THE HOST.  An ed25519 key is generated in the new home directory
#              (no passphrase), signed by the user CA, and installed with the host-CA trust.
#              Suited to service/automation accounts and to users who will work on that host.
#
#   -k PUBKEY  BRING YOUR OWN KEY.  The person gives you their PUBLIC key; it is signed here and
#              the certificate is written to --out DIR for you to hand back.  Their private key
#              never leaves their machine.  Their public key is also added to authorized_keys
#              (so a plain key works as well as the certificate) unless --cert-only.
#
# Options
#   -r TARGET        [USER@]HOST to log in to.  Root, or a sudo user.         (required)
#   -u NAME          account to create                                       (required)
#   -k PUBKEY        use this public key instead of generating one
#   -p PRINCIPALS    login names the certificate is valid for (default: NAME)
#   -e EXPIRY        +12w, +30d, +8h or YYYY-MM-DD (default $SSHCA_USER_EXPIRY or +12w)
#   -s SHELL         login shell (default: /bin/bash on Linux, /bin/sh on FreeBSD, /bin/zsh on macOS)
#   -G GROUPS        comma-separated extra groups, e.g. sudo,docker  (FreeBSD/macOS: wheel / admin)
#   -c COMMENT       full name / description (default: NAME)
#   --out DIR        where the certificate goes with -k   (default ./issued/NAME)
#   --cert-only      with -k: do NOT add their public key to authorized_keys
#   -o OPT / -i FILE extra ssh option / identity file for reaching the target
#   -A               take the CA key from ssh-agent instead of prompting for its passphrase
#
# The account gets no password: it can only be reached with a certificate (or the key from -k).
# An account that already exists is kept; its keys/certs are (re)configured.  See README.md.

set -u
HERE=$(cd "$(dirname "$0")" && pwd) || exit 1
SSHCA_LIB=$HERE/sshca-lib.sh
# shellcheck disable=SC1090
. "$SSHCA_LIB"

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

[ $# -ge 1 ] || { usage; exit 1; }
case $1 in -h|--help|help) usage; exit 0 ;; esac

TARGET=; NAME=; PUBIN=; PRINC=; EXP=$SSHCA_USER_EXPIRY; SHELLP=; GROUPS_=; COMMENT=; OUT=; CERTONLY=0; SSH_OPTS=
while [ $# -gt 0 ]; do
  case $1 in
    -r|--remote)  need_val "$1" $#; TARGET=$2; shift 2 ;;
    -u|--user)    need_val "$1" $#; NAME=$2; shift 2 ;;
    -k|--key)     need_val "$1" $#; PUBIN=$2; shift 2 ;;
    -p|--principals) need_val "$1" $#; PRINC=$2; shift 2 ;;
    -e|--expiry)  need_val "$1" $#; EXP=$2; shift 2 ;;
    -s|--shell)   need_val "$1" $#; SHELLP=$2; shift 2 ;;
    -G|--groups)  need_val "$1" $#; GROUPS_=$2; shift 2 ;;
    -c|--comment) need_val "$1" $#; COMMENT=$2; shift 2 ;;
    --out)        need_val "$1" $#; OUT=$2; shift 2 ;;
    --cert-only)  CERTONLY=1; shift ;;
    -o)           need_val "$1" $#; SSH_OPTS="$SSH_OPTS -o $2"; shift 2 ;;
    -i)           need_val "$1" $#; SSH_OPTS="$SSH_OPTS -i $2"; shift 2 ;;
    -A|--agent)   SSHCA_AGENT=1; export SSHCA_AGENT; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ -n "$TARGET" ] || die "-r [root@]HOST is required"
[ -n "$NAME" ]   || die "-u NAME is required"
check_account "$NAME"
[ -n "$PRINC" ]   || PRINC=$NAME
check_list "principals" "$PRINC"
[ -z "$GROUPS_" ] || check_list "groups" "$GROUPS_"
[ -n "$COMMENT" ] || COMMENT=$NAME
[ -n "$OUT" ]     || OUT=./issued/$NAME
if [ -n "$PUBIN" ] && [ ! -f "$PUBIN" ]; then die "no such file: $PUBIN"; fi
v=$(validity "$EXP") || exit 1

need_cmds ssh-keygen ssh
ca_require user
ca_rebuild_trust
trap 'x_close' EXIT
trap 'x_close; exit 130' INT TERM HUP

x_open
say "=== $TARGET (logged in as $RUSER) ==="

if [ -z "$SHELLP" ]; then
  SHELLP=$(x_run 'case $(uname -s) in
    Darwin) echo /bin/zsh ;;
    FreeBSD) echo /bin/sh ;;
    *) if [ -x /bin/bash ]; then echo /bin/bash; else echo /bin/sh; fi ;;
  esac') || die "cannot query the target"
fi

x_priv t_create_user "$NAME" "$SHELLP" "$GROUPS_" "$COMMENT" || die "account creation failed"

x_put "$SSHCA_DIR/trust/host_ca_known_hosts" known_hosts || die "copy failed"
KEY=id_ed25519

if [ -z "$PUBIN" ]; then
  # generate on the host, sign here, install there
  x_priv t_user_prepare "$NAME" "$KEY" "$STAGE/$NAME.pub" 1 || die "could not prepare a key for $NAME"
  x_cat "$STAGE/$NAME.pub" "$WORK/$NAME.pub" || die "cannot fetch the new public key"
  sign_cert user "$WORK/$NAME.pub" "user_${NAME}_$(now_stamp)" "$PRINC" "$v" || die "signing failed"
  x_put "$WORK/$NAME-cert.pub" "$NAME-cert.pub" || die "copy failed"
  x_priv t_install_user_cert "$STAGE/$NAME-cert.pub" "$NAME" "$KEY" || die "certificate installation failed"
  CERT=$WORK/$NAME-cert.pub
else
  # the person's own key: sign it here, hand the certificate back, authorize the key on the host
  _b=$(basename "$PUBIN" .pub)
  cp "$PUBIN" "$WORK/$_b.pub" || die "cannot read $PUBIN"
  sign_cert user "$WORK/$_b.pub" "user_${NAME}_$(now_stamp)" "$PRINC" "$v" || die "signing failed"
  mkdir -p "$OUT" && cp "$WORK/$_b-cert.pub" "$OUT/" || die "cannot write to $OUT"
  CERT=$OUT/$_b-cert.pub
  if [ "$CERTONLY" = 0 ]; then
    x_put "$PUBIN" "$NAME-auth.pub" || die "copy failed"
    x_priv t_install_authorized_key "$STAGE/$NAME-auth.pub" "$NAME" || die "could not install authorized_keys"
  fi
fi
x_priv t_install_known_hosts "$STAGE/known_hosts" "$NAME" || warn "known_hosts install failed"

say
say "account:    $NAME on ${TARGET#*@}"
say "may log in as: $PRINC   validity: $(cert_valid "$CERT")"
if [ -n "$PUBIN" ]; then
  say "certificate for the user: $CERT"
  say "  they save it next to their private key as <key>-cert.pub, then:  ssh $NAME@${TARGET#*@}"
else
  say "key and certificate are in ~$NAME/.ssh on the host (no passphrase on that key)"
fi
