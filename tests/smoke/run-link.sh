#!/usr/bin/env bash
#
# Two rIRCd servers, two databases, linked to each other.
#
#   tests/smoke/run-link.sh              # bring both up, run test_link.py, tear down
#   tests/smoke/run-link.sh --keep       # leave them running afterwards
#   tests/smoke/run-link.sh --serve-only # just bring them up
#   tests/smoke/run-link.sh --stop       # stop a --keep environment
#   tests/smoke/run-link.sh --tls        # link the two over TLS instead
#
# The MariaDB instance comes from tests/smoke/run.sh, which this reuses rather
# than starting a second one; each server gets its own database inside it, which
# is what a real pair of linked servers has.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SMOKE_DIR="${SMOKE_DIR:-$REPO/target/smoke}"
LINK_DIR="$SMOKE_DIR/link"
DB_SOCK="$SMOKE_DIR/run/mysql.sock"
DB_PORT="${SMOKE_DB_PORT:-3399}"
BIND="${SMOKE_BIND:-127.0.0.1}"

# Server A and server B: their own client port, their own link port, their own
# database, their own name and id.
A_PORT="${LINK_A_PORT:-16687}"
B_PORT="${LINK_B_PORT:-16697}"
A_LINK_PORT="${LINK_A_LINK_PORT:-17000}"
B_LINK_PORT="${LINK_B_LINK_PORT:-17010}"
A_NAME="a.link.test"
B_NAME="b.link.test"
A_SID="1AA"
B_SID="2BB"
A_TO_B="password-a-sends"
B_TO_A="password-b-sends"

KEEP=0
SERVE_ONLY=0
STOP_ONLY=0
# Link the two servers over TLS, each pinned to the other's certificate. The
# tests are the same either way: a link is a link once it is up.
LINK_TLS="${SMOKE_LINK_TLS:-0}"
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --serve-only) SERVE_ONLY=1; KEEP=1 ;;
    --stop) STOP_ONLY=1 ;;
    --tls) LINK_TLS=1 ;;
    -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }

stop_servers() {
  for side in a b; do
    if [ -f "$LINK_DIR/$side.pid" ]; then
      kill "$(cat "$LINK_DIR/$side.pid")" 2>/dev/null || true
      rm -f "$LINK_DIR/$side.pid"
    fi
  done
}

if [ "$STOP_ONLY" = 1 ]; then
  stop_servers
  say "Stopped"
  exit 0
fi

cleanup() {
  status=$?
  if [ "$KEEP" = 1 ]; then
    return
  fi
  say "Tearing down"
  stop_servers
  exit $status
}
trap cleanup EXIT INT TERM

mkdir -p "$LINK_DIR"
stop_servers

# The database instance is the smoke one; start it if it is not already up.
if ! mariadb --socket="$DB_SOCK" -e "SELECT 1" >/dev/null 2>&1; then
  say "Starting the shared MariaDB (via run.sh --serve-only)"
  "$HERE/run.sh" --serve-only >"$LINK_DIR/smoke-up.log" 2>&1
fi
mariadb --socket="$DB_SOCK" -e "SELECT 1" >/dev/null 2>&1 || {
  echo "No MariaDB on $DB_SOCK; see $LINK_DIR/smoke-up.log" >&2
  exit 1
}
# run.sh builds its own directory from scratch, and this one lives inside it, so
# it is made again here rather than only before.
mkdir -p "$LINK_DIR"

for db in rircdb_a rircdb_b; do
  mariadb --socket="$DB_SOCK" -e "DROP DATABASE IF EXISTS $db"
  mariadb --socket="$DB_SOCK" -e "CREATE DATABASE $db CHARACTER SET utf8mb4"
done
say "Databases rircdb_a and rircdb_b ready"

say "Building rircd"
(cd "$REPO" && cargo build --quiet)

# An operator on both sides, so the tests can ask a server to do something only
# an operator may — REHASH, which must not take a live link down.
OPER_PASSWORD="${SMOKE_OPER_PASSWORD:-smoke-oper-password}"
OPER_HASH="$(printf '%s\n%s\n' "$OPER_PASSWORD" "$OPER_PASSWORD" | "$REPO/target/debug/rircd" genpasswd 2>/dev/null | grep -o '\$2[aby]\$[^ ]*')"
[ -n "$OPER_HASH" ] || { echo "could not hash the oper password" >&2; exit 1; }

# A throwaway self-signed certificate per side, and the fingerprint of each, so
# the two can pin one another. This is what an IRC network actually does: the
# operators know each other, so there is nothing a certificate authority adds.
A_FP=""
B_FP=""
if [ "$LINK_TLS" = 1 ]; then
  say "Making a certificate for each side"
  for side in a b; do
    name="$([ "$side" = a ] && echo "$A_NAME" || echo "$B_NAME")"
    if [ ! -f "$LINK_DIR/$side.cert.pem" ]; then
      openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$LINK_DIR/$side.key.pem" -out "$LINK_DIR/$side.cert.pem" \
        -subj "/CN=$name" >/dev/null 2>&1
    fi
  done
  A_FP="$(openssl x509 -in "$LINK_DIR/a.cert.pem" -noout -fingerprint -sha256 \
          | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')"
  B_FP="$(openssl x509 -in "$LINK_DIR/b.cert.pem" -noout -fingerprint -sha256 \
          | sed 's/.*=//; s/://g' | tr 'A-Z' 'a-z')"
  [ -n "$A_FP" ] && [ -n "$B_FP" ] || { echo "could not fingerprint the certificates" >&2; exit 1; }
fi

write_config() {
  # write_config <side> <name> <sid> <client port> <link port> <db> <peer name> <peer sid> <peer link port> <send> <receive> <autoconnect> <peer fingerprint>
  local links_line="listen_links = [\"$BIND:$5\"]"
  local tls_block=""
  local peer_tls=""
  if [ "$LINK_TLS" = 1 ]; then
    links_line="listen_links_tls = [\"$BIND:$5\"]"
    tls_block="
[tls]
cert = \"$LINK_DIR/$1.cert.pem\"
key = \"$LINK_DIR/$1.key.pem\"
"
    peer_tls="tls = true
fingerprint = \"${13}\""
  fi
  cat >"$LINK_DIR/$1.toml" <<EOF
# Generated by tests/smoke/run-link.sh — throwaway configuration.
[server]
name = "$2"
sid = "$3"
listen = ["$BIND:$4"]
$links_line
motd = "linked server $2"
description = "rIRCd link test, side $1"
$tls_block

[network]
name = "LinkNet"

[database]
host = "127.0.0.1"
port = $DB_PORT
user = "link"
password = "link"
database = "$6"

[limits]
max_line_length = 8191
flood_burst = 1000
flood_rate = 1000

[[opers]]
name = "linkoper"
hostmask = "*"
password_hash = "$OPER_HASH"

[[links]]
name = "$7"
sid = "$8"
host = "$BIND"
port = $9
send_password = "${10}"
receive_password = "${11}"
autoconnect = ${12}
$peer_tls
EOF
}

# A dials B; B waits to be dialled. Both sides know each other's secret.
write_config a "$A_NAME" "$A_SID" "$A_PORT" "$A_LINK_PORT" rircdb_a \
  "$B_NAME" "$B_SID" "$B_LINK_PORT" "$A_TO_B" "$B_TO_A" true "$B_FP"
write_config b "$B_NAME" "$B_SID" "$B_PORT" "$B_LINK_PORT" rircdb_b \
  "$A_NAME" "$A_SID" "$A_LINK_PORT" "$B_TO_A" "$A_TO_B" false "$A_FP"

for side in a b; do
  say "Starting server $side"
  RUST_LOG="${RUST_LOG:-rircd=info}" "$REPO/target/debug/rircd" \
    --config "$LINK_DIR/$side.toml" run >"$LINK_DIR/$side.log" 2>&1 &
  echo $! >"$LINK_DIR/$side.pid"
done

for port in "$A_PORT" "$B_PORT"; do
  for _ in $(seq 1 40); do
    if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('$BIND',$port))==0 else 1)"; then
      break
    fi
    sleep 0.5
  done
done

# The link is dialled with a short delay and a retry, so give it a moment.
linked=0
for _ in $(seq 1 40); do
  if grep -q "Linked" "$LINK_DIR/a.log" && grep -q "Linked" "$LINK_DIR/b.log"; then
    linked=1
    break
  fi
  sleep 0.5
done
if [ "$linked" = 1 ]; then
  say "Servers are linked"
else
  warn "The servers did not report a link; see $LINK_DIR/a.log and $LINK_DIR/b.log"
fi

export SMOKE_IRC_HOST="$BIND"
export LINK_TLS="$LINK_TLS"
export LINK_A_PORT="$A_PORT"
export LINK_B_PORT="$B_PORT"
export LINK_A_NAME="$A_NAME"
export LINK_B_NAME="$B_NAME"
export LINK_A_LINK_PORT="$A_LINK_PORT"
export LINK_B_LINK_PORT="$B_LINK_PORT"
export LINK_DIR="$LINK_DIR"
export SMOKE_OPER_PASSWORD="$OPER_PASSWORD"
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"

status=0
if [ "$SERVE_ONLY" = 0 ]; then
  # The stress run goes first, because test_link.py ends by killing server B to
  # watch the split, and nothing after that has two servers to stress.
  # Set SMOKE_STRESS_SECONDS=0 to skip it.
  if [ "${SMOKE_STRESS_SECONDS:-20}" != "0" ]; then
    say "Running test_stress.py"
    python3 "$HERE/test_stress.py" || status=1
  fi
  say "Running test_link.py"
  python3 "$HERE/test_link.py" || status=1
  # Last, because it takes the place of server B — which test_link.py has just
  # killed to watch the split — and speaks the link protocol by hand.
  say "Running test_link_hostile.py"
  python3 "$HERE/test_link_hostile.py" || status=1
fi

if [ "$KEEP" = 1 ]; then
  cat <<EOF

$(say "Left running")
  Server A ......... $BIND:$A_PORT   ($A_NAME, sid $A_SID, links on $A_LINK_PORT)
  Server B ......... $BIND:$B_PORT   ($B_NAME, sid $B_SID, links on $B_LINK_PORT)
  Logs ............. $LINK_DIR/a.log, $LINK_DIR/b.log
  Stop them with ... tests/smoke/run-link.sh --stop
EOF
fi
exit $status
