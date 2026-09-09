#!/usr/bin/env bash
#
# Smoke-test rIRCd against a throwaway MariaDB and a local SMTP sink.
#
#   tests/smoke/run.sh                 # bring everything up, run every suite, tear down
#   tests/smoke/run.sh --keep          # leave the server running afterwards
#   tests/smoke/run.sh --serve-only    # just bring the server up (no tests)
#   tests/smoke/run.sh test_core.py    # run one suite
#   tests/smoke/run.sh --reuse         # run against an environment already up (leaves it up)
#   tests/smoke/run.sh --stop          # stop a --keep/--serve-only environment
#
# Ports and paths can be overridden: SMOKE_IRC_PORT, SMOKE_DB_PORT, SMOKE_SMTP_PORT,
# SMOKE_WS_PORT, SMOKE_DIR, SMOKE_BIND.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

SMOKE_DIR="${SMOKE_DIR:-$REPO/target/smoke}"
IRC_PORT="${SMOKE_IRC_PORT:-16667}"
WS_PORT="${SMOKE_WS_PORT:-16668}"
DB_PORT="${SMOKE_DB_PORT:-3399}"
SMTP_PORT="${SMOKE_SMTP_PORT:-12525}"
BIND="${SMOKE_BIND:-127.0.0.1}"
OPER_PASSWORD="${SMOKE_OPER_PASSWORD:-smoke-oper-password}"

RUN_DIR="$SMOKE_DIR/run"
DB_DIR="$SMOKE_DIR/db"
ETC_DIR="$SMOKE_DIR/etc"
MAIL_DIR="$SMOKE_DIR/mail"
DB_SOCK="$RUN_DIR/mysql.sock"
SERVER_LOG="$RUN_DIR/rircd.log"

KEEP=0
SERVE_ONLY=0
BUILD=1
SUITES=()

REUSE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --serve-only) SERVE_ONLY=1; KEEP=1 ;;
    --reuse) REUSE=1; KEEP=1; BUILD=0 ;;
    --no-build) BUILD=0 ;;
    --stop) STOP_ONLY=1 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) SUITES+=("$1") ;;
  esac
  shift
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }

stop_everything() {
  if [ -f "$RUN_DIR/rircd.pid" ]; then
    kill "$(cat "$RUN_DIR/rircd.pid")" 2>/dev/null || true
  fi
  if [ -f "$ETC_DIR/rircd.pid" ]; then
    kill "$(cat "$ETC_DIR/rircd.pid")" 2>/dev/null || true
  fi
  # A wedged or orphaned server keeps the port, and the next run would silently
  # attach to it instead of to the build under test.
  pkill -f "rircd --config $ETC_DIR/config.toml" 2>/dev/null || true
  if [ -f "$RUN_DIR/smtp.pid" ]; then
    kill "$(cat "$RUN_DIR/smtp.pid")" 2>/dev/null || true
  fi
  if [ -S "$DB_SOCK" ]; then
    mariadb --socket="$DB_SOCK" -e "SHUTDOWN" >/dev/null 2>&1 || true
  fi
  sleep 0.5
}

if [ "${STOP_ONLY:-0}" = 1 ]; then
  say "Stopping the smoke environment"
  stop_everything
  say "Stopped. Data left in $SMOKE_DIR"
  exit 0
fi

for tool in mariadbd mariadb mariadb-install-db python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

server_is_up() {
  python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('$BIND',$IRC_PORT))==0 else 1)"
}

if [ "$REUSE" = 1 ]; then
  server_is_up || { echo "nothing listening on $BIND:$IRC_PORT — start one with --serve-only" >&2; exit 1; }
  [ -S "$DB_SOCK" ] || { echo "no database socket at $DB_SOCK" >&2; exit 1; }
  say "Reusing the environment already running on $BIND:$IRC_PORT"
else
  # A previous --keep run may still be up.
  stop_everything

  say "Workspace: $SMOKE_DIR"
  rm -rf "$SMOKE_DIR"
  mkdir -p "$RUN_DIR" "$ETC_DIR" "$MAIL_DIR"
fi

cleanup() {
  local status=$?
  if [ "$KEEP" = 1 ] || [ "$REUSE" = 1 ]; then
    return
  fi
  say "Tearing down"
  stop_everything
  exit $status
}
trap cleanup EXIT INT TERM

if [ "$REUSE" = 0 ]; then
say "Initialising MariaDB in $DB_DIR"
mariadb-install-db --datadir="$DB_DIR" --auth-root-authentication-method=normal \
  >"$RUN_DIR/mariadb-install.log" 2>&1

# --skip-grant-tables: this instance is throwaway and listens on localhost only,
# so the server config can use any user/password. Every path is forced into the
# workspace, because the system my.cnf points at directories only the mysql user
# may write (e.g. /run/mariadb).
mariadbd --datadir="$DB_DIR" --socket="$DB_SOCK" --port="$DB_PORT" \
  --pid-file="$RUN_DIR/mariadb.pid" --tmpdir="$RUN_DIR" \
  --bind-address=127.0.0.1 --skip-grant-tables --skip-name-resolve \
  --log-error="$RUN_DIR/mariadb.log" >/dev/null 2>&1 &

for _ in $(seq 1 30); do
  mariadb --socket="$DB_SOCK" -e "SELECT 1" >/dev/null 2>&1 && break
  sleep 1
done
mariadb --socket="$DB_SOCK" -e "SELECT 1" >/dev/null 2>&1 || { echo "MariaDB did not start; see $RUN_DIR/mariadb.log" >&2; exit 1; }
mariadb --socket="$DB_SOCK" -e "CREATE DATABASE IF NOT EXISTS rircdb CHARACTER SET utf8mb4"
say "MariaDB ready on port $DB_PORT (socket $DB_SOCK)"

say "Starting SMTP sink on port $SMTP_PORT"
python3 "$HERE/smtpsink.py" "$SMTP_PORT" "$MAIL_DIR" >"$RUN_DIR/smtp.log" 2>&1 &
echo $! >"$RUN_DIR/smtp.pid"

if [ "$BUILD" = 1 ]; then
  say "Building rircd"
  (cd "$REPO" && cargo build --quiet)
fi

# Oper credentials for the suites that need privileges.
OPER_HASH="$(printf '%s\n%s\n' "$OPER_PASSWORD" "$OPER_PASSWORD" | "$REPO/target/debug/rircd" genpasswd 2>/dev/null | grep -o '\$2[aby]\$[^ ]*')"
[ -n "$OPER_HASH" ] || { echo "could not hash the oper password" >&2; exit 1; }

cat >"$ETC_DIR/config.toml" <<EOF
# Generated by tests/smoke/run.sh — throwaway configuration.
[server]
name = "irc.smoke.test"
listen = ["$BIND:$IRC_PORT"]
listen_ws = ["$BIND:$WS_PORT"]
motd = """
rIRCd smoke test server.
Everything here is throwaway.
"""

# Channels suggested to draft/auto-join clients.
auto_join = "#lobby, #help"
# Cloak connecting clients so the cloaking path is exercised.
cloak_key = "smoke-cloak-key"
# One account, several connections. On by default here because the session
# path is where a connection id and a user id stop being the same string,
# and only a test that opens two connections notices when they are confused.
multiclient = true
persistent_sessions = true

[network]
name = "SmokeNet"

[webirc]
password = "smoke-gateway-secret"

[database]
host = "127.0.0.1"
port = $DB_PORT
user = "smoke"
password = "smoke"
database = "rircdb"

[limits]
max_channels_per_client = 50
# Every suite connects from 127.0.0.1, so the per-address limit is off here.
# It defaults to 16 and is exercised by the unit tests instead.
max_connections_per_ip = 0
max_line_length = 512

[email]
smtp_host = "127.0.0.1"
smtp_port = $SMTP_PORT
encryption = "none"
from = "SmokeNet <noreply@smoke.test>"
code_expiry_secs = 900

[[opers]]
name = "smokeoper"
hostmask = "*"
password_hash = "$OPER_HASH"

# A deliberately limited operator, to check that privileges are enforced.
[[opers]]
name = "smokehelper"
hostmask = "*"
password_hash = "$OPER_HASH"
privileges = ["kill"]

[webpush]
contact = "mailto:admin@smoke.test"
key_file = "$ETC_DIR/vapid.key"
# The suites point endpoints at a closed local port, so private addresses are
# allowed here. Never do this on a real server.
allow_private_endpoints = true
max_failures = 1000
EOF

say "Starting rircd on $BIND:$IRC_PORT (WebSocket $BIND:$WS_PORT)"
RUST_LOG="${RUST_LOG:-rircd=info}" "$REPO/target/debug/rircd" --config "$ETC_DIR/config.toml" run \
  >"$SERVER_LOG" 2>&1 &
echo $! >"$RUN_DIR/rircd.pid"

for _ in $(seq 1 30); do
  if python3 -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('$BIND',$IRC_PORT))==0 else 1)"; then
    break
  fi
  sleep 0.5
done
python3 - "$BIND" "$IRC_PORT" <<'PROBE' || { echo "rircd is not answering; see $SERVER_LOG" >&2; tail -20 "$SERVER_LOG" >&2; exit 1; }
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(b"NICK smokeprobe\r\nUSER smokeprobe 0 * :probe\r\n")
    s.settimeout(5)
    got, end = b"", time.time() + 5
    while time.time() < end:
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
        if b" 001 " in got:
            break
    s.sendall(b"QUIT :probe\r\n")
    s.close()
    sys.exit(0 if b" 001 " in got else 1)
except OSError:
    sys.exit(1)
PROBE
say "Server up and answering. Log: $SERVER_LOG"
fi  # end of environment bring-up

export SMOKE_IRC_HOST="$BIND"
export SMOKE_IRC_PORT="$IRC_PORT"
export SMOKE_DB_SOCKET="$DB_SOCK"
export SMOKE_MAIL_DIR="$MAIL_DIR"
export SMOKE_SERVER_LOG="$SERVER_LOG"
export SMOKE_OPER_NAME="smokeoper"
export SMOKE_OPER_PASSWORD="$OPER_PASSWORD"
export SMOKE_CONFIG="$ETC_DIR/config.toml"
export SMOKE_RIRCD_BIN="$REPO/target/debug/rircd"
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"

status=0
if [ "$SERVE_ONLY" = 0 ]; then
  if [ ${#SUITES[@]} -eq 0 ]; then
    SUITES=(test_core.py test_ircv3.py test_features.py test_websocket.py test_account.py test_webpush.py test_multiclient.py)
  fi
  for suite in "${SUITES[@]}"; do
    say "Running $suite"
    if ! python3 "$HERE/$suite"; then
      status=1
      warn "$suite failed"
    fi
  done
fi

if [ "$KEEP" = 1 ]; then
  cat <<EOF

$(say "Environment left running")
  IRC .............. $BIND:$IRC_PORT        (WebSocket: ws://$BIND:$WS_PORT)
  Server log ....... $SERVER_LOG
  Config ........... $ETC_DIR/config.toml
  Database ......... mariadb --socket=$DB_SOCK rircdb
  Captured mail .... $MAIL_DIR
  Stop it with ..... tests/smoke/run.sh --stop
EOF
fi

exit $status
