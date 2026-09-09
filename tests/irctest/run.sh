#!/usr/bin/env bash
# Run irctest (https://github.com/progval/irctest) against rIRCd.
#
# irctest is the conformance suite the other IRC servers are measured with —
# RFC 1459/2812, the Modern specification, and IRCv3 — so it says how rIRCd
# compares on the same terms rather than on a capability list we wrote.
#
#   tests/irctest/run.sh                    # everything, minus other servers' quirks
#   tests/irctest/run.sh -k Lusers          # one area
#   tests/irctest/run.sh --no-parallel      # one at a time, easier to read
#
# Anything else is passed to pytest.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IRCTEST_DIR="$REPO/target/irctest"
VENV="$REPO/target/irctest-venv"

DB_HOST="${IRCTEST_RIRCD_DB_HOST:-127.0.0.1}"
DB_PORT="${IRCTEST_RIRCD_DB_PORT:-3399}"
DB_USER="${IRCTEST_RIRCD_DB_USER:-root}"

blue() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

PARALLEL="-n 4"
PYTEST_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --no-parallel) PARALLEL="" ;;
    *) PYTEST_ARGS+=("$arg") ;;
  esac
done

blue "Building rircd (release)"
(cd "$REPO" && cargo build --release --quiet)

if [ ! -d "$IRCTEST_DIR" ]; then
  blue "Cloning irctest"
  git clone --depth 1 https://github.com/progval/irctest.git "$IRCTEST_DIR"
fi

if [ ! -x "$VENV/bin/pytest" ]; then
  blue "Creating virtualenv"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet pytest pytest-xdist pytest-timeout ecdsa filelock websockets
fi

# Every test starts a server, and every server needs a database. The smoke
# harness already runs a throwaway MariaDB; reuse it rather than starting a
# second one.
if ! mariadb --protocol=TCP -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -e "SELECT 1" >/dev/null 2>&1; then
  cat >&2 <<MSG
No MariaDB at $DB_HOST:$DB_PORT (user $DB_USER).

irctest needs one it may create and empty databases in. The smoke harness
starts a throwaway instance:

    tests/smoke/run.sh --serve-only

or point this run at another one with IRCTEST_RIRCD_DB_HOST / _DB_PORT /
_DB_USER / _DB_PASSWORD.
MSG
  exit 1
fi

# Deselect what is not about us: tests for another server's own extensions
# (irctest doubles as Ergo's and Sable's integration suite), for deprecated
# specifications, and ones asserting a stricter reading than the specification
# requires.
MARKERS="${IRCTEST_MARKERS:-not implementation-specific and not deprecated and not strict}"

# rIRCd's services are part of the server rather than a second one linked to
# it, so LINKS on a one-server network lists one server. This test asserts a
# separate `My.Little.Services` in the list, which only exists on a network
# where services are linked in. Nothing to implement short of server-to-server
# linking, so it is left out rather than left failing.
DESELECT=(--deselect
  "irctest/server_tests/links.py::ServicesLinksTestCase::testLinksWithServices")

blue "Running irctest against rIRCd"
cd "$IRCTEST_DIR"
PYTHONPATH="$REPO/tests/irctest" \
IRCTEST_RIRCD="$REPO/target/release/rircd" \
IRCTEST_RIRCD_DB_HOST="$DB_HOST" \
IRCTEST_RIRCD_DB_PORT="$DB_PORT" \
IRCTEST_RIRCD_DB_USER="$DB_USER" \
  "$VENV/bin/pytest" --controller rircd -m "$MARKERS" "${DESELECT[@]}" \
  --timeout 600 $PARALLEL "${PYTEST_ARGS[@]}"
