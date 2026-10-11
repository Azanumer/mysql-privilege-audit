#!/usr/bin/env bash
# mysql-privilege-audit — audit MySQL/MariaDB users for common security mistakes.
#
# Checks:
#   1. Anonymous users (empty username)
#   2. Users allowed from any host ('%')
#   3. Accounts with no password set
#   4. Non-admin users holding SUPER / FILE / SHUTDOWN / GRANT OPTION
#   5. The default `test` database still present
#
# Credentials: uses ~/.my.cnf, or pass --user/--password.
# Exit code: 0 = clean, 1 = warnings/failures found.
#
# Example: ./mysql-privilege-audit.sh --user root
set -u

USER="${MYSQL_USER:-root}"
PASS="${MYSQL_PASSWORD:-}"
HOST="${MYSQL_HOST:-localhost}"
JSON=0
FAIL=0
WARN=0

usage() {
    cat <<'EOF'
Usage: mysql-privilege-audit.sh [--user USER] [--password PASS] [--host HOST] [--json]

Audits MySQL/MariaDB users for anonymous accounts, wildcard hosts,
password-less accounts and excessive privileges.
EOF
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --user)     USER="$2"; shift 2 ;;
        --password) PASS="$2"; shift 2 ;;
        --host)     HOST="$2"; shift 2 ;;
        --json)     JSON=1; shift ;;
        -h|--help)  usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done

command -v mysql >/dev/null || { echo "ERROR: mysql client not found" >&2; exit 2; }

ARGS=(-N -B -h "$HOST" -u "$USER")
[ -n "$PASS" ] && ARGS+=(-p"$PASS")

query() { mysql "${ARGS[@]}" -e "$1" 2>/dev/null; }

# Bail out early if the credentials do not work.
if ! query "SELECT 1;" >/dev/null 2>&1; then
    echo "ERROR: cannot connect to MySQL as $USER@$HOST (check credentials)" >&2
    exit 2
fi

report() { # level message
    case "$1" in
        FAIL) FAIL=$((FAIL+1)) ;;
        WARN) WARN=$((WARN+1)) ;;
    esac
    if [ "$JSON" -eq 1 ]; then
        printf '{"level":"%s","message":"%s"}\n' "$1" "$2"
    else
        printf '[%-4s] %s\n' "$1" "$2"
    fi
}

# --- 1. Anonymous users -------------------------------------------------------
anon=$(query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='';" | wc -l)
if [ "$anon" -gt 0 ]; then
    report FAIL "Anonymous user accounts found ($anon) — remove with: DROP USER ''@'host';"
else
    report OK "No anonymous users"
fi

# --- 2. Wildcard hosts --------------------------------------------------------
wild=$(query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%' AND user<>'';")
if [ -n "$wild" ]; then
    while IFS= read -r acct; do
        report WARN "Account $acct allows connections from ANY host ('%')"
    done <<< "$wild"
else
    report OK "No '%' wildcard hosts"
fi

# --- 3. Accounts without a password -------------------------------------------
# MariaDB >= 10.4 uses the `authentication_string` column; older servers use `password`.
col=$(query "SHOW COLUMNS FROM mysql.user LIKE 'authentication_string';" | awk '{print $1}')
[ -z "$col" ] && col="password"
nopw=$(query "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user<>'' AND plugin NOT IN ('unix_socket','auth_socket') AND COALESCE($col,'')='';")
if [ -n "$nopw" ]; then
    while IFS= read -r acct; do
        report FAIL "Account $acct has NO password set"
    done <<< "$nopw"
else
    report OK "All password-based accounts have a password"
fi

# --- 4. Excessive privileges ---------------------------------------------------
# global_priv (MariaDB 10.4+) holds a JSON blob; fall back to classic columns.
privs=$(query "SELECT user, host,
    COALESCE(Super_priv,'N'), COALESCE(File_priv,'N'), COALESCE(Shutdown_priv,'N'),
    COALESCE(Create_user_priv,'N'), COALESCE(Grant_priv,'N')
    FROM mysql.user;")
while IFS=$'\t' read -r u h super file shut createuser grantpriv; do
    [ -z "$u" ] && continue
    # root@localhost is the expected admin; anything else is worth a second look.
    if { [ "$u" = "root" ] && [ "$h" = "localhost" ]; } then
        continue
    fi
    [ "$super" = "Y" ]      && report WARN "$u@$h holds SUPER (full server control)"
    [ "$file" = "Y" ]       && report WARN "$u@$h holds FILE (can read/write server files)"
    [ "$shut" = "Y" ]       && report WARN "$u@$h holds SHUTDOWN"
    [ "$createuser" = "Y" ] && report WARN "$u@$h holds CREATE USER"
    [ "$grantpriv" = "Y" ]  && report WARN "$u@$h holds GRANT OPTION"
done <<< "$privs"

# --- 5. Default test database --------------------------------------------------
testdb=$(query "SHOW DATABASES LIKE 'test';")
if [ -n "$testdb" ]; then
    report WARN "Default 'test' database exists (world-readable by design) — consider dropping it"
else
    report OK "No default 'test' database"
fi

# --- Summary -------------------------------------------------------------------
if [ "$JSON" -eq 0 ]; then
    echo
    echo "Accounts checked: $(query 'SELECT COUNT(*) FROM mysql.user;') — $FAIL failure(s), $WARN warning(s)"
fi

[ "$FAIL" -gt 0 ] && exit 1
exit 0
