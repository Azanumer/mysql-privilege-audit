# MySQL Privilege Audit

A zero-dependency bash script that audits MySQL/MariaDB user accounts for common security mistakes — the kind `mysql_secure_installation` misses.

## What it checks

| Check | Severity |
|---|---|
| Anonymous user accounts (`''@host`) | FAIL |
| Accounts with **no password** set | FAIL |
| Users allowed from any host (`%`) | WARN |
| Non-admin users with `SUPER`, `FILE`, `SHUTDOWN`, `CREATE USER`, `GRANT OPTION` | WARN |
| Default `test` database still present | WARN |

## Usage

```bash
chmod +x mysql-privilege-audit.sh

# Uses ~/.my.cnf by default
./mysql-privilege-audit.sh

# Explicit credentials
./mysql-privilege-audit.sh --user root --host db1.internal

# Machine-readable output
./mysql-privilege-audit.sh --json
```

Exit code is `1` when any failure is found, so it drops straight into cron or CI:

```bash
0 6 * * * /opt/mysql-privilege-audit.sh --json | mail -s "MySQL audit" you@example.com
```

## Compatibility

Works against both `authentication_string` (MariaDB 10.4+ / MySQL 8) and the legacy `password` column, and skips `unix_socket`/`auth_socket` accounts in the password check. `root@localhost` is treated as the expected admin and not flagged for its privileges.

## License

MIT
