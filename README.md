# Log_Guard 🛡️

**Brute-force detector and blocklist generator for auth logs.** Log_Guard parses sshd/PAM failed-login lines, counts failures per source IP, flags any IP at or above a threshold, and prints ready-to-paste pf, iptables, and nftables block rules. `watch` tails a live log and alerts as attacks arrive. Zero dependencies, pure Python stdlib.

## Why it exists

Every internet-facing SSH daemon is under constant credential-guessing attack. `auth.log` records it all, but a wall of `Failed password` lines tells you nothing at a glance. Log_Guard collapses that noise into per-IP counts, flags the real offenders above a threshold you choose, and emits the exact firewall commands to shut them down — on macOS (`pf`) or Linux (`iptables`/`nftables`).

## One tool, many domains

| Domain | What Log_Guard does for you |
|---|---|
| **Security / SOC** | Triage brute-force campaigns; hand the blocklist straight to a firewall |
| **SRE / Ops** | Automate IP banning from `auth.log`; `--format json` feeds a response script |
| **Agentic AI** | Give an LLM agent structured attacker counts and generated remediation rules |
| **Compliance** | Produce evidence of monitored failed-auth volume and response |
| **Homelab** | `watch` a log and get live alerts the moment a host starts getting hammered |

## Install

```bash
git clone git@github.com:realMNohgee/Log_Guard.git
cd Log_Guard
python3 Log_Guard.py --help
```

## Quick start

```bash
# Count failed logins per IP, flag anyone with >= 5 failures
python3 Log_Guard.py analyze /var/log/auth.log

# Generate block rules for the offenders (default threshold 5)
python3 Log_Guard.py blocklist /var/log/auth.log

# Raise the bar to 10 failures
python3 Log_Guard.py analyze /var/log/auth.log --threshold 10

# Machine-readable output
python3 Log_Guard.py analyze /var/log/auth.log --format json
```

Sample `analyze` output:

```
Log_Guard analyze — /tmp/auth.log
Threshold:       5 failures
Total failures:  7
Unique source IPs: 2

Flagged (1 IP(s) at or above threshold):
  203.0.113.7      6 failures

All source IPs:
  203.0.113.7      6
  198.51.100.4     1
```

Sample `blocklist` output:

```
# Log_Guard blocklist — 1 IP(s) at or above 5 failures
# pf
block drop from 203.0.113.7/32 to any
# iptables
iptables -A INPUT -s 203.0.113.7/32 -j DROP
# nftables
nft add rule ip filter input ip saddr 203.0.113.7/32 drop
```

## Live monitoring

`watch` follows a log like `tail -f` and prints an alert for every new failure, escalating to a `THRESHOLD` alert when an IP crosses the count:

```bash
python3 Log_Guard.py watch /var/log/auth.log --threshold 5
```

```
[FAIL]      ip=203.0.113.7 user=admin count=1
[FAIL]      ip=203.0.113.7 user=admin count=2
...
[THRESHOLD] ip=203.0.113.7 user=admin count=5
```

Use `--format json` for a newline-delimited JSON alert stream, and `--interval` to tune the poll rate.

## Recognized failure lines

Log_Guard matches the common signatures:

- `Failed password for [invalid user] <user> from <ip>`
- `Failed publickey|none for … from <ip>`
- `Invalid user <user> from <ip>`
- `… authentication failure … rhost=<ip>`
- `maximum authentication attempts exceeded … from <ip>`

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
