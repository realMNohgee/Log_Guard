#!/usr/bin/env python3
"""Log_Guard — brute-force detector and blocklist generator for auth logs.

Parses sshd / PAM style authentication logs, counts failed logins per source
IP, flags any IP at or above a failure threshold, and emits pf / iptables /
nftables block rules for the offenders. `watch` tails a live log and alerts as
new failures appear. Zero dependencies — Python stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time

# Matches a dotted-quad IPv4 address (used as a named group in every pattern).
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

# Ordered list of failure signatures. First match wins for a given line.
FAIL_PATTERNS = (
    re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from " + _IP),
    re.compile(r"Failed (?:publickey|none) for (?:invalid user )?(?P<user>\S+) from " + _IP),
    re.compile(r"Invalid user (?P<user>\S+) from " + _IP),
    re.compile(r"authentication failure.*?rhost=" + _IP),
    re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?"
               r"(?P<user>\S+) from " + _IP),
)


def _fail(msg: str, code: int = 2) -> int:
    """Print an error to stderr and return a non-zero exit code."""
    print(f"error: {msg}", file=sys.stderr)
    return code


def extract_failure(line: str):
    """Return (user, ip) for a failed-auth log line, or None if it isn't one."""
    for rx in FAIL_PATTERNS:
        m = rx.search(line)
        if m:
            gd = m.groupdict()  # groups vary per pattern
            user = gd.get("user") or "unknown"
            return user, m.group("ip")
    return None


def parse_failures(path: str):
    """Read a log file and return a list of (user, ip) failure tuples."""
    failures = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            hit = extract_failure(line)
            if hit:
                failures.append(hit)
    return failures


def count_by_ip(failures):
    """Aggregate failures into {ip: count}, sorted by descending count."""
    counts = {}
    for _user, ip in failures:
        counts[ip] = counts.get(ip, 0) + 1
    # Sort by count desc, then IP asc for a stable, readable ordering.
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def flagged_ips(counts, threshold):
    """Return [(ip, count)] for every IP at or above `threshold`."""
    return [(ip, c) for ip, c in counts.items() if c >= threshold]


def cmd_analyze(args) -> int:
    """Count failed logins per IP and flag offenders (`analyze`)."""
    if not os.path.isfile(args.file):
        return _fail(f"file not found: {args.file}")

    failures = parse_failures(args.file)
    counts = count_by_ip(failures)
    flagged = flagged_ips(counts, args.threshold)

    result = {
        "file": args.file,
        "threshold": args.threshold,
        "total_failures": len(failures),
        "unique_ips": len(counts),
        "flagged": [{"ip": ip, "count": c} for ip, c in flagged],
        "by_ip": [{"ip": ip, "count": c} for ip, c in counts.items()],
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Log_Guard analyze — {args.file}")
        print(f"Threshold:       {args.threshold} failures")
        print(f"Total failures:  {len(failures)}")
        print(f"Unique source IPs: {len(counts)}")
        print()
        if flagged:
            print(f"Flagged ({len(flagged)} IP(s) at or above threshold):")
            for ip, c in flagged:
                print(f"  {ip:<16} {c} failures")
        else:
            print("No IP reached the failure threshold.")
        print()
        print("All source IPs:")
        for ip, c in counts.items():
            print(f"  {ip:<16} {c}")
    return 0


def _rules_for(ip: str):
    """Build the pf / iptables / nftables block rule for one IPv4 address."""
    host = f"{ip}/32"  # explicit /32 so the address is treated as a single host
    return (
        f"block drop from {host} to any",
        f"iptables -A INPUT -s {host} -j DROP",
        f"nft add rule ip filter input ip saddr {host} drop",
    )


def cmd_blocklist(args) -> int:
    """Emit firewall block rules for flagged IPs (`blocklist`)."""
    if not os.path.isfile(args.file):
        return _fail(f"file not found: {args.file}")

    counts = count_by_ip(parse_failures(args.file))
    flagged = flagged_ips(counts, args.threshold)

    pf, iptables, nftables = [], [], []  # one rule per flagged IP per backend
    for ip, _c in flagged:
        r_pf, r_ipt, r_nft = _rules_for(ip)
        pf.append(r_pf)
        iptables.append(r_ipt)
        nftables.append(r_nft)

    result = {
        "file": args.file,
        "threshold": args.threshold,
        "flagged": [{"ip": ip, "count": c} for ip, c in flagged],
        "pf": pf,
        "iptables": iptables,
        "nftables": nftables,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"# Log_Guard blocklist — {len(flagged)} IP(s) at or above "
              f"{args.threshold} failures")
        if not flagged:
            print("# no IP reached the failure threshold")
        print("# pf")
        for r in pf:
            print(r)
        print("# iptables")
        for r in iptables:
            print(r)
        print("# nftables")
        for r in nftables:
            print(r)
    return 0


def cmd_watch(args) -> int:
    """Tail a live log and alert on new failed logins (`watch`)."""
    if not os.path.isfile(args.file):
        return _fail(f"file not found: {args.file}")

    counts = {}          # running failure count per IP
    alerted = set()      # IPs already reported as crossing the threshold
    print(f"# Log_Guard watch — tailing {args.file} (Ctrl-C to stop)", file=sys.stderr)

    with open(args.file, "r", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)  # start at EOF, like `tail -f`
        try:
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(args.interval)  # idle: wait for more data
                    continue
                hit = extract_failure(line)
                if not hit:
                    continue
                user, ip = hit
                counts[ip] = counts.get(ip, 0) + 1
                crossed = counts[ip] >= args.threshold and ip not in alerted
                if crossed:
                    alerted.add(ip)
                event = {"ip": ip, "user": user, "count": counts[ip],
                         "threshold": args.threshold, "crossed": crossed}
                if args.format == "json":
                    print(json.dumps(event), flush=True)  # NDJSON stream
                else:
                    tag = "THRESHOLD" if crossed else "FAIL"
                    print(f"[{tag}] ip={ip} user={user} count={counts[ip]}", flush=True)
        except KeyboardInterrupt:
            # Clean Ctrl-C exit: summarize what was seen.
            print(f"\n# watched {len(counts)} IP(s), {sum(counts.values())} failures",
                  file=sys.stderr)
    return 0


def main(argv=None) -> int:
    """Build the CLI, parse argv exactly once, and dispatch to a subcommand."""
    # Shared --format lives ONLY on the parent parser, attached to every subparser.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")

    parser = argparse.ArgumentParser(
        prog="Log_Guard",
        description="Brute-force detector and blocklist generator for auth logs.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_analyze = sub.add_parser("analyze", parents=[common],
                               help="Count failed logins per IP and flag offenders")
    p_analyze.add_argument("file", help="Auth log file to parse (e.g. /var/log/auth.log)")
    p_analyze.add_argument("--threshold", type=int, default=5,
                           help="Flag IPs at or above this many failures (default: 5)")
    p_analyze.set_defaults(func=cmd_analyze)

    p_block = sub.add_parser("blocklist", parents=[common],
                             help="Emit pf/iptables/nftables block rules for flagged IPs")
    p_block.add_argument("file", help="Auth log file to parse")
    p_block.add_argument("--threshold", type=int, default=5,
                         help="Flag IPs at or above this many failures (default: 5)")
    p_block.set_defaults(func=cmd_blocklist)

    p_watch = sub.add_parser("watch", parents=[common],
                             help="Tail a log and alert on new failed logins")
    p_watch.add_argument("file", help="Auth log file to tail")
    p_watch.add_argument("--threshold", type=int, default=5,
                         help="Report when an IP reaches this many failures (default: 5)")
    p_watch.add_argument("--interval", type=float, default=1.0,
                         help="Poll interval in seconds (default: 1.0)")
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args(argv)  # single parse
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
