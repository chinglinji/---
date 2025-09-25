#!/usr/bin/env python3
"""
nginx_stats.py

用法:
    python nginx_stats.py /path/access.log --domain domain1.com --date 2019-02-28

功能:
 - 统计 referer 为 https 且 hostname 为 domain 的请求数量
 - 计算给定 UTC 日期（YYYY-MM-DD）内请求的成功比例（默认 2xx 为成功）
"""
import argparse
import re
from datetime import datetime, date, timezone
from urllib.parse import urlparse

LOG_PATTERN = re.compile(
    r'(?P<remote>\S+) \S+ \S+ \[(?P<time>[^]]+)] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
    r'(?: "(?P<extra>[^"]*)")?'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"  # example: 28/Feb/2019:13:17:10 +0000

def parse_line(line):
    """Parse one access log line. Returns dict or None if no match."""
    m = LOG_PATTERN.search(line)
    if not m:
        return None
    d = m.groupdict()
    return d

def host_matches(target_host, parsed_host, include_subdomains=False):
    """Return True if parsed_host matches target_host.
       If include_subdomains is True then sub.domain1.com also matches.
    """
    if parsed_host is None:
        return False
    # strip possible port
    host = parsed_host.split(':', 1)[0].lower()
    target = target_host.lower()
    if include_subdomains:
        return host == target or host.endswith('.' + target)
    else:
        return host == target

def main(log_path, domain, date_str=None, include_subdomains=False, success_status_min=200, success_status_max=299):
    """
    Process the log file line by line.
    - domain: domain to check in referer (e.g., domain1.com)
    - date_str: if given, compute success ratio for this UTC date (YYYY-MM-DD)
    - include_subdomains: whether to accept sub.domain1.com as match
    """
    target_date = None
    if date_str:
        try:
            target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            raise SystemExit("date must be YYYY-MM-DD")

    total_https_domain = 0
    total_on_date = 0
    success_on_date = 0
    malformed = 0
    lines = 0

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            lines += 1
            parsed = parse_line(line)
            if not parsed:
                malformed += 1
                continue

            # ---- 1) HTTPS + domain counting (from referrer) ----
            ref = parsed.get("referrer", "")
            if ref and ref != "-":
                # parse URL
                try:
                    p = urlparse(ref)
                except Exception:
                    p = None

                if p and p.scheme.lower() == "https" and host_matches(domain, p.hostname, include_subdomains):
                    total_https_domain += 1

            # ---- 2) date-based success ratio ----
            if target_date is not None:
                timestr = parsed.get("time")
                if not timestr:
                    continue
                try:
                    # parse log time (with timezone) and convert to UTC
                    dt = datetime.strptime(timestr, TIME_FORMAT)
                    dt_utc = dt.astimezone(timezone.utc)
                except Exception:
                    # if parsing fails, skip
                    continue

                if dt_utc.date() == target_date:
                    total_on_date += 1
                    try:
                        status = int(parsed.get("status", 0))
                    except ValueError:
                        status = 0
                    if success_status_min <= status <= success_status_max:
                        success_on_date += 1

            # (optional) minimal progress output for very large files could be added here

    # results
    print("Processed lines:", lines)
    if malformed:
        print("Malformed/unmatched lines:", malformed)
    print()
    print(f"HTTPS referer with domain '{domain}': {total_https_domain}")

    if target_date is not None:
        if total_on_date == 0:
            ratio = None
            print(f"No entries found for UTC date {target_date.isoformat()}.")
        else:
            ratio = success_on_date / total_on_date
            print(f"UTC date: {target_date.isoformat()}")
            print(f"  total requests on date: {total_on_date}")
            print(f"  successful (status {success_status_min}-{success_status_max}): {success_on_date}")
            print(f"  success ratio: {ratio:.6f} ({ratio*100:.4f}%)")

    # return useful numbers for programmatic use
    return {
        "lines": lines,
        "malformed": malformed,
        "https_domain_count": total_https_domain,
        "date_total": total_on_date,
        "date_success": success_on_date,
        "date_success_ratio": (success_on_date / total_on_date) if (target_date is not None and total_on_date>0) else None
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute nginx log stats.")
    parser.add_argument("logfile", help="path to nginx access log")
    parser.add_argument("--domain", required=True, help="domain to match in referer (e.g. domain1.com)")
    parser.add_argument("--date", required=False, help="UTC date YYYY-MM-DD to compute success ratio for")
    parser.add_argument("--include-subdomains", action="store_true", help="count sub.domain1.com as domain1.com")
    args = parser.parse_args()

    main(args.logfile, args.domain, date_str=args.date, include_subdomains=args.include_subdomains)
