import argparse
import sys

from . import __version__
from .models import OWASP, Severity
from .reporters import to_json, to_text
from .rules import AST_CHECKS, REGEX_RULES
from .scanner import scan_paths


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="owaspscan", description="Static OWASP Top 10 issue detector")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan files or directories")
    s.add_argument("paths", nargs="+")
    s.add_argument("-f", "--format", choices=["text", "json"], default="text")
    s.add_argument("--min-severity", default="low", choices=[x.name.lower() for x in Severity])
    s.add_argument("--fail-on", default="high", choices=[x.name.lower() for x in Severity] + ["never"],
                   help="exit 1 if a finding at/above this severity exists (CI gate)")
    s.add_argument("--only", help="comma-separated OWASP ids, e.g. A01,A03")

    sub.add_parser("rules", help="list available rules")

    w = sub.add_parser(
        "web",
        help="run safe, read-only checks against a live URL/domain (authorized targets only)",
        description=("Sends real HTTP(S) requests. Only use against hosts you own or are "
                      "explicitly authorized to test — unauthorized scanning can be illegal "
                      "even when every request is non-destructive."),
    )
    w.add_argument("urls", nargs="+", help="e.g. example.com or https://example.com/page?id=1")
    w.add_argument("--i-have-permission", action="store_true", required=True,
                   help="required: confirms you own or are authorized to test these targets")
    w.add_argument("-f", "--format", choices=["text", "json"], default="text")
    w.add_argument("--min-severity", default="low", choices=[x.name.lower() for x in Severity])
    w.add_argument("--fail-on", default="high", choices=[x.name.lower() for x in Severity] + ["never"])
    w.add_argument("--timeout", type=float, default=8.0)
    w.add_argument("--delay", type=float, default=0.25, help="seconds between requests (rate limit)")
    w.add_argument("--no-path-probe", action="store_true", help="skip checks for exposed .git/.env/etc.")
    w.add_argument("--no-param-probe", action="store_true",
                   help="skip reflected-XSS / SQL-error probes on query parameters")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "rules":
        for r in REGEX_RULES:
            print(f"{r.id}  {r.severity.name:<8} {OWASP[r.owasp]:<50} {r.title}")
        print(f"(+ {len(AST_CHECKS)} AST checks: OWS-A01-002, OWS-A09-002; manifest check: OWS-A06-001)")
        print("(+ 'web' command: live checks — headers, cookies, TLS, exposed paths, reflected XSS/SQLi)")
        return 0

    if args.cmd == "web":
        from .webscan import scan_urls
        findings = scan_urls(
            args.urls, timeout=args.timeout, delay=args.delay,
            path_probe=not args.no_path_probe, param_probe=not args.no_param_probe,
        )
        findings = [f for f in findings if f.severity >= Severity.parse(args.min_severity)]
        print(to_json(findings) if args.format == "json" else to_text(findings))
        if args.fail_on != "never" and any(f.severity >= Severity.parse(args.fail_on) for f in findings):
            return 1
        return 0

    findings = scan_paths(args.paths)
    findings = [f for f in findings if f.severity >= Severity.parse(args.min_severity)]
    if args.only:
        wanted = {x.strip().upper() for x in args.only.split(",")}
        findings = [f for f in findings if f.owasp in wanted]

    print(to_json(findings) if args.format == "json" else to_text(findings))

    if args.fail_on != "never" and any(f.severity >= Severity.parse(args.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
