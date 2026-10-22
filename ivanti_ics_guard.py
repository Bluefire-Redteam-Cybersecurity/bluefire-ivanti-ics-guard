#!/usr/bin/env python3
"""Bluefire Redteam — Ivanti Connect Secure exposure check.

Checker only. Defensive version and reachability check for CVE-2026-104935.
The only fix is a resolved Ivanti build. If an affected portal was
reachable, upgrading in place is not a cleanup. This tool does not
send exploit traffic and does not test whether a bypass works.
See README for the disclaimer and LICENSE for the MIT terms.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CVE = "CVE-2026-104935"
CVSS = "8.6"
ADVISORY = "https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935"
CISA = "https://www.cisa.gov/news-events/alerts/2026/10/13/cisa-urges-patching-newly-exploited-vulnerability-ivanti-connect-secure"
SITE = "https://bluefire-redteam.com"
CONTACT = "contact@bluefire-redteam.com"
CTA = f"Need this checked across your VPN estate? {SITE}"

# 22.7R2.14 and earlier are outside the affected set. Compare as
# (major, minor, release, service-pack).
NOT_AFFECTED_THROUGH = (22, 7, 2, 14)
EOL_228 = "31 January 2027"


@dataclass(frozen=True)
class Build:
    raw: str
    kind: str  # dotted | release
    parts: tuple[int, int, int, int]

    @property
    def label(self) -> str:
        major, minor, third, fourth = self.parts
        if self.kind == "dotted":
            return f"{major}.{minor}.{third}.{fourth}"
        if fourth == 0:
            return f"{major}.{minor}R{third}"
        return f"{major}.{minor}R{third}.{fourth}"


@dataclass
class Verdict:
    raw: str
    status: str  # patched, vulnerable, not_affected, review, unknown
    fixed_in: str | None
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_build(raw: str) -> Build | None:
    text = (raw or "").strip()
    release = re.search(r"(\d+)\.(\d+)\s*R\s*(\d+)(?:\.(\d+))?", text, re.I)
    if release:
        major, minor, rel, pack = release.groups()
        return Build(
            text,
            "release",
            (int(major), int(minor), int(rel), int(pack or 0)),
        )
    dotted = re.search(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", text)
    if dotted:
        return Build(text, "dotted", tuple(int(part) for part in dotted.groups()))  # type: ignore[arg-type]
    return None


def classify(raw: str) -> Verdict:
    """Map a build to the Ivanti table.

    The CVE sentence says "before 25.1.3.0". The product table is more
    precise: 25.1.1.2 is a fix for the 25.1.1 line, and the 25.1.2 line
    stays affected until 25.1.3.0. This function follows the table.
    """
    build = parse_build(raw)
    if build is None:
        return Verdict(raw or "", "unknown", None, "No Ivanti Connect Secure build could be read.")

    if build.kind == "release":
        return _classify_release(build)
    return _classify_dotted(build)


def _classify_release(build: Build) -> Verdict:
    major, minor, rel, pack = build.parts
    if build.parts <= NOT_AFFECTED_THROUGH:
        return Verdict(
            build.label,
            "not_affected",
            None,
            "Ivanti says 22.7R2.14 and earlier are not affected by CVE-2026-104935.",
        )
    if (major, minor) == (22, 8):
        if (rel, pack) < (2, 5):
            return Verdict(
                build.label,
                "vulnerable",
                "22.8R2.5",
                "22.8R2.4 and earlier are affected. 22.8R2.5 is the fix on this branch. "
                f"22.8 reaches end of life on {EOL_228}. Move to 25.1.3.1 when you can.",
            )
        return Verdict(
            build.label,
            "patched",
            "22.8R2.5",
            f"This 22.8 build is at or above 22.8R2.5. The branch reaches end of life on {EOL_228}. "
            "Plan the move to 25.1.3.1.",
        )
    if (major, minor) == (22, 7):
        return Verdict(
            build.label,
            "review",
            None,
            "This 22.7 build is newer than 22.7R2.14. The advisory only clears 22.7R2.14 and earlier.",
        )
    return Verdict(
        build.label,
        "review",
        None,
        "This release is not in the Ivanti affected table. Confirm it with Ivanti before calling it safe.",
    )


def _classify_dotted(build: Build) -> Verdict:
    parts = build.parts
    if parts >= (25, 1, 3, 0):
        return Verdict(
            build.label,
            "patched",
            "25.1.3.0",
            "25.1.3.0 and later do not contain CVE-2026-104935. 25.1.3.1 is the later fixed build named by Ivanti.",
        )
    if parts >= (25, 1, 2, 0):
        return Verdict(
            build.label,
            "vulnerable",
            "25.1.3.1",
            "The 25.1.2 line, including 25.1.2.2 and earlier, stays affected until 25.1.3.0. Install 25.1.3.1.",
        )
    if parts >= (25, 1, 1, 2):
        return Verdict(
            build.label,
            "patched",
            "25.1.1.2",
            "25.1.1.2 and later builds on the 25.1.1 line are fixed. The 25.1.2 line is a separate affected branch.",
        )
    if parts >= (25, 1, 0, 0):
        return Verdict(
            build.label,
            "vulnerable",
            "25.1.1.2",
            "25.1.1.1 and earlier on the 25.1.1 line are affected. The minimum fix on this line is 25.1.1.2. "
            "Prefer 25.1.3.1 if the hardware can take it.",
        )
    return Verdict(
        build.label,
        "review",
        None,
        "This dotted build is outside the rows Ivanti published. Confirm it before calling it safe.",
    )


def versions_in_text(text: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r"\b(\d+\.\d+\s*R\s*\d+(?:\.\d+)?)\b", text, re.I):
        found.append(re.sub(r"\s+", "", match.group(1)))
    for match in re.finditer(r"\b(\d+\.\d+\.\d+\.\d+)\b", text):
        found.append(match.group(1))
    return found


def looks_like_ics(text: str) -> bool:
    sample = text.lower()
    markers = ("ivanti connect secure", "pulse connect secure", "dana-na", "/dana/")
    return any(marker in sample for marker in markers)


def fetch_page(url: str, timeout: float = 8.0) -> tuple[int, str]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    request = Request(url, method="GET", headers={"User-Agent": "Bluefire-ICS-Guard"})
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read(256 * 1024).decode("utf-8", errors="replace")
            return status, body
    except HTTPError as error:
        body = error.read(64 * 1024).decode("utf-8", errors="replace")
        return error.code, body


def decision(verdict: Verdict, reachable: bool | None) -> str:
    if verdict.status == "patched":
        return "PATCHED"
    if verdict.status == "not_affected":
        return "NOT_AFFECTED"
    if verdict.status == "review":
        return "REVIEW"
    if verdict.status == "unknown":
        return "UNKNOWN"
    if reachable:
        return "EXPOSED"
    return "VULNERABLE"


def remediation(verdict: Verdict, name: str, reachable: bool | None) -> list[str]:
    where = name or "this appliance"
    state = decision(verdict, reachable)
    lines = [
        f"1. Put the external portal for {where} behind an allow-list, or take it off the internet, until it is on a fixed build.",
        "   Ivanti published no workaround.",
        "2. Install a resolved build from the Ivanti License Server.",
        "   25.1.1 line: 25.1.1.2 or later on that line. Prefer 25.1.3.1 when the appliance supports it.",
        "   25.1.2 line: 25.1.3.0 or 25.1.3.1.",
        f"   22.8 line: 22.8R2.5 now. That branch reaches end of life on {EOL_228}.",
        "3. If the portal was reachable on an affected build on or after 3 October 2026, treat it as suspect.",
        "   Upgrading in place is not a cleanup. Reported activity included credential theft, data theft, and log tampering.",
        "   Ivanti's integrity checker can miss it, because the commands run in memory.",
        "   a. Back up the configuration.",
        "   b. Factory-reset the hardware, or rebuild a cloud or virtual appliance.",
        "   c. Upgrade to the fixed build, then restore the configuration from that backup.",
        "   d. Reset every password: domain, administrator, and local.",
        "   e. Reissue certificates. Reset API keys and license-server credentials.",
        "4. A privilege-escalation issue used in the same incident was still unpatched in the 13 October releases.",
        "   Ask Ivanti whether the build you install closes it. This check does not cover that issue.",
        f"5. Advisory: {ADVISORY}",
        f"   CISA KEV, added 13 October 2026, due 16 October 2026: {CISA}",
    ]
    if verdict.fixed_in and verdict.status == "vulnerable":
        lines.insert(2, f"   Next build for {where}: {verdict.fixed_in}.")
    if state == "PATCHED":
        lines.insert(
            0,
            "This build is on the resolved list for CVE-2026-104935. "
            "If it was reachable while it was still affected, and you have not rebuilt it, do step 3 anyway.",
        )
    if state == "NOT_AFFECTED":
        return [
            "This build is outside the affected range Ivanti published.",
            f"22.8 still reaches end of life on {EOL_228} if you are on that branch.",
            f"Advisory: {ADVISORY}",
        ]
    return lines


def parse_reachable(value: str | None) -> bool | None:
    if value is None or value.strip() == "":
        return None
    text = value.strip().lower()
    if text in {"yes", "y", "true", "1", "internet", "reachable", "external"}:
        return True
    if text in {"no", "n", "false", "0", "internal", "unreachable"}:
        return False
    raise ValueError(f"Unrecognised reachability value: {value}")


@dataclass
class Host:
    name: str
    version: str
    reachable: bool | None


def load_fleet(path: Path) -> list[Host]:
    hosts: list[Host] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = [part.strip() for part in stripped.split(",")]
        if parts[0].lower() == "name":
            continue
        if len(parts) < 2:
            raise ValueError(f"{path}:{line_no}: expected name,version[,reachable]")
        reachable = parse_reachable(parts[2]) if len(parts) > 2 else None
        hosts.append(Host(parts[0], parts[1], reachable))
    return hosts


class Paint:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled and sys.stdout.isatty()

    def _w(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def title(self, text: str) -> str:
        return self._w("1;34", text)

    def good(self, text: str) -> str:
        return self._w("32", text)

    def bad(self, text: str) -> str:
        return self._w("1;31", text)

    def warn(self, text: str) -> str:
        return self._w("33", text)

    def dim(self, text: str) -> str:
        return self._w("2", text)


def tone(paint: Paint, status: str):
    if status in {"PATCHED", "NOT_AFFECTED"}:
        return paint.good
    if status in {"REVIEW", "UNKNOWN"}:
        return paint.warn
    return paint.bad


def render_host(host: Host, paint: Paint) -> str:
    verdict = classify(host.version)
    status = decision(verdict, host.reachable)
    reach = {True: "reachable", False: "not reachable", None: "reachability unknown"}[host.reachable]
    rows = [
        paint.title("Bluefire Redteam  ·  Ivanti Connect Secure"),
        paint.dim(f"{CVE}   CVSS {CVSS}   CISA KEV"),
        "",
        f"Host       {host.name}",
        f"Build      {verdict.raw or host.version}",
        f"Decision   {tone(paint, status)(status)}",
        f"Portal     {reach}",
    ]
    if verdict.fixed_in and verdict.status == "vulnerable":
        rows.append(f"Fixed in   {verdict.fixed_in}")
    rows.append(paint.dim(verdict.detail))
    rows.append("")
    rows.append(paint.title("Remediation"))
    rows.extend(remediation(verdict, host.name, host.reachable))
    rows.append("")
    rows.append(paint.title("Bluefire Redteam"))
    rows.append("A global offensive security firm.")
    rows.append(CTA)
    return "\n".join(rows)


def render_fleet(hosts: list[Host], paint: Paint) -> str:
    rows = [
        paint.title("Bluefire Redteam  ·  Ivanti Connect Secure fleet"),
        paint.dim(f"{CVE}   CVSS {CVSS}   CISA KEV"),
        "",
    ]
    worst = "NOT_AFFECTED"
    rank = {"NOT_AFFECTED": 0, "PATCHED": 1, "REVIEW": 2, "UNKNOWN": 3, "VULNERABLE": 4, "EXPOSED": 5}
    for host in hosts:
        verdict = classify(host.version)
        status = decision(verdict, host.reachable)
        if rank[status] > rank[worst]:
            worst = status
        fixed = verdict.fixed_in or "-"
        rows.append(f"  {tone(paint, status)(status):<16} {host.name:<24} {verdict.raw or host.version:<16} {fixed}")
    rows.append("")
    rows.append(f"Fleet decision   {tone(paint, worst)(worst)}")
    exposed = [host for host in hosts if decision(classify(host.version), host.reachable) == "EXPOSED"]
    if exposed:
        rows.append("")
        rows.append(paint.title("Reachable and affected"))
        for host in exposed:
            rows.append(f"  {host.name} is on {classify(host.version).raw}. Take the portal off the internet and follow the rebuild steps.")
    rows.append("")
    rows.append(CTA)
    return "\n".join(rows)


def render_markdown(host: Host) -> str:
    verdict = classify(host.version)
    status = decision(verdict, host.reachable)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    reach = {True: "yes", False: "no", None: "unknown"}[host.reachable]
    lines = [
        "# Bluefire Redteam — Ivanti Connect Secure exposure report",
        "",
        f"Prepared {now}.",
        "",
        f"**Decision: {status}**",
        "",
        f"Host `{host.name}` is build `{verdict.raw or host.version}`. "
        f"Portal reachable: {reach}.",
        "",
        verdict.detail,
        "",
        "This check compares the build with Ivanti's published table for CVE-2026-104935. "
        "It does not test exploitability and it is not evidence that an attacker succeeded.",
        "",
        "## Remediation",
        "",
    ]
    for line in remediation(verdict, host.name, host.reachable):
        lines.append(line if line[:1].isdigit() or line.startswith("This") or line.startswith("Ivanti") else f"  {line.strip()}")
    lines.extend([
        "",
        "## Why the rebuild step is in the report",
        "",
        "CISA added this CVE to the Known Exploited Vulnerabilities catalog on 13 October 2026. "
        "The federal due date was 16 October 2026. Exploitation was reported from 3 October 2026. "
        "The integrity checker is not enough to declare an appliance clean.",
        "",
        "## Compliance mapping",
        "",
        "| Framework | Control | How this helps |",
        "|---|---|---|",
        "| CISA BOD 26-04 | KEV | Records a known-exploited VPN vulnerability and the missed due date |",
        "| ISO/IEC 27001:2022 | A.8.8 | Identifies the technical vulnerability and the required build |",
        "| NIST CSF 2.0 | ID.RA-01 | Records the asset, the build, and whether the portal is reachable |",
        "| NIST CSF 2.0 | PR.PS-02 | Checks that the appliance is on a maintained release |",
        "",
        "## Disclaimer",
        "",
        "Checker only. This report compares a build number with Ivanti's published table. "
        "It is not proof of compromise or of safety, and it is not legal advice. "
        "The tool is provided as-is under the MIT License.",
        "",
        "## See also",
        "",
        "- [PHP2Shell Guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-php2shell-guard)",
        "- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)",
        "- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)",
        "",
        "## Bluefire Redteam",
        "",
        "Bluefire Redteam is a global offensive security firm. The work is red teaming, penetration testing, "
        "and AI security testing.",
        "",
        f"To run this across a VPN estate, write to [{CONTACT}](mailto:{CONTACT}) or start at [{SITE}]({SITE}).",
        "",
    ])
    return "\n".join(lines)


def exit_for(status: str) -> int:
    if status in {"PATCHED", "NOT_AFFECTED"}:
        return 0
    if status in {"REVIEW", "UNKNOWN"}:
        return 3
    return 2


def cmd_audit(args: argparse.Namespace) -> int:
    version = args.version
    reachable = parse_reachable(args.reachable) if args.reachable else None
    product_seen = False
    if args.url:
        status, body = fetch_page(args.url)
        product_seen = looks_like_ics(body)
        found = versions_in_text(body)
        if version is None and found:
            version = found[0]
        if reachable is None and status:
            reachable = True
        if version is None:
            print(f"Fetched {args.url} (HTTP {status}). No build number was on the page.", file=sys.stderr)
            if product_seen:
                print("The response looks like Connect Secure. Pass --version from the admin console.", file=sys.stderr)
            return 3
    if version is None:
        print("Pass --version or --url.", file=sys.stderr)
        return 1
    host = Host(args.name or "appliance", version, reachable)
    verdict = classify(host.version)
    status = decision(verdict, host.reachable)
    payload = {
        "decision": status,
        "host": host.name,
        "version": verdict.to_dict(),
        "reachable": host.reachable,
        "product_hint": product_seen,
        "cve": CVE,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(render_host(host, Paint(not args.no_color)))
    return exit_for(status)


def cmd_fleet(args: argparse.Namespace) -> int:
    hosts = load_fleet(Path(args.file))
    if not hosts:
        print("The fleet file had no hosts.", file=sys.stderr)
        return 1
    results = []
    worst = "NOT_AFFECTED"
    rank = {"NOT_AFFECTED": 0, "PATCHED": 1, "REVIEW": 2, "UNKNOWN": 3, "VULNERABLE": 4, "EXPOSED": 5}
    for host in hosts:
        verdict = classify(host.version)
        status = decision(verdict, host.reachable)
        if rank[status] > rank[worst]:
            worst = status
        results.append({
            "host": host.name,
            "decision": status,
            "version": verdict.to_dict(),
            "reachable": host.reachable,
        })
    if args.json:
        print(json.dumps({"decision": worst, "hosts": results, "cve": CVE}, indent=2))
    else:
        print(render_fleet(hosts, Paint(not args.no_color)))
    return exit_for(worst)


def cmd_report(args: argparse.Namespace) -> int:
    host = Host(args.name or "appliance", args.version, parse_reachable(args.reachable) if args.reachable else None)
    document = render_markdown(host)
    if args.out:
        Path(args.out).write_text(document, encoding="utf-8")
        print(f"Wrote {args.out}")
    else:
        print(document)
    return exit_for(decision(classify(host.version), host.reachable))


def cmd_demo(_args: argparse.Namespace) -> int:
    fleet = Path(__file__).resolve().parent / "fixtures" / "fleet.csv"
    hosts = load_fleet(fleet)
    print(render_fleet(hosts, Paint(True)))
    print()
    exposed = next(host for host in hosts if host.name == "hq-vpn")
    print(render_host(exposed, Paint(True)))
    return 0


def selftest() -> int:
    failures: list[str] = []

    def expect(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    cases = {
        "22.8R2.4": "vulnerable",
        "22.8R2": "vulnerable",
        "22.8r2.3": "vulnerable",
        "22.8R1": "vulnerable",
        "22.8R2.5": "patched",
        "22.8R2.10": "patched",
        "22.7R2.14": "not_affected",
        "22.7R2.13": "not_affected",
        "9.1R18": "not_affected",
        "22.7R3": "review",
        "25.1.1.1": "vulnerable",
        "25.1.0.5": "vulnerable",
        "25.1.1.2": "patched",
        "25.1.1.9": "patched",
        "25.1.2.0": "vulnerable",
        "25.1.2.2": "vulnerable",
        "25.1.2.3": "vulnerable",
        "25.1.3.0": "patched",
        "25.1.3.1": "patched",
        "25.2.0.0": "patched",
        "24.3.1": "unknown",
    }
    for raw, status in cases.items():
        got = classify(raw).status
        expect(got == status, f"{raw}: expected {status}, got {got}")

    expect(classify("25.1.1.2").status == "patched", "25.1.1.2 must stay patched despite the loose CVE sentence")
    expect(decision(classify("22.8R2.4"), True) == "EXPOSED", "reachable vulnerable is exposed")
    expect(decision(classify("22.8R2.4"), False) == "VULNERABLE", "internal vulnerable stays vulnerable")
    expect(decision(classify("25.1.3.1"), True) == "PATCHED", "fixed build stays patched when reachable")
    expect(exit_for("EXPOSED") == 2 and exit_for("PATCHED") == 0 and exit_for("REVIEW") == 3, "exit codes")

    page = (Path(__file__).resolve().parent / "fixtures" / "login.html").read_text(encoding="utf-8")
    expect(looks_like_ics(page), "fixture should look like Connect Secure")
    found = versions_in_text(page)
    expect(found and classify(found[0]).status == "vulnerable", f"login fixture version, got {found}")

    hosts = load_fleet(Path(__file__).resolve().parent / "fixtures" / "fleet.csv")
    expect(len(hosts) == 4, "fleet fixture length")
    statuses = [decision(classify(host.version), host.reachable) for host in hosts]
    expect(statuses == ["EXPOSED", "PATCHED", "NOT_AFFECTED", "VULNERABLE"], f"fleet decisions {statuses}")

    text = remediation(classify("22.8R2.4"), "hq-vpn", True)
    joined = "\n".join(text)
    expect("Factory-reset" in joined and "22.8R2.5" in joined and "API keys" in joined, "cleanup steps")

    if failures:
        print("SELFTEST FAILED")
        for item in failures:
            print(f"  - {item}")
        return 1
    print(f"SELFTEST OK  ({CVE})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true")
    parser = argparse.ArgumentParser(
        prog="ivanti_ics_guard.py",
        description="Bluefire Redteam exposure check for Ivanti Connect Secure CVE-2026-104935.",
        parents=[common],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", parents=[common], help="Check one build, or one portal URL")
    audit.add_argument("--version", help="Build, for example 22.8R2.4 or 25.1.2.2")
    audit.add_argument("--url", help="Single GET of a portal URL. Reads a version if the page shows one.")
    audit.add_argument("--name", default="appliance")
    audit.add_argument("--reachable", help="yes or no. A successful --url counts as reachable.")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    fleet = sub.add_parser("fleet", parents=[common], help="Check a CSV of name,version,reachable")
    fleet.add_argument("file")
    fleet.add_argument("--json", action="store_true")
    fleet.set_defaults(func=cmd_fleet)

    report = sub.add_parser("report", parents=[common], help="Write a markdown report for one appliance")
    report.add_argument("--version", required=True)
    report.add_argument("--name", default="appliance")
    report.add_argument("--reachable")
    report.add_argument("--out")
    report.set_defaults(func=cmd_report)

    demo = sub.add_parser("demo", parents=[common], help="Run the bundled fleet")
    demo.set_defaults(func=cmd_demo)

    test = sub.add_parser("selftest", help="Run the built-in checks")
    test.set_defaults(func=lambda _args: selftest())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
