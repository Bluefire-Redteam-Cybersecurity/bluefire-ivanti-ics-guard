# Bluefire Redteam — Ivanti Connect Secure check

Checker only. It compares a build number with the vendor table and prints cleanup steps. It does not try the vulnerability.

Exposure check for **CVE-2026-104935**, an authentication bypass in Ivanti Connect Secure that lets a remote caller run commands without logging in. CVSS 8.6. CISA added it to the Known Exploited Vulnerabilities catalog on 13 October 2026. The federal due date was 16 October 2026.

Bluefire Redteam is a global offensive security firm. We do red teaming, penetration testing, and AI security testing.

This tool compares a build number with Ivanti's published table. It does not try the bypass. A page fetch is one GET, and only to read a version string if the portal already prints one.

| Line | Affected | Resolved |
|---|---|---|
| 25.1.1 | 25.1.1.1 and earlier | 25.1.1.2 |
| 25.1.2 | 25.1.2.2 and earlier, up to but not including 25.1.3.0 | 25.1.3.0 or 25.1.3.1 |
| 22.8 | 22.8R2.4 and earlier | 22.8R2.5 |

22.7R2.14 and earlier are not affected. 25.1.3.0 and later are not affected. There is no workaround. 22.8 reaches end of life on 31 January 2027, so 22.8R2.5 is a bridge, not the place to stay.

The CVE text says "before 25.1.3.0". Ivanti's product table is the one this tool follows: **25.1.1.2 is fixed** even though it is numerically before 25.1.3.0. The 25.1.2 line is affected again until 25.1.3.0.

Advisory: <https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935>

## Show it

```bash
python3 ivanti_ics_guard.py selftest
python3 ivanti_ics_guard.py demo
python3 ivanti_ics_guard.py audit --version 22.8R2.4 --reachable yes --name hq-vpn
python3 ivanti_ics_guard.py fleet fixtures/fleet.csv
python3 ivanti_ics_guard.py report --version 22.8R2.4 --reachable yes --name hq-vpn --out /tmp/ics-report.md
```

`audit --url https://vpn.example` sends one GET. Most portals do not print the build. Take the version from the admin console when the page does not show it.

Exit codes: `0` patched or not affected, `3` needs a human to confirm the build, `2` vulnerable or exposed, `1` usage error.

## If it was on the internet

Reported exploitation started on 3 October 2026. Activity included credential theft, data theft, and log tampering. Ivanti's integrity checker can miss it, because the commands run in memory.

For a portal that was reachable on an affected build:

1. Restrict the portal to known source addresses, or take it offline.
2. Back up the configuration.
3. Factory-reset the hardware, or rebuild a cloud or virtual appliance.
4. Upgrade, then restore the configuration.
5. Reset every password. Reissue certificates. Reset API keys and license-server credentials.

A privilege-escalation issue used in the same incident was still unpatched in the 13 October releases. Ask Ivanti whether the build you install closes it. This check does not cover that issue.

## See also

Other Bluefire Redteam checkers:

- [PHP2Shell Guard](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-php2shell-guard) — CVE-2026-109618 and CVE-2026-109619
- [SharePoint CVE-2025-53770 toolkit](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-sharepoint-cve-2025-53770)
- [Nx s1ngularity check](https://github.com/Bluefire-Redteam-Cybersecurity/bluefire-nx-s1ngularity-check)

## Disclaimer

This repository is a checker. It reads a version you supply, or a version string already printed on a page you ask it to fetch, and compares that with Ivanti's published table. It does not send exploit traffic. A result is not proof that an appliance was compromised, and it is not proof that an appliance is safe.

Use it only on systems you are authorized to assess. The report is not legal advice and it does not replace the Ivanti or CISA advisory. The software is provided as-is, without warranty, under the [MIT License](LICENSE).

## Work with Bluefire Redteam

To run this across a VPN estate, start at [bluefire-redteam.com](https://bluefire-redteam.com) or write to [contact@bluefire-redteam.com](mailto:contact@bluefire-redteam.com).
