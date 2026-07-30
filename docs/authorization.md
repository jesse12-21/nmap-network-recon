# Authorisation and Safe Scanning

Port scanning is the one activity in this portfolio that is unlawful without permission. Everything else here — analysing a packet capture, writing a detection rule, querying a SIEM — operates on data you already hold. Scanning reaches out and touches infrastructure that belongs to someone else.

This document exists because a recon repository that does not address it is incomplete, and because knowing where the line sits is part of the skill.

---

## The legal position, briefly

Unauthorised port scanning is prosecutable in most jurisdictions. In the United States it can fall under the Computer Fraud and Abuse Act; in the United Kingdom under the Computer Misuse Act 1990; across the EU under national implementations of the Directive on attacks against information systems. Whether a given scan crosses the threshold has been litigated inconsistently, and "I was only scanning" has not reliably been a defence.

Two practical consequences:

**Ambiguity is not permission.** The absence of a prohibition is not authorisation. Nor is a bug bounty programme's existence — those define a scope, and activity outside it is unauthorised regardless of intent.

**Your ISP's terms bind you independently of the law.** Most consumer and cloud terms of service prohibit scanning third-party hosts. AWS, GCP, and Azure all require notification or have explicit policies for penetration testing against your own resources.

I am not a lawyer and this is not legal advice. If you are scanning anything you do not own, get written authorisation from someone who can grant it.

---

## Scope this project

Everything in this repository was run against a lab the author controls:

| Component | Detail |
|---|---|
| Hypervisor | Oracle VirtualBox, host-only and NAT networks |
| Scanner | Ubuntu 24.04 VM |
| Targets | Metasploitable and purpose-built VMs on an isolated segment |
| External exposure | None. The lab does not route to the internet for scan traffic. |

Sample data in `samples/` uses RFC 5737 documentation ranges (`198.51.100.0/24`) and `.invalid` hostnames, so the fixtures cannot match real infrastructure even by accident.

---

## Before scanning anything you do not own

A minimum checklist. If you cannot complete it, do not run the scan.

- [ ] **Written authorisation** from someone with authority over the target — not verbal, not implied by a job title
- [ ] **Explicit scope**: IP ranges and hostnames, stated as inclusions rather than exclusions
- [ ] **Time window** agreed, with a named contact reachable during it
- [ ] **Escalation path** if something breaks, including who can authorise stopping
- [ ] **Third-party notification** where the target is hosted by someone else (cloud provider, SaaS, managed hosting)
- [ ] **Rules of engagement** covering whether exploitation is permitted, or discovery only
- [ ] **Data handling** agreed: where scan output is stored, who can read it, when it is destroyed

Scan output is sensitive. A file listing every open port and unpatched service version on a network is a target package. This repository's `.gitignore` excludes `*.xml`, `*.html`, and `scan_results/` for that reason — the only XML tracked is the synthetic fixture set under `samples/`.

---

## Scanning safely once authorised

**Timing is a safety control, not a speed setting.** `-T4` is the tutorial default and is fine on a modern LAN. It is not fine on:

- **OT and ICS networks.** Legacy PLCs and HMIs have been knocked offline by ordinary SYN scans. Some will fail on a single unexpected packet. Use `PROFILE_QUIET`, and get sign-off from whoever owns the process the equipment controls, not just from IT.
- **Medical devices.** Same failure mode, higher consequence.
- **Anything behind an IPS in blocking mode.** You will be blocked mid-scan and receive partial results that look like a clean bill of health.

**A throttled scan is worse than no scan** if you do not know it was throttled. A host that reports no open ports because your packets were dropped is indistinguishable in the output from a genuinely hardened host. Verify with a known-open port before trusting a negative result.

**Prefer discovery before enumeration.** Establish what exists with `PROFILE_DISCOVERY` before running version detection or NSE scripts against it. Scanning things that are not there wastes time and generates noise for no benefit.

**Be attributable.** On any authorised engagement, make your traffic identifiable — see [`purple-team-coverage.md`](purple-team-coverage.md) and `nse/http-scan-attribution.nse`. It costs nothing and it prevents the SOC treating your test as an incident.

---

## The NSE scripts in this repository

All three are in the `safe` category and none attempts exploitation:

| Script | What it sends | Risk |
|---|---|---|
| `tls-pq-readiness` | One TLS ClientHello per port | Negligible. A rejected handshake is a normal event. |
| `http-security-headers` | One HTTP GET | Negligible. Reads response headers only. |
| `http-scan-attribution` | One HTTP GET with identifying headers | Negligible, and deliberately conspicuous. |

`--script vuln`, used in `scripts/network_scan.sh`, is a different matter. Some scripts in that category are intrusive and a few can crash fragile services. It belongs in an authorised assessment with a maintenance window, not in routine discovery.

---

## If something breaks

Stop the scan. Contact the named escalation contact immediately. Do not attempt to diagnose or fix the target yourself — you are outside your authorisation the moment you go beyond scanning, and an honest early report is worth considerably more than a quiet one.

Record what you were running, against what, and when. `scripts/network_scan.sh` timestamps every output file for this reason.
