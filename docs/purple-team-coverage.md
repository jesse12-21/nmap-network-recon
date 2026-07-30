# Purple-Team Detection Coverage

Scanning is only half a skill. The other half is knowing what a defender sees when you do it.

This repository is the offensive side of a four-project pipeline. The other three are defensive, and two of them already contain detections for exactly the activity generated here. That makes a closed loop available: **run the scan, check whether your own detections fired, record the gaps.**

```
   nmap-network-recon  (this repo)
            │  scan traffic
            ├──────────────► wireshark-threat-detection   packet-level analysis
            ├──────────────► suricata-ids-rules           signature detection
            └──────────────► splunk-siem-analysis         risk scoring + correlation
```

---

## Coverage matrix

Each row maps an action in this repository to the detection content that should observe it.

| Scan action | Nmap invocation | Suricata | Splunk | Expected outcome |
|---|---|---|---|---|
| Host discovery sweep | `-sn -PE -PS80,443,22` | — | — | **Gap.** No detection covers ICMP/TCP sweeps. |
| SYN port scan | `-sS --top-ports 1000` | — | — | **Gap.** No port-scan signature exists. |
| Scanner user agent | `--script http-scan-attribution` | SID 1000005 | T1595 | Both should fire |
| Content discovery / 404 burst | `--script http-enum` | SID 1000013 | T1595.003 (risk 35) | Both should fire |
| Version probes to web | `-sV -p 80,443` | — | — | Partial — only if a UA matches |
| NSE vuln scripts against HTTP | `--script vuln` | SID 1000001-1000003 possible | T1190 (risk 60) | Depends on payload shape |
| TLS post-quantum probe | `--script tls-pq-readiness` | — | — | **Gap.** Anomalous ClientHello unmatched. |

The gaps are the useful part of this table. Three of seven scan actions produce no detection at all in content that was written specifically to catch network reconnaissance. That is worth knowing, and it is the kind of thing a coverage exercise surfaces and a tabletop does not.

---

## Running the exercise

**1. Make the traffic attributable.** Before generating anything, ensure a defender can tell your scan from a real one:

```bash
sudo nmap --script ./nse/http-scan-attribution.nse \
  --script-args http-scan-attribution.id=PURPLE-2026-07,http-scan-attribution.contact=secops@example.invalid \
  -p 80,443 <target>
```

Every request carries `X-Scan-Attribution: PURPLE-2026-07` and a matching User-Agent. Without this, a successful detection is indistinguishable from an incident, and the SOC spends an afternoon on you.

**2. Generate the activity.** Use the standard profile so the exercise reflects a realistic scan rather than a deliberately loud one:

```bash
source profiles/profiles.env
# shellcheck disable=SC2086
sudo nmap $PROFILE_STANDARD -oX results/purple-run.xml <target>
```

**3. Check Suricata.** On the sensor:

```bash
grep -E 'SID:100000[0-9]|SID:10000(1[0-9])' /var/log/suricata/eve.json | jq -r '.alert.signature' | sort | uniq -c
```

Or use that project's summary script directly:

```bash
./scripts/alert_summary.sh /var/log/suricata/eve.json
```

**4. Check Splunk.** The relevant question is not "did an alert fire" but "did the source accumulate risk":

```
| from datamodel Risk.All_Risk
| search All_Risk.risk_object="<SCANNER_IP>"
| stats sum(All_Risk.calculated_risk_score) as total_risk,
        dc(All_Risk.search_name) as distinct_detections,
        values(All_Risk.search_name) as detections
  by All_Risk.risk_object
```

Under the risk model in that project, a scan that trips both the wordlist-scanning detection (35) and the scanner-UA path (T1595) should put the source somewhere around 80 — noticeable, below the alerting threshold, and correctly so. A scan on its own is not an incident.

**5. Record the result.** Use the template below. The output of the exercise is the table, not the scan.

---

## Result template

```
EXERCISE: <id>            DATE: <date>
SCANNER:  <ip>            TARGET SCOPE: <cidr>
PROFILE:  <profile used>

| Scan action | Detection expected | Fired? | Latency | Notes |
|---|---|---|---|---|
|             |                    | Y/N    |         |       |

GAPS IDENTIFIED
  1.
  2.

DETECTIONS TO WRITE
  1.

FALSE POSITIVES OBSERVED
  1.
```

---

## Known gaps and why they exist

**No port-scan detection.** Neither companion project detects a SYN sweep. This is a deliberate omission rather than an oversight — port-scan detection is high-volume and low-value on an internet-facing sensor, where scanning is constant background noise. It is worth having *internally*, where a host scanning its own subnet is anomalous. A Suricata threshold rule on SYN-to-many-ports from one source, scoped to `$HOME_NET -> $HOME_NET`, would close it.

**No TLS-anomaly detection for unusual ClientHellos.** The `tls-pq-readiness` script sends a ClientHello advertising only post-quantum groups — a fingerprint no ordinary client produces. The Wireshark project has JA4 tooling that would identify it, and the Suricata project has a JA4 rule scaffold, but neither carries a fingerprint for scanner-generated hellos. Worth adding once a JA4 baseline exists.

**Discovery sweeps are invisible.** ICMP and TCP-ping sweeps generate no signature match. Detecting them is a flow-analysis problem rather than a signature problem, which is why it belongs in the Splunk layer as a `tstats` correlation over `Network_Traffic` rather than as an IDS rule.

---

## Why attribution matters more than it looks

The single most common failure in detection-validation exercises is not a missed detection. It is a SOC that has learned to close scanning alerts without reading them, because most of the scanning they see is their own team testing.

Attribution fixes that. A marker in the traffic lets the SOC triage authorised activity in seconds and keeps their response to unattributed scanning intact. `nse/http-scan-attribution.nse` exists for this reason, and it is the reason it is deliberately conspicuous rather than stealthy.

---

## Related

- [suricata-ids-rules](https://github.com/jesse12-21/suricata-ids-rules) — the signatures referenced above, with per-rule tuning analysis
- [splunk-siem-analysis](https://github.com/jesse12-21/splunk-siem-analysis) — risk scoring model and the `Risk.All_Risk` queries
- [wireshark-threat-detection](https://github.com/jesse12-21/wireshark-threat-detection) — packet-level analysis and JA4 fingerprinting
