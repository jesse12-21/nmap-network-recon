# Known Limitations

Findings from testing this repository's contents against the tools that run them. Each entry records what was tested, what was observed, and what was done about it.

---

## 1. A counting idiom crashed the assessment script on empty results

**Affects:** `scripts/network_scan.sh`
**Found:** 2026-07-29
**Status:** fixed

The script counted results in three places using a pattern that looks correct and is not:

```bash
LIVE_HOSTS=$(grep -c "Host is up" "$file" || echo "0")
```

`grep -c` prints `0` **and** exits 1 when there are no matches. The `|| echo "0"` then appends a second `0`, producing the two-line string `"0\n0"`. Reproduced:

```console
$ LIVE_HOSTS=$(grep -c "Host is up" /tmp/empty.txt || echo "0")
$ echo "[$LIVE_HOSTS]"
[0
0]
$ [ "$LIVE_HOSTS" -eq 0 ]
bash: [: 0
0: integer expression expected
```

Under `set -euo pipefail` that terminates the script. The failure occurred at exactly the point the script most needed to handle gracefully: **a scan that found nothing**. It affected the live-host count, the open-port count, and the vulnerability count.

**Fixed** with a helper that always yields a single integer:

```bash
count_matches() {
    grep -c -- "$1" "$2" 2>/dev/null | head -1 || true
}
```

The open-port count was also tightened from `grep -c "open"` — which matched any line containing the word, including summary lines — to `grep -c "^[0-9]*/tcp.*open"`.

---

## 2. The quick scan ran the same scan twice

**Affects:** `scripts/quick_scan.sh`
**Found:** 2026-07-29
**Status:** fixed

Lines 37 and 41 both ran `nmap -sS --top-ports 100 -T4 "$TARGET" --open` — once to display results, once with `-oG` to extract the port list. Double the runtime and double the packets on the wire.

On an authorised engagement, doubling your scan footprint for no benefit is a real cost: it doubles what the SOC sees and doubles the load on the target.

**Fixed** by scanning once into a grepable temp file and both displaying and parsing that.

---

## 3. A suspected bug that was not one

**Affects:** `scripts/network_scan.sh` HTML report generation
**Status:** no change needed

The script generates HTML with:

```bash
xsltproc "$xml_file" -o "$html_file"
```

This looks wrong — `xsltproc` normally takes a stylesheet as its first argument, and the obvious reading is that the XML is being passed where the stylesheet should be. Tested both forms:

```console
$ xsltproc scan.xml -o out1.html          # the script's form
$ xsltproc -o out2.html /usr/share/nmap/nmap.xsl scan.xml
$ ls -l out1.html out2.html
-rw-r--r-- 7977 out1.html
-rw-r--r-- 7977 out2.html
```

Both produce identical valid HTML. Nmap's XML output embeds an `<?xml-stylesheet?>` processing instruction pointing at `nmap.xsl`, and `xsltproc` honours it. The existing code is correct.

Recorded because the reasoning is more useful than the conclusion: a plausible-looking bug that survives testing should be left alone, and "I checked" is worth writing down.

---

## 4. `.gitignore` would have dropped the test fixtures

**Affects:** `samples/*.xml`
**Found:** 2026-07-29, before pushing
**Status:** fixed

The repository excluded `*.xml` and `*.html` — sensible, because live scan output lands in those formats and may contain real target data.

The synthetic fixtures the pytest suite depends on are also XML. Verified before committing:

```console
$ git check-ignore -q samples/scan-baseline.xml && echo IGNORED
IGNORED
```

The suite would have passed locally and failed on a clean checkout, because the fixtures exist on the developer's machine and not in the repository.

**Fixed** by negating them explicitly while keeping the general exclusion:

```
*.xml
*.html
!samples/*.xml
!samples/*.html
```

CI also verifies the fixtures are present in the checkout before running tests, so a future recurrence names the missing file rather than surfacing as a confusing test failure.

This is the fourth repository in this portfolio where an ignore rule written for generated data silently excluded required data. The pattern is consistent enough to be worth stating as a rule: **a security repository has runtime data dependencies, and version control must distinguish data that is produced from data that is required.**

---

## 5. NSE scripts are engine-validated but not fully behaviour-tested

**Affects:** `nse/*.nse`
**Status:** partial — stated rather than solved

All three scripts are validated by Nmap's own Lua engine in CI:

```console
$ nmap --script-help ./nse/broken.nse
NSE: failed to initialize the script engine:
/usr/share/nmap/nse_main.lua:266: ./broken.nse:6: ')' expected near 'return'
```

That catches syntax errors with file and line, and it is the closest thing NSE has to a compiler. It does **not** verify behaviour.

Coverage as it stands:

| Script | Syntax validated | Runs without error | Behaviour verified |
|---|---|---|---|
| `tls-pq-readiness` | yes | yes, against a live TLS endpoint | **partially** — negative case only |
| `http-security-headers` | yes | not verified | no |
| `http-scan-attribution` | yes | not verified | no |

Two specific gaps:

**No post-quantum server was available to test against.** `tls-pq-readiness` was exercised against a classical TLS endpoint and correctly reported `not supported`. The positive path — a server that *does* negotiate `X25519MLKEM768` — was never exercised, because OpenSSL 3.0 predates ML-KEM support and 3.5 or later was not available in the test environment. The negative result is real; the positive result is untested code.

**The HTTP scripts were not run against a live server.** The test environment blocked loopback listeners, so neither HTTP script was executed end to end. Their logic is straightforward header inspection, but "straightforward" is not "tested".

Closing these needs a lab with an OpenSSL 3.5+ endpoint and a reachable HTTP server. Until then this is a real gap, and the scripts should be treated as reviewed rather than proven.

---

## 6. Nmap's bundled TLS library predates the post-quantum code points

**Affects:** `nse/tls-pq-readiness.nse`
**Status:** worked around

`nselib/tls.lua` carries the IANA supported-groups registry in an `ELLIPTIC_CURVES` table. On Nmap 7.94 it contains no post-quantum entries — `MLKEM`, `Kyber`, and code point 4588 are all absent, which is expected given the group was standardised after that release.

The script therefore injects the code points at runtime rather than depending on the library shipping them:

```lua
tls.ELLIPTIC_CURVES["X25519MLKEM768"] = 4588
```

This works because `EXTENSION_HELPERS["elliptic_curves"]` performs a plain table lookup. It also means the script functions on older Nmap builds, which is the point — asking users to upgrade Nmap to run a script is a poor trade when a two-line injection suffices.

---

## 7. Coverage gaps in the toolkit

| Gap | Detail |
|---|---|
| **No IPv6 in the automation scripts** | `profiles.env` includes IPv6 profiles, but `network_scan.sh` and `quick_scan.sh` are IPv4-only. A dual-stack host firewalled on v4 is frequently open on v6. |
| **Discovery misses hosts that drop all probes** | `-sn` relies on responses. Hosts configured to ignore ICMP and TCP probes are invisible without `-Pn`, which forfeits the discovery phase entirely. |
| **`--script vuln` is version-dependent** | The vuln category changes between Nmap releases. Results are not reproducible across versions, so scan output should record the Nmap version — `network_scan.sh` does. |
| **UDP scanning is unreliable and slow** | The UDP results in Part 2 should be read as indicative. Open-versus-filtered is genuinely ambiguous without a service-specific probe. |
| **No rate limiting in the automation scripts** | Both scripts use `-T4`. Neither exposes a timing argument, so fragile-network use requires editing them or using the profiles directly. |
| **Parser handles TCP and UDP only** | `nmap_to_siem.py` reads `<port>` elements. SCTP and IP-protocol scans are not parsed. |

---

*Findings recorded while testing against Nmap 7.94SVN, Python 3.12, and ShellCheck. CI validates against the current Nmap in the Ubuntu runner image.*
