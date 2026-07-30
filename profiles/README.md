# Scan Profiles

Reusable Nmap option sets. Each profile states what it does, how loud it is, and
when it is the wrong choice — because the most common scanning mistake is not
picking the wrong flags, it is picking aggressive flags on a network that cannot
absorb them.

Load a profile with `nmap --script-args-file` style reuse is not supported for
general options, so these are shell variables sourced into a command line:

```bash
source profiles/profiles.env
# shellcheck disable=SC2086
nmap $PROFILE_DISCOVERY 198.51.100.0/24
```

| Profile | Loudness | Use when |
|---|---|---|
| `PROFILE_DISCOVERY` | Low | Establishing what exists before touching it |
| `PROFILE_STANDARD` | Medium | Routine assessment of a known scope |
| `PROFILE_THOROUGH` | High | Authorised deep assessment with a maintenance window |
| `PROFILE_QUIET` | Very low | Fragile networks, OT/ICS, or evading rate-based detection |
| `PROFILE_PURPLE` | Medium, attributable | Detection-validation exercises — see `docs/purple-team-coverage.md` |

## On timing templates

`-T4` is the default in most tutorials and is fine on a modern LAN. It is not
fine everywhere:

- **OT and ICS networks** — legacy PLCs and HMIs have been knocked offline by
  ordinary SYN scans. Use `PROFILE_QUIET` and get explicit written sign-off.
- **Networks with IPS in blocking mode** — `-T4` gets you blocked mid-scan,
  producing partial results that look like closed ports.
- **Congested or high-latency links** — aggressive timing produces false
  negatives, which is worse than a slow scan because the output looks complete.

A scan that reports "no open ports" because it was throttled is indistinguishable
from a scan of a hardened host. Timing is a correctness concern, not just speed.
