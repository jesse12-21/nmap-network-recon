#!/usr/bin/env python3
"""Convert Nmap XML output into CSV and SIEM-ready JSON.

Nmap's XML is the only output format that is both complete and machine-readable,
but nothing consumes it by default. This turns a scan into rows that can be
diffed between runs or ingested into a SIEM.

Two output shapes:

  CSV   -- one row per open port, for spreadsheets and diffing.
  JSON  -- newline-delimited, one object per port, with field names normalised
           to the Splunk Common Information Model so the records land in the
           right data model without a custom parser at index time.

CIM mapping applied to the JSON output:

    Nmap concept        CIM field       Notes
    ------------------  --------------  --------------------------------------
    host address        dest            The scanned host is the destination
    port number         dest_port
    protocol            transport       tcp / udp
    service name        service
    product + version   service_version
    scanner host        src             Populated from --scanner-host
    state               status          open / filtered / closed

Usage:
    python3 nmap_to_siem.py scan.xml                     # CSV to stdout
    python3 nmap_to_siem.py scan.xml --format json       # NDJSON to stdout
    python3 nmap_to_siem.py scan.xml -o out.csv
    python3 nmap_to_siem.py scan.xml --format json --scanner-host 10.0.2.15
    python3 nmap_to_siem.py old.xml --diff new.xml       # what changed

The diff mode is the one worth having. A single scan is a snapshot; the security
question is almost always what changed since last time.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class PortRecord:
    """One open port on one host, normalised toward Splunk CIM field names."""

    dest: str
    dest_port: int
    transport: str
    status: str
    service: str
    service_version: str
    hostname: str
    scan_start: str
    src: str = ""

    def as_cim(self) -> dict:
        record = asdict(self)
        if not record["src"]:
            record.pop("src")
        return record


def _text(elem: ET.Element | None, attr: str, default: str = "") -> str:
    if elem is None:
        return default
    return elem.get(attr, default) or default


def parse(xml_path: Path, scanner_host: str = "") -> list[PortRecord]:
    """Parse an Nmap XML file into a list of open-port records.

    Raises ValueError on input that is well-formed XML but is not an Nmap run,
    which is a more useful failure than silently returning zero rows.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError(
            f"{xml_path}: root element is <{root.tag}>, expected <nmaprun>. "
            "Is this Nmap XML output (-oX)?"
        )

    scan_start = root.get("startstr", "")
    records: list[PortRecord] = []

    for host in root.findall("host"):
        status = host.find("status")
        if _text(status, "state") != "up":
            continue

        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                address = addr.get("addr", "")
                break
        if not address:
            continue

        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            hostname = _text(hn, "name")

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")
            port_state = _text(state, "state")
            # Filtered ports are reported: "we could not tell" is a finding,
            # and dropping them makes a diff between scans misleading.
            if port_state not in ("open", "filtered", "open|filtered"):
                continue

            service_elem = port.find("service")
            product = _text(service_elem, "product")
            version = _text(service_elem, "version")
            service_version = " ".join(p for p in (product, version) if p)

            records.append(
                PortRecord(
                    dest=address,
                    dest_port=int(port.get("portid", 0)),
                    transport=port.get("protocol", ""),
                    status=port_state,
                    service=_text(service_elem, "name"),
                    service_version=service_version,
                    hostname=hostname,
                    scan_start=scan_start,
                    src=scanner_host,
                )
            )

    return records


def to_csv(records: list[PortRecord], stream) -> None:
    fieldnames = [
        "dest", "hostname", "dest_port", "transport", "status",
        "service", "service_version", "scan_start", "src",
    ]
    writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for record in records:
        writer.writerow(asdict(record))


def to_ndjson(records: list[PortRecord], stream) -> None:
    """Newline-delimited JSON: one object per line, which is what Splunk's
    HTTP Event Collector and most log shippers expect."""
    for record in records:
        stream.write(json.dumps(record.as_cim(), sort_keys=True) + "\n")


def diff(old: list[PortRecord], new: list[PortRecord]) -> dict[str, list[dict]]:
    """Compare two scans by (host, port, protocol).

    Reports ports that appeared, disappeared, or changed service version.
    A new open port on an unchanged host is the single most actionable output
    a recurring scan produces.
    """
    def key(r: PortRecord) -> tuple:
        return (r.dest, r.dest_port, r.transport)

    old_map = {key(r): r for r in old}
    new_map = {key(r): r for r in new}

    appeared = [asdict(new_map[k]) for k in new_map.keys() - old_map.keys()]
    disappeared = [asdict(old_map[k]) for k in old_map.keys() - new_map.keys()]

    changed = []
    for k in old_map.keys() & new_map.keys():
        o, n = old_map[k], new_map[k]
        if o.service_version != n.service_version or o.status != n.status:
            changed.append({
                "dest": n.dest,
                "dest_port": n.dest_port,
                "transport": n.transport,
                "was": f"{o.status} {o.service_version}".strip(),
                "now": f"{n.status} {n.service_version}".strip(),
            })

    return {
        "appeared": sorted(appeared, key=lambda r: (r["dest"], r["dest_port"])),
        "disappeared": sorted(disappeared, key=lambda r: (r["dest"], r["dest_port"])),
        "changed": sorted(changed, key=lambda r: (r["dest"], r["dest_port"])),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Convert Nmap XML to CSV or SIEM-ready NDJSON."
    )
    parser.add_argument("xml", type=Path, help="Nmap XML file (-oX output)")
    parser.add_argument("-f", "--format", choices=("csv", "json"), default="csv")
    parser.add_argument("-o", "--output", type=Path, help="Write to file (default: stdout)")
    parser.add_argument("--scanner-host", default="",
                        help="Populate the CIM src field with the scanning host")
    parser.add_argument("--diff", type=Path, metavar="NEWER_XML",
                        help="Compare against a later scan and report changes as JSON")
    args = parser.parse_args(argv)

    if not args.xml.exists():
        print(f"error: {args.xml} not found", file=sys.stderr)
        return 1

    try:
        records = parse(args.xml, args.scanner_host)
    except ET.ParseError as exc:
        print(f"error: {args.xml} is not valid XML: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    def emit(stream) -> None:
        if args.diff:
            newer = parse(args.diff, args.scanner_host)
            json.dump(diff(records, newer), stream, indent=2, sort_keys=True)
            stream.write("\n")
        elif args.format == "json":
            to_ndjson(records, stream)
        else:
            to_csv(records, stream)

    if args.output:
        with open(args.output, "w", newline="") as fh:
            emit(fh)
    else:
        emit(sys.stdout)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # Normal when piping into head/less. Suppress the interpreter's
        # "Exception ignored" noise on shutdown.
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0)
