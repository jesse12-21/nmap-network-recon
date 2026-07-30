"""Tests for parsers/nmap_to_siem.py.

The fixtures in samples/ are synthetic but modelled on real Nmap -oX output,
including the elements that are easy to get wrong: a down host with no ports
element, a filtered port with no version data, and a service with product but
no version.
"""

from __future__ import annotations

import io
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "parsers"))

import nmap_to_siem as parser

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
BASELINE = SAMPLES / "scan-baseline.xml"
FOLLOWUP = SAMPLES / "scan-followup.xml"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def test_parses_expected_number_of_records():
    records = parser.parse(BASELINE)
    # 3 open + 1 filtered on web01, 2 open on db01. The down host contributes none.
    assert len(records) == 6


def test_down_hosts_are_skipped():
    records = parser.parse(BASELINE)
    assert all(r.dest != "198.51.100.99" for r in records)


def test_filtered_ports_are_retained():
    """A filtered port is a finding, not an absence. Dropping them would make
    a diff between two scans misleading."""
    records = parser.parse(BASELINE)
    filtered = [r for r in records if r.status == "filtered"]
    assert len(filtered) == 1
    assert filtered[0].dest_port == 3306


def test_service_version_concatenates_product_and_version():
    records = parser.parse(BASELINE)
    ssh = next(r for r in records if r.dest_port == 22 and r.dest == "198.51.100.10")
    assert ssh.service_version == "OpenSSH 8.9p1 Ubuntu 3ubuntu0.4"


def test_service_version_empty_when_no_product():
    records = parser.parse(BASELINE)
    mysql = next(r for r in records if r.dest_port == 3306)
    assert mysql.service_version == ""
    assert mysql.service == "mysql"


def test_hostname_is_captured():
    records = parser.parse(BASELINE)
    assert all(
        r.hostname == "web01.example.invalid"
        for r in records if r.dest == "198.51.100.10"
    )


def test_scanner_host_populates_cim_src():
    records = parser.parse(BASELINE, scanner_host="10.0.2.15")
    assert all(r.src == "10.0.2.15" for r in records)


def test_ports_are_integers_not_strings():
    """Splunk will treat a quoted port as a string and numeric comparisons in
    SPL will silently fail."""
    records = parser.parse(BASELINE)
    assert all(isinstance(r.dest_port, int) for r in records)


# --------------------------------------------------------------------------
# Error handling
# --------------------------------------------------------------------------

def test_rejects_non_nmap_xml(tmp_path):
    bad = tmp_path / "notnmap.xml"
    bad.write_text("<foo><bar/></foo>")
    with pytest.raises(ValueError, match="expected <nmaprun>"):
        parser.parse(bad)


def test_raises_on_malformed_xml(tmp_path):
    bad = tmp_path / "broken.xml"
    bad.write_text("<nmaprun><host>")
    with pytest.raises(ET.ParseError):
        parser.parse(bad)


def test_cli_reports_missing_file(capsys):
    rc = parser.main(["/nonexistent/scan.xml"])
    assert rc == 1
    assert "not found" in capsys.readouterr().err


# --------------------------------------------------------------------------
# Output formats
# --------------------------------------------------------------------------

def test_csv_has_header_and_one_row_per_record():
    records = parser.parse(BASELINE)
    buf = io.StringIO()
    parser.to_csv(records, buf)
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert lines[0].startswith("dest,hostname,dest_port")
    assert len(lines) == len(records) + 1


def test_ndjson_is_one_valid_object_per_line():
    records = parser.parse(BASELINE)
    buf = io.StringIO()
    parser.to_ndjson(records, buf)
    lines = [line for line in buf.getvalue().splitlines() if line]
    assert len(lines) == len(records)
    for line in lines:
        obj = json.loads(line)
        assert "dest" in obj and "dest_port" in obj


def test_ndjson_omits_empty_src():
    """An empty src field would create a null-valued CIM field in Splunk."""
    records = parser.parse(BASELINE)
    buf = io.StringIO()
    parser.to_ndjson(records, buf)
    assert all("src" not in json.loads(line) for line in buf.getvalue().splitlines() if line)


def test_ndjson_includes_src_when_supplied():
    records = parser.parse(BASELINE, scanner_host="10.0.2.15")
    buf = io.StringIO()
    parser.to_ndjson(records, buf)
    first = json.loads(buf.getvalue().splitlines()[0])
    assert first["src"] == "10.0.2.15"


# --------------------------------------------------------------------------
# Diff — the mode that turns a snapshot into monitoring
# --------------------------------------------------------------------------

def test_diff_detects_newly_opened_port():
    result = parser.diff(parser.parse(BASELINE), parser.parse(FOLLOWUP))
    appeared = result["appeared"]
    assert len(appeared) == 1
    assert appeared[0]["dest_port"] == 6379
    assert appeared[0]["service"] == "redis"


def test_diff_detects_closed_port():
    result = parser.diff(parser.parse(BASELINE), parser.parse(FOLLOWUP))
    disappeared = result["disappeared"]
    assert len(disappeared) == 1
    assert disappeared[0]["dest_port"] == 5432


def test_diff_detects_version_change():
    result = parser.diff(parser.parse(BASELINE), parser.parse(FOLLOWUP))
    changed = result["changed"]
    assert len(changed) == 2  # ports 80 and 443 both upgraded
    assert all("2.4.52" in c["was"] and "2.4.58" in c["now"] for c in changed)


def test_diff_of_identical_scans_is_empty():
    records = parser.parse(BASELINE)
    result = parser.diff(records, records)
    assert result == {"appeared": [], "disappeared": [], "changed": []}


def test_diff_is_directional():
    """diff(a, b) and diff(b, a) should mirror each other, not match."""
    a, b = parser.parse(BASELINE), parser.parse(FOLLOWUP)
    forward, reverse = parser.diff(a, b), parser.diff(b, a)
    assert len(forward["appeared"]) == len(reverse["disappeared"])
    assert len(forward["disappeared"]) == len(reverse["appeared"])
