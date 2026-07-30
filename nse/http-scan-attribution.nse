local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Tags scan traffic with an identifying marker so defenders can attribute it.

Authorised testing should be distinguishable from a real intrusion. Without a marker a
SOC either treats every scan as an incident, or learns to ignore scanning entirely --
and the second failure mode is considerably worse than the first.

This script issues a request carrying a configurable engagement identifier in the
User-Agent and in a custom header, so that blue-team detection content can attribute
the activity to a known exercise rather than to an unknown actor.

The identifier is deliberately visible. It is an attribution aid, not an evasion
technique, and it must never be used to bypass a control.

Purple-team pairing: the companion Suricata project detects scanner user agents
(SID 1000005) and the Splunk project scores the source under ATT&CK T1595. Both should
fire on this traffic. If they do not, that is a detection gap worth recording -- see
docs/purple-team-coverage.md.
  https://github.com/jesse12-21/suricata-ids-rules
  https://github.com/jesse12-21/splunk-siem-analysis
]]

---
-- @usage
-- nmap --script http-scan-attribution --script-args http-scan-attribution.id=PENTEST-2026-07 -p 80,443 <target>
--
-- @args http-scan-attribution.id Engagement identifier (default: NMAP-RECON-LAB).
-- @args http-scan-attribution.contact Contact string embedded in the marker.
-- @args http-scan-attribution.path Path to request (default: /).
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-scan-attribution:
-- |   engagement_id: PENTEST-2026-07
-- |   marker_sent: X-Scan-Attribution: PENTEST-2026-07
-- |   response_status: 200
-- |_  note: Blue-team detections should attribute this traffic to the engagement ID.

author = "jesse12-21"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local engagement = stdnse.get_script_args("http-scan-attribution.id") or "NMAP-RECON-LAB"
  local contact = stdnse.get_script_args("http-scan-attribution.contact")
  local path = stdnse.get_script_args("http-scan-attribution.path") or "/"

  local ua = string.format("nmap-recon-lab/1.0 (authorised-testing; id=%s)", engagement)
  local headers = {
    ["User-Agent"] = ua,
    ["X-Scan-Attribution"] = engagement,
  }
  if contact then
    headers["X-Scan-Contact"] = contact
  end

  local response = http.get(host, port, path, {header = headers})

  local out = stdnse.output_table()
  out.engagement_id = engagement
  out.marker_sent = string.format("X-Scan-Attribution: %s", engagement)
  out.user_agent = ua
  if contact then out.contact = contact end

  if response and response.status then
    out.response_status = response.status
  else
    out.response_status = "no response"
  end

  out.note = "Blue-team detections should attribute this traffic to the engagement ID."
  return out
end
