local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Audits HTTP response security headers and reports which are missing or weak.

Checks for Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, and Permissions-Policy, and separately flags headers
that disclose server or framework versions.

Header presence is a configuration signal, not a vulnerability. A missing CSP does not
mean a site is exploitable; it means one layer of defence in depth is absent. Output is
graded rather than reported as pass or fail for that reason.
]]

---
-- @usage
-- nmap --script http-security-headers -p 80,443 <target>
--
-- @args http-security-headers.path Path to request (default: /).
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-security-headers:
-- |   grade: C (3/6 present)
-- |   present: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options
-- |   missing: Content-Security-Policy, Referrer-Policy, Permissions-Policy
-- |_  disclosure: server: Apache/2.4.41 (Ubuntu)

author = "jesse12-21"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}

portrule = shortport.http

local CHECKS = {
  {header = "strict-transport-security", label = "Strict-Transport-Security"},
  {header = "content-security-policy",   label = "Content-Security-Policy"},
  {header = "x-content-type-options",    label = "X-Content-Type-Options"},
  {header = "x-frame-options",           label = "X-Frame-Options"},
  {header = "referrer-policy",           label = "Referrer-Policy"},
  {header = "permissions-policy",        label = "Permissions-Policy"},
}

-- Headers that commonly leak product and version information.
local DISCLOSURE = {"server", "x-powered-by", "x-aspnet-version", "x-generator"}

local function grade(present, total)
  local pct = (present / total) * 100
  if pct >= 90 then return "A" end
  if pct >= 70 then return "B" end
  if pct >= 50 then return "C" end
  if pct >= 30 then return "D" end
  return "F"
end

action = function(host, port)
  local path = stdnse.get_script_args("http-security-headers.path") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return nil
  end

  local present, missing = {}, {}
  for _, check in ipairs(CHECKS) do
    if response.header[check.header] then
      present[#present + 1] = check.label
    else
      missing[#missing + 1] = check.label
    end
  end

  local disclosed = {}
  for _, name in ipairs(DISCLOSURE) do
    local value = response.header[name]
    if value and value ~= "" then
      disclosed[#disclosed + 1] = string.format("%s: %s", name, value)
    end
  end

  local out = stdnse.output_table()
  out.grade = string.format("%s (%d/%d present)",
    grade(#present, #CHECKS), #present, #CHECKS)

  if #present > 0 then out.present = table.concat(present, ", ") end
  if #missing > 0 then out.missing = table.concat(missing, ", ") end
  if #disclosed > 0 then out.disclosure = table.concat(disclosed, "; ") end

  -- HSTS over cleartext is inert; browsers ignore the header unless it arrives over TLS.
  if response.header["strict-transport-security"] and port.number == 80 then
    out.note = "HSTS present on cleartext HTTP; browsers ignore it unless served over TLS."
  end

  return out
end
