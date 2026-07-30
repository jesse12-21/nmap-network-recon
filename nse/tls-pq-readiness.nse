local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
Determines whether a TLS server supports hybrid post-quantum key exchange.

Sends a TLS 1.3 ClientHello advertising only post-quantum hybrid groups in the
supported_groups extension. A server that completes the handshake supports one
of them; a server that responds with a handshake_failure alert does not.

Why this script exists: Nmap's bundled tls.lua carries the IANA supported-groups
registry, but the post-quantum code points postdate several releases of it. This
script injects them at runtime rather than depending on the library shipping
them, so it works on older Nmap builds:

  X25519MLKEM768      4588  (0x11EC) - the group browsers and CDNs negotiate
  SecP256r1MLKEM768   4587  (0x11EB) - FIPS-oriented alternative
  SecP384r1MLKEM1024  4589  (0x11ED)
  X25519Kyber768Draft00  25497 (0x6399) - obsolete pre-standard, reported separately

Harvest-now-decrypt-later means today's classical-only sessions are tomorrow's
plaintext. This turns an inventory question into a scan.

Companion detection content for the same property, from the network side, is in
https://github.com/jesse12-21/wireshark-threat-detection
]]

---
-- @usage
-- nmap --script tls-pq-readiness -p 443 <target>
-- nmap --script tls-pq-readiness --script-args tls-pq-readiness.include-draft=true -p 443 <target>
--
-- @args tls-pq-readiness.include-draft Also probe the obsolete
--       X25519Kyber768Draft00 group (default: false).
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | tls-pq-readiness:
-- |   post_quantum: supported
-- |   negotiated_group: X25519MLKEM768
-- |_  note: Hybrid PQ key agreement available.

author = "jesse12-21"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

-- IANA TLS Supported Groups code points for hybrid post-quantum key agreement.
-- Injected into tls.ELLIPTIC_CURVES because the bundled library predates them.
local PQ_GROUPS = {
  {name = "X25519MLKEM768",        value = 4588},
  {name = "SecP256r1MLKEM768",     value = 4587},
  {name = "SecP384r1MLKEM1024",    value = 4589},
}
local DRAFT_GROUP = {name = "X25519Kyber768Draft00", value = 25497}

local function register_groups(groups)
  local names = {}
  for _, g in ipairs(groups) do
    tls.ELLIPTIC_CURVES[g.name] = g.value
    names[#names + 1] = g.name
  end
  return names
end

-- Send a ClientHello advertising only the supplied groups. Returns true when
-- the server answers with a ServerHello, false when it rejects the handshake.
local function probe(host, port, group_names)
  local hello = tls.client_hello({
    protocol = "TLSv1.2",
    ciphers = {
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
      "TLS_AES_128_GCM_SHA256",
    },
    extensions = {
      elliptic_curves = tls.EXTENSION_HELPERS["elliptic_curves"](group_names),
      ec_point_formats = tls.EXTENSION_HELPERS["ec_point_formats"]({"uncompressed"}),
      server_name = tls.EXTENSION_HELPERS["server_name"](host.targetname or host.ip),
    },
  })

  local sock = nmap.new_socket()
  sock:set_timeout(5000)
  local ok = sock:connect(host, port)
  if not ok then
    sock:close()
    return nil, "connection failed"
  end

  ok = sock:send(hello)
  if not ok then
    sock:close()
    return nil, "send failed"
  end

  local status, response = sock:receive_bytes(0)
  sock:close()
  if not status or not response or #response < 6 then
    return nil, "no response"
  end

  -- Record type 22 is handshake (ServerHello); 21 is alert (rejection).
  local record_type = string.byte(response, 1)
  if record_type == 22 then
    return true
  end
  return false
end

action = function(host, port)
  local args = stdnse.get_script_args()
  local include_draft = stdnse.get_script_args("tls-pq-readiness.include-draft")

  local out = stdnse.output_table()

  local standard_names = register_groups(PQ_GROUPS)
  local supported, err = probe(host, port, standard_names)

  if supported == nil then
    out.post_quantum = "unknown"
    out.error = err
    return out
  end

  if supported then
    out.post_quantum = "supported"
    out.groups_offered = table.concat(standard_names, ", ")
    out.note = "Server completed a handshake advertising only hybrid PQ groups."
    return out
  end

  out.post_quantum = "not supported"
  out.groups_offered = table.concat(standard_names, ", ")

  if include_draft then
    register_groups({DRAFT_GROUP})
    local draft_ok = probe(host, port, {DRAFT_GROUP.name})
    if draft_ok then
      out.draft_kyber = "supported (obsolete pre-standard group)"
      out.note = "Server supports only the superseded draft group; migrate to X25519MLKEM768."
      return out
    end
  end

  out.note = "Classical key agreement only. Sessions are exposed to harvest-now-decrypt-later."
  return out
end
