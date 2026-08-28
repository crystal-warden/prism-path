-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
--
-- Wireshark dissector for the Facet/1 datagram profile (PROTOCOL.md section 2).
--
-- Scope, stated honestly: this dissector shows WIRE LEVEL structure only. It decodes the
-- self framing Zeckendorf stream to wire integers and symbol indices, checks strict decode
-- validity (the same contract the kernel decode plane enforces), and labels padding. It can
-- NOT show what a symbol means: the codebook is derived from the signed policy and is never
-- transmitted (invariant I3), so semantics require the policy, not the packet. Corruption
-- that stays a syntactically valid stream decodes to a different valid value here exactly as
-- it does everywhere else; catching that is the Merkle integrity layer's job, not the codec's.
--
-- Two payload forms ride UDP/4711:
--   raw     one byte aligned Facet frame (Zeckendorf codes, MSB first, zero pad to the byte)
--   decoded the kernel decode plane's local rewrite: 'F', u8 count, count x u16le wire ints
-- The decoded form is detected by an exact length check (len == 2 + 2*count with first byte
-- 0x46). A raw frame can collide with that check; when both parses are possible the frame is
-- dissected as decoded and flagged with an expert note, because the rewrite runs upstream of
-- any capture point on the same box. Capture on the wire side of the XDP hook to see raw.

local facet = Proto("facet", "Facet/1 decision wire")

local f_form     = ProtoField.string("facet.form",     "Form")
local f_count    = ProtoField.uint16("facet.count",    "Symbol count")
local f_wireints = ProtoField.string("facet.wireints", "Wire integers")
local f_symbols  = ProtoField.string("facet.symbols",  "Symbols (wire - 1)")
local f_sym      = ProtoField.string("facet.sym",      "Symbol")
local f_cell     = ProtoField.uint16("facet.cell",     "Cell (u16le wire int)")
local f_padbits  = ProtoField.uint8 ("facet.padbits",  "Trailing zero pad (bits)")
local f_mal      = ProtoField.uint8 ("facet.malformed","Malformed (strict decode)")

facet.fields = { f_form, f_count, f_wireints, f_symbols, f_sym, f_cell, f_padbits, f_mal }

local ef_empty    = ProtoExpert.new("facet.expert.empty",    "Empty Facet payload",
                                    expert.group.MALFORMED, expert.severity.ERROR)
local ef_dangling = ProtoExpert.new("facet.expert.dangling", "Dangling partial codeword (strict decode drops this frame)",
                                    expert.group.MALFORMED, expert.severity.ERROR)
local ef_noterm   = ProtoExpert.new("facet.expert.noterm",   "No codeword terminator in frame (strict decode drops this frame)",
                                    expert.group.MALFORMED, expert.severity.ERROR)
local ef_overflow = ProtoExpert.new("facet.expert.overflow", "Wire integer exceeds u16 cell range (kernel decode plane drops this frame)",
                                    expert.group.MALFORMED, expert.severity.WARN)
local ef_declen   = ProtoExpert.new("facet.expert.declen",   "Decoded form length mismatch",
                                    expert.group.MALFORMED, expert.severity.ERROR)
local ef_ambig    = ProtoExpert.new("facet.expert.ambiguous","Payload also parses as a raw Facet frame; dissected as decoded (capture wire side of the XDP hook to see raw)",
                                    expert.group.PROTOCOL, expert.severity.NOTE)

facet.experts = { ef_empty, ef_dangling, ef_noterm, ef_overflow, ef_declen, ef_ambig }

facet.prefs.port   = Pref.uint("UDP port", 4711, "UDP port carrying Facet datagrams")
facet.prefs.fields = Pref.string("Canonical field names", "",
    "Optional comma separated field names in canonical (sorted) order, used to label symbols. " ..
    "Labels are a viewing convenience only; real semantics live in the signed policy.")

-- Zeckendorf decode of one payload, strict contract (mirrors the kernel decode plane):
-- returns { ints = {..}, spans = {{firstbit,lastbit}..}, pad_bits, malformed, reason }
-- Bits are numbered from 0, MSB first within each byte, matching packed.pack(bits, 8).
local function strict_decode(tvb, len)
  local nbits = len * 8
  local bit_at = function(i)
    local b = tvb(math.floor(i / 8), 1):uint()
    local shift = 7 - (i % 8)
    return math.floor(b / (2 ^ shift)) % 2
  end
  local ints, spans = {}, {}
  local start = 0
  local i = 0
  local last_end = -1  -- bit index of the last terminator's second '1'
  while i < nbits - 1 do
    if bit_at(i) == 1 and bit_at(i + 1) == 1 then
      -- data bits are start .. i, terminator is i + 1
      local ndata = i - start + 1
      if ndata > 70 then
        return { ints = ints, spans = spans, pad_bits = 0, malformed = true, reason = "overflow" }
      end
      local fa, fb = 1, 2  -- F2, F3
      local v = 0
      for j = start, i do
        if bit_at(j) == 1 then v = v + fa end
        fa, fb = fb, fa + fb
      end
      ints[#ints + 1] = v
      spans[#spans + 1] = { start, i + 1 }
      last_end = i + 1
      i = i + 2
      start = i
    else
      i = i + 1
    end
  end
  -- tail: everything after the last terminator
  local pad = 0
  local dangling = false
  for j = last_end + 1, nbits - 1 do
    if bit_at(j) == 1 then dangling = true break end
    pad = pad + 1
  end
  if #ints == 0 then
    return { ints = ints, spans = spans, pad_bits = 0, malformed = true, reason = "noterm" }
  end
  if dangling then
    return { ints = ints, spans = spans, pad_bits = 0, malformed = true, reason = "dangling" }
  end
  for _, v in ipairs(ints) do
    if v > 65535 then
      return { ints = ints, spans = spans, pad_bits = pad, malformed = true, reason = "overflow" }
    end
  end
  return { ints = ints, spans = spans, pad_bits = pad, malformed = false, reason = "" }
end

local function split_fields(s)
  local out = {}
  for name in string.gmatch(s or "", "([^,]+)") do
    out[#out + 1] = (name:gsub("^%s+", ""):gsub("%s+$", ""))
  end
  return out
end

local function looks_decoded(tvb, len)
  return len >= 4 and tvb(0, 1):uint() == 0x46 and len == 2 + 2 * tvb(1, 1):uint()
      and tvb(1, 1):uint() > 0
end

function facet.dissector(tvb, pinfo, tree)
  local len = tvb:len()
  pinfo.cols.protocol = "FACET"
  local subtree = tree:add(facet, tvb(), "Facet Frame")
  local names = split_fields(facet.prefs.fields)

  if len == 0 then
    subtree:add(f_form, tvb(0, 0), "raw")
    subtree:add(f_mal, tvb(0, 0), 1):set_generated()
    subtree:add_proto_expert_info(ef_empty)
    pinfo.cols.info = "Facet raw: empty (malformed)"
    return
  end

  if looks_decoded(tvb, len) then
    local n = tvb(1, 1):uint()
    subtree:add(f_form, tvb(0, 1), "decoded")
    subtree:add(f_count, tvb(1, 1), n)
    local cells, syms = {}, {}
    for k = 0, n - 1 do
      local off = 2 + 2 * k
      local v = tvb(off, 2):le_uint()
      cells[#cells + 1] = tostring(v)
      syms[#syms + 1] = tostring(v - 1)
      local label = names[k + 1] and (names[k + 1] .. " ") or ""
      subtree:add(f_cell, tvb(off, 2), v)
             :append_text(string.format("  (%ssymbol %d)", label, v - 1))
    end
    subtree:add(f_wireints, tvb(2, len - 2), table.concat(cells, ",")):set_generated()
    subtree:add(f_symbols, tvb(2, len - 2), table.concat(syms, ",")):set_generated()
    subtree:add(f_mal, tvb(0, 0), 0):set_generated()
    -- ambiguity note: does the same payload also strict decode as raw?
    local raw = strict_decode(tvb, len)
    if not raw.malformed then
      subtree:add_proto_expert_info(ef_ambig)
    end
    pinfo.cols.info = string.format("Facet decoded: %d cells [%s]", n, table.concat(cells, ","))
    return
  end

  -- raw form
  local r = strict_decode(tvb, len)
  subtree:add(f_form, tvb(0, 0), "raw")
  subtree:add(f_count, tvb(0, 0), #r.ints):set_generated()
  local ints, syms = {}, {}
  for k, v in ipairs(r.ints) do
    ints[#ints + 1] = tostring(v)
    syms[#syms + 1] = tostring(v - 1)
    local b0 = math.floor(r.spans[k][1] / 8)
    local b1 = math.floor(r.spans[k][2] / 8)
    local label = names[k] and (names[k] .. " ") or ""
    subtree:add(f_sym, tvb(b0, b1 - b0 + 1),
                string.format("%swire %d, symbol %d (bits %d..%d)",
                              label, v, v - 1, r.spans[k][1], r.spans[k][2]))
  end
  if #r.ints > 0 then
    subtree:add(f_wireints, tvb(0, len), table.concat(ints, ",")):set_generated()
    subtree:add(f_symbols, tvb(0, len), table.concat(syms, ",")):set_generated()
  end
  subtree:add(f_padbits, tvb(0, 0), r.pad_bits):set_generated()
  subtree:add(f_mal, tvb(0, 0), r.malformed and 1 or 0):set_generated()
  if r.malformed then
    if r.reason == "noterm" then subtree:add_proto_expert_info(ef_noterm)
    elseif r.reason == "dangling" then subtree:add_proto_expert_info(ef_dangling)
    elseif r.reason == "overflow" then subtree:add_proto_expert_info(ef_overflow)
    end
    pinfo.cols.info = string.format("Facet raw: malformed (%s)", r.reason)
  else
    pinfo.cols.info = string.format("Facet raw: %d symbols [%s]", #r.ints, table.concat(ints, ","))
  end
end

local current_port = 4711
local udp_table = DissectorTable.get("udp.port")
udp_table:add(current_port, facet)

function facet.prefs_changed()
  if facet.prefs.port ~= current_port then
    udp_table:remove(current_port, facet)
    current_port = facet.prefs.port
    if current_port > 0 then udp_table:add(current_port, facet) end
  end
end
