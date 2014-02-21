module(...,package.seeall)

local ffi = require("ffi")
local bit = require("bit")
local ip = require("apps.packet_filter.ip")

PacketFilter = {}

function isBigEndian ()
   local x = ffi.new("uint16_t[1]", 1)
   local p = ffi.cast("uint8_t*", x)
   if p[0] == 1 then
      return true
   end
   return false
end

assert(isBigEndian(), "little-endian platform not supported")
-- in network order already
ETHERTYPE_IPV6 = "0xDD86"
ETHERTYPE_IPV4 = "0x0080"

local IP_UDP = 17
local IP_TCP = 6
local IP_ICMP = 1

local ETHERTYPE_OFFSET = 12

local IPV4_SOURCE_OFFSET = 26
local IPV4_DEST_OFFSET = 30
local IPV4_PROTOCOL_OFFSET = 24
local IPV4_SOURCE_PORT_OFFSET = 34
local IPV4_DEST_PORT_OFFSET = 36

local IPV6_SOURCE_OFFSET = 22
local IPV6_DEST_OFFSET = 38
local IPV6_NEXT_HEADER_OFFSET = 20 -- protocol
local IPV6_SOURCE_PORT_OFFSET = 54
local IPV6_DEST_PORT_OFFSET = 56

-- from https://github.com/lua-nucleo/lua-nucleo
-- MIT licensed
local make_concatter = function()
 local buf = { }

 local function cat(v)
   buf[#buf + 1] = v
   return cat
 end

 local concat = function()
   return table.concat(buf, "\n")
 end

 return cat, concat
end

-- used for source/destination adresses matching
local function generateIpv4CidrMatch(t, cidr, offset)
   local ok, prefix, mask = assert(ip.parse_cidr_ipv4(cidr))

   if not prefix then
      -- any address
      return
   end

   prefix = string.format("%x", prefix)
   t("   local p = ffi.cast(\"uint32_t*\", buffer + " .. offset .. ")")
   if mask then
      t("   local result = bit.bor(bit.band(" .. mask .. ", p[0]), 0x" .. prefix .. ")")
      t"   if result == 0 then break end"
   else
      -- single IP address
      t("   if p[0] ~= 0x" .. prefix .. " then break end")
   end
end

-- used for source/destination adresses matching
local function generateIpv6CidrMatch(t, cidr, offset)
   local ok, prefix1, prefix2, mask = assert(ip.parse_cidr_ipv6(cidr))

   if not prefix1 then
      -- any address
      return
   end

   t("   local p = ffi.cast(\"uint64_t*\", buffer + " .. offset .. ")")

   if not prefix2 and mask then
      t("   local result = bit.bor(bit.band(0x" .. bit.tohex(mask) ..
        "ULL, p[0]), 0x" .. bit.tohex(prefix1) .. "ULL)")
      t"   if result == 0 then break end"
      return
   end

   t("   if p[0] ~= 0x" .. bit.tohex(prefix1) .. "ULL  then break end")
   if not prefix2 and not mask then
      return
   end

   if prefix2 and not mask then
      t("   if p[1] ~= 0x" .. bit.tohex(prefix2) .. "ULL  then break end")
      return
   end

   -- prefix1 and prefix2 and mask
   t("   local result = bit.bor(bit.band(0x" .. bit.tohex(mask) ..
     "ULL, p[0]), 0x" .. bit.tohex(prefix1) .. "ULL)")
   t"   if result == 0 then break end"
end

local function generateProtocolMatch(t, protocol, offset)
   t("   local protocol = buffer[" .. offset .. "]")
   t("   if protocol ~= " .. protocol .. " then break end")
end

-- used for source/destination port matching
local function generatePortMatch(t, offset, port_min, port_max)
   if port_min == port_max then
      -- specialization for single port matching
      -- avoid conversion to host order on runtime
      local port_network_order =
         bit.lshift(bit.band(port_min, 0xff), 8) + bit.rshift(port_min, 8)
      -- TODO: generalize htons()

      t("   local p = ffi.cast(\"uint16_t*\", buffer + " .. offset .. ")")
      t("   if p[0] ~= " .. port_network_order .. " then break end")
   end
   t("   local offset = " .. offset)
   t("   local port = buffer[offset] * 0xFFFF + buffer[offset + 1]")
   t("   if port < " .. port_min .. " or port > " .. port_max .. " then break end")
end

local function generateRule(
      t,
      rule,
      generateIpMatch,
      source_ip_offset,
      dest_ip_offset,
      protocol_offset,
      source_port_offset,
      dest_port_offset
   )
   t"repeat"

   assert(rule.ethertype)
   t("   local p = ffi.cast(\"uint16_t*\", buffer + " .. ETHERTYPE_OFFSET .. ")")
   local ethertype
   if rule.ethertype == "ipv4" then
      ethertype = ETHERTYPE_IPV4
   elseif rule.ethertype == "ipv6" then
      ethertype = ETHERTYPE_IPV6
   else
      error("unknown ethertype")
   end
   t("   if p[0] ~= " .. ethertype .. " then break end")
   
   if rule.source_cidr then
      generateIpMatch(t, rule.source_cidr, source_ip_offset)
   end
   if rule.destination_cidr then
      generateIpMatch(t, rule.destination_cidr, dest_ip_offset)
   end
   if rule.protocol then
      if rule.protocol == "tcp" then
         generateProtocolMatch(t, IP_TCP, protocol_offset)
      elseif rule.protocol == "udp" then
         generateProtocolMatch(t, IP_UDP, protocol_offset)
      elseif rule.protocol == "icmp" then
         generateProtocolMatch(t, IP_ICMP, protocol_offset)
      else
         error("unknown protocol")
      end
      if rule.protocol == "tcp" or rule.protocol == "udp" then
         if rule.source_port_min then
            if not rule.source_port_max then
               rule.source_port_max = rule.source_port_min
            end
            generatePortMatch(
                  t,
                  source_port_offset,
                  rule.source_port_min,
                  rule.source_port_max
               )
         end
         if rule.dest_port_min then
            if not rule.dest_port_max then
               rule.dest_port_max = rule.dest_port_min
            end
            generatePortMatch(
                  t,
                  dest_port_offset,
                  rule.dest_port_min,
                  rule.dest_port_max
               )
         end
      end
   end
   t"   return true"
   t"until false"
end

local function generateConformFunctionString(rules)
   local t, concatter = make_concatter()
   t"local ffi = require(\"ffi\")"
   t"local bit = require(\"bit\")"
   t"return function(buffer, size)"

   for i = 1, #rules do
      if rules[i].ethertype == "ipv4" then
         generateRule(
               t,
               rules[i],
               generateIpv4CidrMatch,
               IPV4_SOURCE_OFFSET,
               IPV4_DEST_OFFSET,
               IPV4_PROTOCOL_OFFSET,
               IPV4_SOURCE_PORT_OFFSET,
               IPV4_DEST_PORT_OFFSET
            )

      elseif rules[i].ethertype == "ipv6" then
         generateRule(
               t,
               rules[i],
               generateIpv6CidrMatch,
               IPV6_SOURCE_OFFSET,
               IPV6_DEST_OFFSET,
               IPV6_NEXT_HEADER_OFFSET,
               IPV6_SOURCE_PORT_OFFSET,
               IPV6_DEST_PORT_OFFSET
            )
      else
         error("unknown ethertype")
      end
   end
   t"return false"
   t"end"
   return concatter()
end

function PacketFilter:new (rules)
   assert(rules)
   assert(#rules > 0)
   
   local o =
   {
      tokens_on_tick = rate / TICKS_PER_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity,
      conform = assert(loadstring(generateConformFunctionString(rules)))
    }
   return setmetatable(o, {__index = PacketFilter})
end

function PacketFilter:push ()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   local packets_tx = 0
   local max_packets_to_send = app.nwritable(o)
   if max_packets_to_send == 0 then
      return
   end

   local nreadable = app.nreadable(i)
   for n = 1, nreadable do
      local p = app.receive(i)
      -- test min allowed packet size, drop or fire error?
      -- all headers should be within first buffer

      if self.conform(p) then 
         app.transmit(o, p)
      else
         -- discard packet
         packet.deref(p)
      end
   end
end

function selftest1 ()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6 = ffi.new("uint16_t", 0xDD86)
   local p = ffi.cast("uint16_t*", buffer + ETHERTYPE_OFFSET)
   p[0] = ETHERTYPE_IPV6
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 100 do
      for i = 1, 1e8 do
         local p = ffi.cast("uint16_t*", buffer + i)
         if p[0] == ETHERTYPE_IPV6 then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest1_1 ()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6 = ffi.new("uint16_t", 0xDD86)
   local p = ffi.cast("uint16_t*", buffer + ETHERTYPE_OFFSET)
   p[0] = ETHERTYPE_IPV6
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 100 do
      for i = 1, 1e8 do
         local p = ffi.cast("uint16_t*", buffer + i)
         if p[0] == 0xDD86 then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest2 ()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6_BYTE1 = ffi.new("uint16_t", 0x86)
   local ETHERTYPE_IPV6_BYTE2 = ffi.new("uint16_t", 0xDD)
   buffer[ETHERTYPE_OFFSET] = ETHERTYPE_IPV6_BYTE1
   buffer[ETHERTYPE_OFFSET + 1] = ETHERTYPE_IPV6_BYTE2
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 100 do
      for i = 1, 1e8 do
         if buffer[i] == ETHERTYPE_IPV6_BYTE1 and buffer[i+1] == ETHERTYPE_IPV6_BYTE2 then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest2_2 ()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6_BYTE1 = ffi.new("uint16_t", 0x86)
   local ETHERTYPE_IPV6_BYTE2 = ffi.new("uint16_t", 0xDD)
   buffer[ETHERTYPE_OFFSET] = ETHERTYPE_IPV6_BYTE1
   buffer[ETHERTYPE_OFFSET + 1] = ETHERTYPE_IPV6_BYTE2
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 100 do
      for i = 1, 1e8 do
         if buffer[i] == 0x86 and buffer[i+1] == 0xDD then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest3 ()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6 = ffi.new("uint16_t", 0xDD86)
   local p = ffi.cast("uint16_t*", buffer + ETHERTYPE_OFFSET)
   p[0] = ETHERTYPE_IPV6
   p = ffi.cast("uint16_t*", buffer)
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 200 do
      for i = 1, 1e8/2 do
         if p[i] == ETHERTYPE_IPV6 then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest5()
   local buffer = ffi.new("uint8_t[100000000]")
   local ETHERTYPE_IPV6 = ffi.new("uint16_t", 0xDD86)
   local p = ffi.cast("uint16_t*", buffer + ETHERTYPE_OFFSET)
   p[0] = ETHERTYPE_IPV6
   local counter = 0
   require("jit.p").start('vl4')
   for k = 1, 100 do
      for i = 1, 1e8 do
         local p = ffi.cast("uint32_t*", buffer + i)
         local result = bit.bor(bit.band(0xFFFF0000, p[0]), 0x12340000)
         if result == 0 then
            counter = counter + 1
         end
      end
   end
   require("jit.p").stop()
   print(counter)
end

function selftest()
   local fstring = generateConformFunctionString
   {
      {
         ethertype = "ipv6",
         source_cidr = "ffff:0:ffff:0:0:0:0:8/34",
         protocol = "tcp",
         dest_port_min = 80,
         dest_port_max = 81,
      },
      {
         ethertype = "ipv6",
         source_cidr = "ffff:0:ffff:0:0:0:0:8/64",
         protocol = "udp",
         dest_port_min = 80,
         dest_port_max = 80,
      },
      {
         ethertype = "ipv6",
         source_cidr = "ffff:0:ffff:0:ffff:0:0:8/100",
      },
      {
         ethertype = "ipv6",
         source_cidr = "ffff:0:ffff:0:ffff:0:0:8/128",
      },
      {
         ethertype = "ipv4",
         source_cidr = "1.2.3.4/10",
      },
      {
         ethertype = "ipv4",
         source_cidr = "1.2.3.4/32",
      }
   }
   print(fstring)
   local chunk = loadstring(fstring)
   local conform = assert(chunk())

   local ok, prefix, mask = ip.parse_cidr_ipv4("1.2.3.4/12")
   print(prefix, mask)
   print(bit.tohex(prefix), bit.tohex(mask))

   local ok, p1, p2, mask = ip.parse_cidr_ipv6("0:0:0:0:0:0:0:0/12")
   print(tostring(p1), tostring(p2), tostring(mask))
   print(bit.tohex(p1), bit.tohex(mask))
   
-- local binary = ip.parse_cidr_ipv6("1:0:0:0:0:0:0:8/34")
-- local binary = ip.parse_cidr_ipv6("1::8/120")


end
