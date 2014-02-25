module(...,package.seeall)

local ffi = require("ffi")
local bit = require("bit")
local app = require("core.app")
local basic_apps = require("apps.basic.basic_apps")
local lib = require("core.lib")
local packet = require("core.packet")
local buffer = require("core.buffer")
local pcap = require("apps.pcap.pcap")

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

local IP_UDP = 0x11
local IP_TCP = 6
local IP_ICMP = 1
local IPV6_ICMP = 0x3a

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

function parse_cidr_ipv4 (cidr)
   local address, prefix_size =  string.match(cidr, "^(.+)/(%d+)$")

   if not ( address and prefix_size ) then
      return false, "malformed IPv4 CIDR: " .. cidr
   end
   prefix_size = tonumber(prefix_size)
   if prefix_size > 32 then
      return false, "IPv6 CIDR mask is too big: " .. prefix_size
   end
   if prefix_size == 0 then
      return true -- any IP
   end

   local in_addr  = ffi.new("int32_t[1]")
   local AF_INET = 2 -- TODO: generalize
   local result = ffi.C.inet_pton(AF_INET, address, in_addr)
   if result ~= 1 then
      return false, "malformed IPv4 address: " .. address
   end

   if prefix_size == 32 then
      -- single IP address
      return true, in_addr[0]
   end

   local mask = bit.bswap(bit.lshift(bit.tobit(0xffffffff), prefix_size))
   return true, bit.band(in_addr[0], mask), mask
end

function parse_cidr_ipv6 (cidr)
   local address, prefix_size = string.match(cidr, "^(.+)/(%d+)$")

   if not ( address and prefix_size ) then
      return false, "malformed IPv6 CIDR: " .. cidr
   end

   prefix_size = tonumber(prefix_size)

   if prefix_size > 128 then
      return false, "IPv6 CIDR mask is too big: " .. prefix_size
   end
   if prefix_size == 0 then
      return true -- any IP
   end

   local in6_addr  = ffi.new("uint64_t[2]")
   local AF_INET6 = 10 -- TODO: generalize
   local result = ffi.C.inet_pton(AF_INET6, address, in6_addr)
   if result ~= 1 then
      return false, "malformed IPv6 address: " .. address
   end

   if prefix_size < 64 then
      local mask =
         bit.bswap(bit.bnot(bit.rshift(bit.bnot(0ULL), prefix_size)))
      return true, bit.band(in6_addr[0], mask), nil, mask
   end
   if prefix_size == 64 then
      return true, in6_addr[0]
   end
   if prefix_size < 128 then
      local mask =
         bit.bswap(bit.bnot(bit.rshift(bit.bnot(0ULL), prefix_size - 64)))
      return true, in6_addr[0], bit.band(in6_addr[1], mask), mask
   end
   -- prefix_size == 128
   return true, in6_addr[0], in6_addr[1]
end

-- used for source/destination adresses matching
local function generateIpv4CidrMatch(t, cidr, offset)
   local ok, prefix, mask = assert(parse_cidr_ipv4(cidr))

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

local function generateIpv6CidrMatch(t, cidr, offset)
   local ok, prefix1, prefix2, mask = assert(parse_cidr_ipv6(cidr))

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
   t("print('1', bit.tohex(p[1]))")
   t("   local masked = bit.band(0x" .. bit.tohex(mask) .. "ULL, p[1])")
   t("print('2', bit.tohex(p[1]))")
   t("   if 0x" .. bit.tohex(prefix2) .. "ULL ~= bit.band(0x" .. bit.tohex(mask) .. "ULL, p[1]) then break end")
   t("print('3', bit.tohex(p[1]))")
   --t("   if 0x" .. bit.tohex(prefix2) .. "ULL ~= masked then break end")
end

local function generateProtocolMatch(t, protocol, offset)
   t("   local protocol = buffer[" .. offset .. "]")
   t("   if protocol ~= " .. protocol .. " then break end")
end

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
      icmp_type,
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
   if rule.dest_cidr then
      generateIpMatch(t, rule.dest_cidr, dest_ip_offset)
   end
   if rule.protocol then
      if rule.protocol == "tcp" then
         generateProtocolMatch(t, IP_TCP, protocol_offset)
      elseif rule.protocol == "udp" then
         generateProtocolMatch(t, IP_UDP, protocol_offset)
      elseif rule.protocol == "icmp" then
         generateProtocolMatch(t, icmp_type, protocol_offset)
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
               IP_ICMP,
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
               IPV6_ICMP,
               IPV6_SOURCE_PORT_OFFSET,
               IPV6_DEST_PORT_OFFSET
            )
      else
         error("unknown ethertype")
      end
   end
   t"return false"
   t"end"
   local ret = concatter()
   print(ret)
   return ret
end

function PacketFilter:new (rules)
   assert(rules)
   assert(#rules > 0)
   
   local o =
   {
      conform = assert(loadstring(
            generateConformFunctionString(rules)
         ))()
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
      -- support only one iovec

      if self.conform(
            p.iovecs[0].buffer.pointer + p.iovecs[0].offset,
            p.iovecs[0].length
         )
      then 
         app.transmit(o, p)
      else
         -- discard packet
         packet.deref(p)
      end
   end
end

function selftest1()
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

   local ok, prefix, mask = parse_cidr_ipv4("1.2.3.4/12")
   print(prefix, mask)
   print(bit.tohex(prefix), bit.tohex(mask))

   local ok, p1, p2, mask = parse_cidr_ipv6("0:0:0:0:0:0:0:0/12")
   print(tostring(p1), tostring(p2), tostring(mask))
   print(bit.tohex(p1), bit.tohex(mask))
end

local rule_udp = 
{
   ethertype = "ipv6",
   protocol = "udp"
}

local rule_tcp = 
{
   ethertype = "ipv6",
   protocol = "tcp"
}

local rule_icmp = 
{
   ethertype = "ipv6",
   protocol = "icmp",
   source_cidr = "3ffe:501:0:1001::2/128", -- single IP
   dest_cidr = "3ffe:507:0:1:200:86ff:fe05:8000/116",
}
-- Src: 3ffe:501:0:1001::2, Dst: 3ffe:507:0:1:200:86ff:fe05:80da


function selftest ()
   local test_mask = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:f000"
   local in6_addr  = ffi.new("uint64_t[2]")
   local AF_INET6 = 10 -- TODO: generalize
   local result = ffi.C.inet_pton(AF_INET6, test_mask, in6_addr)
   if result ~= 1 then
      print("malformed IPv6 address")
      return
   end
   print(bit.tohex(in6_addr[0]), bit.tohex(in6_addr[1]))

   app.apps.source1 = app.new(pcap.PcapReader:new("src/apps/packet_filter/v6.pcap"))
   app.apps.packet_filter1   = app.new(PacketFilter:new({rule_icmp}))
   app.apps.sink1   = app.new(basic_apps.Sink:new())
   app.connect("source1", "output", "packet_filter1", "input")
   app.connect("packet_filter1", "output", "sink1", "input")
   app.relink()
   app.breathe() -- v6.pcap contains 161 packets, one breathe is enough
   app.report()

   app.apps.source2 = app.new(pcap.PcapReader:new("src/apps/packet_filter/v6.pcap"))
   app.apps.packet_filter2   = app.new(PacketFilter:new({rule_tcp}))
   app.apps.sink2   = app.new(basic_apps.Sink:new())
   app.connect("source2", "output", "packet_filter2", "input")
   app.connect("packet_filter2", "output", "sink2", "input")
   app.relink()
   app.breathe() -- v6.pcap contains 161 packets, one breathe is enough
   app.report()
end
