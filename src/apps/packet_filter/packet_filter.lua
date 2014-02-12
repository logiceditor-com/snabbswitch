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
ETHERTYPE_IPV6 = 0xDD86
ETHERTYPE_IPV4 = 0x0080

local IPV4_UDP = 17
local IPV4_TCP = 6
local IPV4_ICMP = 1

local ETHERTYPE_OFFSET = 12

local IPV4_SOURCE_OFFSET = 26
local IPV4_DESTINATION_OFFSET = 30
local IPV4_PROTOCOL_OFFSET = 24
local IPV4_SOURCE_PORT_OFFSET = 0 -- TODO
local IPV4_DESTINATION_PORT_OFFSET = 0 -- TODO

local IPV6_SOURCE_OFFSET = 22
local IPV6_DEST_OFFSET = 38
local IPV6_NEXT_HEADER_OFFSET = 20 -- protocol
local IPV6_SOURCE_PORT_OFFSET = 0 -- TODO
local IPV6_DEST_PORT_OFFSET = 0 -- TODO

-- UDP/TCP ports - 16 bits value

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

-- depends from offset used for source/destination adresses matching
local function generateIpv4CidrMatch(t, cidr, offset)
   local binary = assert(ip.parse_cidr_ipv4(cidr))

   if #binary == 0 and not binary.mask then
      -- any address
      return
   end

   t("   local p = ffi.cast(\"uint32_t*\", buffer + " .. offset .. ")")
   if not binary.mask then
      -- single IP address
      t("   if p[0] == " .. binary[1] .. "then break end")
   else
      t("   local result = bit.bor(bit.band(" .. binary.mask .. ", p[0]), " .. binary.prefix .. ")")
      t"   if result == 0 then break end"
   end
end

local function generateIpv4ProtocolMatch(t, protocol)
   t("   local protocol = buffer[" .. IPV4_PROTOCOL_OFFSET .. "]")
   t("   if protocol ~= " .. protocol .. " then break end")
end

local function generateIpv4PortMatch(t, offset, port_min, port_max)
   t("   local offset = " .. offset)
   t("   local port = buffer[offset] * 0xFFFF + buffer[offset + 1]")
   t("   if port < " .. port_min .. " or port > " .. port_max .. " then break end")
end

local function generateIpv4Rule(t, rule)
   t"repeat"
   if rule.source_cidr then
      generateIpv4CidrMatch(t, rule.source_cidr, IPV4_SOURCE_OFFSET)
   end
   if rule.destination_cidr then
      generateIpv4Cidr(t, rule.destination_cidr, IPV4_DEST_OFFSET)
   end
   if rule.protocol then
      if rule.protocol == "tcp" then
         generateIpv4ProtocolMatch(t, IPV4_TCP)
      elseif rule.protocol == "udp" then
         generateIpv4ProtocolMatch(t, IPV4_UDP)
      elseif rule.protocol == "icmp" then
         generateIpv4ProtocolMatch(t, IPV4_ICMP)
      else
         error("unknown protocol")
      end
      if rule.protocol == "tcp" or rule.protocol == "udp" then
         if rule.source_port_min then
            if not rule.source_port_max then
               rule.source_port_max = rule.source_port_min
            end
            generateIpv4PortMatch(
                  t,
                  IPV4_SOURCE_PORT_OFFSET,
                  rule.source_port_min,
                  rule.source_port_max
               )
         end
         if rule.dest_port_min then
            if not rule.dest_port_max then
               rule.dest_port_max = rule.dest_port_min
            end
            generateIpv4PortMatch(
                  t,
                  IPV6_DEST_PORT_OFFSET,
                  rule.dest_port_min,
                  rule.dest_port_max
               )
         end
      end
   end
   t"   return true"
   t"until false"
end

local function generateIpv6Rule(rule)
end

local function generateConformFunctionString(rules)
   local t, concatter = make_concatter()
   t"local ffi = require(\"ffi\")"
   t"local bit = require(\"bit\")"
   t"return function(buffer, size)"

   for i = 1, #rules do
      if rules[i].ethertype == "ipv4" then
         generateIpv4Rule(t, rules[i])

      elseif rules[i].ethertype == "ipv6" then
         generateIpv6Rule(t, rules[i])

      else
         error("unknown ethertype")
      end
   end
   t"return false"
   t"end"
   return concatter()
end

function getEtherType(buffer, offset)
   local p = ffi.cast("uint16_t*", buffer + offset + ETHERTYPE_OFFSET)
   return p[0] == ETHERTYPE_IPV6
end

function matchSourceIPv4(buffer, offset, prefix, mask)
   local p = ffi.cast("uint32_t*", buffer + offset + IPV4_SOURCE_OFFSET)
   local result = bit.bor(bit.band(mask, p[0]), prefix)
   if result == 0 then
      return false
   end
   return true
end

function PacketFilter:new (rules)
   assert(rules)
   assert(#rules > 0)
   
   local o =
   {
      tokens_on_tick = rate / TICKS_PER_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity
    }
   return setmetatable(o, {__index=RateLimiter})
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

function PacketFilter:process (packet)
   
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
         ethertype = "ipv4",
         source_cidr = "12.23.34.45/12",
         protocol = "tcp",
         dest_port_min = 80,
         dest_port_max = 81,
      },
      {
         ethertype = "ipv4",
         protocol = "udp",
      }
   }
   print(fstring)
   local chunk = loadstring(fstring)
   local conform = assert(chunk())
end
