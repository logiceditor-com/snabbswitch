module(...,package.seeall)

local ffi = require("ffi")

function parse_cidr_ipv4 (cidr)
   local address, prefix_size = 
      string.match(cidr, "^(.+)/(%d+)$")

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

   local mask = bit.lshift(bit.tobit(0xffffffff), prefix_size)
   return true, bit.band(in_addr[0], mask), mask
end

function parse_cidr_ipv6 (cidr)
   local address, prefix_size = 
      string.match(cidr, "^(.+)/(%d+)$")

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
      local mask = bit.bnot(bit.rshift(bit.bnot(0ULL), prefix_size))
      return true, bit.band(in6_addr[0], mask), nil, mask
   end
   if prefix_size == 64 then
      return true, in6_addr[0]
   end
   if prefix_size < 128 then
      local mask = bit.bnot(bit.rshift(bit.bnot(0ULL), prefix_size - 64))
      return true, in6_addr[0], bit.band(in6_addr[0], mask), mask
   end
   -- prefix_size == 128
   return true, in6_addr[0], in6_addr[1]
end

