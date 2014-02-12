module(...,package.seeall)

local ffi = require("ffi")

-- some utilities function to manipulate IP and CIDR

convert_ipv4_binary = function(ip)
   local octet1, octet2, octet3, octet4 = 
      string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
   if not (octet1 and octet2 and octet3 and octet4) then
      return nil, "malformed IPv4"
   end
   octet1 = tonumber(octet1)
   octet2 = tonumber(octet2)
   octet3 = tonumber(octet3)
   octet4 = tonumber(octet4)
   if octet1 > 255 and
      octet2 > 255 and
      octet3 > 255 and
      octet4 > 255
   then
      return nil, "malformed IPv4"
   end
   local ip_binary = ffi.new("uint32_t[1]")
   local p = ffi.new("uint8_t*", ffi.cast("uint8_t*", ip_binary))
   p[0] = octet1
   p[1] = octet2
   p[2] = octet3
   p[3] = octet4
   return ip_binary[0]
end

local masks_dotted = {}
masks_dotted[1] = "255.255.255.254" 
masks_dotted[2] = "255.255.255.252"
masks_dotted[3] = "255.255.255.248"
masks_dotted[4] = "255.255.255.240"
masks_dotted[5] = "255.255.255.224"
masks_dotted[6] = "255.255.255.192"
masks_dotted[7] = "255.255.255.128"
masks_dotted[8] = "255.255.255.000"
masks_dotted[9] = "255.255.254.000"
masks_dotted[10] = "255.255.252.000"
masks_dotted[11] = "255.255.248.000"
masks_dotted[12] = "255.255.240.000"
masks_dotted[13] = "255.255.224.000"
masks_dotted[14] = "255.255.192.000"
masks_dotted[15] = "255.255.128.000"
masks_dotted[16] = "255.255.000.000"
masks_dotted[17] = "255.254.000.000"
masks_dotted[18] = "255.252.000.000"
masks_dotted[19] = "255.248.000.000"
masks_dotted[20] = "255.240.000.000"
masks_dotted[21] = "255.224.000.000"
masks_dotted[22] = "255.192.000.000"
masks_dotted[23] = "255.128.000.000"
masks_dotted[24] = "255.000.000.000"
masks_dotted[25] = "254.000.000.000"
masks_dotted[26] = "252.000.000.000"
masks_dotted[27] = "248.000.000.000"
masks_dotted[28] = "240.000.000.000"
masks_dotted[29] = "224.000.000.000"
masks_dotted[30] = "192.000.000.000"
masks_dotted[31] = "128.000.000.000"

local masks_binary = {}
for i =1, #masks_dotted do
   masks_binary[#masks_binary + 1] = convert_ipv4_binary(masks_dotted[i])
end

-- IP prefix data structure, Lua table
-- array part - uint32_t values to match exactly, mandatory if mask/prefix are missed
-- mask - last byte mask, mandatory if array part is empty
-- prefix - last byte prefix, mandatory if array part is empty
-- for IPv4 only one component may be present
-- for IPv6 every alone and both allowed
-- all values in network order
-- empty table means - any address
function parse_cidr_ipv4 (cidr)
   local ip, prefix_size = 
      string.match(cidr, "^(.+)/(%d+)$")
   if not ( ip and prefix_size ) then
      print(ip, prefix_size)
      return nil, "malformed IPv4 CIDR: " .. cidr
   end
   prefix_size = tonumber(prefix_size)
   if prefix_size > 32 then
      return nil, "malformed IPv4 CIDR: " .. cidr
   end
   if prefix_size == 0 then
      return {} -- any IP
   end
   local ip_binary, err = convert_ipv4_binary(ip)
   if prefix_size == 32 then
      return { ip_binary } -- single uint32_t match
   end
   if not ip_binary then
      return nil, err
   end
   return { mask = masks_binary[prefix_size], prefix = ip_binary }
end

function parse_cidr_ipv6 (cidr)
   local ip, prefix_size = 
      string.match(cidr, "^(.)/(%d+)$")
   if not ( ip and prefix_size ) then
      return nil, "malformed IPv6 CIDR"
   end
   prefix_size = tonumber(prefix_size)
   if prefix_size > 128 then
      return nil, "malformed IPv4 CIDR"
   end
   if prefix_size == 0 then
      return {} -- any IP
   end
   assert(false, "parse_cidr_ipv6 is not implemented")
end

