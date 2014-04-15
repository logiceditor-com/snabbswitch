module(...,package.seeall)

-- http://tools.ietf.org/html/draft-mkonstan-keyed-ipv6-tunnel-01

-- TODO: generalize
local AF_INET6 = 10

local ffi = require("ffi")
local bit = require("bit")

local app = require("core.app")
local link = require("core.link")
local lib = require("core.lib")
local packet = require("core.packet")
local buffer = require("core.buffer")
local config = require("core.config")

local pcap = require("apps.pcap.pcap")
local basic_apps = require("apps.basic.basic_apps")

local header_struct_ctype = ffi.typeof[[
struct {
   // ethernet
   char dmac[6];
   char smac[6];
   uint16_t ethertype;
   // ipv6
   uint32_t flow_id; // version, tc, flow_id
   int16_t payload_length;
   int8_t  next_header;
   uint8_t hop_limit;
   char src_ip[16];
   char dst_ip[16];
   // tunnel
   uint32_t session_id;
   char cookie[8];
} __attribute__((packed))
]]

local HEADER_SIZE = ffi.sizeof(header_struct_ctype)
-- should be in sync with previous line
local header_array_ctype = ffi.typeof("uint8_t[?]")
local cookie_ctype = ffi.typeof("uint64_t[1]")
local address_ctype = ffi.typeof("uint64_t[2]")
local paddress_ctype = ffi.typeof("uint64_t*")

local SRC_IP_OFFSET = ffi.offsetof(header_struct_ctype, 'src_ip')
local DST_IP_OFFSET = ffi.offsetof(header_struct_ctype, 'dst_ip')
local COOKIE_IP_OFFSET = ffi.offsetof(header_struct_ctype, 'cookie')

local header_prototype = header_array_ctype(HEADER_SIZE)

local function prepare_header_template ()
   -- set const fields
   local offset = ffi.offsetof(header_struct_ctype, 'ethertype')
   header_prototype[offset] = 0x86
   header_prototype[offset + 1] = 0xDD

   offset = ffi.offsetof(header_struct_ctype, 'ethertype')
   -- first 4 bits - version
   header_prototype[offset] = 0x60

   offset = ffi.offsetof(header_struct_ctype, 'next_header')
   header_prototype[19] = 0x73
   
   offset = ffi.offsetof(header_struct_ctype, 'session_id')
   header_prototype[offset] = 0xFF
   header_prototype[offset + 1] = 0xFF
   header_prototype[offset + 2] = 0xFF
   header_prototype[offset + 3] = 0xFF
end

SimpleKeyedTunnel = {}

function SimpleKeyedTunnel:new (confstring)
   local config = confstring and loadstring("return " .. confstring)() or {}
   -- required fields:
   -- local_address, string, ipv6 address 
   -- remote_address, string, ipv6 address
   -- local_cookie, 8 bytes string 
   -- remote_cookie, 8 bytes string
   assert(
         type(config.local_cookie) == "string"
         and #config.local_cookie == 8,
         "local_cookie should be 8 bytes string"
      )
   assert(
         type(config.remote_cookie) == "string"
         and #config.remote_cookie == 8,
         "remote_cookie should be 8 bytes string"
      )
   local header = header_array_ctype(HEADER_SIZE)
   ffi.copy(header, header_prototype, HEADER_SIZE)
   ffi.copy(
         header + COOKIE_IP_OFFSET,
         config.local_cookie,
         #config.local_cookie
      )

   -- convert dest, sorce ipv6 addressed to network order binary
   local result =
      ffi.C.inet_pton(AF_INET6, config.local_address, header + SRC_IP_OFFSET)
   assert(result == 1,"malformed IPv6 address: " .. config.local_address)
   result =
      ffi.C.inet_pton(AF_INET6, config.remote_address, header + DST_IP_OFFSET)
   assert(result == 1,"malformed IPv6 address: " .. config.remote_address)
   -- store casted pointers for fast matching
   local remote_address = ffi.cast(paddress_ctype, header + DST_IP_OFFSET)
   local local_address = ffi.cast(paddress_ctype, header + SRC_IP_OFFSET)

   local remote_cookie = cookie_ctype()
   ffi.copy(remote_cookie, config.remote_cookie, #config.remote_cookie)
 
   local o =
   {
      header = header,
      remote_address = remote_address,
      local_address = local_address,
      remote_cookie = remote_cookie
   }
   return setmetatable(o, {__index = SimpleKeyedTunnel})
end

function SimpleKeyedTunnel:push()
   local l_in = self.input.decapsulated
   local l_out = self.output.encapsulated
   assert(l_in and l_out)
   while not link.empty(l_in) and not link.full(l_out) do
      locap p = packet.want_change(link.receive(l_in))
      local new_b = buffer.allocate()
      ffi.copy(new_b.pointer, self.header, HEADER_SIZE)
      -- TODO: set payload size
      packet.insert_iovec(p, new_b, HEADER_SIZE)
      link.transmit(l_out, p)
   end

   l_in = self.input.encapsulated
   l_out = self.output.decapsulated
   assert(l_in and l_out)
   while not link.empty(l_in) and not link.full(l_out) do
      locap p = packet.want_change(link.receive(l_in))
      -- TODO: where tunnel header is? in which iovec?
      -- usually it will be in first one, should we support others use case?
   end
end
prepare_header_template ()

function selftest ()
   buffer.preallocate(10000)
   local c = config.new()

   print("1")
   config.app(
         c,
      "tunnel",
      SimpleKeyedTunnel,
      [[{
      local_address = "00::01",
      remote_address = "00::02",
      local_cookie = "12345678",
      remote_cookie = "12345678"
      }
      ]]
   )
   app.configure(c)
   print("2")
end


