module(...,package.seeall)

local ffi = require("ffi")

local app    = require("core.app")
local config = require("core.config")
local link   = require("core.link")
local buffer = require("core.buffer")
local packet = require("core.packet")
local lib    = require("core.lib")

local basic_apps = require("apps.basic.basic_apps")
local raw_socket = require("apps.socket.raw")
local tunnel = require("apps.keyed_ipv6_tunnel.tunnel")

local ns_responder = require("apps.ipv6.ns_responder")
local ipv6 = require("lib.protocol.ipv6")
local ethernet = require("lib.protocol.ethernet")
local ipv6_endpoint = require("apps.ipv6.ipv6_")

local function get_mac_address (ifname)
   local pipe = io.popen("cat /sys/class/net/" .. ifname .. "/address", "r")
   local mac = pipe:read("*l")
   print(ifname, mac)
   return mac
end

-- helper for SimpleIPv6
local function get_mac_string (mac)
   local bytes = {}
   local i = 1;
   for b in mac:gmatch('[0-9a-fA-F][0-9a-fA-F]') do
      bytes[i] = string.char(tonumber(b, 16))
      i = i + 1
   end
   local ret = table.concat(bytes)
   print(ret)
   return ret
end

local function get_ll_ip (mac)
   local pipe = io.popen("./mac_to_ll " .. mac, "r")
   local ll = pipe:read("*l")
   print(ll)
   return ll
end

-- get Solicited-node multicast address
local function get_snma (mac)
   local t = {}
   t[#t + 1] = "ff02:0:0:0:0:1:ff"
   t[#t + 1] = mac:sub(10, 11)
   t[#t + 1] = ":"
   t[#t + 1] = mac:sub(13, 14)
   t[#t + 1] = mac:sub(16, 17)
   local ret = table.concat(t)
   print(ret)
   return ret
end

function selftest ()
   os.execute("sudo ip link del dev snabbtun0")
   os.execute("sudo ip link del dev snabbtun1")
   os.execute("sudo ip link add name snabbtun0 type veth peer name linuxtun0")
   os.execute("sudo ip link add name snabbtun1 type veth peer name linuxtun1")
   
   local snabbtun0_MAC = get_mac_address("snabbtun0")
   local linuxtun0_MAC = get_mac_address("linuxtun0")
   local snabbtun0_global = "fc00:1:0:0:0:0:0:2"
   local snabbtun0_ll = get_ll_ip(snabbtun0_MAC)
   local linuxtun0_global = "fc00:1:0:0:0:0:0:1"
   local snabbtun0_ll_snma = get_snma(snabbtun0_MAC)
   local snabbtun0_ll_b = ipv6:pton(snabbtun0_global)

   local snabbtun1_MAC = get_mac_address("snabbtun1")
   local linuxtun1_MAC = get_mac_address("linuxtun1")
   local snabbtun1_global = "fc00:2:0:0:0:0:0:2"
   local snabbtun1_ll = get_ll_ip(snabbtun1_MAC)
   local linuxtun1_global = "fc00:2:0:0:0:0:0:1"
   local snabbtun1_ll_snma = get_snma(snabbtun1_MAC)
   local snabbtun1_ll_b = ipv6:pton(snabbtun1_global)

   os.execute("sudo ip addr add " .. linuxtun0_global .. "/64 dev linuxtun0")
   os.execute("sudo ip addr add " .. linuxtun1_global .. "/64 dev linuxtun1")

   os.execute("sleep 1")

   buffer.preallocate(10000)
   local c = config.new()

   config.app(c, "source0", basic_apps.Source)
   config.app(c, "snabbtun0", raw_socket, "snabbtun0")
   config.app(c, "ns_responder0", ns_responder,
         {
            local_mac = ethernet:pton(snabbtun0_MAC),
            local_ip = ipv6:pton(snabbtun0_ll_snma)
         }
      )
--   config.app(c, "ns_responder0", ipv6_endpoint.SimpleIPv6,
--         ([[{
--            own_mac = "%s",
--            own_ip = "%s"
--         }]]):format(get_mac_string(snabbtun0_MAC), ffi.string(snabbtun0_ll_b, 16))
--      )
   config.app(c, "tunnel0", tunnel.SimpleKeyedTunnel,
         ([[{
            local_address = "%s",
            remote_address = "%s",
            local_cookie = "12345678",
            remote_cookie = "12345678",
            default_gateway_MAC = "%s",
            local_MAC = "%s"
         }]]):format(snabbtun0_global, snabbtun1_global, linuxtun0_MAC, snabbtun0_MAC)
      )
   config.app(c, "sink0", basic_apps.Sink)
   config.link(c, "snabbtun0.tx -> ns_responder0.south")
   config.link(c, "ns_responder0.north -> tunnel0.encapsulated")
   config.link(c, "tunnel0.decapsulated -> sink0.input")
   config.link(c, "source0.output -> tunnel0.decapsulated")
   config.link(c, "tunnel0.encapsulated -> ns_responder0.north")
   config.link(c, "ns_responder0.south -> snabbtun0.rx")

   config.app(c, "source1", basic_apps.Source)
   config.app(c, "snabbtun1", raw_socket, "snabbtun1")
   config.app(c, "ns_responder1", ns_responder,
         {
            local_mac = ethernet:pton(snabbtun1_MAC),
            local_ip = ipv6:pton(snabbtun1_ll_snma)
         }
      )
--   config.app(c, "ns_responder1", ipv6_endpoint.SimpleIPv6,
--         ([[{
--            own_mac = "%s",
--            own_ip = "%s"
--         }]]):format(get_mac_string(snabbtun1_MAC), ffi.string(snabbtun1_ll_b, 16))
--      )
   config.app(c, "tunnel1", tunnel.SimpleKeyedTunnel,
         ([[{
            local_address = "%s",
            remote_address = "%s",
            local_cookie = "12345678",
            remote_cookie = "12345678",
            default_gateway_MAC = "%s",
            local_MAC = "%s"
         }]]):format(snabbtun1_global, snabbtun0_global, linuxtun1_MAC, snabbtun1_MAC)
      )
   config.app(c, "sink1", basic_apps.Sink)
   config.link(c, "snabbtun1.tx -> ns_responder1.south")
   config.link(c, "ns_responder1.north -> tunnel1.encapsulated")
   config.link(c, "tunnel1.decapsulated -> sink1.input")
   config.link(c, "source1.output -> tunnel1.decapsulated")
   config.link(c, "tunnel1.encapsulated -> ns_responder1.north")
   config.link(c, "ns_responder1.south -> snabbtun1.rx")

   print("about to configure ...")
   app.configure(c)
   print("configure done")
   

   app.main({duration = 10})
end
