module(...,package.seeall)

local app    = require("core.app")
local config = require("core.config")
local link   = require("core.link")
local buffer = require("core.buffer")
local packet = require("core.packet")
local lib    = require("core.lib")
local vhost  = require("apps.vhost.vhost")
local basic_apps = require("apps.basic.basic_apps")

local ipv6 = require("apps.ipv6.ipv6_")
--local ns_responder = require("apps.ipv6.ns_responder")
--local ipv6 = require("lib.protocol.ipv6")
--local ethernet = require("lib.protocol.ethernet")

TapVhost = {}

function TapVhost:new (ifname)
   local dev = vhost.new(ifname)
   return setmetatable({ dev = dev }, {__index = TapVhost})
end

function TapVhost:pull ()
   self.dev:sync_receive()
   self.dev:sync_transmit()
   local l = self.output.tx
   if l == nil then return end
   while not link.full(l) and self.dev:can_receive() do
      print("vhost - got a packet")
      link.transmit(l, self.dev:receive())
   end
   while self.dev:can_add_receive_buffer() do
      self.dev:add_receive_buffer(buffer.allocate())
   end
end

function TapVhost:push ()
   local l = self.input.rx
   if l == nil then return end
   while not link.empty(l) and self.dev:can_transmit() do
      local p = link.receive(l)
      self.dev:transmit(p)
      packet.deref(p)
   end
end

function selftest ()
   if not vhost.is_tuntap_available() then
      print("/dev/net/tun absent or not avaiable\nTest skipped")
      os.exit(app.test_skipped_code)
   end

-- ba:5f:ae:8c:47:8e
-- 2a01:4f8:191:1422::1025

   local c = config.new()
--   config.app(c, "source", basic_apps.Source)
   config.app(c, "tapvhost", TapVhost, "tap0")
   config.app(c, "ipv6", ipv6.SimpleIPv6,
              [[ { own_ip  = "\x2a\x01\x04\xf8\x01\x91\x14\x22\x00\x00\x00\x00\x00\x00\x10\x25",
                   own_mac = "\xba\x5f\xae\x8c\x47\x8e" } ]])

   config.app(c, "sink", basic_apps.Sink)
--   config.app(c, "ns_responder", ns_responder,
--       {
--          local_mac = ethernet:pton("7e:5c:9e:ca:9a:77"),
--          locap_ip = ipv6:pton("fe80:0:0:0:7c5c:9eff:feca:9a77")
--      }
--      )
--   config.link(c, "source.out -> tapvhost.rx")
--   config.link(c, "tapvhost.tx -> ipv6.tap")
   config.link(c, "tapvhost.tx -> ipv6.south")
   config.link(c, "ipv6.north -> sink.input")
   config.link(c, "ipv6.south -> tapvhost.rx")
--   config.link(c, "tapvhost.tx -> sink.input")
   app.configure(c)
   buffer.preallocate(100000)
   app.main({duration = 1000})
end

