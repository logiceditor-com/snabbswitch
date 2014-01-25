module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local timer = require("core.timer")
local basic_apps = require("apps.basic.basic_apps")
local buffer = require("core.buffer")
local ffi = require("ffi")
local C = ffi.C
local floor, min = math.floor, math.min

--- # `Rate limiter` app: enforce a byte-per-second limit

-- uses http://en.wikipedia.org/wiki/Token_bucket algorithm
-- single bucket, drop non-conformant packets

-- bucket capacity and content - bytes
-- rate - bytes per second

RateLimiter = {}

local TICKS_PER_SECOND = 10

local function tick (self)
   self.bucket_content = min(
         self.bucket_content + self.tokens_on_tick,
         self.bucket_capacity
      )
end

function RateLimiter:new (rate, bucket_capacity, initial_capacity)
   assert(rate)
   assert(bucket_capacity)
   initial_capacity = initial_capacity or bucket_capacity / 2
   local o =
   {
      tokens_on_tick = rate / TICKS_PER_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity,
      packets_tx = 0,
      packets_rx = 0
    }
   return setmetatable(o, {__index=RateLimiter})
end

function RateLimiter:reset_stat()
   self.packets_tx = 0
   self.packets_rx = 0
end

function RateLimiter:push ()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   local packets_tx = 0
   local max_packets_to_send = app.nwritable(o)
   if max_packets_to_send == 0 then
      return
   end

   local nreadable = app.nreadable(i)
   for _ = 1, nreadable do
      local p = app.receive(i)
      local length = p.length

      if length <= self.bucket_content then
         self.bucket_content = self.bucket_content - length
         app.transmit(o, p)
         packets_tx = packets_tx + 1

         if packets_tx == max_packets_to_send then
            break
         end
      else
         -- discard packet
         packet.deref(p)
      end
   end
   self.packets_rx = self.packets_rx + nreadable
   self.packets_tx = self.packets_tx + packets_tx
end

function selftest ()
   print("selftest: rate limiter")
   timer.init()

   -- Source produces 1000 60-bytes packets on one "inhale"
   app.apps.source = app.new(basic_apps.Source:new())

   -- Source produces synthetic packets of such size
   local PACKET_SIZE = 60

   -- bytes per second
   local rate = 10000

   -- should be big enough to compensate poor timer subsystem
   local bucket_size = 1000

   local packets_per_second = rate / PACKET_SIZE

   local rl = app.new(RateLimiter:new(rate, bucket_size))
   app.apps.rate_limiter = rl

   -- activate timer to place tokens to bucket every 1 ms
   timer.activate(timer.new(
         "tick",
         function () tick(rl) end,
         1e9 / TICKS_PER_SECOND,
         'repeating'
      ))

   app.apps.sink = app.new(basic_apps.Sink:new())

   -- Create a pipeline:
   -- Source --> RateLimiter --> Sink
   app.connect("source", "output", "rate_limiter", "input")
   app.connect("rate_limiter", "output", "sink", "input")
   app.relink()

   buffer.preallocate(10000)

   print("mesure max throughput ...")
   local start_time = tonumber(C.get_time_ns())
   for i = 1, 100000 do
      app.breathe()
      timer.run()
   end
   local elapsed_time = tonumber(C.get_time_ns()) - start_time
   print(
         "process",
         math.floor(rl.packets_rx / elapsed_time * 1e9),
         "packets per second"
      )
end
