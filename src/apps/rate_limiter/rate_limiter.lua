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

local MS_IN_SECOND = 1000

-- to be called every 1 ms
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
      tokens_on_tick = rate / MS_IN_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity,
      sent_packets = 0,
      got_packets = 0
   }
   return setmetatable(o, {__index=RateLimiter})
end

function RateLimiter:stat()
	local sent_packets, got_packets = self.sent_packets, self.got_packets
	self.sent_packets = 0
   self.got_packets = 0
	return sent_packets, got_packets
end

function RateLimiter:push ()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   local sent_packets = 0
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
         sent_packets = sent_packets + 1

         if sent_packets == max_packets_to_send then
            break
         end
      else
         -- discard packet
         packet.deref(p)
      end
   end
   self.got_packets = self.got_packets + nreadable
   self.sent_packets = self.sent_packets + sent_packets
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

   app.apps.rate_limiter = app.new(RateLimiter:new(rate, bucket_size))

   -- activate timer to place tokens to bucket every 1 ms
   timer.activate(timer.new(
         "tick",
         function () tick(app.apps.rate_limiter) end,
         1e6, -- every ms
         'repeating'
      ))

   app.apps.sink = app.new(basic_apps.Sink:new())

   -- Create a pipeline:
   -- Source --> RateLimiter --> Sink
   app.connect("source", "output", "rate_limiter", "input")
   app.connect("rate_limiter", "output", "sink", "input")
   app.relink()

   buffer.preallocate(10000)

   do
      print("mesure max throughput ...")
      local start_time = tonumber(C.get_time_ns())
      for i = 1, 100000 do
         app.breathe()
         timer.run()
      end
      local elapsed_time = tonumber(C.get_time_ns()) - start_time
      local _, got_packets = app.apps.rate_limiter:stat()
      print(
            "process",
            math.floor(got_packets / elapsed_time * 1e9),
            "packets per second"
         )
   end

   do
      -- print packets statistics every second
      timer.activate(timer.new(
            "report",
            function () app.report() end,
            1e9, -- every second
            'repeating'
         ))

      print("\ntest effective rate")
      local start_time = tonumber(C.get_time_ns() / 1e9)
      
      -- push some packets through it
      for i = 1, 10000 do
         app.breathe()
         timer.run()    -- get timers chance to fire
         C.usleep(10)   -- don't do it too fast
      end

      local elapsed_time = tonumber(C.get_time_ns() / 1e9) - start_time
      -- print final report
      app.report()


      local sent_packets = app.apps.rate_limiter:stat()
      local effective_rate = floor(sent_packets * PACKET_SIZE / elapsed_time)
      print("configured rate is", rate, "bytes per second")
      print("effective rate is", effective_rate, "bytes per second")
      local accepted_min = floor(rate * 0.9)
      local accepted_max = floor(rate * 1.1)

      if effective_rate > accepted_min and effective_rate < accepted_max then
         print("selftest passed")
      else
         print("selftest failed")
         os.exit(1)
      end
   end
end
