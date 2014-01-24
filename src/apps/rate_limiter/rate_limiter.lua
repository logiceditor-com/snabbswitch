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

-- one tick per ms is too expensive
-- 100 ms tick is good enough
local TICKS_PER_SECOND = 10
local NS_PER_TICK = 1e9 / TICKS_PER_SECOND


function RateLimiter.new (rate, bucket_capacity, initial_capacity)
   assert(rate)
   assert(bucket_capacity)
   initial_capacity = initial_capacity or bucket_capacity / 2
   local o =
   {
      tokens_on_tick = rate / TICKS_PER_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity,
      tx_packets = 0,
      rx_packets = 0,
      ticks = 0
   }
   return setmetatable(o, {__index=RateLimiter})
end

function RateLimiter:reset_stat ()
	self.tx_packets = 0
   self.rx_packets = 0
   self.ticks = 0
end

function RateLimiter:tick ()
   self.ticks = self.ticks + 1
   self.bucket_content = min(
         self.bucket_content + self.tokens_on_tick,
         self.bucket_capacity
      )
end

function RateLimiter:push ()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   local tx_packets = 0
   local max_packets_to_send = app.nwritable(o)
   if max_packets_to_send == 0 then
      return
   end

   local nreadable = app.nreadable(i)
   for n = 1, nreadable do
      local p = app.receive(i)
      local length = p.length

      if length <= self.bucket_content then
         self.bucket_content = self.bucket_content - length
         app.transmit(o, p)
         tx_packets = tx_packets + 1

         if tx_packets == max_packets_to_send then
            nreadable = n
            break
         end
      else
         -- discard packet
         packet.deref(p)
      end
   end
   self.rx_packets = self.rx_packets + nreadable
   self.tx_packets = self.tx_packets + tx_packets
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

   app.apps.rate_limiter = app.new(RateLimiter.new(rate, bucket_size))

   -- activate timer to place tokens to bucket every tick
   timer.activate(timer.new(
         "tick",
         function () app.apps.rate_limiter:tick() end,
         NS_PER_TICK,
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
      print(
            "process",
            math.floor(app.apps.rate_limiter.rx_packets / elapsed_time * 1e9),
            "packets per second"
         )
   end

   do
      app.apps.rate_limiter:reset_stat()

      local seconds_to_run = 5
      -- print packets statistics every second
      timer.activate(timer.new(
            "report",
            function ()
               app.report()
               seconds_to_run = seconds_to_run - 1
            end,
            1e9, -- every second
            'repeating'
         ))

      print("\ntest effective rate")
      local start_time = tonumber(C.get_time_ns() / 1e9)
      
      -- push some packets through it
      while seconds_to_run > 0 do
         app.breathe()
         timer.run()    -- get timers chance to fire
         C.usleep(10)   -- avoid busy loop
      end
      -- print final report
      app.report()

      local elapsed_time = tonumber(C.get_time_ns() / 1e9) - start_time
      print("elapsed time:", elapsed_time)
      print("ticks:", app.apps.rate_limiter.ticks)

      local effective_rate = floor(app.apps.rate_limiter.tx_packets * PACKET_SIZE / elapsed_time)
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
