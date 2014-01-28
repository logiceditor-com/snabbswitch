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

-- Source produces synthetic packets of such size
local PACKET_SIZE = 60

function RateLimiter.new (rate, bucket_capacity, initial_capacity)
   assert(rate)
   assert(bucket_capacity)
   initial_capacity = initial_capacity or bucket_capacity
   local o =
   {
      tokens_on_tick = rate / TICKS_PER_SECOND,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity
    }
   return setmetatable(o, {__index=RateLimiter})
end

function RateLimiter:init_timer()
      -- activate timer to place tokens to bucket every tick
   timer.activate(timer.new(
         "tick",
         function () self:tick() end,
         NS_PER_TICK,
         'repeating'
      ))
end

-- return statistics snapshot
function RateLimiter:snapshot ()
   return
   {
      rx = self.input.input.ring.stats.tx,
      tx = self.output.output.ring.stats.tx,
      time = tonumber(C.get_time_ns()),
   }
end

function RateLimiter:tick ()
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
   for _ = 1, nreadable do
      local p = app.receive(i)
      local length = p.length

      if length <= self.bucket_content then
         self.bucket_content = self.bucket_content - length
         app.transmit(o, p)
         tx_packets = tx_packets + 1

         if tx_packets == max_packets_to_send then
            break
         end
      else
         -- discard packet
         packet.deref(p)
      end
   end
end

local function effective_rate (rl, rate, snapshot)
   local elapsed_time =
      (tonumber(C.get_time_ns()) - snapshot.time) / 1e9
   local tx = tonumber(rl.output.output.ring.stats.tx - snapshot.tx)
   return floor(tx * PACKET_SIZE / elapsed_time)
end

function selftest ()
   print("Rate limiter selftest")
   timer.init()
   buffer.preallocate(10000)

   -- bytes per second
   --local rate_non_busy_loop = 200000
   local rate_non_busy_loop = 100000000
   local effective_rate_non_busy_loop
   do
      app.apps.source = app.new(basic_apps.Source:new())

      -- bytes, should be able to process 1000 packets
      -- generated by single Source:pull()
      -- small value may limit effective rate
      local bucket_size = rate_non_busy_loop / 2

      local rl = app.new(RateLimiter.new(rate_non_busy_loop, bucket_size))
      app.apps.rate_limiter = rl
      rl:init_timer()
      app.apps.sink = app.new(basic_apps.Sink:new())

      -- Create a pipeline:
      -- Source --> RateLimiter --> Sink
      app.connect("source", "output", "rate_limiter", "input")
      app.connect("rate_limiter", "output", "sink", "input")
      app.relink()

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

      print("\ntest effective rate, non-busy loop")
      local snapshot = rl:snapshot()

      -- push some packets through it
      while seconds_to_run > 0 do
         app.breathe()
         timer.run()
         C.usleep(10) -- avoid busy loop
      end
      -- print final report
      app.report()

      effective_rate_non_busy_loop = effective_rate(
            rl,
            rate_non_busy_loop,
            snapshot
         )
      print("configured rate is", rate_non_busy_loop, "bytes per second")
      print(
            "effective rate is",
            effective_rate_non_busy_loop,
            "bytes per second"
         )
   end

   -- bytes per second
   local rate_busy_loop = 1000000000
   local effective_rate_busy_loop
   do
      -- Source produces 1000 60-bytes packets on one "inhale"
      app.apps.source = app.new(basic_apps.Source:new())

      -- bytes, should be able to process packets generated by Source:pull()
      -- during 100 ms - internal RateLimiter timer resulution
      -- small value may limit effective rate
      local bucket_size = rate_busy_loop / 2

      local rl = app.new(RateLimiter.new(rate_busy_loop, bucket_size))
      app.apps.rate_limiter = rl
      rl:init_timer()
      app.apps.sink = app.new(basic_apps.Sink:new())

      -- Create a pipeline:
      -- Source --> RateLimiter --> Sink
      app.connect("source", "output", "rate_limiter", "input")
      app.connect("rate_limiter", "output", "sink", "input")
      app.relink()

      print("mesure throughput ...")
      local snapshot = rl:snapshot()
      for i = 1, 100000 do
         app.breathe()
         timer.run()
      end
      local elapsed_time =
         (tonumber(C.get_time_ns()) - snapshot.time) / 1e9
      print("elapsed time ", elapsed_time, "seconds")

      local rx = tonumber(rl.input.input.ring.stats.tx - snapshot.rx)
      print("packets received", rx)
      print(floor(rx / elapsed_time), "packets per second")

      effective_rate_busy_loop = effective_rate(
            rl,
            rate_busy_loop,
            snapshot
         )
      print("configured rate is", rate_busy_loop, "bytes per second")
      print(
            "effective rate is",
            effective_rate_busy_loop,
            "bytes per second"
         )
      print(
            "throughput",
            floor(effective_rate_busy_loop / PACKET_SIZE / 1e6),
            "Mpps")
   end

   local accepted_min = floor(rate_non_busy_loop * 0.9)
   local accepted_max = floor(rate_non_busy_loop * 1.1)

   if effective_rate_non_busy_loop < accepted_min or
      effective_rate_non_busy_loop > accepted_max then
      print("selftest failed")
      os.exit(1)
   end

   local accepted_min = floor(rate_busy_loop * 0.9)
   local accepted_max = floor(rate_busy_loop * 1.1)

   if effective_rate_busy_loop < accepted_min or
      effective_rate_busy_loop > accepted_max then
      print("selftest failed")
      os.exit(1)
   end

   print("selftest passed")
end