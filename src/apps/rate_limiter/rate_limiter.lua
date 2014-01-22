module(...,package.seeall)

local app = require("core.app")
local packet = require("core.packet")
local timer = require("core.timer")
local basic_apps = require("apps.basic.basic_apps")
local buffer = require("core.buffer")
local ffi = require("ffi")
local C = ffi.C

--- # `Rate limiter` app: enforce a byte-per-second limit

-- uses http://en.wikipedia.org/wiki/Token_bucket algorithm
-- single bucket, drop non-conformant packets

-- bucket capacity and content - bytes
-- rate - bytes per second

RateLimiter = {}

local MS_IN_SECOND = 1000

-- to be called every 1 ms
local function tick (self)
   self.bucket_content = math.min(
         self.bucket_content + self.rate / MS_IN_SECOND,
         self.bucket_capacity
      )
end

function RateLimiter:new (rate, bucket_capacity, initial_capacity)
   assert(rate)
   assert(bucket_capacity)
   initial_capacity = initial_capacity or bucket_capacity / 2
   local o =
   {
      rate = rate,
      bucket_capacity = bucket_capacity,
      bucket_content = initial_capacity
   }
   return setmetatable(o, {__index=RateLimiter})
end

function RateLimiter:push ()
   local i = assert(self.input.input, "input port not found")
   local o = assert(self.output.output, "output port not found")

   local sent_packets = 0
   local max_packets_to_send = app.nwritable(o)
   if max_packets_to_send == 0 then
      return
   end

   for _ = 1, app.nreadable(i) do
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
end

function selftest ()
   print("selftest: rate limiter")
   timer.init()

   -- Source produces 1000 60-bytes packets on one "inhale"
   app.apps.source = app.new(basic_apps.Source:new())

   -- 1000 bytes per second - it is about 17 60-bytes packets per second
   local rl = app.new(RateLimiter:new(1000, 1000))
   app.apps.rate_limiter = rl

   -- activate timer to place tokens to bucket every 1 ms
   timer.activate(timer.new(
         "tick",
         function () tick(rl) end,
         1e6, -- every ms
         'repeating'
      ))

   app.apps.sink   = app.new(basic_apps.Sink:new())

   -- Create a pipeline:
   -- Source --> RateLimiter --> Sink
   app.connect("source", "output", "rate_limiter", "input")
   app.connect("rate_limiter", "output", "sink", "input")
   app.relink()

   buffer.preallocate(10000)

   -- print packets statistics every second
   -- you may see number of packets produced by Source
   -- and number of packets passed through rate limiter
   timer.activate(timer.new(
         "report",
         function () app.report() end,
         1e9, -- every second
         'repeating'
      ))

   -- push some packets through it.      
   for i = 1, 5000 do
      app.breathe()
      timer.run()    -- get timers chance to fire
      C.usleep(1000) -- don't do it too fast
   end

   -- print final report
   app.report()
end
