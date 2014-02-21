module(...,package.seeall)

local ffi = require("ffi")
local bit = require("bit")

function selftest_64()
   local p1, p2, mask = 1234567ULL, 321ULL, 61695ULL
   local t1, t2 = 1234567ULL, 321ULL
   local counter = 0
   for i = 1, 1e10 do
      if p1 == t1 then 
         counter = counter + 1
      end
      local result = bit.bor(bit.band(t2, mask), p1 )
   end
end

function selftest_64()
   local p1, p2, p3, p4, mask = 123, 432, 61695, 123321, 123129387
   local t1, t2, t3, t4 = 123, 432, 34456456, 123
   local counter = 0
   for i = 1, 1e10 do
      if p1 == t1 and p2 == t2 and p3 == t3 then 
         counter = counter + 1
      end
      local result = bit.bor(bit.band(t4, mask), p4 )
   end
end

function build_masks()
   local mask = bit.tobit(0xffffffff)
   for i = 31, 1, -1 do
      mask = bit.lshift(mask, 1)
      print(bit.tohex(mask))
   end

   print(bit.tohex(123ULL))
end

selftest = build_masks
