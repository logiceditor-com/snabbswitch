module(...,package.seeall)

local buffer = require("core.buffer")
local packet = require("core.packet")
local lib    = require("core.lib")
local link   = require("core.link")
local config = require("core.config")
local timer  = require("core.timer")
local zone   = require("jit.zone")
local ffi    = require("ffi")
local C      = ffi.C
require("core.packet_h")

test_skipped_code = 43

-- The set of all active apps and links in the system.
-- Indexed both by name (in a table) and by number (in an array).
app_table,  app_array  = {}, {}
link_table, link_array = {}, {}

configuration = config.new()

monotinic_now = false

-- Return current monotonic time in seconds.
-- Can be used to drive timers in apps.
function now ()
   return monotonic_now
end

-- Configure the running app network to match new_configuration.
-- 
-- Successive calls to configure() will migrate from the old to the
-- new app network by making the changes needed.
function configure (new_config)
   local actions = compute_config_actions(configuration, new_config)
   apply_config_actions(actions, new_config)
   configuration = new_config
end

-- Return the configuration actions needed to migrate from old config to new.
-- The return value is a table:
--   app_name -> stop | start | keep | restart | reconfig
function compute_config_actions (old, new)
   local actions = {}
   for appname, info in pairs(new.apps) do
      local class, arg = info.class, info.arg
      local action = nil
      if not old.apps[appname]                then action = 'start'
      elseif old.apps[appname].class ~= class then action = 'restart'
      elseif (type(old.apps[appname].arg) == "string" and
	   old.apps[appname].arg ~= arg)      then action = 'reconfig'
      else                                         action = 'keep'  end
      actions[appname] = action
   end
   for appname in pairs(old.apps) do
      if not new.apps[appname] then actions[appname] = 'stop' end
   end
   return actions
end

-- Update the active app network by applying the necessary actions.
function apply_config_actions (actions, conf)
   -- The purpose of this function is to populate these tables:
   local new_app_table,  new_app_array  = {}, {}, {}
   local new_link_table, new_link_array = {}, {}, {}
   -- Temporary name->index table for use in link renumbering
   local app_name_to_index = {}
   -- Table of functions that execute config actions
   local ops = {}
   function ops.stop (name)
      if app_table[name].stop then app_table[name]:stop() end
   end
   function ops.keep (name)
      new_app_table[name] = app_table[name]
      table.insert(new_app_array, app_table[name])
      app_name_to_index[name] = #new_app_array
   end
   function ops.start (name)
      local class = conf.apps[name].class
      local arg = conf.apps[name].arg
      local app = class:new(arg)
      local zone = app.zone or getfenv(class.new)._NAME or name
      app.output = {}
      app.input = {}
      new_app_table[name] = app
      table.insert(new_app_array, app)
      app_name_to_index[name] = #new_app_array
      app.zone = zone
   end
   function ops.restart (name)
      ops.stop(name)
      ops.start(name)
   end
   function ops.reconfig (name)
      if app_table[name].reconfig then
         app_table[name]:reconfig(config)
      else
         ops.restart(name)
      end
   end
   -- dispatch all actions
   for name, action in pairs(actions) do
      ops[action](name)
   end
   -- Setup links: create (or reuse) and renumber.
   for linkspec in pairs(conf.links) do
      local fa, fl, ta, tl = config.parse_link(linkspec)
      if not new_app_table[fa] then error("no such app: " .. fa) end
      if not new_app_table[ta] then error("no such app: " .. ta) end
      -- Create or reuse a link and assign/update receiving app index
      local link = link_table[linkspec] or link.new()
      link.receiving_app = app_name_to_index[ta]
      -- Add link to apps
      new_app_table[fa].output[fl] = link
      new_app_table[ta].input[tl] = link
      -- Remember link
      new_link_table[linkspec] = link
      table.insert(new_link_array, link)
   end
   for _, app in ipairs(new_app_array) do
      if app.relink then app:relink() end
   end
   -- commit changes
   app_table, link_table = new_app_table, new_link_table
   app_array, link_array = new_app_array, new_link_array
end

-- Call this to "run snabb switch".
function main (options)
   local done = nil
   options = options or {}
   local no_timers = options.no_timers
   if options.duration then done = lib.timer(options.duration * 1e9) end
   repeat
      breathe()
      if not no_timers then timer.run() end
   until done and done()
   report(options.report)
end

function breathe ()
   monotonic_now = C.get_monotonic_time()
   -- Inhale: pull work into the app network
   for _, app in ipairs(app_array) do
      if app.pull then
         zone(app.zone) app:pull() zone()
      end
   end
   -- Exhale: push work out through the app network
   local firstloop = true
   repeat
      local progress = false
      -- For each link that has new data, run the receiving app
      for _, link in ipairs(link_array) do
         if firstloop or link.has_new_data then
            link.has_new_data = false
            local receiver = app_array[link.receiving_app]
            if receiver.push then
               zone(receiver.zone) receiver:push() zone()
               progress = true
            end
         end
      end
      firstloop = false
   until not progress  -- Stop after no link had new data
end

function report (options)
   if not options or options.showlinks then
      print("link report")
      for name, l in pairs(link_table) do
         print(lib.comma_value(tostring(tonumber(l.stats.txpackets))), "sent on", name)
      end
   end
   if options and options.showapps then
      print ("apps report")
      for name, a in pairs(app_table) do
         if a.report then
            print (name)
            a:report()
         end
      end
   end
end

function report_each_app ()
   for i = 1, #app_array do
      if app_array[i].report then
         app_array[i]:report()
      end
   end
end

function selftest ()
   print("selftest: app")
   local App = {}
   function App:new () return setmetatable({}, {__index = App}) end
   local c1 = config.new()
   config.app(c1, "app1", App)
   config.app(c1, "app2", App)
   config.link(c1, "app1.x -> app2.x")
   print("empty -> c1")
   configure(c1)
   assert(#app_array == 2)
   assert(#link_array == 1)
   assert(app_table.app1 and app_table.app2)
   local orig_app1 = app_table.app1
   local orig_app2 = app_table.app2
   local orig_link = link_array[1]
   print("c1 -> c1")
   configure(c1)
   assert(app_table.app1 == orig_app1)
   assert(app_table.app2 == orig_app2)
   local c2 = config.new()
   config.app(c2, "app1", App, "config")
   config.app(c2, "app2", App)
   config.link(c2, "app1.x -> app2.x")
   config.link(c2, "app2.x -> app1.x")
   print("c1 -> c2")
   configure(c2)
   assert(#app_array == 2)
   assert(#link_array == 2)
   assert(app_table.app1 ~= orig_app1) -- should be restarted
   assert(app_table.app2 == orig_app2) -- should be the same
   -- tostring() because == does not work on FFI structs?
   assert(tostring(orig_link) == tostring(link_table['app1.x -> app2.x']))
   print("c2 -> c1")
   configure(c1) -- c2 -> c1
   assert(app_table.app1 ~= orig_app1) -- should be restarted
   assert(app_table.app2 == orig_app2) -- should be the same
   assert(#app_array == 2)
   assert(#link_array == 1)
   print("c1 -> empty")
   configure(config.new())
   assert(#app_array == 0)
   assert(#link_array == 0)
   print("OK")
end

-- XXX add graphviz() function back.

function module_init ()
   -- XXX Find a better place for this.
   require("lib.hardware.bus").scan_devices()
end

module_init()
