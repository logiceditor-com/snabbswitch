// ------------------------------------------------------------------------- //
// Config
// ------------------------------------------------------------------------- //

var dataAppPath = "./data/app.csv"
var dataLinkPath = "./data/link.csv"
var secondsReload = 120
var graphStepSeconds = 30

// ------------------------------------------------------------------------- //
// Loda data from app and and reload every secondsReload
// ------------------------------------------------------------------------- //
var color = d3.scale.category10()
var appRaw
var linkRaw

$(document).ready(function() {
  d3.csv(dataAppPath, function(data) {
    setAppStatus(data)
    setCpuStatus(data)
    appRaw = data
  })

  d3.csv(dataLinkPath, function(data) {
    reinitializeD3Structure(data)
    setAppStatus(data)
    setNetworkStatus(data)
    linkRaw = data
  })
})

setInterval(function(){
  d3.csv(dataAppPath, function(data) {
    setAppStatus(data)
    setCpuStatus(data)
    appRaw = data
  })

  d3.csv(dataLinkPath, function(data) {
    reinitializeD3Structure(data)
    setAppStatus(data)
    setNetworkStatus(data)
    linkRaw = data
  })

}, secondsReload * 1000)

// ------------------------------------------------------------------------- //
// Utilities
// ------------------------------------------------------------------------- //
function getReadableSizeString(fileSizeInBytes) {
    if (fileSizeInBytes < 1024) {
      return fileSizeInBytes + " B"
    }
    var i = -1
    var byteUnits = [' kB', ' MB', ' GB', ' TB', ' PB', 'EB', 'ZB', 'YB']
    do {
        fileSizeInBytes = fileSizeInBytes / 1024
        i++
    } while (fileSizeInBytes > 1024)

    return Math.max(fileSizeInBytes, 0.01).toFixed(2) + byteUnits[i]
}

function getReadableSize(size) {
    if (size < 1000) { return size }
    var i = -1
    var byteUnits = ['K', 'M']
    do {
        size = size / 1000
        i++
    } while (size > 1000 && i < 1)
    return Math.max(size, 0.01).toFixed(2) + byteUnits[i]
}

function timeConverter(UNIX_timestamp, short) {
  var a = new Date(UNIX_timestamp*1000),
      months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],
      year = a.getFullYear(),
      month = months[a.getMonth()],
      date = a.getDate(),
      hour = a.getHours(),
      min = a.getMinutes(),
      sec = a.getSeconds(),
      short_time = hour + ':' + min + ':' + sec,
      time = date + ' ' + month + ' ' + year + ' ' + short_time
  if (short) {
    return short_time
  }
  return time
 }

function showTooltip(x, y, contents) {
  $('<div id="tooltip">' + contents + '</div>').css({
      position: 'absolute',
      display: 'none',
      top: y + 5,
      width: 100,
      left: x + 5,
      border: '1px solid #000',
      padding: '2px 8px',
      color: '#ccc',
      'background-color': '#000',
      opacity: 0.9
  }).appendTo("body").fadeIn(200)
}

function insertCheckboxes(id, prefix) {
  var choiceContainer = $("#" + id)
  choiceContainer.text("")
  for (i = 0; i < uniqClassList.length; ++i) {
    var classKey = uniqClassList[i]
    choiceContainer.append("<div class='appClass'>" + classKey + "</div>")
    var classVal = uniqClass[classKey]
    for (j = 0; j < classVal.length; ++j)
    {
      var key = classVal[j].Name
      var val = uniqApps[key]
      var checked = (uniqApps[key][prefix] == true) ? "checked='checked'" : ""

      choiceContainer.append("<div class='appCheckbox'><input type='checkbox' name='"
        + prefix + "_" + key + "' " + checked + " id='"
        + prefix + "_" + key + "' onchange='toggle"
        + prefix + "Checkbox(this, \"" + key + "\")'></input>" +
        "<label style='color:" + val.color + ";' for='"
        + prefix + "_" + key + "'>" + val.Name + "</label></div>")
    }
  }
}

// ------------------------------------------------------------------------- //
// App an link status
// ------------------------------------------------------------------------- //
var not_loaded = "reading..."
var lastTime = 0
var appStatus = [],
    linkStatus = [],
    uniqApps = {},
    uniqClass = {},
    uniqClassList = [],
    uniqLinks = {}

function setAppStatus(data) {
  var arrayLength = data.length
  for (var i = arrayLength - 1; i >= 0; --i) {
    var d = data[i]
    if (d.hasOwnProperty('from_app')) { // somehow define that's link.data
      var name = d.from_app + "." + d.from_port + "->" + d.to_app + "." + d.to_port
      if(!uniqLinks[name]) {
        uniqLinks[name] = {
          "Link": name,
          "Last updated":timeConverter(d.time),
          "RX bytes": getReadableSizeString(Number(d.txbytes)),
          "TX bytes": getReadableSizeString(Number(d.rxbytes)),
          "Drop bytes": getReadableSizeString(Number(d.dropbytes)),
          "RX packets": Number(d.txpackets),
          "TX packets": Number(d.rxpackets),
          "Drop packets": Number(d.droppackets),
          txbytes: Number(d.txbytes),
          rxbytes: Number(d.rxbytes),
          dropbytes: Number(d.dropbytes),
          time: d.time,
          from_app: d.from_app,
          to_app: d.to_app
        }
        linkStatus.push(uniqLinks[name])
      }
      else {
        if (!uniqLinks[name].hasOwnProperty("Last updated") || uniqLinks[name].time < d.time) {
          uniqLinks[name]["RX bytes"] = getReadableSizeString(Number(d.rxbytes))
          uniqLinks[name]["TX bytes"] = getReadableSizeString(Number(d.txbytes))
          uniqLinks[name]["Drop bytes"] = getReadableSizeString(Number(d.dropbytes))
          uniqLinks[name]["RX packets"] = Number(d.rxpackets)
          uniqLinks[name]["packets packets"] = Number(d.txpackets)
          uniqLinks[name]["Drop packets"] = Number(d.droppackets)
          uniqLinks[name].txbytes = Number(d.txbytes)
          uniqLinks[name].rxbytes = Number(d.rxbytes)
          uniqLinks[name].dropbytes = Number(d.dropbytes)
          uniqLinks[name]["Last updated"] = timeConverter(d.time)
          uniqLinks[name].time = Number(d.time)
        }
      }
      if (lastTime < d.time) { lastTime = d.time }
    }
    else if (d.hasOwnProperty('starttime')) { // somehow define that's app.data
      if(!uniqApps[d.name]) {
        uniqApps[d.name] = {
          Name: d.name,
          Class: d.class,
          Started:timeConverter(d.starttime),
          Processor: d.cpu,
          Log:('<td><a href="path/to/'
            + d.name + '.log"><i class="fa fa-file-text"></i>&nbsp;View log</a></td>'),
          Diagnostics:('<td><a href="path/to/'
            + d.name + '.dbg"><i class="fa fa-exclamation-triangle"></i>&nbsp;Debug Dump</a></td>'),
          lastTime: d.time,
          CpuDraw: true,
          NetworkDraw: true
        }
        if(!uniqClass[d.class]) {
          uniqClass[d.class] = []
          uniqClassList.push(d.class)
        }
        uniqClass[d.class].push(uniqApps[d.name])
        appStatus.push(uniqApps[d.name])
        uniqApps[d.name].color = color(appStatus.length)
      }
      else {
        if (uniqApps[d.name].lastTime < d.time) {
          uniqApps[d.name].lastTimeLinks = d.time
          uniqApps[d.name].Processor = d.cpu
          uniqApps[d.name].lastTime = d.time
        }
      }
      if (lastTime < d.time) { lastTime = d.time }
    }
  }

  var arrayLength = linkStatus.length
  for (var name in uniqApps) {
    var rxbytes = 0,
        txbytes = 0,
        dropbytes = 0,
        rxpackets = 0,
        txpackets = 0,
        droppackets = 0
    for (var i = 0; i < arrayLength; i++) {
      if (linkStatus[i].from_app == name) {
        txbytes += linkStatus[i].txbytes + linkStatus[i].dropbytes
        txpackets += linkStatus[i]["TX packets"] + linkStatus[i]["Drop packets"]
      }
      if (linkStatus[i].to_app == name) {
        rxbytes += linkStatus[i].rxbytes
        rxpackets += linkStatus[i]["RX packets"]
        dropbytes += linkStatus[i].dropbytes
        droppackets += linkStatus[i]["Drop packets"]
      }
    }
    uniqApps[name]["RX bytes"] = getReadableSizeString(rxbytes)
    uniqApps[name]["TX bytes"] = getReadableSizeString(txbytes)
    uniqApps[name]["Drop bytes"] = getReadableSizeString(dropbytes)
    uniqApps[name]["RX packets"] = getReadableSize(rxpackets)
    uniqApps[name]["TX packets"] = getReadableSize(txpackets)
    uniqApps[name]["Drop packets"] = getReadableSize(droppackets)
  }

  createAppStatusTable(appStatus)
}

function createAppStatusTable(appStatus) {
  $('#dataAppTable tbody').remove()
  $('#dataAppTable').append('<tbody>')

  var tbody = $('#dataAppTable tbody'),
  props = [
    "Name", "Class", "Started", "Processor",
    "RX packets", "RX bytes", "TX packets", "TX bytes", "Drop packets", "Drop bytes",
    "Log", "Diagnostics"]

  for (i = 0; i < uniqClassList.length; ++i) {
    var classKey = uniqClassList[i]
    var classVal = uniqClass[classKey]
    for (j = 0; j < classVal.length; ++j)
    {
      var name = classVal[j].Name
      var tr = $('<tr>')
      $.each(props, function(i, prop) {
        $('<td>').html(uniqApps[name][prop]).appendTo(tr)
      })
      tbody.append(tr)
    }
  }

  $('#dataLinkTable tbody').remove()
  $('#dataLinkTable').append('<tbody>')
    var tbody = $('#dataLinkTable tbody'),
    props = [
      "Link", "Last updated", "RX bytes", "TX bytes",
      "Drop bytes", "RX packets", "TX packets", "Drop packets"]

    $.each(linkStatus, function(i, app) {
      var tr = $('<tr>')
      $.each(props, function(i, prop) {
        $('<td>').html(app[prop]).appendTo(tr)
      })
      tbody.append(tr)
    })
  $('#lastUpdated').text("Last updated " + timeConverter(lastTime))
}
// App status ends

// ------------------------------------------------------------------------- //
// CPU chart starts
// ------------------------------------------------------------------------- //
var CPU_APP = 1
var CPU_CLASS = 2
var CPU_SUM = 3

var cpuType = CPU_APP

function cpuApp()
{
  cpuType = CPU_APP
  setCpuStatus(appRaw)
}

function cpuClass()
{
  cpuType = CPU_CLASS
  setCpuStatus(appRaw)
}

function cpuSum()
{
  cpuType = CPU_SUM
  setCpuStatus(appRaw)
}

function toggleCpuDrawCheckbox(element, key)
{
  uniqApps[key].CpuDraw = element.checked
  setCpuStatus(appRaw)
}

function setCpuStatus(data) {
  var arrayLength = data.length

  var curVal = { }
  var curTime = { }
  var graphCpuData = { }
  var length = graphStepSeconds * 1000
  switch(cpuType)
  {
    case CPU_APP:
      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var name = d.name
        if (uniqApps[name].CpuDraw) {
          if(!graphCpuData[name]) { graphCpuData[name] = [] }
          if(!curTime[name]) { curTime[name] = 0 }

          var recordTime = parseFloat(d.time) * 1000

          if (curTime[name] + length < recordTime) {
            if(!curVal[name]) {
              curVal[name] = {
                val: parseFloat(d.cpu),
                num: 1
              }
              curTime[name] = recordTime
            }
            else {
              graphCpuData[name].push([curTime[name] + length / 2, curVal[name].val / curVal[name].num])
              curVal[name].val = parseFloat(d.cpu)
              curVal[name].num = 1
              curTime[name] = recordTime
            }
          }
          else {
              curVal[name].val += parseFloat(d.cpu)
              curVal[name].num += 1
          }
        }
      }
      break
    case CPU_CLASS:
      var multipliers = {}
      for (i = 0; i < uniqClassList.length; ++i) {
        var name = uniqClassList[i]
        multipliers[name] = 0
        for (j = 0; j < uniqClass[name].length; ++j) {
          var appName = uniqClass[name][j].Name
          if (uniqApps[appName].CpuDraw) {
            ++multipliers[name]
          }
        }
      }

      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var name = d.class
        if (uniqApps[d.name].CpuDraw) {
          if(!graphCpuData[name]) { graphCpuData[name] = []; }
          if(!curTime[name]) { curTime[name] = 0; }

          var recordTime = parseFloat(d.time) * 1000

          if (curTime[name] + length < recordTime) {
            if(!curVal[name]) {
              curVal[name] = {
                val: parseFloat(d.cpu),
                num: 1
              }
              curTime[name] = recordTime
            }
            else {
              graphCpuData[name].push(
                  [curTime[name] + length / 2,
                  curVal[name].val * multipliers[name] / curVal[name].num]
                )
              curVal[name].val = parseFloat(d.cpu)
              curVal[name].num = 1
              curTime[name] = recordTime
            }
          }
          else {
            curVal[name].val += parseFloat(d.cpu)
            curVal[name].num += 1
          }
        }
      }

      break
    case CPU_SUM:
      var multiplier = 0
      for (i = 0; i < appStatus.length; ++i) {
        var name = appStatus[i].Name
        if (uniqApps[name].CpuDraw) {
          ++ multiplier
        }
      }
      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var name = "sum"

        if (uniqApps[d.name].CpuDraw) {
          if(!graphCpuData[name]) { graphCpuData[name] = []; }
          if(!curTime[name]) { curTime[name] = 0; }

          var recordTime = parseFloat(d.time) * 1000

          if (curTime[name] + length < recordTime) {
            if(!curVal[name]) {
              curVal[name] = {
                val: parseFloat(d.cpu),
                num: 1
              }
              curTime[name] = recordTime
            }
            else {
              graphCpuData[name].push(
                  [curTime[name] + length / 2,
                  curVal[name].val * multiplier / curVal[name].num]
                )
              curVal[name].val = parseFloat(d.cpu)
              curVal[name].num = 1
              curTime[name] = recordTime
            }
          }
          else {
            curVal[name].val += parseFloat(d.cpu)
            curVal[name].num += 1
          }
        }
      }
    // case ends
  }

  insertCheckboxes("CPUchoices", "CpuDraw")
  createCpuGraph(graphCpuData)
}

function createCpuGraph(graphData) {
  var data = []
  var colors = []

  switch(cpuType)
  {
    case CPU_APP:
      for (i = 0; i < uniqClassList.length; ++i) {
        var classKey = uniqClassList[i]
        var classVal = uniqClass[classKey]
        for (j = 0; j < classVal.length; ++j)
        {
          var name = classVal[j].Name
          if (uniqApps[name].CpuDraw) {
            var cpuData = graphData[name]
            data.push({ data: cpuData, label: name})
            colors.push(uniqApps[name].color)
          }
        }
      }
    break
    case CPU_CLASS:
      for (i = 0; i < uniqClassList.length; ++i) {
        var name = uniqClassList[i]
        var cpuData = graphData[name]
        data.push({ data: cpuData, label: name})
        colors.push(uniqClass[name][0].color)
      }
    break
    case CPU_SUM:
      var cpuData = graphData["sum"]
      data.push({ data: cpuData, label: "sum"})
      colors.push("#777777")
    break
  }

  $('#cpu-chart').empty()
  var plot = $.plot($("#cpu-chart"),
  data, {
      series: {
          lines: {
            show: true,
            fill: true,
            fillColor: { colors: [{ opacity: 0.05 }, { opacity: 0.01 }]}
          },
          points: { show: true }
      },
      grid: { hoverable: true, clickable: true, borderWidth:0 },
      yaxis: { min: 0 },
      xaxis: { mode: "time", timeformat: "%H:%M:%S", minTickSize: [1, "second"] },
      colors: colors
    })

  var previousPoint = null
  $("#cpu-chart").bind("plothover", function (event, pos, item) {
    $("#x").text(pos.x.toFixed(2))
    $("#y").text(pos.y.toFixed(2))
    if (item) {
      if (previousPoint != item.dataIndex) {
        previousPoint = item.dataIndex
        $("#tooltip").remove()
        var x = item.datapoint[0].toFixed(2),
            y = item.datapoint[1].toFixed(2)
        showTooltip(item.pageX, item.pageY, item.series.label + " in "
          + timeConverter(x/1000, true) + " used " + y + "% CPU")
      }
    }
    else {
        $("#tooltip").remove()
        previousPoint = null
    }
  })

}
// CPU chart ends

// ------------------------------------------------------------------------- //
// Traffic chart starts
// ------------------------------------------------------------------------- //
var NETWORK_APP = 1
var NETWORK_CLASS = 2
var NETWORK_SUM = 3

var NETWORK_BYTES = 1
var NETWORK_PACKAGES = 2

var networkType = NETWORK_APP
var networkData = NETWORK_BYTES
var networkRx = true
var networkTx = true

function networkApp()
{
  networkType = NETWORK_APP
  setNetworkStatus(linkRaw)
}

function networkClass()
{
  networkType = NETWORK_CLASS
  setNetworkStatus(linkRaw)
}

function networkSum()
{
  networkType = NETWORK_SUM
  setNetworkStatus(linkRaw)
}

function switchNetworkRx()
{
  networkRx = !networkRx
  console.log(networkRx)
  setNetworkStatus(linkRaw)
}

function switchNetworkTx()
{
  networkTx = !networkTx
  console.log(networkTx)
  setNetworkStatus(linkRaw)
}

function networkBytes()
{
  networkData = NETWORK_BYTES
  setNetworkStatus(linkRaw)
}

function networkPackets()
{
  networkData = NETWORK_PACKAGES
  setNetworkStatus(linkRaw)
}

function toggleNetworkDrawCheckbox(element, key)
{
  console.log(key, element.checked)
  uniqApps[key].NetworkDraw = element.checked
  setNetworkStatus(linkRaw)
}

function sumIteration(currApp, currVal, currTime, bytes, packets, outBytes, outPackets, recordTime)
{
  var length = graphStepSeconds * 1000

  if (uniqApps[currApp].NetworkDraw) {
    if(!currVal[currApp]) {
      currVal[currApp] = {
        bytes: bytes,
        packets: packets,
        prevBytes: 0,
        prevPackets: 0,
        num: 1
      }
    }
    if(currTime == 0) {
      currTime = recordTime
    }
    else if (currTime + length < recordTime) {
      var NewValBytes = 0,
          NewValPackets = 0

      for (var app in currVal) {
        var currSum = (currVal[app].bytes / currVal[app].num - currVal[app].prevBytes)
        NewValBytes += currSum / graphStepSeconds > 1 ? currSum / graphStepSeconds : 1 // to see 0 on exp scale

        currSum = (currVal[app].packets / currVal[app].num - currVal[app].prevPackets)
        NewValPackets += currSum / graphStepSeconds > 1 ? currSum / graphStepSeconds : 1 // to see 0 on exp scale

        currVal[app].prevBytes = currVal[app].bytes / currVal[app].num
        currVal[app].prevPackets = currVal[app].packets / currVal[app].num
        if (app == currApp) {
          currVal[currApp].bytes = bytes
          currVal[currApp].packets = packets
          currVal[currApp].num = 1
        }
        else {
          currVal[app].bytes = 0
          currVal[app].packets = 0
          currVal[app].num = 0
        }
      }
      outBytes.push([currTime + length / 2, NewValBytes])
      outPackets.push([currTime + length / 2, NewValPackets])

      currTime = recordTime
    }
    else {
      currVal[currApp].bytes += bytes
      currVal[currApp].packets += packets
      currVal[currApp].num += 1
    }
  }
  return currTime
}

function setNetworkStatus(data) {
  var arrayLength = data.length

  var currValRx = { },
      currValTx = { },
      currTimeRx = { },
      currTimeTx = { },
      graphNetworkDataRxBytes = { },
      graphNetworkDataRxPackets = { },
      graphNetworkDataTxBytes = { },
      graphNetworkDataTxPackets = { },
      length = graphStepSeconds * 1000

  switch(networkType)
  {
    case NETWORK_APP:
      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var from = d.from_app
        var to = d.to_app

        if(!graphNetworkDataTxBytes[from]) { graphNetworkDataTxBytes[from] = [ ] }
        if(!graphNetworkDataTxPackets[from]) { graphNetworkDataTxPackets[from] = [ ] }
        if(!graphNetworkDataRxBytes[to]) { graphNetworkDataRxBytes[to] = [ ] }
        if(!graphNetworkDataRxPackets[to]) { graphNetworkDataRxPackets[to] = [ ] }
        if(!currValTx[from]) { currValTx[from] = { } }
        if(!currValRx[to]) { currValRx[to] = { } }
        if(!currTimeTx[from]) { currTimeTx[from] = 0 }
        if(!currTimeRx[to]) { currTimeRx[to] = 0 }

        var recordTime = parseFloat(d.time) * 1000

        currTimeTx[from] = sumIteration(
            from,
            currValTx[from],
            currTimeTx[from],
            parseFloat(d.txbytes),
            parseFloat(d.txpackets),
            graphNetworkDataTxBytes[from],
            graphNetworkDataTxPackets[from],
            recordTime
          )

        currTimeRx[to] = sumIteration(
            to,
            currValRx[to],
            currTimeRx[to],
            parseFloat(d.rxbytes),
            parseFloat(d.rxpackets),
            graphNetworkDataRxBytes[to],
            graphNetworkDataRxPackets[to],
            recordTime
          )
      }
    break

    case NETWORK_CLASS:
      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var fromApp = d.from_app
        var toApp = d.to_app
        var from = uniqApps[d.from_app].Class
        var to = uniqApps[d.to_app].Class

        if(!graphNetworkDataTxBytes[from]) { graphNetworkDataTxBytes[from] = [ ] }
        if(!graphNetworkDataTxPackets[from]) { graphNetworkDataTxPackets[from] = [ ] }
        if(!graphNetworkDataRxBytes[to]) { graphNetworkDataRxBytes[to] = [ ] }
        if(!graphNetworkDataRxPackets[to]) { graphNetworkDataRxPackets[to] = [ ] }
        if(!currValTx[from]) { currValTx[from] = { } }
        if(!currValRx[to]) { currValRx[to] = { } }
        if(!currTimeTx[from]) { currTimeTx[from] = 0 }
        if(!currTimeRx[to]) { currTimeRx[to] = 0 }

        var recordTime = parseFloat(d.time) * 1000

        currTimeTx[from] = sumIteration(
            fromApp,
            currValTx[from],
            currTimeTx[from],
            parseFloat(d.txbytes),
            parseFloat(d.txpackets),
            graphNetworkDataTxBytes[from],
            graphNetworkDataTxPackets[from],
            recordTime
          )

        currTimeRx[to] = sumIteration(
            toApp,
            currValRx[to],
            currTimeRx[to],
            parseFloat(d.rxbytes),
            parseFloat(d.rxpackets),
            graphNetworkDataRxBytes[to],
            graphNetworkDataRxPackets[to],
            recordTime
          )
      }
    break

    case NETWORK_SUM:
      var sum = "sum"
      currTimeTx = 0
      currTimeRx = 0

      if(!graphNetworkDataTxBytes[sum]) { graphNetworkDataTxBytes[sum] = [ ] }
      if(!graphNetworkDataTxPackets[sum]) { graphNetworkDataTxPackets[sum] = [ ] }
      if(!graphNetworkDataRxBytes[sum]) { graphNetworkDataRxBytes[sum] = [ ] }
      if(!graphNetworkDataRxPackets[sum]) { graphNetworkDataRxPackets[sum] = [ ] }

      for (var i = 0; i < arrayLength; i++) {
        var d = data[i]
        var from = d.from_app
        var to = d.to_app
        var recordTime = parseFloat(d.time) * 1000

        currTimeTx = sumIteration(
            from,
            currValTx,
            currTimeTx,
            parseFloat(d.txbytes),
            parseFloat(d.txpackets),
            graphNetworkDataTxBytes[sum],
            graphNetworkDataTxPackets[sum],
            recordTime
          )

        currTimeRx = sumIteration(
            to,
            currValRx,
            currTimeRx,
            parseFloat(d.rxbytes),
            parseFloat(d.rxpackets),
            graphNetworkDataRxBytes[sum],
            graphNetworkDataRxPackets[sum],
            recordTime
          )

      }
    // case ends
  }

  insertCheckboxes("NetworkChoices", "NetworkDraw")
  createTrafficGraph(
      graphNetworkDataRxBytes,
      graphNetworkDataRxPackets,
      graphNetworkDataTxBytes,
      graphNetworkDataTxPackets
    )
}

function checkNotEmpty(dataObject) {
  return dataObject && dataObject.length
}

function createTrafficGraph(rxBytes, rxPackets, txBytes, txPackets) {
  var data = [ ]
  var colors = [ ]

  switch(networkType || NETWORK_APP)
  {
    case NETWORK_APP:
      for (i = 0; i < uniqClassList.length; ++i) {
        var classKey = uniqClassList[i]
        var classVal = uniqClass[classKey]
        for (j = 0; j < classVal.length; ++j)
        {
          var name = classVal[j].Name
          if (uniqApps[name].NetworkDraw) {
            switch(networkData)
            {
              case NETWORK_BYTES:
                if(networkRx) {
                  data.push({ data: rxBytes[name], label: name + ".rx"})
                  colors.push(d3.rgb(uniqApps[name].color).darker(0.5))
                }
                if(networkTx) {
                  data.push({ data: txBytes[name], label: name + ".tx"})
                  colors.push(d3.rgb(uniqApps[name].color).brighter(0.5))
                }
              break

              case NETWORK_PACKAGES:
                if(networkRx) {
                  data.push({ data: rxPackets[name], label: name + ".rx"})
                  colors.push(d3.rgb(uniqApps[name].color).darker(0.5))
                }
                if(networkTx) {
                  data.push({ data: txPackets[name], label: name + ".tx"})
                  colors.push(d3.rgb(uniqApps[name].color).brighter(0.5))
                }

            }
          }
        }
      }
    break
    case NETWORK_CLASS:
      for (i = 0; i < uniqClassList.length; ++i) {
        var name = uniqClassList[i]
        switch(networkData)
        {
          case NETWORK_BYTES:
            if(networkRx) {
              if(checkNotEmpty(rxBytes[name])) {
                data.push({ data: rxBytes[name], label: name + ".rx"})
                colors.push(d3.rgb(uniqClass[name][0].color).darker(0.5))
              }
            }
            if(networkTx) {
              if(checkNotEmpty(txBytes[name])) {
                data.push({ data: txBytes[name], label: name + ".tx"})
                colors.push(d3.rgb(uniqClass[name][0].color).brighter(0.5))
              }
            }
          break
          case NETWORK_PACKAGES:
            if(networkRx) {
              if(checkNotEmpty(rxPackets[name])) {
                data.push({ data: rxPackets[name], label: name + ".rx"})
                colors.push(d3.rgb(uniqClass[name][0].color).darker(0.5))
              }
            }
            if(networkTx) {
              if(checkNotEmpty(txPackets[name])) {
                data.push({ data: txPackets[name], label: name + ".tx"})
                colors.push(d3.rgb(uniqClass[name][0].color).brighter(0.5))
              }
            }
        }
      }
    break
    case NETWORK_SUM:
      switch(networkData)
      {
        case NETWORK_BYTES:
          if(networkRx) {
            data.push({ data: rxBytes["sum"], label: "sum.rx"})
            colors.push(d3.rgb("#777777").darker(0.5))
          }
          if(networkTx) {
            data.push({ data: txBytes["sum"], label: "sum.tx"})
            colors.push(d3.rgb("#777777").brighter(0.5))
          }
        break
        case NETWORK_PACKAGES:
          if(networkRx) {
            data.push({ data: rxPackets["sum"], label: "sum.rx"})
            colors.push(d3.rgb("#777777").darker(0.5))
          }
          if(networkTx) {
            data.push({ data: txPackets["sum"], label: "sum.tx"})
            colors.push(d3.rgb("#777777").brighter(0.5))
          }
      }
    break
  }

  switch(networkData)
  {
    case NETWORK_BYTES:
      var plot = $.plot($("#traffic-chart"),
      data, {
          series: {
              lines: {
                show: true,
                fill: true,
                fillColor: { colors: [{ opacity: 0.05 }, { opacity: 0.01 }]}
              },
              points: { show: true }
          },
          yaxis: {
            min: 1,
            max: 1024 * 1024 * 1024 * 1024,
            mode: "byte",
            axisLabel: "Bytes of data",
            transform: function(v) {return Math.log(v + 1);},
            ticks: [
              1,
              1024,
              10 * 1024,
              100 * 1024,
              1024 * 1024,
              10 * 1024 * 1024,
              100 * 1024 * 1024,
              1024 * 1024 * 1024,
              10 * 1024 * 1024 * 1024,
              100 * 1024 * 1024 * 1024,
              1024 * 1024 * 1024 * 1024
            ],
            tickDecimals: 0
          },
          grid: { hoverable: true, clickable: true, borderWidth:0 },
          xaxis: { mode: "time", timeformat: "%H:%M:%S", minTickSize: [1, "second"] },
          colors: colors
        })

      var previousPoint = null
      $("#traffic-chart").bind("plothover", function (event, pos, item) {

        $("#x").text(pos.x.toFixed(2))
        $("#y").text(pos.y.toFixed(2))

        if (item) {
          if (previousPoint != item.dataIndex) {
            previousPoint = item.dataIndex

            $("#tooltip").remove()
            var x = item.datapoint[0].toFixed(2),
                y = item.datapoint[1].toFixed(2)
            showTooltip(item.pageX, item.pageY, item.series.label + " in "
              + timeConverter(x/1000, true) + " sent " + (y - 1) + "bytes")
          }
        }
        else {
            $("#tooltip").remove()
            previousPoint = null
        }
      })
    break

    case NETWORK_PACKAGES:
      var plot = $.plot($("#traffic-chart"),
      data, {
          series: {
              lines: {
                show: true,
                fill: true,
                fillColor: { colors: [{ opacity: 0.05 }, { opacity: 0.01 }]}
              },
              points: { show: true }
          },
          grid: { hoverable: true, clickable: true, borderWidth:0 },
          xaxis: { mode: "time", timeformat: "%H:%M:%S", minTickSize: [1, "second"] },
          colors: colors
        })

      var previousPoint = null
      $("#traffic-chart").bind("plothover", function (event, pos, item) {

        $("#x").text(pos.x.toFixed(2))
        $("#y").text(pos.y.toFixed(2))

        if (item) {
          if (previousPoint != item.dataIndex) {
            previousPoint = item.dataIndex

            $("#tooltip").remove()
            var x = item.datapoint[0].toFixed(2),
                y = item.datapoint[1].toFixed(2)
            showTooltip(item.pageX, item.pageY, item.series.label + " in "
              + timeConverter(x/1000, true) + " sent " + (y - 1) + "<br /> packages")
          }
        }
        else {
            $("#tooltip").remove()
            previousPoint = null
        }
      })
  }
}
// Traffic charts ends
