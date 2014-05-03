var width = $('#d3-graph').width(),
    height = 500,
    r = 30

var color = d3.scale.category10()

var nodes = [],
    links = [],
    uniq_links = {},
    uniq_nodes = {}

var force = d3.layout.force()
    .nodes(nodes)
    .links(links)
    .charge(-800)
    .linkDistance(120)
    .size([width, height])
    .on("tick", tick)

var svg = d3.select("#d3-graph").append("svg")
    .attr("width", width)
    .attr("height", height)

var node = svg.selectAll(".node"),
    link = svg.selectAll(".link")

// Reload data from data path
function reinitializeD3Structure(data) {
  var arrayLength = data.length
  for (var i = 0; i < arrayLength; i++) {
    var d = data[i]
    var source = d.from_app
    var target = d.to_app

    if(!uniq_nodes[source]) {
      uniq_nodes[source] = { id:source }
      nodes.push(uniq_nodes[source])
    }
    if(!uniq_nodes[target]) {
      uniq_nodes[target] = { id:target }
      nodes.push(uniq_nodes[target])
    }
    if(uniq_links[source.concat(target)] !== true) {
      uniq_links[source.concat(target)] = true
      links.push({ source:uniq_nodes[source], target:uniq_nodes[target] })
    }
  }

  start()
}

function start() {
  link = link.data(force.links(), function(d) { return d.source.id + "-" + d.target.id; })
  link.enter().insert("line", ".node").attr("class", "link")
  link.exit().remove()

  node = node.data(force.nodes(), function(d) { return d.id;})
  var g = node.enter().append('svg:g')
  g.append('svg:circle')
    .attr("fill", function(d) { return uniqApps[d.id].color })
    .attr('r', r)
  g.append('svg:text')
    .attr("text-anchor", "middle")
    .attr('x', 0)
    .attr('y', 4)
    .text(function(d) { return d.id; })
  node.exit().remove()

  force.start()
}

function tick() {
  node.attr('transform', function(d)
  {
    return 'translate(' + (d.x || 1) + ',' + (d.y || 1) + ')'
  })

  function distance(d, coords) {
    var deltaX = d.target.x - d.source.x,
        deltaY = d.target.y - d.source.y,
        dist = Math.sqrt(deltaX * deltaX + deltaY * deltaY),
        normX = deltaX / dist,
        normY = deltaY / dist,
        sourcePadding = r + 3,
        targetPadding = r + 3

    if (coords === "x1") { return d.source.x + (sourcePadding * normX) }
    if (coords === "y1") { return d.source.y + (sourcePadding * normY) }
    if (coords === "x2") { return d.target.x - (targetPadding * normX) }
    if (coords === "y2") { return d.target.y - (targetPadding * normY) }
  }

  link.attr("x1", function(d) { return distance(d, "x1") })
      .attr("y1", function(d) { return distance(d, "y1") })
      .attr("x2", function(d) { return distance(d, "x2") })
      .attr("y2", function(d) { return distance(d, "y2") })
}
