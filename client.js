$(document).ready(function() {

    var ws;

    function mkForce(nodes, links, width, height) {
        return d3.layout.force()
            .nodes(nodes)
            .links(links)
            .gravity(0.05)
            .distance(function(l) { return 30 + 1.5 * (l.source.displaySize +
                                                       l.target.displaySize); })
            .charge(function(d) { return -100 - d.displaySize; })
            .size([width, height]);
    }

    //TODO:  this shouldn't append svg, leave that to the specific tabs
    function mkTab(tabId, tabText, active) {
        var tabTop = d3.select('#force-graph-tabs')
            .append("li")
            .append("a").attr("href", "#"+tabId).attr("data-toggle", "tab")
            .text(tabText);
        var tabCont = d3.select('#force-graph-contents')
            .append("div").attr("id", tabId);

        if(active) {
            tabTop.attr("class", "active");
            tabCont.attr("class", "tab-pane active");
        } else {
            tabCont.attr("class", "tab-pane");
        }

        return tabCont;
    }

    function mkConnsTab(tabId, type, active) {
        var boundary = $('.tab-content');
        var width = boundary[0].offsetWidth;
        var height = width * 0.66;
        return mkTab(tabId, type, active)
            .append("svg").attr("width", width)
                          .attr("height", height);
    }

    function mkConns(type, active) {
        var tabId = "tab_"+type;
        var chart = mkConnsTab(tabId, type, active);

        var width = chart.attr("width");
        var height = chart.attr("height");
        var nodes = [], links = [];

        var force = mkForce(nodes, links, width, height);
        force.on("tick", function() {
            chart.selectAll(".link")
                .attr("x1", function(d) { return d.source.x; })
                .attr("y1", function(d) { return d.source.y; })
                .attr("x2", function(d) { return d.target.x; })
                .attr("y2", function(d) { return d.target.y; });
            chart.selectAll(".node")
                .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        });

        return {
            nodes: nodes,
            nodeMap: {},
            links: links,
            linkNodes: {},
            chart: chart,
            force: force
        };
    }

    function cmp() {
        for(var i=0; i<arguments.length; i+=2) {
            var a = arguments[i];
            var b = arguments[i+1];
            if(a < b) {
                return -1;
            } else if(a > b) {
                return 1;
            }
        }
        return 0;
    }

    function displaySize(size) {
        return 2 + Math.sqrt(size / Math.PI) / 120;
    }

    var types = {
        'ip4': mkConns('ip4', true),
        'ip6': mkConns('ip6', false),
        'mac': mkConns('mac', false)
    };

    var pie = d3.layout.pie()
        .value(function(d) { return d.sz; })
        .sort(null);

    var color = d3.scale.category10();

    var update = function(c) {
        c.force.start();
        c.chart.selectAll(".link")
            .data(c.links)
            .enter().insert("line", "g")
            .attr("class", "link")
            .style("stroke-width", function(d) { return Math.sqrt(d.value); });

        var nodes = c.chart.selectAll(".node").data(c.nodes);
        var newNodes = nodes.enter()
            .append("svg:g")
            .attr("class", "node")
            .call(c.force.drag);

        newNodes.append("svg:text")
            .attr("class", "nodetext")
            .attr("dx", 12)
            .attr("dy", ".35em")
            .text(function(d) { return d.addr; });


        //update size for all nodes, not just new ones.
        var arcs = nodes.selectAll(".slice")
            .data(function(d) { return pie([{r:d.displaySize, sz: d.sizeFrom},
                                            {r:d.displaySize, sz: d.sizeTo}]); });

        arcs.enter()
            .append("svg:path")
            .attr("class", "slice")
            .attr("fill", function(d, i) { return color(i); });

        arcs.attr("d", function(d) {
            return d3.svg.arc()
                .innerRadius(d.data.r * 0.4)
                .outerRadius(d.data.r)(d);
        });
    };



    function updateNode(c, addr, countFrom, sizeFrom, countTo, sizeTo) {
        var updateLinks = false;
        var index = c.nodeMap[addr];
        if(index === undefined) {
            index = c.nodes.length;
            c.nodes.push({addr: addr,
                          countFrom: countFrom,
                          sizeFrom: sizeFrom,
                          countTo: countTo,
                          sizeTo: sizeTo,
                          displaySize: displaySize(sizeFrom+sizeTo)});
            c.nodeMap[addr] = index;
            updateLinks = true;
        } else {
            var node = c.nodes[index];
            node.countFrom += countFrom;
            node.sizeFrom += sizeFrom;
            node.countTo += countTo;
            node.sizeTo += sizeTo;
            node.displaySize = displaySize(node.sizeFrom+node.sizeTo);
        }
        return updateLinks;
    }

    $('#connectForm').on('submit', function() {
        ws = new WebSocket($('#wsServer').val());
        ws.onopen = function() {
            console.log("websocket opened");
            $('#wsServer').attr('disabled', 'disabled');
            $('#connect').attr('disabled', 'disabled');
            $('#disconnect').removeAttr('disabled');
            $('#message').removeAttr('disabled').focus();
            $('#send').removeAttr('disabled');
        };

        ws.onerror = function() {
            console.log("websocket error");
            ws.close();
        };

        ws.onmessage = function(event) {
            var msg = JSON.parse(event.data);
            var c = types[msg.type];
            if(!c) {
                return;
            }

            var linkKey = msg.a+"_"+msg.b;
            var oldLinkNode = c.linkNodes[linkKey];
            if(oldLinkNode) {
                var oldA = c.nodes[c.nodeMap[oldLinkNode.a]];
                oldA.countFrom -= oldLinkNode.from_a_count;
                oldA.sizeFrom -= oldLinkNode.from_a_size;
                oldA.countTo -= oldLinkNode.from_b_count;
                oldA.sizeTo -= oldLinkNode.from_b_size;

                var oldB = c.nodes[c.nodeMap[oldLinkNode.b]];
                oldB.countFrom -= oldLinkNode.from_b_count;
                oldB.sizeFrom -= oldLinkNode.from_b_size;
                oldB.countTo -= oldLinkNode.from_a_count;
                oldB.sizeTo -= oldLinkNode.from_a_size;
            }
            c.linkNodes[linkKey] = msg;

            //bitwise-or to avoid short-circuit
            var updateLinks = updateNode(c, msg.a, msg.from_a_count, msg.from_a_size, msg.from_b_count, msg.from_b_size)
                            | updateNode(c, msg.b, msg.from_b_count, msg.from_b_size, msg.from_a_count, msg.from_a_size);

            if(updateLinks) {
                c.links.push({source: c.nodeMap[msg.a],
                              target: c.nodeMap[msg.b]});
            }

            update(c);
        };

        ws.onclose = function() {
            console.log("websocket closed");
            $('#wsServer').removeAttr('disabled');
            $('#connect').removeAttr('disabled');
            $('#disconnect').attr('disabled', 'disabled');
            $('#message').attr('disabled', 'disabled');
            $('#send').attr('disabled', 'disabled');
        };

        (function() {
            if(ws.readyState === 1) {
                ws.send("ping");
            }
            if(ws.readyState !== 3) {
                setTimeout(arguments.callee, 1000);
            }
        })();

        return false;
    });
    $('#disconnect').on('click', function() {
        ws.close();
        return false;
    });
});
