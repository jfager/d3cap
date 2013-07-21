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

    function mkChartTab(tabId, tabText, active) {
        var boundary = $('.tab-content');
        var width = boundary[0].offsetWidth;
        var height = width * 0.66;
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

        return tabCont.append("svg").attr("width", width).attr("height", height);
    }

    function mkConns(type, active) {
        var tabId = "tab_"+type;
        var chart = mkChartTab(tabId, type, active);

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
            conns: [],
            nodes: nodes,
            nodeSet: {},
            links: links,
            chart: chart,
            force: force
        };
    }

    function displaySize(size) {
        return 2 + Math.sqrt(size / Math.PI) / 120;
    }

    var types = {
        'ip4': mkConns('ip4', true),
        'ip6': mkConns('ip6', false),
        'mac': mkConns('mac', false)
    };

    var update = function(c) {
        c.force.start();
        c.chart.selectAll(".link")
            .data(c.links)
            .enter().insert("line", "g")
            .attr("class", "link")
            .style("stroke-width", function(d) { return Math.sqrt(d.value); });

        var nodes = c.chart.selectAll(".node");
        var newNodes = nodes.data(c.nodes).enter()
            .append("svg:g")
            .attr("class", "node")
            .call(c.force.drag);

        newNodes.append("svg:circle");

        newNodes.append("svg:text")
            .attr("class", "nodetext")
            .attr("dx", 12)
            .attr("dy", ".35em")
            .text(function(d) { return d.addr; });

        //update size for all nodes, not just new ones.
        nodes.selectAll("circle").attr("r", function(d) {
            return d.displaySize;
        });
    };

    $('#connectForm').on('submit', function() {
        if ("WebSocket" in window) {
            ws = new WebSocket($('#wsServer').val());
            ws.onopen = function() {
                $('#ws_log').append('<li><span class="badge badge-success">websocket opened</span></li>');

                $('#wsServer').attr('disabled', 'disabled');
                $('#connect').attr('disabled', 'disabled');
                $('#disconnect').removeAttr('disabled');
                $('#message').removeAttr('disabled').focus();
                $('#send').removeAttr('disabled');
            };

            ws.onerror = function() {
                $('#ws_log').append('<li><span class="badge badge-important">websocket error</span></li>');
                ws.close();
            };

            ws.onmessage = function(event) {
                var msg = JSON.parse(event.data);
                $('#ws_log').append("<li>received: " + JSON.stringify(msg) + "</li>");
                var c = types[msg.type];
                if(!c) {
                    return;
                }
                c.conns.push(msg);
                var s = c.nodeSet[msg.src];
                var updateLinks = false;
                if(s === undefined) {
                    s = c.nodes.length;
                    c.nodes.push({addr: msg.src,
                                  size: msg.size,
                                  displaySize: displaySize(msg.size)});
                    c.nodeSet[msg.src] = s;
                    updateLinks = true;
                } else {
                    var node = c.nodes[s];
                    node.size += msg.size;
                    node.displaySize = displaySize(node.size);
                }
                var d = c.nodeSet[msg.dst];
                if(d === undefined) {
                    d = c.nodes.length;
                    c.nodes.push({addr: msg.dst, size: 1, displaySize: 1});
                    c.nodeSet[msg.dst] = d;
                    updateLinks = true;
                }
                if(updateLinks) {
                    c.links.push({source: s, target: d});
                }

                update(c);
            };

            ws.onclose = function() {
                $('#ws_log').append('<li><span class="badge badge-important">websocket closed</span></li>');
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
        } else {
            $('#ws_log').append('<li><span class="badge badge-important">WebSocket NOT supported in this browser</span></li>');
        }

        return false;
    });
    $('#disconnect').on('click', function() {
        ws.close();
        return false;
    });
});
