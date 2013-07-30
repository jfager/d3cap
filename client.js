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

        // if(active) {
        //     tabTop.attr("class", "active");
        //     tabCont.attr("class", "tab-pane active");
        // } else {
            tabCont.attr("class", "tab-pane");
        // }

        return tabCont.append("svg").attr("width", width).attr("height", height);
    }

    function mkTableTab() {
        var boundary = $('.tab-content');
        var width = boundary[0].offsetWidth;
        var height = width * 0.66;
        var tabTop = d3.select('#force-graph-tabs')
            .append("li")
            .append("a").attr("href", "#tab_ws_log").attr("data-toggle", "tab")
            .text("log");
        var tabCont = d3.select('#force-graph-contents')
            .append("div").attr("id", "tab_ws_log");

        // if(active) {
             tabTop.attr("class", "active");
             tabCont.attr("class", "tab-pane active");
        // } else {
        //     tabCont.attr("class", "tab-pane");
        // }

        return tabCont.append("table");
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
            nodeMap: {},
            links: links,
            chart: chart,
            force: force
        };
    }

    function mkTable() {
        var table = mkTableTab();

        return {
            pairs: [],
            pairMap: {},
            table: table
        }
    }

    var table = mkTable();

    function updateTable(t, msg) {
        var pair = [msg.src, msg.dst];
        pair.sort();
        var i = t.pairMap[pair];
        if(i === undefined) {
            i = t.pairs.length;
            t.pairs.push({ a: pair[0], b: pair[1], total: 0, from_a: 0, from_b: 0 });
            t.pairMap[pair] = i;
        }

        var pairData = t.pairs[i];
        pairData.total += msg.size;
        if(msg.src == pair[0]) {
            pairData.from_a += msg.size;
        } else {
            pairData.from_b += msg.size;
        }

        var ps = t.table.selectAll("tr").data(t.pairs);
        ps.enter().append("tr");
        ps.html(mkRow);

        // var lis = ps.data(t.pairs).enter().insert("div").attr("class", "row");
        // lis.append("div").attr("class", "addr_a col-2");
        // lis.append("div").attr("class", "addr_b col-2");
        // lis.append("div").attr("class", "size_t col-2");
        // lis.append("div").attr("class", "size_a col-2");
        // lis.append("div").attr("class", "size_b col-2");

        ps.sort(function(p1,p2) { return -cmp(p1.total, p2.total); });
    }

    function mkRow(d) {
        return "<td class='addr_a'>"+d.a+"</td>" +
               "<td class='addr_b'>"+d.b+"</td>" +
               "<td class='size_t'>"+d.total+"</td>" +
               "<td class='size_a'>"+d.from_a+"</td>" +
               "<td class='size_b'>"+d.from_b+"</td>";
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
            updateTable(table, msg);
            var c = types[msg.type];
            if(!c) {
                return;
            }
            c.conns.push(msg);
            var s = c.nodeMap[msg.src];
            var updateLinks = false;
            if(s === undefined) {
                s = c.nodes.length;
                c.nodes.push({addr: msg.src,
                              size: msg.size,
                              displaySize: displaySize(msg.size)});
                c.nodeMap[msg.src] = s;
                updateLinks = true;
            } else {
                var node = c.nodes[s];
                node.size += msg.size;
                node.displaySize = displaySize(node.size);
            }
            var d = c.nodeMap[msg.dst];
            if(d === undefined) {
                d = c.nodes.length;
                c.nodes.push({addr: msg.dst, size: 1, displaySize: 1});
                c.nodeMap[msg.dst] = d;
                updateLinks = true;
            }
            if(updateLinks) {
                c.links.push({source: s, target: d});
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
