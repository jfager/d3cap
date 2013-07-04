$(document).ready(function() {


    // var link = svg.selectAll(".link")
    //     .data(links)
    //     .enter().append("line")
    //     .attr("class", "link");

    // var node = svg.selectAll(".node")
    //     .data(nodes)
    //     .enter().append("g")
    //     .attr("class", "node")
    //     .call(force.drag);

    // node.append("image")
    //     .attr("xlink:href", "https://github.com/favicon.ico")
    //     .attr("x", -8)
    //     .attr("y", -8)
    //     .attr("width", 16)
    //     .attr("height", 16);

    // node.append("text")
    //     .attr("dx", 12)
    //     .attr("dy", ".35em")
    //     .text(function(d) { return d.name });

    // force.on("tick", function() {
    //     link.attr("x1", function(d) { return d.source.x; })
    //         .attr("y1", function(d) { return d.source.y; })
    //         .attr("x2", function(d) { return d.target.x; })
    //         .attr("y2", function(d) { return d.target.y; });

    //     node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
    // });

    var ws;

    function mkForce(nodes, links, width, height) {
        return d3.layout.force()
            .nodes(nodes)
            .links(links)
            .gravity(.05)
            .distance(100)
            .charge(-100)
            .size([width, height]);


        return force;
    }

    function mkConns() {
        var nodes = [], links = [];
        var width = 1000, height = 300;
        var out = {
            conns: [],
            nodes: nodes,
            nodeSet: {},
            links: links,
            chart: d3.select('#log').append("svg").attr("width", width).attr("height", height),
            force: mkForce(nodes, links, width, height)
        };

        out.force.on("tick", function() {
            out.chart.selectAll(".link")
                .attr("x1", function(d) { return d.source.x; })
                .attr("y1", function(d) { return d.source.y; })
                .attr("x2", function(d) { return d.target.x; })
                .attr("y2", function(d) { return d.target.y; });
            out.chart.selectAll(".node")
                .attr("cx", function(d) { return d.x; })
                .attr("cy", function(d) { return d.y; });
        });

        return out;
    }

    var types = {
        'ip4': mkConns(),
        //'ip6': mkConns(),
        'mac': mkConns()
    };

    var update = function(c) {
        c.force.start();
        c.chart.selectAll(".link")
            .data(c.links)
            .enter().insert("line", "circle")
            .attr("class", "link")
            .style("stroke-width", function(d) { return Math.sqrt(d.value); });
        c.chart.selectAll(".node")
            .data(c.nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", 5)
            .call(c.force.drag);
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
                    c.nodes.push({addr: msg.src});
                    c.nodeSet[msg.src] = s;
                    updateLinks = true;
                }
                var d = c.nodeSet[msg.dst];
                if(d === undefined) {
                    d = c.nodes.length;
                    c.nodes.push({addr: msg.dst});
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
