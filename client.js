$(document).ready(function() {
    var ws;

    function mkConns() {
        return {
            conns: [],
            chart: d3.select('#log').append("svg").attr("width", 1000).attr("height", 200)
        };
    }

    var types = {
        'mac': mkConns(),
        'ip4': mkConns(),
        'ip6': mkConns()
    };

    var update = function(c) {
        c.chart.selectAll("circle")
            .data(c.conns, function(d) { return d.conn_id; })
            .enter()
            .append("circle")
            .attr("class", function(d) { return d.type; })
            .attr("cx", function(d, i) { return (i * 50) + 25; })
            .attr("cy", 200)
            .attr("r", 10);
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
                c.conns.push(msg);
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
    /*$('#sendForm').on('submit', function() {
        var message = $('#message').val();
        ws.send(message);
        $('#log').append('<li>sended: <span class="badge">' + message + '</span></li>');

        return false;
    });*/
    $('#disconnect').on('click', function() {
        ws.close();

        return false;
    });
});
