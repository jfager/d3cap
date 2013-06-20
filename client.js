$(document).ready(function() {
    var ws;
    var conns = [];
    var chart = d3.select('#log');

    var update = function() {
        chart.selectAll("li")
            .data(conns, function(d) { return d.conn_id; })
            .enter()
            .append("li")
            .text(function(d) { return "received: " + JSON.stringify(d); });
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
                conns.push(msg);
                update();
                ws.send("ack");
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
                    setTimeout(arguments.callee, 2000);
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
