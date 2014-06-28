# d3cap

A [libpcap]-based network activity visualizer / playground for learning [d3] and [Rust].

[libpcap]: http://www.tcpdump.org/
[d3]: http://d3js.org/
[rust]: http://www.rust-lang.org/

Includes half-assed rust bindings for libpcap and a quarter-assed rust websocket server implementation.

To try it out, you'll need libpcap installed and a recent rust compiler.  Once these are set up, clone the project and use [cargo] to build, like so:

[cargo]: http://crates.io

    $ git clone https://github.com/jfager/d3cap.git
    $ cd d3cap
    $ cargo build

The resulting binary ends up in target/d3cap.  Run this and open src/client/client.html in a browser and hit the Connect button, and you should start seeing network activity pop up:

![](https://raw.github.com/jfager/d3cap/master/d3cap.png "d3cap")

The size of each node indicates how much data has passed through the corresponding host, with blue and orange showing the proportion sent and received.  You can mouse over a node to see the corresponding address.
