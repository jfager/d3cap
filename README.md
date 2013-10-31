# d3cap

A [libpcap]-based network activity visualizer / playground for learning [d3] and [Rust].

[libpcap]: http://www.tcpdump.org/
[d3]: http://d3js.org/
[rust]: http://www.rust-lang.org/

Includes half-assed rust bindings for libpcap and a quarter-assed rust websocket server implementation.

To run, you need libpcap installed and a recent rust compiler (I try to track rust master).  Due to crypto code being pulled out of core rust, you'll also need the openssl bindings provided by the [rustcrypto] project (d3cap's Makefile assumes that this is checked out and built in a sibling directory).

[rustcrypto]: https://github.com/kballard/rustcrypto

Once your deps are set up, to build

    $ git clone https://github.com/jfager/d3cap.git
    $ cd d3cap
    $ make run

I'm going to try to convert to rustpkg at some point soon, which should make all this much easier.

Open d3cap/client.html in a browser and hit the Connect button to attach to this running backend and you should start seeing network activity pop up, like so:

![](https://raw.github.com/jfager/d3cap/master/d3cap.png "d3cap")

The size of each node indicates how much data has passed through the corresponding host, with blue and orange showing the proportion sent and received.  You can mouse over a node to see the corresponding address.
