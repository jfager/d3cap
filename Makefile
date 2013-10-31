RUSTC?=rustc
RUST_FLAGS?=--cfg ndebug --cfg ncpuspew
RUST_DBG_FLAGS?=-Z debug-info
RUST_LD_FLAGS?=-L../rustcrypto

.PHONY: all
all:	d3cap

d3cap:	d3cap.rs rustwebsocket.rs rustpcap.rs ring.rs
		$(RUSTC) $(RUST_FLAGS) $(RUST_LD_FLAGS) $< -o $@

.PHONY: clean
clean:
		rm -rf d3cap d3capdbg *.dSYM *.o

run:	d3cap
		./d3cap

d3capdbg: d3cap.rs rustwebsocket.rs rustpcap.rs ring.rs
		$(RUSTC) $(RUST_DBG_FLAGS) $(RUST_LD_FLAGS) $< -o $@

debug:  d3capdbg
		gdb d3capdbg
