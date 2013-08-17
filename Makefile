RUSTC?=rustc
RUST_FLAGS?=--cfg ndebug --cfg ncpuspew
RUST_DBG_FLAGS?=-Z debug-info
RUST_LD_FLAGS?=-L .

.PHONY: all
all:	hud

hud:	hud.rs rustwebsocket.rs rustpcap.rs ring.rs
		$(RUSTC) $(RUST_FLAGS) $(RUST_LD_FLAGS) $< -o $@

.PHONY: clean
clean:
		rm -rf hud huddbg *.dSYM *.o

run:	hud
		./hud

huddbg: hud.rs rustwebsocket.rs rustpcap.rs ring.rs
		$(RUSTC) $(RUST_DBG_FLAGS) $(RUST_LD_FLAGS) $< -o $@

debug:  huddbg
		gdb huddbg
