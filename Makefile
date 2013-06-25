RUSTC?=rustc
RUSTFLAGS?=--cfg ndebug --cfg ncpuspew -O
RUSTLDFLAGS?=-L .

.PHONY: all
all:	hud

hud:	hud.rc rustwebsocket.rs rustpcap.rs main.rs
		$(RUSTC) $(RUSTFLAGS) $(RUSTLDFLAGS) $< -o $@

.PHONY: clean
clean:
		rm -f hud
