RUSTC?=rustc
RUST_FLAGS?=--cfg ndebug --cfg ncpuspew
RUST_DBG_FLAGS?=-Z debug-info
RUST_LD_FLAGS?=-L../rust-openssl/build -Lbuild/pcap

D3CAP=build/d3cap/d3cap
PCAP=build/pcap/libpcap*.rlib

.PHONY: all
all:  $(D3CAP)

.PHONY: clean
clean:
	rm -rf build

run: $(D3CAP)
	./build/d3cap/d3cap

$(D3CAP): src/d3cap/*.rs $(PCAP)
	mkdir -p build/d3cap
	$(RUSTC) $(RUST_FLAGS) $(RUST_LD_FLAGS) src/d3cap/main.rs --out-dir build/d3cap/

$(PCAP): src/pcap/*.rs
	mkdir -p build/pcap
	$(RUSTC) $(RUST_FLAGS) src/pcap/lib.rs --out-dir build/pcap/
