# Makefile for WARP radare2 plugin

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LIB_EXT = so
endif
ifeq ($(UNAME_S),Darwin)
	LIB_EXT = dylib
endif

# Rust target
ifeq ($(UNAME_S),Linux)
	RUST_TARGET = x86_64-unknown-linux-gnu
endif
ifeq ($(UNAME_S),Darwin)
	RUST_TARGET = x86_64-apple-darwin
endif

# radare2 plugin directory
R2_PLUGINS = $(HOME)/.local/share/radare2/plugins

.PPHONY: all build install clean test

all: build

build:
	cargo build --release
	ln -sf target/release/libcore_warp.$(LIB_EXT) core_warp.$(LIB_EXT)

install: build
	mkdir -p $(R2_PLUGINS)
	cp target/release/libcore_warp.$(LIB_EXT) $(R2_PLUGINS)/core_warp.$(LIB_EXT)

test:
	cargo test

clean:
	cargo clean
	rm -f core_warp.$(LIB_EXT)

# Development targets
fmt:
	cargo fmt

check:
	cargo check --all-targets

clippy:
	cargo clippy -- -D warnings

.PHONY: all build install clean test fmt check clippy