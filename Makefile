R2_LIBEXT  ?= $(shell r2 -H R2_LIBEXT)
R2_PLUGINS ?= $(shell r2 -H R2_USER_PLUGINS)

build:
	cargo build --release

install: build
	mkdir -p $(R2_PLUGINS)
	cp target/release/libcore_warp.$(R2_LIBEXT) $(R2_PLUGINS)/core_warp.$(R2_LIBEXT)

test:
	cargo test --lib

clean:
	cargo clean

fmt:
	cargo fmt

check:
	cargo check --all-targets

clippy:
	cargo clippy -- -D warnings

all: build

.PHONY: all build install clean test fmt check clippy
