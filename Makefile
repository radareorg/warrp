R2_LIBEXT  ?= $(shell r2 -H R2_LIBEXT)
R2_PLUGINS ?= $(shell r2 -H R2_USER_PLUGINS)

build:
	cargo build --release

ifeq ($(R2_LIBEXT),dll)
install: build
	if not exist "$(R2_PLUGINS)" mkdir "$(R2_PLUGINS)"
	copy target\release\core_warp.$(R2_LIBEXT) $(R2_PLUGINS)\core_warp.$(R2_LIBEXT)
else
install: build
	mkdir -p $(R2_PLUGINS)
	cp target/release/libcore_warp.$(R2_LIBEXT) $(R2_PLUGINS)/libcore_warp.$(R2_LIBEXT)
endif

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
