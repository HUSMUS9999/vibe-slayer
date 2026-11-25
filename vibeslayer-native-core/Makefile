ROOT_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
BIN_DIR  := $(ROOT_DIR)/bin
REPO_ROOT := $(abspath $(ROOT_DIR)/..)
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
  CET_CFLAGS := -fcf-protection=full
  CET_LDFLAGS := -Wl,-z,ibt,-z,shstk
else
  CET_CFLAGS :=
  CET_LDFLAGS :=
endif

RUST_SRCS := $(wildcard $(REPO_ROOT)/Cargo.toml $(REPO_ROOT)/crates/*/Cargo.toml $(REPO_ROOT)/crates/*/src/*.rs $(ROOT_DIR)/rust_core/Cargo.toml $(ROOT_DIR)/rust_core/src/*.rs)

.PHONY: all windows cross test bench clean

# Default target builds native host Linux artifacts (no Windows cross-compiler required)
all: $(BIN_DIR)/vibeslayer $(BIN_DIR)/vibe-slayer $(REPO_ROOT)/vibe-slayer $(BIN_DIR)/libvibeslayer.so $(BIN_DIR)/test_c_sdk

# Optional Windows PE32+ cross-build (requires rustup target x86_64-pc-windows-gnu & x86_64-w64-mingw32-gcc)
windows: $(BIN_DIR)/vibeslayer.exe $(BIN_DIR)/vibe-slayer.exe $(BIN_DIR)/vibeslayer.dll

cross: all windows

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/vibeslayer: $(RUST_SRCS) | $(BIN_DIR)
	cargo build --release --manifest-path $(REPO_ROOT)/Cargo.toml --bin vibe-slayer
	cp $(REPO_ROOT)/target/release/vibe-slayer $@
	chmod +x $@

$(BIN_DIR)/vibe-slayer: $(BIN_DIR)/vibeslayer | $(BIN_DIR)
	cp $< $@
	chmod +x $@

$(REPO_ROOT)/vibe-slayer: $(BIN_DIR)/vibeslayer
	cp $< $@
	chmod +x $@

$(BIN_DIR)/vibeslayer.exe: $(RUST_SRCS) | $(BIN_DIR)
	cargo build --release --target x86_64-pc-windows-gnu --manifest-path $(REPO_ROOT)/Cargo.toml --bin vibe-slayer
	cp $(REPO_ROOT)/target/x86_64-pc-windows-gnu/release/vibe-slayer.exe $@

$(BIN_DIR)/vibe-slayer.exe: $(BIN_DIR)/vibeslayer.exe | $(BIN_DIR)
	cp $< $@

$(BIN_DIR)/libvibeslayer.so: $(ROOT_DIR)/sdk_c/vibeslayer.c $(ROOT_DIR)/sdk_c/vibeslayer.h $(REPO_ROOT)/vibeslayer-suite/native_src/vs_crypto_core.h | $(BIN_DIR)
	gcc -O3 -fPIC -shared -fvisibility=hidden -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $(CET_CFLAGS) -Wl,-z,relro,-z,now $(CET_LDFLAGS) -Wall -Wextra -Werror $(ROOT_DIR)/sdk_c/vibeslayer.c -o $@
	strip --strip-unneeded $@

$(BIN_DIR)/vibeslayer.dll: $(ROOT_DIR)/sdk_c/vibeslayer.c $(ROOT_DIR)/sdk_c/vibeslayer.h $(REPO_ROOT)/vibeslayer-suite/native_src/vs_crypto_core.h | $(BIN_DIR)
	x86_64-w64-mingw32-gcc -O3 -shared -s -Wall -Wextra -Werror $(ROOT_DIR)/sdk_c/vibeslayer.c -o $@

$(BIN_DIR)/test_c_sdk: $(BIN_DIR)/libvibeslayer.so $(ROOT_DIR)/sdk_c/test_c_sdk.c | $(BIN_DIR)
	gcc -O3 -fPIE -pie -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 $(CET_CFLAGS) -Wl,-z,relro,-z,now $(CET_LDFLAGS) -Wall -Wextra -Werror $(ROOT_DIR)/sdk_c/test_c_sdk.c -L$(BIN_DIR) -lvibeslayer -Wl,-rpath,'$$ORIGIN' -o $@
	strip -s $@

test: all
	cargo clippy --workspace --all-targets --manifest-path $(REPO_ROOT)/Cargo.toml -- -D warnings
	cargo test --workspace --release --manifest-path $(REPO_ROOT)/Cargo.toml
	python3 $(ROOT_DIR)/tests/test_v2_polyglot.py

bench: all
	cargo test --workspace --release --manifest-path $(REPO_ROOT)/Cargo.toml -- --nocapture

clean:
	rm -rf $(BIN_DIR) $(REPO_ROOT)/vibe-slayer
	cargo clean --manifest-path $(REPO_ROOT)/Cargo.toml
