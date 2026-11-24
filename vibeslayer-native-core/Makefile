ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BIN_DIR  := $(ROOT_DIR)/bin
REPO_ROOT := $(abspath $(ROOT_DIR)/..)

.PHONY: all test clean

all: $(BIN_DIR)/vibeslayer $(BIN_DIR)/vibe-slayer $(REPO_ROOT)/vibe-slayer $(BIN_DIR)/vibeslayer.exe $(BIN_DIR)/vibe-slayer.exe $(BIN_DIR)/libvibeslayer.so $(BIN_DIR)/vibeslayer.dll $(BIN_DIR)/test_c_sdk

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/vibeslayer: $(BIN_DIR) rust_core/src/*.rs
	cargo build --release --manifest-path $(ROOT_DIR)/rust_core/Cargo.toml
	cp $(ROOT_DIR)/rust_core/target/release/vibe-slayer $(BIN_DIR)/vibeslayer
	cp $(ROOT_DIR)/rust_core/target/release/vibe-slayer $(BIN_DIR)/vibe-slayer
	cp $(ROOT_DIR)/rust_core/target/release/vibe-slayer $(REPO_ROOT)/vibe-slayer
	chmod +x $(BIN_DIR)/vibeslayer $(BIN_DIR)/vibe-slayer $(REPO_ROOT)/vibe-slayer

$(BIN_DIR)/vibe-slayer: $(BIN_DIR)/vibeslayer
	@test -x $(BIN_DIR)/vibe-slayer

$(REPO_ROOT)/vibe-slayer: $(BIN_DIR)/vibeslayer
	@test -x $(REPO_ROOT)/vibe-slayer

$(BIN_DIR)/vibeslayer.exe: $(BIN_DIR) rust_core/src/*.rs
	cargo build --release --target x86_64-pc-windows-gnu --manifest-path $(ROOT_DIR)/rust_core/Cargo.toml
	cp $(ROOT_DIR)/rust_core/target/x86_64-pc-windows-gnu/release/vibe-slayer.exe $(BIN_DIR)/vibeslayer.exe
	cp $(ROOT_DIR)/rust_core/target/x86_64-pc-windows-gnu/release/vibe-slayer.exe $(BIN_DIR)/vibe-slayer.exe

$(BIN_DIR)/vibe-slayer.exe: $(BIN_DIR)/vibeslayer.exe
	@test -f $(BIN_DIR)/vibe-slayer.exe

$(BIN_DIR)/libvibeslayer.so: $(BIN_DIR) sdk_c/vibeslayer.c sdk_c/vibeslayer.h ../vibeslayer-suite/native_src/vs_crypto_core.h
	gcc -O3 -fPIC -shared -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fcf-protection=full -Wl,-z,relro,-z,now,-z,ibt,-z,shstk -Wall -Wextra -Werror sdk_c/vibeslayer.c -o $(BIN_DIR)/libvibeslayer.so
	strip --strip-unneeded $(BIN_DIR)/libvibeslayer.so

$(BIN_DIR)/vibeslayer.dll: $(BIN_DIR) sdk_c/vibeslayer.c sdk_c/vibeslayer.h ../vibeslayer-suite/native_src/vs_crypto_core.h
	x86_64-w64-mingw32-gcc -O3 -shared -s -Wall -Wextra -Werror sdk_c/vibeslayer.c -o $(BIN_DIR)/vibeslayer.dll

$(BIN_DIR)/test_c_sdk: $(BIN_DIR)/libvibeslayer.so sdk_c/test_c_sdk.c
	gcc -O3 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fcf-protection=full -Wl,-z,relro,-z,now,-z,ibt,-z,shstk -Wall -Wextra -Werror sdk_c/test_c_sdk.c -L$(BIN_DIR) -lvibeslayer -Wl,-rpath,'$$ORIGIN' -o $(BIN_DIR)/test_c_sdk
	strip -s $(BIN_DIR)/test_c_sdk

test: all
	python3 $(ROOT_DIR)/tests/run_polyglot_suite.py
	python3 $(ROOT_DIR)/tests/test_v090_elite.py
	python3 $(ROOT_DIR)/tests/test_v100_zero_overhead.py
	python3 $(ROOT_DIR)/tests/test_vibe_slayer_cli.py
	python3 $(ROOT_DIR)/tests/test_encrypted_compute_and_shield3d.py
	python3 $(ROOT_DIR)/tests/redteam_adversarial_audit.py
	python3 $(ROOT_DIR)/tests/bench_sota_performance.py

clean:
	rm -rf $(BIN_DIR) $(ROOT_DIR)/rust_core/target
