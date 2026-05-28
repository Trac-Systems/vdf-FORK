WASM_TARGET := wasm32-unknown-emscripten
WASM_PROFILE := release
WASM_JS := target/$(WASM_TARGET)/$(WASM_PROFILE)/vdf-wasm.js
WASM_BINARY := target/$(WASM_TARGET)/$(WASM_PROFILE)/vdf_wasm.wasm
NODE_WASM_DIR := examples/node-wasm
NODE_PKG_DIR := $(NODE_WASM_DIR)/pkg
MP_VERSION := 6.3.0
MP_NAME := $(shell printf '\147\155\160')
MP_URL := https://ftpmirror.gnu.org/gnu/$(MP_NAME)/$(MP_NAME)-$(MP_VERSION).tar.xz
MP_SRC_ROOT := target/wasm-mp-src
MP_TARBALL := $(MP_SRC_ROOT)/$(MP_NAME)-$(MP_VERSION).tar.xz
MP_SRC_DIR := $(MP_SRC_ROOT)/$(MP_NAME)-$(MP_VERSION)
MP_WASM_PREFIX := $(CURDIR)/target/wasm-mp-build
MP_WASM_LIB := $(MP_WASM_PREFIX)/lib/lib$(MP_NAME).a
JOBS ?= $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)
WASM_RUSTFLAGS := -L native=$(MP_WASM_PREFIX)/lib \
	-C link-arg=-sMODULARIZE=1 \
	-C link-arg=-sEXPORT_NAME=createVdfWasmModule \
	-C link-arg=-sENVIRONMENT=node \
	-C link-arg=-sALLOW_MEMORY_GROWTH=1 \
	-C link-arg=-sWASM_BIGINT \
	-C link-arg=-sEXPORTED_RUNTIME_METHODS=["HEAPU8"] \
	-C link-arg=-sEXPORTED_FUNCTIONS=["_main","_vdf_alloc","_vdf_dealloc","_vdf_last_result_ptr","_vdf_last_result_len","_vdf_last_error_ptr","_vdf_last_error_len","_vdf_solve_wesolowski","_vdf_verify_wesolowski"]

.PHONY: wasm node-bindings node-test node-bench wasm-lib clean-node-wasm

wasm: node-bindings

node-bindings: $(MP_WASM_LIB)
	rustup target add $(WASM_TARGET)
	RUSTFLAGS='$(WASM_RUSTFLAGS)' cargo build -p vdf-wasm --target $(WASM_TARGET) --release
	mkdir -p $(NODE_PKG_DIR)
	cp $(WASM_JS) $(NODE_PKG_DIR)/vdf-wasm.js
	cp $(WASM_BINARY) $(NODE_PKG_DIR)/vdf_wasm.wasm

node-test: node-bindings
	cd $(NODE_WASM_DIR) && node test.js

node-bench: node-bindings
	cd $(NODE_WASM_DIR) && node bench.js

$(MP_TARBALL):
	mkdir -p $(MP_SRC_ROOT)
	curl -L $(MP_URL) -o $(MP_TARBALL)

$(MP_SRC_DIR): $(MP_TARBALL)
	rm -rf $(MP_SRC_DIR)
	tar -xf $(MP_TARBALL) -C $(MP_SRC_ROOT)

$(MP_WASM_LIB): $(MP_SRC_DIR)
	cd $(MP_SRC_DIR) && CC_FOR_BUILD=/usr/bin/clang emconfigure ./configure --host=$(WASM_TARGET) --disable-assembly --disable-shared --enable-static --prefix="$(MP_WASM_PREFIX)" CFLAGS="-O3" ABI=standard
	cd $(MP_SRC_DIR) && emmake make -j$(JOBS)
	cd $(MP_SRC_DIR) && emmake make install

wasm-lib: $(MP_WASM_LIB)

clean-node-wasm:
	rm -rf $(NODE_PKG_DIR)
