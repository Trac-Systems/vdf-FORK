# vdf-wasm

Node/Emscripten WASM build for the VDF wrapper.

Build and smoke-test:

```sh
make node-test
```

Benchmark:

```sh
npm run bench --prefix examples/node-wasm
```

This target requires Emscripten (`emcc`, `emconfigure`, and `emmake`). The
Makefile downloads the required arithmetic library into `target/`, builds a
static WASM library, then links the `vdf-wasm` crate against it.
