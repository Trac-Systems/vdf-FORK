<!--
Copyright 2026 Trac Systems.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

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
