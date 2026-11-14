# Vendored: @relate/relate-wasm 1.0.1

The files in this directory are an unmodified copy of the run-time files of the npm
package `@relate/relate-wasm@1.0.1`: Relate, the embedded Cypher graph database,
compiled to WebAssembly. The TaintTrail viewer loads them from `../worker.js`.

Includes Relate (https://github.com/relatedb/relate), Copyright 2026 The Relate
Authors, licensed under the Apache License 2.0. TaintTrail is not affiliated with or
endorsed by Neo4j or the Relate authors.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `relate.js` | 26,133 | `b3910d98694ba2c4abaced19127b8fe27cce8b9b070b259fe19287e6ff9abcd5` |
| `relate_bg.wasm` | 6,932,319 | `c1fc8f46906129c7981ec8a2d1a181c0bf6dca4174fdf38d5ac89f3c04b95a46` |
| `trap.js` | 753 | `d50e37f6163e14d8d990754f80fb5b0cc3257836313bef4474505bf1a27d832a` |
| `snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js` | 3,101 | `493a1c8d8a761ead191addd9701a2dd15276db250cda2323ad3659c1c9c7474e` |
| `LICENSE` | 11,348 | `ac87d12e27d69f09130a7b4178e48e995ab131e4b476aa188e58ffac7ed7fab3` |

`tests/test_serve.py` checks these checksums, so an accidental edit fails the suite.

- Source: `npm pack @relate/relate-wasm@1.0.1` (tarball `relate-relate-wasm-1.0.1.tgz`,
  2,468,291 bytes, npm shasum `5aa60971245626ccc6340013e7804f320d55091a`).
- Upstream repository: https://github.com/relatedb/relate
- License: Apache License 2.0 (`package.json` of the npm package declares
  `"license": "Apache-2.0"`). The npm tarball contains no `LICENSE` and no `NOTICE` file,
  so `LICENSE` here is the Apache-2.0 text from the root of the upstream repository,
  byte-identical to the `LICENSE` inside the `relate-db` 1.0.1 Python wheel. Its appendix
  carries `Copyright 2026 The Relate Authors`. Upstream has no `NOTICE` file for this
  artifact, so there are no further attribution notices to reproduce.
- Not copied because nothing loads them at run time: the TypeScript declarations
  (`relate.d.ts`, `trap.d.ts`, `opfs.d.ts`, `relate_bg.wasm.d.ts`), the package's
  `package.json` and `README.md`, and `opfs.js` at the package root (a byte-identical
  duplicate of the snippet).
- Not verified: the `.wasm` statically links third-party Rust crates and the npm package
  ships no list of them. The SBOM of the native `relate-db` wheel lists permissive
  licences only (MIT, Apache-2.0 and similar); the dependency set of the WebAssembly
  build itself was not extracted.

Keep the directory layout. `relate.js` imports
`./snippets/relate-wasm-1db7a39dcbf9937d/js/opfs.js` and fetches `./relate_bg.wasm`, both
relative to its own URL. If one of these files is ever patched, Apache-2.0 section 4(b)
requires a prominent notice of the change in that file; say so here as well.
