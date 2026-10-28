// Copyright 2026 Trac Systems.
// Licensed under the Apache License, Version 2.0.

// Fast verification only; generating these eight native proofs is opt-in.
// Usage: node scripts/verify-wasm-large-l-vectors.mjs /path/to/vdf.mjs [legacy-wrapper]
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

const [modulePath, legacyPath] = process.argv.slice(2);
if (!modulePath) throw new Error('Provide the WASM wrapper module path');
const fixture = name => readFileSync(new URL(`../vdf/tests/fixtures/${name}`, import.meta.url), 'utf8').trim();
const challenge = Buffer.from(fixture('lab_12000000_1024.challenge.hex'), 'hex');
const broken = Buffer.from(fixture('lab_12000000_1024.invalid-proof.hex'), 'hex');
const expected = [10_000_000, 10_000_001, 12_000_000, 20_000_000, 30_000_000, 31_000_000, 40_000_000, 50_000_000];
const vectors = fixture('wesolowski_10m_50m.csv').split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => {
    const fields = line.split(',');
    assert.equal(fields.length, 3);
    const [difficulty, bits, proofHex] = fields;
    assert.match(proofHex, /^[a-f0-9]{520}$/);
    assert.equal(Number(bits), 1024);
    return { difficulty: Number(difficulty), proof: Buffer.from(proofHex, 'hex') };
});
assert.deepEqual(vectors.map(vector => vector.difficulty), expected);

for (const path of [modulePath, legacyPath].filter(Boolean)) {
    const loaded = await import(pathToFileURL(resolve(path)).href);
    const api = loaded.default ?? loaded;
    const start = performance.now();
    for (const { difficulty, proof } of vectors) {
        assert.equal(await api.verifyWesolowski(challenge, difficulty, proof, 1024), true, `T=${difficulty}: valid proof`);
        assert.equal(await api.verifyWesolowski(challenge, difficulty + 1, proof, 1024), false, `T=${difficulty}: wrong difficulty`);
    }
    assert.equal(await api.verifyWesolowski(challenge, 12_000_000, broken, 1024), false);
    console.log(JSON.stringify({ module: path, vectorsAccepted: vectors.length, wrongDifficultiesRejected: vectors.length, capturedBadProofRejected: true, elapsedSeconds: (performance.now() - start) / 1000 }));
}
