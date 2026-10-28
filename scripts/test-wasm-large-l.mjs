// Copyright 2026 Trac Systems.
// Licensed under the Apache License, Version 2.0.

// Opt-in test against an explicitly selected, freshly built wrapper artifact.
// Usage: node scripts/test-wasm-large-l.mjs /path/to/dist/wasm/vdf.mjs [1024|2048] [legacy-wrapper]
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';

const [modulePath, bitsArgument = '1024', legacyPath] = process.argv.slice(2);
if (!modulePath) throw new Error('Provide the freshly built wrapper module path');
const bits = Number(bitsArgument);
assert.ok(bits === 1024 || bits === 2048);
const iterations = 12_000_000;
const fixture = name => Buffer.from(readFileSync(new URL(`../vdf/tests/fixtures/${name}`, import.meta.url), 'utf8').trim(), 'hex');
const challenge = fixture('lab_12000000_1024.challenge.hex');
const broken = fixture('lab_12000000_1024.invalid-proof.hex');
const load = async path => {
    const imported = await import(pathToFileURL(resolve(path)).href);
    return imported.default ?? imported;
};
const api = await load(modulePath);
const legacy = legacyPath ? await load(legacyPath) : null;
assert.equal(await api.verifyWesolowski(challenge, iterations, broken, 1024), false);
if (legacy) assert.equal(await legacy.verifyWesolowski(challenge, iterations, broken, 1024), false);

const started = performance.now();
let nextReport = 1_000_000n;
let phase;
const proof = Buffer.from(await api.solveWesolowski(challenge, iterations, bits, {
    onProgress(event) {
        if (event.phase !== phase || (event.phase === 'squaring' && event.completed >= nextReport)) {
            console.log(JSON.stringify({ phase: event.phase, completed: event.completed.toString(), elapsedSeconds: (performance.now() - started) / 1000 }));
            phase = event.phase;
            if (event.phase === 'squaring') nextReport = (event.completed / 1_000_000n + 1n) * 1_000_000n;
        }
    },
}));
const solveSeconds = (performance.now() - started) / 1000;
assert.equal(proof.length, 4 * ((bits + 16) >> 4));
assert.equal(await api.verifyWesolowski(challenge, iterations, proof, bits), true);
if (bits === 1024) {
    assert.notDeepEqual(proof, broken);
    assert.deepEqual(proof.subarray(0, 130), broken.subarray(0, 130), 'VDF output y is unchanged');
}
if (legacy) assert.equal(await legacy.verifyWesolowski(challenge, iterations, proof, bits), true, 'unchanged published verifier accepts the new proof');
if (process.env.VDF_LARGE_L_PROOF_OUTPUT) writeFileSync(process.env.VDF_LARGE_L_PROOF_OUTPUT, proof.toString('hex'));
console.log(JSON.stringify({ iterations, bits, proofBytes: proof.length, solveSeconds, verified: true, legacyVerified: legacy ? true : null }));
