// Copyright 2026 Trac Systems.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const { loadVdfWasm } = require('./index.js');

async function main() {
  const vdf = await loadVdfWasm();
  const challenge = Buffer.from([0xaa]);
  const difficulty = 500n;
  const proof = vdf.solveWesolowski(challenge, difficulty, 40);
  if (!vdf.verifyWesolowski(challenge, difficulty, proof, 40)) {
    throw new Error('Wesolowski proof did not verify');
  }
  console.log('wasm wesolowski ok', {
    proofBytes: proof.length,
    proofHex: proof.toString('hex'),
  });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
