// Copyright 2026 Trac Systems
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

#[macro_use]
extern crate criterion;

use classgroup::{gmp_classgroup::GmpClassGroup, ClassGroup};
use criterion::Criterion;
use std::hint::black_box;
use vdf::create_discriminant;

type Mpz = <GmpClassGroup as ClassGroup>::BigNum;

fn seed(seed_index: u16) -> Vec<u8> {
    seed_index.to_be_bytes().to_vec()
}

fn bench_discriminant_generation(c: &mut Criterion) {
    for &bits in &[512u16, 1024, 2048] {
        for seed_index in 0..16 {
            let seed = seed(seed_index);
            c.bench_function(
                &format!("discriminant generation: {} bits seed {}", bits, seed_index),
                move |b| {
                    b.iter(|| create_discriminant::<Mpz>(black_box(&seed), black_box(bits)));
                },
            );
        }
    }
}

criterion_group!(benches, bench_discriminant_generation);
criterion_main!(benches);
