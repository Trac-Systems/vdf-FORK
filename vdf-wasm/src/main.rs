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

#![allow(unsafe_code)]

use std::{
    convert::TryFrom,
    slice,
    sync::{Mutex, OnceLock},
};
use vdf::{SolveProgress, VDFParams, WesolowskiVDFParams, VDF};

#[cfg(target_os = "emscripten")]
extern "C" {
    fn vdf_report_progress(phase: u32, completed_lo: u32, completed_hi: u32);
}

fn report_progress(progress: SolveProgress) {
    #[cfg(target_os = "emscripten")]
    unsafe {
        vdf_report_progress(
            progress.phase as u32,
            progress.completed as u32,
            (progress.completed >> 32) as u32,
        );
    }
    #[cfg(not(target_os = "emscripten"))]
    let _ = progress;
}

static LAST_RESULT: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
static LAST_ERROR: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();

fn result_store() -> &'static Mutex<Vec<u8>> {
    LAST_RESULT.get_or_init(|| Mutex::new(Vec::new()))
}

fn error_store() -> &'static Mutex<Vec<u8>> {
    LAST_ERROR.get_or_init(|| Mutex::new(Vec::new()))
}

fn set_error(message: impl AsRef<str>) -> i32 {
    let mut error = error_store().lock().expect("error mutex should not poison");
    error.clear();
    error.extend_from_slice(message.as_ref().as_bytes());
    -1
}

fn clear_error() {
    error_store()
        .lock()
        .expect("error mutex should not poison")
        .clear();
}

fn difficulty(lo: u32, hi: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

fn checked_bits(bits: u32) -> Result<u16, i32> {
    u16::try_from(bits).map_err(|_| set_error("discriminant_size_bits exceeds u16::MAX"))
}

unsafe fn read_input<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], i32> {
    if ptr.is_null() && len != 0 {
        return Err(set_error(format!("{name} pointer is null")));
    }
    Ok(slice::from_raw_parts(ptr, len))
}

fn write_result(bytes: Vec<u8>) {
    *result_store()
        .lock()
        .expect("result mutex should not poison") = bytes;
}

#[no_mangle]
pub extern "C" fn vdf_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn vdf_dealloc(ptr: *mut u8, capacity: usize) {
    if !ptr.is_null() {
        drop(Vec::from_raw_parts(ptr, 0, capacity));
    }
}

#[no_mangle]
pub extern "C" fn vdf_last_result_ptr() -> *const u8 {
    result_store()
        .lock()
        .expect("result mutex should not poison")
        .as_ptr()
}

#[no_mangle]
pub extern "C" fn vdf_last_result_len() -> usize {
    result_store()
        .lock()
        .expect("result mutex should not poison")
        .len()
}

#[no_mangle]
pub extern "C" fn vdf_last_error_ptr() -> *const u8 {
    error_store()
        .lock()
        .expect("error mutex should not poison")
        .as_ptr()
}

#[no_mangle]
pub extern "C" fn vdf_last_error_len() -> usize {
    error_store()
        .lock()
        .expect("error mutex should not poison")
        .len()
}

#[no_mangle]
pub unsafe extern "C" fn vdf_solve_wesolowski(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_lo: u32,
    difficulty_hi: u32,
    discriminant_size_bits: u32,
) -> i32 {
    solve_wesolowski(
        challenge_ptr, challenge_len, difficulty_lo, difficulty_hi, discriminant_size_bits, false,
    )
}

#[no_mangle]
pub unsafe extern "C" fn vdf_solve_wesolowski_with_progress(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_lo: u32,
    difficulty_hi: u32,
    discriminant_size_bits: u32,
) -> i32 {
    solve_wesolowski(
        challenge_ptr, challenge_len, difficulty_lo, difficulty_hi, discriminant_size_bits, true,
    )
}

unsafe fn solve_wesolowski(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_lo: u32,
    difficulty_hi: u32,
    discriminant_size_bits: u32,
    observe: bool,
) -> i32 {
    clear_error();
    let challenge = match read_input(challenge_ptr, challenge_len, "challenge") {
        Ok(challenge) => challenge,
        Err(code) => return code,
    };
    let bits = match checked_bits(discriminant_size_bits) {
        Ok(bits) => bits,
        Err(code) => return code,
    };
    let solver = WesolowskiVDFParams(bits).new();
    let iterations = difficulty(difficulty_lo, difficulty_hi);
    let result = if observe {
        solver.solve_with_progress(challenge, iterations, &mut report_progress)
    } else {
        solver.solve(challenge, iterations)
    };
    match result {
        Ok(proof) => {
            write_result(proof);
            0
        }
        Err(err) => set_error(format!("invalid iterations: {err:?}")),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vdf_verify_wesolowski(
    challenge_ptr: *const u8,
    challenge_len: usize,
    difficulty_lo: u32,
    difficulty_hi: u32,
    proof_ptr: *const u8,
    proof_len: usize,
    discriminant_size_bits: u32,
) -> i32 {
    clear_error();
    let challenge = match read_input(challenge_ptr, challenge_len, "challenge") {
        Ok(challenge) => challenge,
        Err(code) => return code,
    };
    let proof = match read_input(proof_ptr, proof_len, "proof") {
        Ok(proof) => proof,
        Err(code) => return code,
    };
    let bits = match checked_bits(discriminant_size_bits) {
        Ok(bits) => bits,
        Err(code) => return code,
    };
    let vdf = WesolowskiVDFParams(bits).new();
    match vdf.check_difficulty(difficulty(difficulty_lo, difficulty_hi)) {
        Ok(()) => {}
        Err(err) => return set_error(format!("invalid iterations: {err:?}")),
    }
    if vdf
        .verify(challenge, difficulty(difficulty_lo, difficulty_hi), proof)
        .is_ok()
    {
        1
    } else {
        0
    }
}

fn main() {}
