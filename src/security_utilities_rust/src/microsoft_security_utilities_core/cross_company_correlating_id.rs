// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::fmt::Write;

thread_local! {
    static THREAD_LOCAL_SHA256: RefCell<Sha256> = RefCell::new(Sha256::new());
}

pub fn generate_cross_company_correlating_id(text: &str) -> String {
    let hash = generate_sha256_hash(text);

    let checksum = THREAD_LOCAL_SHA256.with(|sha| {
        let mut sha = sha.borrow_mut();

        sha.update("CrossMicrosoftCorrelatingId:");
        sha.update(hash);
        sha.finalize_reset()
    });

    let to_encode = &checksum[0..15];
    STANDARD.encode(to_encode)
}

fn generate_sha256_hash(text: &str) -> String {
    let result = THREAD_LOCAL_SHA256.with(|sha| {
        sha.borrow_mut().update(text.as_bytes());
        sha.borrow_mut().finalize_reset()
    });

    let mut output = String::with_capacity(2 * 32);
    write!(output, "{:X}", result).unwrap();
    output
}
