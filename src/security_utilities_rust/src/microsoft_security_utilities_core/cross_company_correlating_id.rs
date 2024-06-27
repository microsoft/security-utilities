// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Sha256, Digest};
use std::fmt;
use std::cell::RefCell;

thread_local! {
    static THREAD_LOCAL_SHA256: RefCell<Sha256> = RefCell::new(Sha256::new());
}

pub fn generate_cross_company_correlating_id(text: &str) -> String {
    let hash = generate_sha256_hash(text);

    let hash = format!("CrossMicrosoftCorrelatingId:{}", hash);

    let checksum = THREAD_LOCAL_SHA256.with(|sha| {
        sha.borrow_mut().update(hash.as_bytes());
        sha.borrow_mut().finalize_reset()
    });

    let to_encode = &checksum[0..15];
    STANDARD.encode(to_encode)
}

pub fn generate_sha256_hash(text: &str) -> String {

    let result = THREAD_LOCAL_SHA256.with(|sha| {
        sha.borrow_mut().update(text.as_bytes());
        sha.borrow_mut().finalize_reset()
    });

    fmt::format(format_args!("{:X}", result))
}