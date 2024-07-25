// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

thread_local! {
    static THREAD_LOCAL_SHA256: RefCell<Sha256> = RefCell::new(Sha256::new());
}

pub fn generate_cross_company_correlating_id(text: &str) -> String {
    let mut buffer = [0u8; 64];
    let hash = generate_sha256_hash(text, &mut buffer);

    let checksum = THREAD_LOCAL_SHA256.with(|sha| {
        let mut sha = sha.borrow_mut();

        sha.update("CrossMicrosoftCorrelatingId:");
        sha.update(hash);
        sha.finalize_reset()
    });

    let to_encode = &checksum[0..15];
    STANDARD.encode(to_encode)
}

fn generate_sha256_hash<'a>(text: &str, buffer: &'a mut [u8; 64]) -> &'a [u8; 64] {
    let result = THREAD_LOCAL_SHA256.with(|sha| {
        let mut sha = sha.borrow_mut();
        sha.update(text.as_bytes());
        sha.finalize_reset()
    });

    let data: [u8; 32] = result.into();

    for (idx, byte) in data.into_iter().enumerate() {
        // NOTE(unwrap): u8 & 0xF is always valid.
        let lhs = hex_encode((byte >> 4) & 0xF).unwrap();
        let rhs = hex_encode(byte & 0xF).unwrap();

        buffer[idx * 2] = lhs;
        buffer[(idx * 2) + 1] = rhs;
    }

    buffer
}

pub(crate) fn hex_encode(value: u8) -> Option<u8> {
    if value < 10 {
        Some(value.wrapping_add(b'0'))
    } else if value < 16 {
        Some(value.wrapping_sub(10).wrapping_add(b'A'))
    } else {
        None
    }
}
