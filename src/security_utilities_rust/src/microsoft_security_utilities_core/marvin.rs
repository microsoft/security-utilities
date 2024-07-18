// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/// This is a Rust implementation of the Marvin32 checksum algorithm, the definitive native code for which is
/// at https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c.
use std::mem;

/// Convenience method to compute a Marvin hash and collapse it into a 32-bit hash.
pub fn compute_hash32(data: &[u8], seed: u64, offset: i32, length: i32) -> i32 {
    let hash64: i64 = compute_hash(data, seed, offset, length);
    return ((hash64 >> 32) as i32) ^ (hash64 as i32);
}

/// Computes a 64-bit hash using the Marvin algorithm.
pub fn compute_hash(data: &[u8], seed: u64, offset: i32, mut length: i32) -> i64 {
    // Marvin by design can produce a checksum for empty input buffers, which
    // is why it's ok for the offset to point just past the end of the buffer
    // or for the input buffer to be empty;
    if offset < 0 || offset > data.len() as i32 {
        panic!("Offset '{}' is out of range", offset);
    }

    if length < 0 {
        panic!("Length '{}' is out of range", length);
    }

    if (offset + length) > data.len() as i32 {
        panic!(
            "Offset ({}) + length ({}) exceeds data length ({})",
            offset,
            length,
            data.len()
        );
    }

    let mut p0: u32 = seed as u32;
    let mut p1: u32 = (seed >> 32) as u32;

    let mut remaining_data_offset: i32 = 0;

    let uint_count = length / 4;

    if length as usize >= mem::size_of::<u32>() {
        let mut index: i32 = 0 + offset;

        for _i in 0..uint_count {
            let d3: u32 = (data[(index + 3) as usize] as u32) << 24;
            let d2: u32 = (data[(index + 2) as usize] as u32) << 16;
            let d1: u32 = (data[(index + 1) as usize] as u32) << 8;
            let d0: u32 = data[(index + 0) as usize] as u32;
            p0 = p0.wrapping_add(d3 | d2 | d1 | d0);

            block(&mut p0, &mut p1);
            index += 4;
        }

        remaining_data_offset = length & (!3);
        length -= remaining_data_offset;
    }

    remaining_data_offset += offset;

    match length {
        0 => p0 += 0x80,
        1 => p0 = p0.wrapping_add(0x8000 | (data[remaining_data_offset as usize] as u32)),
        2 => {
            let d1 = (data[(remaining_data_offset as usize) + 1] as u32) << 8;
            let d0: u32 = data[remaining_data_offset as usize] as u32;
            p0 = p0.wrapping_add(0x800000 | d1 | d0);
        }
        3 => {
            let d2 = (data[(remaining_data_offset as usize) + 2] as u32) << 16;
            let d1 = (data[(remaining_data_offset as usize) + 1] as u32) << 8;
            let d0: u32 = data[remaining_data_offset as usize] as u32;
            p0 = p0.wrapping_add(0x80000000 | d2 | d1 | d0);
        }
        _ => panic!("Hash computation reached an invalid state"),
    }

    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);

    return (((p1 as i64) << 32) | (p0 as i64)) as i64;
}

/// Combines hash code of multiple objects while trying to minimize possibility of collisions.
/// rp0: hash code seed.
/// rp1: Delegates to generate hash codes to combine.
fn block(rp0: &mut u32, rp1: &mut u32) {
    let mut p0: u32 = *rp0;
    let mut p1: u32 = *rp1;

    p1 = p1 ^ p0;
    p0 = rotate(p0, 20);

    p0 = p0.wrapping_add(p1);
    p1 = rotate(p1, 9);

    p1 = p1 ^ p0;
    p0 = rotate(p0, 27);

    p0 = p0.wrapping_add(p1);
    p1 = rotate(p1, 19);

    *rp0 = p0;
    *rp1 = p1;
}

/// Shift bits in an unsigned integer.
fn rotate(value: u32, shift: i32) -> u32 {
    (value << shift) | (value >> (32 - shift))
}
