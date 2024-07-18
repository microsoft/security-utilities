// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/// This is a Rust implementation of the Marvin32 checksum algorithm, the definitive native code for which is
/// at https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c.

/// Convenience method to compute a Marvin hash and collapse it into a 32-bit hash.
pub fn compute_hash32(data: &[u8], seed: u64, offset: i32, length: i32) -> i32 {
    let hash64 = compute_hash(data, seed, offset, length);
    return ((hash64 >> 32) as i32) ^ (hash64 as i32);
}

/// Convenience method to compute a Marvin hash from a slice and collapse it into a 32-bit hash.
pub fn compute_hash32_slice(data: &[u8], seed: u64) -> i32 {
    let hash64 = compute_hash_slice(data, seed);
    return ((hash64 >> 32) as i32) ^ (hash64 as i32);
}

/// Computes a 64-bit hash using the Marvin algorithm from the given slice,
/// using the provided length and offset to determine the data to hash.
pub fn compute_hash(data: &[u8], seed: u64, offset: i32, length: i32) -> i64 {
    if offset > data.len() as i32 {
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

    let data = &data[offset as usize..(offset + length) as usize];
    compute_hash_slice(data, seed)
}

/// Computes a 64-bit hash using the Marvin algorithm from a slice.
pub fn compute_hash_slice(data: &[u8], seed: u64) -> i64 {
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;

    let mut chunks = data.chunks_exact(4);

    for chunk in &mut chunks {
        let u32_value = u32::from_le_bytes(chunk.try_into().expect("A slice of exactly 4 bytes"));
        p0 = p0.wrapping_add(u32_value);

        let (p0_new, p1_new) = block(p0, p1);
        p0 = p0_new;
        p1 = p1_new;
    }

    let remainder = chunks.remainder();
    match remainder.len() {
        0 => p0 += 0x80,
        1 => p0 = p0.wrapping_add(0x8000 | (remainder[0] as u32)),
        2 => {
            let d1 = (remainder[1] as u32) << 8;
            let d0 = remainder[0] as u32;
            p0 = p0.wrapping_add(0x800000 | d1 | d0);
        }
        3 => {
            let d2 = (remainder[2] as u32) << 16;
            let d1 = (remainder[1] as u32) << 8;
            let d0 = remainder[0] as u32;
            p0 = p0.wrapping_add(0x80000000 | d2 | d1 | d0);
        }
        _ => unreachable!("Hash computation reached an invalid state"),
    }

    let (p0, p1) = block(p0, p1);
    let (p0, p1) = block(p0, p1);

    return ((p1 as i64) << 32) | (p0 as i64);
}

/// Combines hash code of multiple objects while trying to minimize possibility of collisions.
/// rp0: hash code seed.
/// rp1: Delegates to generate hash codes to combine.
fn block(mut p0: u32, mut p1: u32) -> (u32, u32) {
    p1 = p1 ^ p0;
    p0 = p0.rotate_left(20);

    p0 = p0.wrapping_add(p1);
    p1 = p1.rotate_left(9);

    p1 = p1 ^ p0;
    p0 = p0.rotate_left(27);

    p0 = p0.wrapping_add(p1);
    p1 = p1.rotate_left(19);

    (p0, p1)
}
