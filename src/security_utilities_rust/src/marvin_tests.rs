// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#![cfg(test)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_assignments)]

use super::*;
use microsoft_security_utilities_core::marvin::{
    compute_hash, compute_hash32, compute_hash32_slice, compute_hash_slice,
};

/// Compare a Marvin checksum against a well-known test case from the native code.
#[test]
fn marvin_basic() {
    // This test verifies that our Rust implementation provides
    // the same result as SymCrypt for their standard test.
    // https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c#L316

    // Assume
    let seed: u64 = 0xd53cd9cecd0893b7;
    let v: Vec<u8> = String::from("abc").into_bytes();
    let input: [u8; 3] = v.try_into().unwrap();
    let expected: i64 = 0x22c74339492769bf;

    // Act
    let marvin: i64 = compute_hash(&input, seed, 0, input.len() as i32);

    // Assert
    assert_eq!(expected, marvin);
}

/// Compare a Marvin checksum against a well-known test case from the native code.
#[test]
#[allow(overflowing_literals)]
fn marvin_longer_string() {
    // This test verifies that our C# implementation provides
    // the same result as SymCrypt for their standard test.
    // https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c#L316

    // Assume
    let seed: u64 = 0xddddeeeeffff000;
    let v: Vec<u8> = String::from("abcdefghijklmnopqrstuvwxyz").into_bytes();
    let input: [u8; 26] = v.try_into().unwrap();
    let expected: i64 = 0xa128eb7e7260aca2;

    // Act
    let marvin: i64 = compute_hash(&input, seed, 0, input.len() as i32);
    let marvin_slice = compute_hash_slice(&input, seed);

    // Assert
    assert_eq!(marvin, marvin_slice);
    assert_eq!(expected, marvin);
}

#[derive(Clone)]
struct TestCase {
    seed: u64,
    text: Vec<u8>,
    length: usize,
    checksum: u64,
    offset: i32,
}

impl TestCase {
    pub fn new<T>(seed: u64, checksum: u64, text: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            seed,
            checksum,
            offset: 0,
            text: text.as_ref().to_vec(),
            length: text.as_ref().len(),
        }
    }

    pub fn add_offset(&self, offset: i32) -> Self {
        let mut text = vec![0u8; offset as usize];
        text.extend_from_slice(&self.text);

        Self {
            seed: self.seed,
            checksum: self.checksum,
            text,
            offset,
            length: self.length,
        }
    }

    pub fn add_byte_at_end(mut self) -> Self {
        self.text.push(0);
        self
    }
}

/// In the spirit of cross-checking, these tests are pulled from a non-Microsoft
/// Marvin32 implementation. This implementation, per Niels Ferguson is not considered
/// completely compliant/correct and so it should not be used. But the simple test
/// cases here do result in matching output.
/// https://github.com/skeeto/marvin32/blob/21020faea884799879492204af70414facfd27e9/marvin32.c#L112
fn create_test_cases() -> Vec<TestCase> {
    // A random seed value used by the tests referenced below.
    let seed_0: u64 = 0x004fb61a001bdbcc;

    // A random seed value used by the tests referenced below.
    let seed_1: u64 = 0x804fb61a001bdbcc;

    // A random seed value used by the tests referenced below.
    let seed_2: u64 = 0x804fb61a801bdbcc;

    #[rustfmt::skip]
    let v = vec![
        // seed_0 test cases
        TestCase::new(seed_0, 0x30ed35c100cd3c7d, b"",),
        TestCase::new(seed_0, 0x48e73fc77d75ddc1, [175]),
        TestCase::new(seed_0, 0xb5f6e1fc485dbff8, [231, 15]),
        TestCase::new(seed_0, 0xf0b07c789b8cf7e8, [55, 244, 149]),
        TestCase::new(seed_0, 0x7008f2e87e9cf556,[134, 66, 220, 89]),
        TestCase::new(seed_0, 0xe6c08c6da2afa997,[21, 63, 183, 152, 38]),
        TestCase::new(seed_0, 0x6f04bf1a5ea24060, [9, 50, 230, 36, 108, 71]),
        TestCase::new(seed_0, 0xe11847e4f0678c41, [171, 66, 126, 168, 209, 15, 199]),

        TestCase::new(seed_1,  0x10a9d5d3996fd65d, ""),
        TestCase::new(seed_1, 0x68201f91960ebf91, [175]),
        TestCase::new(seed_1, 0x64b581631f6ab378, [231, 15]),
        TestCase::new(seed_1, 0xe1f2dfa6e5131408, [55, 244, 149]),
        TestCase::new(seed_1, 0x36289d9654fb49f6, [134, 66, 220, 89]),
        TestCase::new(seed_1, 0x0a06114b13464dbd, [21, 63, 183, 152, 38]),
        TestCase::new(seed_1, 0xd6dd5e40ad1bc2ed, [9, 50, 230, 36, 108, 71]),
        TestCase::new(seed_1, 0xe203987dba252fb3, [171, 66, 126, 168, 209, 15, 199]),

        TestCase::new(seed_2, 0xa37fb0da2ecae06c, [0]),
        TestCase::new(seed_2, 0xfecef370701ae054, [255]),
        TestCase::new(seed_2, 0xa638e75700048880, [0, 255]),
        TestCase::new(seed_2, 0xbdfb46d969730e2a, [255, 0]),
        TestCase::new(seed_2, 0x9d8577c0fe0d30bf, [255, 0, 255]),
        TestCase::new(seed_2, 0x4f9fbdde15099497, [0,255, 0]),
        TestCase::new(seed_2, 0x24eaa279d9a529ca, [0, 255, 0, 255]),
        TestCase::new(seed_2, 0xd3bec7726b057943, [255, 0, 255, 0]),
        TestCase::new(seed_2, 0x920b62bbca3e0b72, [255, 0, 255, 0, 255]),
        TestCase::new(seed_2, 0x1d7ddf9dfdf3c1bf, [0, 255, 0, 255, 0]),
        TestCase::new(seed_2, 0xec21276a17e821a5, [0, 255, 0, 255, 0, 255]),
        TestCase::new(seed_2, 0x6911a53ca8c12254, [255, 0, 255, 0, 255, 0]),
        TestCase::new(seed_2, 0xfdfd187b1d3ce784, [255, 0, 255, 0, 255, 0, 255]),
        TestCase::new(seed_2, 0x71876f2efb1b0ee8, [0, 255, 0, 255, 0, 255, 0]),
    ];

    // Generate offsets
    let v = v
        .iter()
        .flat_map(|v| [0, 1, 5, 100].map(|o| v.add_offset(o).add_byte_at_end()))
        .collect();

    return v;
}

#[test]
fn marvin_various_cases() {
    let testcases = create_test_cases();

    for testcase in testcases {
        // Assume
        let input: &[u8] = &(testcase.text);
        let seed = testcase.seed;
        let expected64: i64 = testcase.checksum as i64;
        let expected32: i32 = (expected64 ^ expected64 >> 32) as i32;
        let offset = testcase.offset;

        // Act
        let marvin64 = compute_hash(input, seed, offset, testcase.length as i32);
        let marvin32: i32 = compute_hash32(input, seed, offset, testcase.length as i32);

        let offsetu = offset as usize;
        let marvin64_slice = compute_hash_slice(&input[offsetu..(offsetu + testcase.length)], seed);
        let marvin32_slice =
            compute_hash32_slice(&input[offsetu..(offsetu + testcase.length)], seed);

        // Assert
        assert_eq!(marvin64, marvin64_slice);
        assert_eq!(expected64, marvin64);
        assert_eq!(marvin32, marvin32_slice);
        assert_eq!(expected32, marvin32);
    }
}

#[test]
#[should_panic]
fn marvin_compute_hash_panic_if_invalid_args_1() {
    let input = "".as_bytes();
    compute_hash(input, 0, -1, 0);
}

#[test]
#[should_panic]
fn marvin_compute_hash_panic_if_invalid_args_2() {
    let input = "".as_bytes();
    compute_hash(input, 0, 5, 0);
}

#[test]
#[should_panic]
fn marvin_compute_hash_panic_if_invalid_args_3() {
    let input = "".as_bytes();
    compute_hash(input, 0, 1, -1);
}

#[test]
#[should_panic]
fn marvin_compute_hash_panic_if_invalid_args_4() {
    let input = "".as_bytes();
    compute_hash(input, 0, 3, 3);
}
