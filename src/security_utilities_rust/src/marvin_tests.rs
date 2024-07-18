// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#![cfg(test)]
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_assignments)]

use super::*;
use microsoft_security_utilities_core::marvin::{compute_hash, compute_hash32};

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

    // Assert
    assert_eq!(expected, marvin);
}

struct TestCase {
    seed: u64,
    text: Vec<u8>,
    checksum: u64,
}

/// In the spirit of cross-checking, these tests are pulled from a non-Microsoft
/// Marvin32 implementation. This implementation, per Niels Ferguson is not considered
/// completely compliant/correct and so it should not be used. But the simple test
/// cases here do result in matching output.
/// https://github.com/skeeto/marvin32/blob/21020faea884799879492204af70414facfd27e9/marvin32.c#L112
#[rustfmt::skip]
fn create_test_cases() -> Vec<TestCase>
{
    let mut v: Vec<TestCase> = Vec::new();

    // A random seed value used by the tests referenced below.
    let seed_0: u64 = 0x004fb61a001bdbcc;

    // A random seed value used by the tests referenced below.
    let seed_1: u64 = 0x804fb61a001bdbcc;

    // A random seed value used by the tests referenced below.
    let seed_2: u64 = 0x804fb61a801bdbcc;

    // seed_0 testcases
    v.push(TestCase { seed: seed_0, text: "".as_bytes().to_vec(),  checksum: 0x30ed35c100cd3c7d});
    v.push(TestCase { seed: seed_0, text: [175].to_vec(), checksum: 0x48e73fc77d75ddc1});
    v.push(TestCase { seed : seed_0, text : [231, 15].to_vec(),  checksum : 0xb5f6e1fc485dbff8});
    v.push(TestCase { seed : seed_0, text : [55, 244, 149].to_vec(),  checksum : 0xf0b07c789b8cf7e8});
    v.push(TestCase { seed : seed_0, text : [134, 66, 220, 89].to_vec(),  checksum : 0x7008f2e87e9cf556});
    v.push(TestCase { seed : seed_0, text : [21, 63, 183, 152, 38].to_vec(),  checksum : 0xe6c08c6da2afa997});
    v.push(TestCase { seed : seed_0, text : [9, 50, 230, 36, 108, 71].to_vec(),  checksum :0x6f04bf1a5ea24060});
    v.push(TestCase { seed : seed_0, text : [171, 66, 126, 168, 209, 15, 199].to_vec(),  checksum : 0xe11847e4f0678c41});

    // seed_1 testcases
    v.push(TestCase { seed : seed_1, text : "".as_bytes().to_vec(),  checksum : 0x10a9d5d3996fd65d});
    v.push(TestCase { seed : seed_1, text : [175].to_vec(), checksum : 0x68201f91960ebf91});
    v.push(TestCase { seed : seed_1, text : [231, 15].to_vec(),  checksum : 0x64b581631f6ab378});
    v.push(TestCase { seed : seed_1, text : [55, 244, 149].to_vec(),  checksum : 0xe1f2dfa6e5131408});
    v.push(TestCase { seed : seed_1, text : [134, 66, 220, 89].to_vec(),  checksum : 0x36289d9654fb49f6});
    v.push(TestCase { seed : seed_1, text : [21, 63, 183, 152, 38].to_vec(),  checksum : 0x0a06114b13464dbd});
    v.push(TestCase { seed : seed_1, text : [9, 50, 230, 36, 108, 71].to_vec(),  checksum : 0xd6dd5e40ad1bc2ed});
    v.push(TestCase { seed : seed_1, text : [171, 66, 126, 168, 209, 15, 199].to_vec(),  checksum : 0xe203987dba252fb3});

    // seed_2 testcases
    v.push( TestCase { seed : seed_2, text : [0].to_vec(),  checksum : 0xa37fb0da2ecae06c});
    v.push( TestCase { seed : seed_2, text : [255].to_vec(),  checksum : 0xfecef370701ae054});
    v.push( TestCase { seed : seed_2, text : [0, 255].to_vec(),  checksum : 0xa638e75700048880});
    v.push( TestCase { seed : seed_2, text : [255, 0].to_vec(),  checksum : 0xbdfb46d969730e2a});
    v.push( TestCase { seed : seed_2, text : [255, 0, 255].to_vec(),  checksum : 0x9d8577c0fe0d30bf});
    v.push( TestCase { seed : seed_2, text : [0,255, 0].to_vec(),  checksum : 0x4f9fbdde15099497});
    v.push( TestCase { seed : seed_2, text : [0, 255, 0, 255].to_vec(),  checksum : 0x24eaa279d9a529ca});
    v.push( TestCase { seed : seed_2, text : [255, 0, 255, 0].to_vec(),  checksum : 0xd3bec7726b057943});
    v.push( TestCase { seed : seed_2, text : [255, 0, 255, 0, 255].to_vec(),  checksum : 0x920b62bbca3e0b72});
    v.push( TestCase { seed : seed_2, text : [0, 255, 0, 255, 0].to_vec(),  checksum : 0x1d7ddf9dfdf3c1bf});
    v.push( TestCase { seed : seed_2, text : [0, 255, 0, 255, 0, 255].to_vec(),  checksum : 0xec21276a17e821a5});
    v.push( TestCase { seed : seed_2, text : [255, 0, 255, 0, 255, 0].to_vec(),  checksum : 0x6911a53ca8c12254});
    v.push( TestCase { seed : seed_2, text : [255, 0, 255, 0, 255, 0, 255].to_vec(),  checksum : 0xfdfd187b1d3ce784});
    v.push( TestCase { seed : seed_2, text : [0, 255, 0, 255, 0, 255, 0].to_vec(),  checksum : 0x71876f2efb1b0ee8});

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

        // Act
        let marvin64 = compute_hash(input, seed, 0, input.len() as i32);
        let marvin32: i32 = compute_hash32(input, seed, 0, input.len() as i32);

        // Assert
        assert_eq!(expected64, marvin64);
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
