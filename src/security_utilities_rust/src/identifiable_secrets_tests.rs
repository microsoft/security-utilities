// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#![cfg(test)]
#![allow(unused_imports)]
#![allow(dead_code)]

use super::*;
use std::{collections::HashSet};
use std::time::{Duration, Instant};
use base64::{engine::general_purpose, Engine as _};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use uuid::Uuid;
use crate::microsoft_security_utilities_core::identifiable_secrets::SecretMasker;

static S_BASE62_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

use rand::Rng;
use crate::microsoft_security_utilities_core::cross_company_correlating_id;

#[test]
fn secret_masker_test() {
    let mut masking_times_with_checksum_validation: Vec<Duration> = Vec::new();
    let mut masking_times_without_checksum_validation: Vec<Duration> = Vec::new();

    let valid_signature = "ABCD";
    let options = microsoft_security_utilities_core::identifiable_scans::ScanOptions::default();
    let mut secret_masker = SecretMasker {
        scan:  microsoft_security_utilities_core::identifiable_scans::Scan::new(options)
    };

    #[cfg(debug_assertions)]
    let iterations = 1000;

    #[cfg(not(debug_assertions))]
    let iterations = 500_000;

    for _ in 0..iterations {
        // generate a key
        let valid_key = microsoft_security_utilities_core::identifiable_secrets::
        generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            Some('A')
        );

        let valid_key = valid_key.unwrap().clone();

        let mut input = format!("{} test_string {}", valid_key, valid_key);
        let valid_key_c3id = cross_company_correlating_id::generate_cross_company_correlating_id(&valid_key);
        let redacted_input = format!("SEC101/200:{} test_string SEC101/200:{}", valid_key_c3id, valid_key_c3id);

        let start = Instant::now();
        secret_masker.mask_secrets(&mut input, None, true);
        let duration = start.elapsed();

        assert_eq!(input, redacted_input);
        masking_times_with_checksum_validation.push(duration);

        let mut input = format!("{} test_string {}", valid_key, valid_key);
        let start = Instant::now();
        secret_masker.mask_secrets(&mut input, None, false);
        let duration = start.elapsed();

        assert_eq!(input, redacted_input);
        masking_times_without_checksum_validation.push(duration);
    }

    let total_masking_time_with_checksum: Duration = masking_times_with_checksum_validation.iter().sum();
    let mean_masking_time_with_checksum = total_masking_time_with_checksum / masking_times_with_checksum_validation.len() as u32;

    let total_masking_time_without_checksum: Duration = masking_times_without_checksum_validation.iter().sum();
    let mean_masking_time_without_checksum = total_masking_time_without_checksum / masking_times_without_checksum_validation.len() as u32;

    println!("Mean time for masking with checksum validation: {:?}", mean_masking_time_with_checksum);
    println!("Mean time for masking without checksum validation: {:?}", mean_masking_time_without_checksum);
}

#[test]
fn identifiable_secrets_try_validate_common_annotated_key_generate_common_annotated_key_long_form() {
    for &long_form in &[true, false] {
        let valid_signature = "ABCD";
        let valid_key = microsoft_security_utilities_core::identifiable_secrets::
            generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            long_form.clone(),
            None
        );

        let valid_key = valid_key.unwrap().clone();
        let valid_key_len = valid_key.len();

        let result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(
            &valid_key,
            valid_signature,
        );
        assert!(result, "a generated key should validate");

        let expected_length = if long_form {
            microsoft_security_utilities_core::identifiable_secrets::LONG_FORM_COMMON_ANNOTATED_KEY_SIZE
        } else {
            microsoft_security_utilities_core::identifiable_secrets::STANDARD_COMMON_ANNOTATED_KEY_SIZE
        };

        assert_eq!(
            valid_key_len,
            expected_length
        );
    }
}

#[test]
fn identifiable_secrets_try_validate_common_annotated_key_reject_null_empty_and_whitespace_arguments() {
    let valid_signature = "ABCD";
    let valid_key = microsoft_security_utilities_core::identifiable_secrets::
        generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            None
    );

    let valid_key = valid_key.unwrap().clone();

    let result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(&valid_key, valid_signature);
    assert!(result, "a generated key should validate");

    let args = vec![String::new(), String::from(" ")];
    for arg in args {
        let result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(&arg, valid_signature);
        assert!(!result, "{}", format!("the key {} is not a valid argument", arg));

        let result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(&valid_key, &arg);
        assert!(!result, "{}", format!("the signature '{}' is not a valid argument", arg.to_string()));
    }
}

#[test]
fn identifiable_secrets_try_validate_common_annotated_key_reject_invalid_signatures() {
    let valid_signature = "ABCD";
    let valid_key = microsoft_security_utilities_core::identifiable_secrets::
        generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            None
    );

    let valid_key = valid_key.unwrap().clone();

    let result = microsoft_security_utilities_core::identifiable_secrets::
        try_validate_common_annotated_key(&valid_key, valid_signature);
    assert!(result, "a generated key should validate");

    let signatures = vec!["Z", "YY", "XXX", "WWWWW", "1AAA"];

    for signature in signatures {
        for &long_form in &[true, false] {
            let action =
                microsoft_security_utilities_core::identifiable_secrets::
                generate_common_annotated_key(
                    signature,
                    true,
                    Some(&vec![0; 9]),
                    Some(&vec![0; 3]),
                    long_form,
                    None
                );


            assert!(action.is_err(), "{}", format!("the signature '{}' is not valid", signature));

            let result = microsoft_security_utilities_core::identifiable_secrets::
                try_validate_common_annotated_key(&valid_key, signature);
            assert!(!result, "{}", format!("'{}' is not a valid signature argument", signature));
        }
    }
}

#[test]
fn identifiable_secrets_try_validate_common_annotated_key_reject_invalid_key() {
    let valid_signature = "Z123";
    let valid_key = microsoft_security_utilities_core::identifiable_secrets::
        generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            None
    );

    let valid_key = valid_key.unwrap().clone();

    let result = microsoft_security_utilities_core::identifiable_secrets::
    try_validate_common_annotated_key(&valid_key, valid_signature);
    assert!(result, "a generated key should validate");

    let result = microsoft_security_utilities_core::identifiable_secrets::
        try_validate_common_annotated_key(
            &format!("{}a", valid_key),
            valid_signature,
    );
    assert!(!result, "a key with an invalid length should not validate");

    let result = microsoft_security_utilities_core::identifiable_secrets::
        try_validate_common_annotated_key(
            &valid_key[1..],
            valid_signature,
    );
    assert!(!result, "a key with an invalid length should not validate");
}

#[test]
fn identifiable_secrets_validate_common_annotated_key_signature() {
    for invalid_signature in ["AbAA", "aaaB", "1AAA"] {
        assert!(matches!(
                    microsoft_security_utilities_core::identifiable_secrets::validate_common_annotated_key_signature(invalid_signature),
                    Err(_)
                ));
    }
}

#[test]
fn identifiable_secrets_compute_checksum_seed_enforces_length_requirement() 
{
    for i in 0..16 
    {
        let literal = "A".repeat(i) + "0";

        let result = std::panic::catch_unwind(|| microsoft_security_utilities_core::identifiable_secrets::compute_his_v1_checksum_seed(&literal));

        if i == 7 
        {
            assert!(result.is_ok(), "literal '{}' should generate a valid seed", literal);
        } else 
        {
            assert!(result.is_err(), "literal '{}' should raise an exception as it's not the correct length", literal);
        }
    }
}

#[test]
fn identifiable_secrets_platform_annotated_security_keys() {
    let iterations: u8 = 10;
    let mut keys_generated: u64 = 0;
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    for _i in 0..iterations
    {
        for _j in 0..iterations
        {
            for _k in 0..iterations
            {
                let mut signature: String = format!("{:?}", Uuid::new_v4().simple()).chars().skip(1).take(4).collect::<String>();

                signature = format!("{}{}", alphabet.chars().nth(((keys_generated as i32) % (alphabet.len() as i32)) as usize).unwrap().to_string(), &signature[1..]);

                let mut platform_reserved = [0u8; 9];
                let mut provider_reserved = [0u8; 3];

                let c_bits = 28;
                let p_bits = 41;
                let r_bits = 43;
                let t_bits = 45;

                let mut metadata: i32 = (c_bits << 18) | (c_bits << 12) | (c_bits << 6) | c_bits;
                let mut metadata_bytes = metadata.to_ne_bytes();

                platform_reserved[0] = metadata_bytes[1];
                platform_reserved[1] = metadata_bytes[2];
                platform_reserved[2] = metadata_bytes[3];

                metadata = (r_bits << 18) | (r_bits << 12) | (r_bits << 6) | r_bits;
                metadata_bytes = metadata.to_ne_bytes();

                platform_reserved[3] = metadata_bytes[1];
                platform_reserved[4] = metadata_bytes[2];
                platform_reserved[5] = metadata_bytes[3];

                metadata = (t_bits << 18) | (t_bits << 12) | (t_bits << 6) | t_bits;
                metadata_bytes = metadata.to_ne_bytes();

                platform_reserved[6] = metadata_bytes[1];
                platform_reserved[7] = metadata_bytes[2];
                platform_reserved[8] = metadata_bytes[3];

                metadata = (p_bits << 18) | (p_bits << 12) | (p_bits << 6) | p_bits;
                metadata_bytes = metadata.to_ne_bytes();

                provider_reserved[0] = metadata_bytes[1];
                provider_reserved[1] = metadata_bytes[2];
                provider_reserved[2] = metadata_bytes[3];

                let platform_reserved_vec = platform_reserved.to_vec();
                let provider_reserved_vec = provider_reserved.to_vec();

                for &customer_managed in &[true, false] {
                    for &long_form in &[true, false] {
                        let mut cased_signature = signature.clone();
                        if customer_managed {
                            cased_signature = cased_signature.to_uppercase();
                        } else {
                            cased_signature = cased_signature.to_lowercase();
                        }

                        let key = microsoft_security_utilities_core::identifiable_secrets::generate_common_annotated_key(&cased_signature, customer_managed, Some(&platform_reserved_vec), Some(&provider_reserved_vec), long_form, None).unwrap();

                        let mut result = microsoft_security_utilities_core::identifiable_secrets::COMMON_ANNOTATED_KEY_REGEX.is_match(key.as_str());
                        assert!(result, "the key '{}' should match the common annotated key regex", key);

                        result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(key.as_str(), &cased_signature);
                        assert!(result, "the key '{}' should comprise an HIS v2-conformant pattern", key);

                        keys_generated += 1;
                    }
                }
            }
        }
    }
}
    

#[test]
fn identifiable_secrets_compute_checksum_seed()
{
    let input_literal1 = "ROSeed00";
    let input_literal2 = "RWSeed00";
    let expected_checksum_seed1 = 0x524f536565643030;
    let expected_checksum_seed2 = 0x5257536565643030;

    let checksum_seed1 = microsoft_security_utilities_core::identifiable_secrets::compute_his_v1_checksum_seed(input_literal1);
    let checksum_seed2 = microsoft_security_utilities_core::identifiable_secrets::compute_his_v1_checksum_seed(input_literal2);

    assert_eq!(checksum_seed1, expected_checksum_seed1);
    assert_eq!(checksum_seed2, expected_checksum_seed2);
}

#[test]
fn identifiable_secrets_base62_alphabet_recognized()
{
    let mut alphabet = HashSet::new();

    for c in S_BASE62_ALPHABET.chars()
    {
        alphabet.insert(c);
    }

    for i in 0..256
    {
        let c: char = unsafe {char::from_u32_unchecked(i)};
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities_core::identifiable_secrets::is_base62_encoding_char(c));
    }
}

#[test]
fn identifiable_secrets_base64_alphabet_recognized()
{
    let mut s = String::from(S_BASE62_ALPHABET);
    s.push_str("+/");
    let base64_alphabet = s.as_str();
    let mut alphabet = HashSet::new();

    for c in base64_alphabet.chars()
    {
        alphabet.insert(c);
    }
    
    for i in 0..256
    {
        let c: char = unsafe {char::from_u32_unchecked(i)};
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities_core::identifiable_secrets::is_base64_encoding_char(c));
    }
}

#[test]
fn identifiable_secrets_base64_url_alphabet_recognized()
{
    let mut s = String::from(S_BASE62_ALPHABET);
    s.push_str("-_");
    let base64_alphabet = s.as_str();
    let mut alphabet = HashSet::new();

    for c in base64_alphabet.chars()
    {
        alphabet.insert(c);
    }
    
    for i in 0..256
    {
        let c: char = unsafe {char::from_u32_unchecked(i)};
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities_core::identifiable_secrets::is_base64_url_encoding_char(c));
    }
}

#[test]
fn identifiable_secrets_generate_standard_base64_key_should_throw_exception_for_invalid_lengths()
{        
    let signature = "ABCD";
    let seed = 0;
    
    let mut result = std::panic::catch_unwind(|| microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key
                                                                                  (seed,
                                                                            microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE + 1,
                                                                signature)
                                                            );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key
        (seed,
            microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE - 1,
            signature)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key
        (seed,
            32,
            "")
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key
        (seed,
            32,
            "this signature is too long")
        );
    assert!(result.is_err());
}

#[test]
fn identifiable_secrets_generate_url_base64_key_should_throw_exception_for_invalid_lengths()
{        
    let signature = "ABCD";
    let seed = 0;
    
    let mut result = std::panic::catch_unwind(|| 
                                                            microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key
                                                            (seed,
                                                                microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE + 1,
                                                                signature,
                                                                true),
                                                            );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key
        (seed,
            microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE - 1,
            signature,
            true)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key
        (seed,
            32,
            "",
            true)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key
        (seed,
            32,
            "this signature is too long",
            true)
        );
    assert!(result.is_err());

}

#[test]
fn identifiable_secrets_generate_standard_base64_key_should_panic_for_invalid_signatures()
{
    let mut rng = ChaCha20Rng::from_entropy();
    let seed = rng.gen::<u64>();
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(false);
    
    // This set of characters are is illegal in the signature.
    for i in 0..42
    {
        let injected_char = unsafe {char::from_u32_unchecked(i)};
        println!("Testing character {} for {}", injected_char, i);
        let mut signature: String = String::from("XXX");
        signature.push(injected_char);

        if !alphabet.contains(&injected_char)
        {
           // All illegal characters in the signature should raise an exception.
        let result = std::panic::catch_unwind(|| 
            microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key
            (seed,
                key_length_in_bytes,
                signature.as_str()
            ));
            assert!(result.is_err());
        }
    }
}

#[test]
fn identifiable_secrets_generate_url_base64_key_should_panic_for_invalid_signatures()
{
    let mut rng = ChaCha20Rng::from_entropy();
    let seed = rng.gen::<u64>();
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(true);
    
    // This set of characters is illegal in the signature.
    for i in 0..42
    {
        let injected_char = unsafe {char::from_u32_unchecked(i)};
        println!("Testing character {} for {}", injected_char, i);
        let mut signature: String = String::from("XXX");
        signature.push(injected_char);

        if !alphabet.contains(&injected_char)
        {
           // All illegal characters in the signature should raise an exception.
            let result = std::panic::catch_unwind(|| 
            microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key
            (seed,
                key_length_in_bytes,
                signature.as_str(),
                true
            ));
            assert!(result.is_err());
        }
    }
}

#[test]
fn identifiable_secrets_generate_standard_base64_key_basic()
{
    let mut rng = ChaCha20Rng::from_entropy();
    let seed = rng.gen::<u64>();
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(false);
    
    for injected_char in alphabet.iter()
    {
        let mut signature: String = String::from("XXX");
        signature.push(*injected_char);

        let secret =  microsoft_security_utilities_core::identifiable_secrets::generate_standard_safe_base64_key(seed,
        key_length_in_bytes,
        signature.as_str());
        
        validate_secret(secret, seed, signature, false);
    }
}

#[test]
fn identifiable_secrets_generate_url_base64_key_basic()
{
    let mut rng = ChaCha20Rng::from_entropy();
    let seed = rng.gen::<u64>();
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities_core::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities_core::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(true);
    
    for injected_char in alphabet.iter()
    {
        let mut signature: String = String::from("XXX");
        signature.push(*injected_char);

        let secret =  microsoft_security_utilities_core::identifiable_secrets::generate_url_safe_base64_key(seed,
        key_length_in_bytes,
        signature.as_str(),
        false);
        
        validate_secret(secret, seed, signature, true);
    }
}

// function, take HashSet as input, add elements and return it
fn add_to_set(encode_for_url: bool) -> HashSet<char> 
{
    let mut set = HashSet::new();

    let elements: Vec<char> = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

    for element in elements {
        set.insert(element);
    }

    if encode_for_url
    {
        set.insert('-');
        set.insert('_');
    }
    else
    {
        set.insert('+');
        set.insert('/');
    }
    set
}


fn validate_secret(secret: String, seed: u64, signature: String, encode_for_url: bool)
{
    let is_valid = crate::microsoft_security_utilities_core::identifiable_secrets::validate_base64_key(secret, seed, signature, encode_for_url);
    assert!(is_valid);
}


