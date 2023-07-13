// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#[cfg(test)]
use super::*;
use std::{collections::HashSet, hash::Hash};
use base64::alphabet;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

static S_BASE62_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

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
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities::identifiable_secrets::is_base62_encoding_char(c));
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
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities::identifiable_secrets::is_base64_encoding_char(c));
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
        assert_eq!(alphabet.contains(&c), microsoft_security_utilities::identifiable_secrets::is_base64_url_encoding_char(c));
    }
}

#[test]
fn identifiable_secrets_generate_standard_base64_key_should_throw_exception_for_invalid_lengths()
{        
    let signature = "ABCD";
    let seed = 0;
    
    let mut result = std::panic::catch_unwind(|| microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key
                                                                                  (seed,
                                                                            microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE + 1,
                                                                signature)
                                                            );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key
        (seed,
            microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE - 1,
            signature)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key
        (seed,
            32,
            "")
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key
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
                                                            microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key
                                                            (seed,
                                                                microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE + 1,
                                                                signature,
                                                                true),
                                                            );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key
        (seed,
            microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE - 1,
            signature,
            true)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key
        (seed,
            32,
            "",
            true)
        );
    assert!(result.is_err());

    result = std::panic::catch_unwind(|| 
        microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key
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
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

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
            microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key
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
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

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
            microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key
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
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(false);
    
    for injected_char in alphabet.iter()
    {
        let mut signature: String = String::from("XXX");
        signature.push(*injected_char);

        let secret =  microsoft_security_utilities::identifiable_secrets::generate_standard_safe_base64_key(seed,
        key_length_in_bytes,
        signature.as_str());
        
        // validate_secret(secret, seed, signature, false);
    }
}

#[test]
fn identifiable_secrets_generate_url_base64_key_basic()
{
    let mut rng = ChaCha20Rng::from_entropy();
    let seed = rng.gen::<u64>();
    let key_length_in_bytes: u32 = rng.gen_range(microsoft_security_utilities::identifiable_secrets::MINIMUM_GENERATED_KEY_SIZE..microsoft_security_utilities::identifiable_secrets::MAXIMUM_GENERATED_KEY_SIZE);

    let alphabet: HashSet<char> = add_to_set(true);
    
    for injected_char in alphabet.iter()
    {
        let mut signature: String = String::from("XXX");
        signature.push(*injected_char);

        let secret =  microsoft_security_utilities::identifiable_secrets::generate_url_safe_base64_key(seed,
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
    let is_valid = crate::microsoft_security_utilities::identifiable_secrets::validate_base64_key(secret, seed, signature, encode_for_url);
    assert!(is_valid);
}


