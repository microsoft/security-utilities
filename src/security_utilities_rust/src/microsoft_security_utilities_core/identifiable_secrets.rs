// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

use base_62;
use base64::{engine::general_purpose, Engine as _};
use chrono::Datelike;
use core::panic;
use lazy_static::lazy_static;
use std::{mem};
use super::*;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use substring::Substring;

lazy_static! {
    pub static ref VERSION_TWO_CHECKSUM_SEED: u64 = compute_his_v1_checksum_seed("Default0");
}

pub static COMMON_ANNOTATED_KEY_REGEX_PATTERN: &str = r"(?-i)[A-Za-z0-9]{52}JQQJ9(9|D)[A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}([A-Za-z0-9]{2}==)?";

lazy_static! {
    pub static ref COMMON_ANNOTATED_KEY_REGEX: Regex = Regex::new(COMMON_ANNOTATED_KEY_REGEX_PATTERN).unwrap();
    }

pub static MAXIMUM_GENERATED_KEY_SIZE: u32 = 4096;
pub static MINIMUM_GENERATED_KEY_SIZE: u32 = 24;
static BITS_IN_BYTES: i32 = 8;
static BITS_IN_BASE64_CHARACTER: i32 = 6;
static SIZE_OF_CHECKSUM_IN_BYTES: i32 = mem::size_of::<u32>() as i32;

static COMMON_ANNOTATED_KEY_SIZE_IN_BYTES: usize = 63;

pub fn is_base62_encoding_char(ch: char) -> bool
{
    return (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9');
}

pub fn is_base64_encoding_char(ch: char) -> bool 
{
    return is_base62_encoding_char(ch) ||
                   ch == '+' ||
                   ch == '/';
}

pub fn is_base64_url_encoding_char(ch: char) -> bool
{
    return is_base62_encoding_char(ch) ||
                   ch == '-' ||
                   ch == '_';
}

/// Generate a u64 an HIS v1 compliant checksum seed from a string literal
/// that is 8 characters long and ends with at least one digit, e.g., 'ReadKey0', 'RWSeed00',
/// etc. The checksum seed is used to initialize the Marvin32 algorithm to watermark a
/// specific class of generated security keys.
///
/// # Arguments
///
/// * `versioned_key_kind` - A readable name that identifies a specific set of generated keys with at least one trailing digit in the name.
///
/// # Returns
///
/// The computed checksum seed as a u64.
///
/// # Errors
///
/// This function will return an error if the `versioned_key_kind` does not meet the required criteria.
pub fn compute_his_v1_checksum_seed(versioned_key_kind: &str) -> u64 {

    if versioned_key_kind.len() != 8 || !versioned_key_kind.chars().nth(7).unwrap().is_digit(10) {
        panic!("The versioned literal must be 8 characters long and end with a digit.");
    }

    let bytes = versioned_key_kind.as_bytes().iter().rev().cloned().collect::<Vec<u8>>();
    let result = u64::from_le_bytes(bytes.try_into().unwrap());

    result
}

pub fn try_validate_common_annotated_key(key: &str, base64_encoded_signature: &str) -> bool {
    let checksum_seed: u64 = VERSION_TWO_CHECKSUM_SEED.clone();

    let key_bytes = general_purpose::STANDARD.decode(&key).unwrap();

    assert_eq!(key_bytes.len(), COMMON_ANNOTATED_KEY_SIZE_IN_BYTES);

    let key_bytes_length = key_bytes.len();

    let bytes_for_checksum = &key_bytes[..key_bytes_length - 3];
    let actual_checksum_bytes = &key_bytes[key_bytes_length - 3..key_bytes_length];

    let computed_marvin = marvin::compute_hash32(bytes_for_checksum, checksum_seed, 0, bytes_for_checksum.len() as i32);
    let computed_marvin_bytes = computed_marvin.to_ne_bytes();

    // The HIS v2 standard requires a match for the first 3-bytes (24 bits) of the Marvin checksum.
    actual_checksum_bytes[0] == computed_marvin_bytes[0]
    && actual_checksum_bytes[1] == computed_marvin_bytes[1]
    && actual_checksum_bytes[2] == computed_marvin_bytes[2]
}

pub fn generate_common_annotated_key(base64_encoded_signature: &str,
    customer_managed_key: bool,
    platform_reserved: Option<&[u8]>,
    provider_reserved: Option<&[u8]>,
    test_char: Option<char>) -> Result<String, String> {
generate_common_annotated_test_key(VERSION_TWO_CHECKSUM_SEED.clone(),
      base64_encoded_signature,
      customer_managed_key,
      platform_reserved,
      provider_reserved,
      test_char)
}

pub fn generate_common_annotated_test_key(
    checksum_seed: u64,
    base64_encoded_signature: &str,
    customer_managed_key: bool,
    platform_reserved: Option<&[u8]>,
    provider_reserved: Option<&[u8]>,
    test_char: Option<char>,
) -> Result<String, String> {
    const PLATFORM_RESERVED_LENGTH: usize = 9;
    const PROVIDER_RESERVED_LENGTH: usize = 3;

    let platform_reserved = match platform_reserved {
        Some(reserved) if reserved.len() != PLATFORM_RESERVED_LENGTH => {
            return Err(format!(
                "When provided, there must be {} reserved bytes for platform metadata.",
                PLATFORM_RESERVED_LENGTH
            ));
        }
        Some(reserved) => reserved,
        None => &[0; PLATFORM_RESERVED_LENGTH],
    };

    let provider_reserved = match provider_reserved {
        Some(reserved) if reserved.len() != PROVIDER_RESERVED_LENGTH => {
            return Err(format!(
                "When provided, there must be {} reserved bytes for resource provider metadata.",
                PROVIDER_RESERVED_LENGTH
            ));
        }
        Some(reserved) => reserved,
        None => &[0; PROVIDER_RESERVED_LENGTH],
    };

    let base64_encoded_signature = if customer_managed_key {
        base64_encoded_signature.to_uppercase()
    } else {
        base64_encoded_signature.to_lowercase()
    };

    let mut key = String::new();

    loop {
        let key_length_in_bytes = 66;
        let mut key_bytes = vec![0; key_length_in_bytes];

        if let Some(test_char) = test_char {
            key = format!("{:86}==", test_char.to_string().repeat(86));
        } else {
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut key_bytes);
        }

        let key_string = general_purpose::STANDARD.encode(&key_bytes);
        key_bytes = general_purpose::STANDARD.decode(&key_string).unwrap();

        let j_bits = b'J' - b'A';
        let q_bits = b'Q' - b'A';

        let reserved = (j_bits as i32) << 18 | (q_bits as i32) << 12 | (q_bits as i32) << 6 | j_bits as i32;
        let reserved_bytes = reserved.to_ne_bytes();

        let key_bytes_length = key_bytes.len();

        key_bytes[key_bytes_length - 27] = reserved_bytes[2];
        key_bytes[key_bytes_length - 26] = reserved_bytes[1];
        key_bytes[key_bytes_length - 25] = reserved_bytes[0];

        let years_since_2024 = (chrono::Utc::now().year() - 2024) as u8;
        let zero_indexed_month = (chrono::Utc::now().month() - 1) as u8;

        let metadata: i32 = (61 << 18) | (61 << 12) | (years_since_2024 << 6) as i32 | zero_indexed_month as i32;
        let metadata_bytes = metadata.to_ne_bytes();

        key_bytes[key_bytes_length - 24] = metadata_bytes[2];
        key_bytes[key_bytes_length - 23] = metadata_bytes[1];
        key_bytes[key_bytes_length - 22] = metadata_bytes[0];

        key_bytes[key_bytes_length - 21] = platform_reserved[0];
        key_bytes[key_bytes_length - 20] = platform_reserved[1];
        key_bytes[key_bytes_length - 19] = platform_reserved[2];
        key_bytes[key_bytes_length - 18] = platform_reserved[3];
        key_bytes[key_bytes_length - 17] = platform_reserved[4];
        key_bytes[key_bytes_length - 16] = platform_reserved[5];
        key_bytes[key_bytes_length - 15] = platform_reserved[6];
        key_bytes[key_bytes_length - 14] = platform_reserved[7];
        key_bytes[key_bytes_length - 13] = platform_reserved[8];

        key_bytes[key_bytes_length - 12] = provider_reserved[0];
        key_bytes[key_bytes_length - 11] = provider_reserved[1];
        key_bytes[key_bytes_length - 10] = provider_reserved[2];

        let signature_offset = key_bytes_length - 9;
        let sig_bytes = general_purpose::STANDARD.decode(&base64_encoded_signature).unwrap();

        for i in 0..sig_bytes.len() {
            key_bytes[signature_offset + i] = sig_bytes[i];
        }

        let checksum = marvin::compute_hash32(&key_bytes, checksum_seed, 0, (key_bytes_length - 6) as i32);

        let checksum_bytes = checksum.to_ne_bytes();

        key_bytes[key_bytes_length - 6] = checksum_bytes[0];
        key_bytes[key_bytes_length - 5] = checksum_bytes[1];
        key_bytes[key_bytes_length - 4] = checksum_bytes[2];
        key_bytes[key_bytes_length - 3] = checksum_bytes[3];

        key = general_purpose::STANDARD.encode(&key_bytes[..COMMON_ANNOTATED_KEY_SIZE_IN_BYTES]);

        // The HIS v2 standard requires that there be no special characters in the generated key.
        if !key.contains('+') && !key.contains('/') {
            break;
        } else if test_char.is_some() {
            key = String::new();
            break;
        }
    }

    Ok(key)
}

/// Generate an identifiable secret with a URL-compatible format (replacing all '+'
/// characters with '-' and all '/' characters with '_') and eliding all padding
/// characters (unless the caller chooses to retain them). Strictly speaking, only
/// the '+' character is incompatible for tokens expressed as a query string
/// parameter. For this case, however, replacing the '/ character as well allows
/// for a full 64-character alphabet that can be decoded by standard API in .NET, 
/// Go, etc.
pub fn generate_url_safe_base64_key(checksum_seed: u64,
                                    key_length_in_bytes: u32,
                                    base64_encoded_signature: &str,
                                    elide_padding: bool) -> String
{
    let secret = generate_base64_key_helper(checksum_seed,
                                            key_length_in_bytes,
                                            base64_encoded_signature,
                                            true);

    
    // The '=' padding must be encoded in some URL contexts but can be 
    // directly expressed in others, such as a query string parameter.
    // Additionally, some URL Base64 Encoders (such as Azure's 
    // Base64UrlEncoder class) expect padding to be removed while
    // others (such as Go's Base64.URLEncoding helper) expect it to
    // exist. We therefore provide an option to express it or not.
    if elide_padding 
    { 
        return secret.as_str().trim_end_matches('=').to_string(); 
    } 
    else 
    {
        return secret; 
    }
}

pub fn generate_standard_safe_base64_key(checksum_seed: u64,
                                    key_length_in_bytes: u32,
                                    base64_encoded_signature: &str) -> String
{
    return generate_base64_key_helper(checksum_seed,
        key_length_in_bytes,
        base64_encoded_signature,
        false);
}

pub fn validate_base64_key(key: String, checksum_seed: u64, mut base64_encoded_signature: String, encode_for_url: bool) -> bool
{
    validate_base64_encoded_signature(&base64_encoded_signature, encode_for_url);

    let checksum_size_in_bytes = mem::size_of::<u32>();

    let mut bytes: Vec<u8> = Vec::new();
    convert_from_base64_string(&key, &mut bytes);
    let expected_checksum = i32::from_ne_bytes(bytes[bytes.len() - checksum_size_in_bytes..bytes.len()].try_into().unwrap());
    let actual_checksum = marvin::compute_hash32(&bytes, checksum_seed, 0, (bytes.len() - checksum_size_in_bytes) as i32);

    if actual_checksum != expected_checksum
    {
        return false;
    }

    // Compute the padding or 'spillover' into the final base64-encoded secret
    // for the random portion of the token, which is our data array minus
    // the bytes allocated for the checksum (4) and fixed signature (3). Every
    // base64-encoded character comprises 6 bits and so we can compute the 
    // underlying bytes for this data by the following computation:
    let signature_size_in_bytes = base64_encoded_signature.len() * 6 / 8;
    let padding = compute_spillover_bits_into_final_encoded_character((bytes.len() - signature_size_in_bytes - checksum_size_in_bytes) as i32);

    // Moving in the other direction, we can compute the encoded length of the checksum
    // calculating the # of bits for the checksum, and diving this value by 6 to 
    // determine the # of base64-encoded characters. Strictly speaking, for a 4-byte value,
    // the Ceiling computation isn't required, as there will be no remainder for this
    // value (4 * 8 / 6).
    let length_of_encoded_checksum: i32 = ((checksum_size_in_bytes as f64 * 8 as f64) / (6 as f64)).ceil() as i32;

    let mut equals_signs = "";
    let equals_sign_index = index_of(key.clone(), '=');
    let mut prefix_length = (key.len() as i32) - length_of_encoded_checksum - (base64_encoded_signature.len() as i32);
    let mut pattern = String::from("");

    if equals_sign_index > -1
    {
        equals_signs = key.substring(equals_sign_index as usize, key.len());
        prefix_length = equals_sign_index - length_of_encoded_checksum - base64_encoded_signature.len() as i32;
    }

    let trimmed_key = key.trim_matches('=');

    let signature_offset: i32 = trimmed_key.len() as i32 - length_of_encoded_checksum - base64_encoded_signature.len() as i32;
    
    if base64_encoded_signature != String::from(trimmed_key.substring(signature_offset as usize, (signature_offset as usize) + base64_encoded_signature.len()))
    {
        return false;
    }

    let  last_char: char = trimmed_key.chars().nth(trimmed_key.len() - 1).unwrap();
    let  first_char: char = trimmed_key.chars().nth(trimmed_key.len() - length_of_encoded_checksum as usize).unwrap();

    let mut special_chars = String::from("");
    if encode_for_url
    {
        special_chars.push_str("\\-_");
    }
    else 
    {
        special_chars.push_str("\\\\/+");
    }

    let mut secret_alphabet = String::from("[a-zA-Z0-9");
    for c in special_chars.chars()
    {
        secret_alphabet.push(c);
    }
    secret_alphabet.push(']');

    // We need to escape characters in the signature that are special in regex.
    base64_encoded_signature = base64_encoded_signature.replace("+", "\\+");

    let mut checksum_prefix = ""; 
    let mut checksum_suffix = "";

    match padding
    {
        2 =>
        {
            // When we are required to right-shift the fixed signatures by two
            // bits, the first encoded character of the checksum will have its
            // first two bits set to zero, limiting encoded chars to A-P.
            checksum_prefix = "[A-P]";

            // The following condition should always be true, since we 
            // have already verified the checksum earlier in this routine.
            // We explode all conditions in this check in order to
            // 'convince' VS code coverage these conditions are 
            // exhaustively covered.
            debug_assert!(first_char == 'A' || first_char == 'B' ||
                            first_char == 'C' || first_char == 'D' ||
                            first_char == 'E' || first_char == 'F' ||
                            first_char == 'G' || first_char == 'H' ||
                            first_char == 'I' || first_char == 'J' ||
                            first_char == 'K' || first_char == 'L' ||
                            first_char == 'M' || first_char == 'N' ||
                            first_char == 'O' || first_char == 'P');
        }

        4 =>
        {
            // When we are required to right-shift the fixed signatures by four
            // bits, the first encoded character of the checksum will have its
            // first four bits set to zero, limiting encoded chars to A-D.
            checksum_prefix = "[A-D]";

            // The following condition should always be true, since we 
            // have already verified the checksum earlier in this routine.
            debug_assert!(first_char == 'A' || first_char == 'B' ||
                            first_char == 'C' || first_char == 'D');
        }

        _ =>
        {
            // In this case, we have a perfect aligment between our decoded
            // signature and checksum and their encoded representation. As
            // a result, two bits of the final checksum byte will spill into
            // the final encoded character, followed by four zeros of padding.
            // This limits the possible values for the final checksum character
            // to one of A, Q, g & w.
            checksum_suffix = "[AQgw]";

            // The following condition should always be true, since we 
            // have already verified the checksum earlier in this routine.
            debug_assert!(last_char == 'A' || last_char == 'Q' ||
                            last_char == 'g' || last_char == 'w');
        }
    }

    // Example patterns, URL-friendly encoding:
    //   [a-zA-Z0-9\-_]{22}XXXX[A-D][a-zA-Z0-9\-_]{5}
    //   [a-zA-Z0-9\-_]{25}XXXX[A-P][a-zA-Z0-9\\-_]{5}
    //   [a-zA-Z0-9\-_]{24}XXXX[a-zA-Z0-9\-_]{5}[AQgw]

    pattern.push_str(secret_alphabet.as_str());
    pattern.push('{');
    pattern.push_str(prefix_length.to_string().as_str());
    pattern.push('}');
    pattern.push_str(base64_encoded_signature.as_str());
    pattern.push_str(checksum_prefix);
    pattern.push_str(&secret_alphabet);
    pattern.push_str("{5}");
    pattern.push_str(checksum_suffix);
    pattern.push_str(equals_signs);

    let re = Regex::new(pattern.as_str()).unwrap();
    return re.is_match(key.as_str());
}

// This helper is a primary focus of unit-testing, due to the fact it
// contains the majority of the logic for base64-encoding scenarios.
fn generate_base64_key_helper(checksum_seed: u64,
                              key_length_in_bytes: u32,
                              base64_encoded_signature: &str,
                              encode_for_url: bool) -> String
{
    if key_length_in_bytes > MAXIMUM_GENERATED_KEY_SIZE
    {
        panic!("Key length ({} bytes) must be less than {} bytes.", key_length_in_bytes, MAXIMUM_GENERATED_KEY_SIZE);
    }

    if key_length_in_bytes < MINIMUM_GENERATED_KEY_SIZE
    {
        panic!("Key length ({} bytes) must be at least {} bytes to provide sufficient security (>128 bits of entropy).",
                key_length_in_bytes,
                MINIMUM_GENERATED_KEY_SIZE);
    }

    validate_base64_encoded_signature(&String::from(base64_encoded_signature), encode_for_url);

    // NOTE: 'identifiable keys' help create security value by encoding signatures in
    //       both the binary and encoded forms of the token. Because of the minimum
    //       key length enforcement immediately above, this code DOES NOT COMPROMISE
    //       THE ACTUAL SECURITY OF THE KEY. The current SDL standard recommends 192
    //       bits of entropy. The minimum threshold is 128 bits.
    //
    //       Encoding signatures both at the binary level and within the base64-encoded
    //       version virtually eliminates false positives and false negatives in
    //       detection and enables for extremely efficient scanning. These values
    //       allow for much more stringent security controls, such as blocking keys
    //       entirely from source code, work items, etc.
    //
    // 'S' == signature byte : 'C' == checksum byte : '?' == sensitive byte
    // ????????????????????????????????????????????????????????????????????????????SSSSCCCCCC==
    //
    let random_bytes = get_csrandom_bytes(key_length_in_bytes);
    
    return generate_key_with_appended_signature_and_checksum(random_bytes,
                                                            String::from(base64_encoded_signature),
                                                            checksum_seed,
                                                            encode_for_url);
}

fn validate_base64_encoded_signature(base64_encoded_signature: &String, encode_for_url: bool)
{
    let required_encoded_signature_length = 4;

    if base64_encoded_signature.len() != required_encoded_signature_length
    {
        panic!("Base64-encoded signature must be 4 characters long.");
    }

    for ch in base64_encoded_signature.chars()
    {
        let mut is_valid_char = true;

        if encode_for_url
        {
            is_valid_char = is_base64_url_encoding_char(ch);
        }
        else
        {
            is_valid_char = is_base64_encoding_char(ch);
        }

        if !is_valid_char
        {
            let mut prefix = "";
            if encode_for_url
            {
                prefix = "URL ";
            }
            panic!("Signature contains one or more illegal characters {}base64-encoded characters: {}",
                prefix, base64_encoded_signature);
        }
    }
}

fn get_csrandom_bytes(key_length_in_bytes: u32) -> Vec<u8>
{
    let mut rng = ChaCha20Rng::from_entropy();
    let mut random_bytes: Vec<u8> = Vec::new();

    for i in 0..key_length_in_bytes
    {
        random_bytes.push(rng.gen::<u8>());
    }

    return random_bytes.try_into().unwrap();
}

fn generate_key_with_appended_signature_and_checksum(mut key_value: Vec<u8>,
                                                    base64_encoded_signature: String,
                                                    checksum_seed: u64,
                                                    encode_for_url: bool) -> String
{
    let key_length_in_bytes = key_value.len();
    let checksum_offset = key_length_in_bytes - 4;
    let signature_offset = checksum_offset - 4;

    // Compute a signature that will render consistently when
    // base64-encoded. This potentially requires consuming bits
    // from the byte that precedes the signature (to keep data
    // aligned on a 6-bit boundary, as required by base64).
    let signature_prefix_byte = key_value[signature_offset];

    let mut signature_bytes: Vec<u8> = Vec::new();
    get_base64_encoded_signature_bytes(key_length_in_bytes,
                                        &base64_encoded_signature,
                                        &signature_prefix_byte,
                                        &mut signature_bytes);

    copy(&signature_bytes, &mut key_value, signature_offset);

    // We will disregard the final four bytes of the randomized input, as 
    // these bytes will be overwritten with the checksum, and therefore
    // aren't relevant to that computation.
    let size_of_checksum_in_bytes = mem::size_of::<u32>();
    let checksum = marvin::compute_hash32(&key_value, checksum_seed, 0, (key_value.len() - size_of_checksum_in_bytes) as i32);

    let checksum_bytes = checksum.to_le_bytes().to_vec();
    copy(&checksum_bytes, &mut key_value, checksum_offset);

    return convert_to_base64_string(key_value, encode_for_url);
}
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
fn get_base64_encoded_signature_bytes(key_length_in_bytes: usize,
                                    base64_encoded_signature: &String,
                                    signature_prefix_byte: &u8,
                                    mut signature_bytes: &mut Vec<u8>)
{
    convert_from_base64_string(&base64_encoded_signature, &mut signature_bytes);

    let mut signature: u32 = (*signature_prefix_byte as u32) << 24;

    // Compute the padding or 'spillover' into the final base64-encoded secret
    // for the random portion of the token, which is our data array minus
    // 7 bytes (3 bytes for the fixed signature, 4 bytes for the checksum).
    let padding: i32 = compute_spillover_bits_into_final_encoded_character((key_length_in_bytes - 7) as i32);            
    
    let mut mask = u32::MAX;

    match padding 
    {
        2 =>
        {
            // Clear two bits where the signature will be right-shifted
            // to align on the base64-encoded 6-bit boundary. 
            mask = 0xfcffffff;
        },
        4 =>
        {
            // Clear four bits where the signature will be right-shifted
            // to remain aligned with base64-encoded 6-bit boundary.
            mask = 0xf0ffffff;
        }
        _ => {}
    }

    signature &= mask;

    signature |= (signature_bytes[0] as u32) << (16 + padding);
    signature |= (signature_bytes[1] as u32) << (8 + padding);
    signature |= (signature_bytes[2] as u32) << (0 + padding);

    signature_bytes.clear();

    for i in signature.to_ne_bytes().iter()
    {
        signature_bytes.push(*i);
    }

    if cfg!(target_endian = "little") {
        signature_bytes.reverse();
    } 
}

fn convert_from_base64_string(text: &String, signature_bytes: &mut Vec<u8>)
{
    let mut text_ = transform_to_standard_encoding(&text);
    text_.push_str(retrieve_padding_for_base64_encoded_text(&text).as_str());

    let decoded_txt = general_purpose::STANDARD.decode(&text_).unwrap();
    signature_bytes.clear();

    for i in decoded_txt
    {
        signature_bytes.push(i);
    }
}

fn transform_to_standard_encoding(url_safe_base64_encoded_text: &String) -> String
{
    return url_safe_base64_encoded_text.replace("-", "+").replace("_", "/");
}

fn transform_to_url_safe_encoding(base64_encoded_text: &String) -> String
{
    return base64_encoded_text.replace("+", "-").replace("/", "_");
}

fn retrieve_padding_for_base64_encoded_text(text: &String) -> String
{
    let padding_count = 4 - text.len() % 4;

    if !text.ends_with("=") && padding_count < 3
    {
        let x = std::iter::repeat("=").take(padding_count).collect::<String>();
        return x;
    }
    else 
    {
        return "".to_string();
    }
}

fn compute_spillover_bits_into_final_encoded_character(count_of_bytes: i32) -> i32
{
    // Retrieve padding required to maintain the 6-bit alignment
    // that allows the base64-encoded signature to render.
    // 
    // First we compute the # of bits of total information to encode.
    // Next, using the modulo operator, we determine the number of 
    // 'spillover' bits that will flow into, but not not completely 
    // fill, the final 6-bit encoded value. 
    count_of_bytes * BITS_IN_BYTES % BITS_IN_BASE64_CHARACTER
}

fn copy(from: &Vec<u8>, to: &mut Vec<u8>, start_idx: usize)
{
    let mut idx: usize = 0;
    for i in from
    {
        to[start_idx + idx] = *i;
        idx += 1;
    }
}

fn convert_to_base64_string(data: Vec<u8>, encode_for_url: bool) -> String
{
    let mut text = general_purpose::STANDARD.encode(&data);

    if encode_for_url
    {
        text = String::from(transform_to_url_safe_encoding(&text));
    }
    return text;
}

fn index_of(input_string: String, search_char: char) -> i32
{
    let res = input_string.chars().position(|c| c == search_char);

    match res
    {
        None => -1,
        Some(index) => index as i32
    }
}

