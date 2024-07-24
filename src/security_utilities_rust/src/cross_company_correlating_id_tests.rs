#![cfg(test)]

use microsoft_security_utilities_core::cross_company_correlating_id::hex_encode;

use super::*;

/// Compare a Rust generated C3Id against a well-known test case from C#.
#[test]
fn validate_cross_company_correlation_id() {
    // Assume
    let secret = "test";
    let expected_c3id = "rPHgxCVAOw6CZsT9xXEw";

    // Act
    let actual_c3id: String = microsoft_security_utilities_core::cross_company_correlating_id::generate_cross_company_correlating_id(secret);

    // Assert
    assert_eq!(expected_c3id, actual_c3id);
}

#[test]
fn hex_valid() {
    let res = [
        (0, b'0'),
        (1, b'1'),
        (2, b'2'),
        (3, b'3'),
        (4, b'4'),
        (5, b'5'),
        (6, b'6'),
        (7, b'7'),
        (8, b'8'),
        (9, b'9'),
        (10, b'A'),
        (11, b'B'),
        (12, b'C'),
        (13, b'D'),
        (14, b'E'),
        (15, b'F'),
    ];

    for (input, output) in res {
        let hex = hex_encode(input).unwrap();
        assert_eq!(hex, output, "{}, {}, {}", input, output, hex as char);
    }
}

#[test]
fn hex_invalid() {
    for v in 16..u8::MAX {
        assert!(hex_encode(v).is_none());
    }
}
