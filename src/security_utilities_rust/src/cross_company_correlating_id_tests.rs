#[cfg(test)]
use super::*;

/// Compare a Marvin checksum against a well-known test case from the native code.
#[test]
fn validate_cross_company_correlation_id() {
    // This test verifies that our Rust implementation provides
    // the same result as SymCrypt for their standard test.
    // https://github.com/microsoft/SymCrypt/blob/master/lib/marvin32.c#L316
    
    // Assume
    let secret = "test";
    let expected_c3id = "rPHgxCVAOw6CZsT9xXEw";

    // Act
    let actual_c3id: String = microsoft_security_utilities_core::cross_company_correlating_id::generate_cross_company_correlating_id(secret);
    
    // Assert
    assert_eq!(expected_c3id, actual_c3id);
}