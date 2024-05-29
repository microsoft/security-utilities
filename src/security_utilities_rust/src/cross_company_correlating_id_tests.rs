#[cfg(test)]
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