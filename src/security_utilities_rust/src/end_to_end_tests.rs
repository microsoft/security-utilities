#[cfg(test)]
use super::*;

#[test]
fn generate_and_detect_common_annotated_key_test() {
    let options = microsoft_security_utilities_core::identifiable_scans::ScanOptions::default();
    let mut scan = microsoft_security_utilities_core::identifiable_scans::Scan::new(options);

    let input = microsoft_security_utilities_core::identifiable_secrets::generate_common_annotated_test_key(
                                                    microsoft_security_utilities_core::identifiable_secrets::VERSION_TWO_CHECKSUM_SEED.clone(),
                                                    "TEST",
                                                    true,
                                                    None,
                                                    None,
                                                    false,
                                                    Some('a')
                                                    );

    let generated_input = input.clone().unwrap();
    let input_as_bytes = generated_input.as_bytes();
    scan.parse_bytes(input_as_bytes);

    let check = scan.possible_matches().first().unwrap();
    let scan_match = check.matches_bytes(input_as_bytes, true);
    assert!(scan_match.is_some(), "identifiable_scan: at least one match found");

    let scan_match = scan_match.unwrap();
    assert_eq!(generated_input, scan_match.text(), "identifiable_scan: matched string equals generated input");

    let validation_result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(
        &generated_input,
        "TEST"
    );

    assert_eq!(validation_result, true, "checksum validation of generated input passes");
}