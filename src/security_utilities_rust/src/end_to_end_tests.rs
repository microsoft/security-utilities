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

#[test]
fn identifiable_scanning_and_validation_perf_benchmark() {
    use std::time::{Duration, Instant};

    let mut identifiable_scan_durations: Vec<Duration> = Vec::new();
    let mut validation_durations: Vec<Duration> = Vec::new();

    let valid_signature = "ABCD";

    let options = microsoft_security_utilities_core::identifiable_scans::ScanOptions::default();
    let mut scan = microsoft_security_utilities_core::identifiable_scans::Scan::new(options);

    #[cfg(debug_assertions)]
    let iterations = 1_000;

    #[cfg(not(debug_assertions))]
    let iterations = 5_000_000;

    for _ in 0..iterations {
        let valid_key = microsoft_security_utilities_core::identifiable_secrets::
        generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            Some('A')
        );

        let generated_input = valid_key.clone().unwrap();
        let input_as_bytes = generated_input.as_bytes();
        scan.reset();

        let start = Instant::now();
        scan.parse_bytes(input_as_bytes);
        let check = scan.possible_matches().first().unwrap();
        let scan_match = check.matches_bytes(input_as_bytes, true);
        let duration = start.elapsed();

        assert!(scan_match.is_some(), "identifiable_scan: at least one match found");

        let scan_match = scan_match.unwrap();
        assert_eq!(generated_input, scan_match.text(), "identifiable_scan: matched string equals generated input");

        identifiable_scan_durations.push(duration);

        let start = Instant::now();
        let validation_result = microsoft_security_utilities_core::identifiable_secrets::try_validate_common_annotated_key(
            &generated_input,
            "ABCD"
        );
        let duration = start.elapsed();

        assert!(validation_result);

        validation_durations.push(duration);
    }

    let total_identifiable_scan_duration: Duration = identifiable_scan_durations.iter().sum();
    let mean_identifiable_scan_duration = total_identifiable_scan_duration / identifiable_scan_durations.len() as u32;

    let total_validation_duration: Duration = validation_durations.iter().sum();
    let mean_validation_duration = total_validation_duration / validation_durations.len() as u32;

    println!("Mean time for identifiable_scan: {:?}", mean_identifiable_scan_duration);
    println!("Mean time for checksum validation: {:?}", mean_validation_duration);
}

