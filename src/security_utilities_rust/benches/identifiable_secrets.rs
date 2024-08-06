use std::time::Duration;

use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use microsoft_security_utilities_core::microsoft_security_utilities_core::{
    identifiable_scans::{Scan, ScanOptions},
    identifiable_secrets::{
        generate_common_annotated_key, try_validate_common_annotated_key, SecretMasker,
    },
};

fn id_secrets_benchmark(c: &mut Criterion) {
    let valid_signature = "ABCD";

    // generate a key
    let valid_key = generate_common_annotated_key(
        valid_signature,
        true,
        Some(&vec![0; 9]),
        Some(&vec![0; 3]),
        true,
        Some('A'),
    )
    .unwrap();

    c.bench_function("validate", |b| {
        b.iter(|| try_validate_common_annotated_key(&valid_key, "ABCD"))
    });

    let mut masking_group = c.benchmark_group("mask_secrets");
    let masking_input = include_str!("../test_files/bench_data.utf8");

    let mask_secrets = |b: &mut Bencher, token, validate| {
        let options = ScanOptions::default();
        let mut secret_masker = SecretMasker {
            scan: Scan::new(options),
        };

        b.iter(|| {
            let mut input = masking_input.to_string();
            secret_masker.mask_secrets(&mut input, token, validate);
        });
    };

    masking_group
        .bench_function("mask_secrets (validate without default)", |b| {
            mask_secrets(b, None, true)
        })
        .bench_function("mask_secrets (don't validate without default)", |b| {
            mask_secrets(b, None, false)
        })
        .bench_function("mask_secrets (validate with default)", |b| {
            mask_secrets(b, Some("abcdefghijkl"), true)
        })
        .bench_function("mask_secrets (don't validate with default)", |b| {
            mask_secrets(b, Some("abcdefghijkl"), false)
        });
}

criterion_group! {
    name = id_secrets;
    config = Criterion::default().warm_up_time(Duration::from_millis(500));
    targets = id_secrets_benchmark,
}

criterion_main!(id_secrets);
