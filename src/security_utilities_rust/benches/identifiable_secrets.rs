use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use microsoft_security_utilities_core::microsoft_security_utilities_core::identifiable_secrets::{
    generate_common_annotated_key, try_validate_common_annotated_key,
};

fn id_secrets_benchmark(c: &mut Criterion) {
    let data = generate_common_annotated_key(
        "ABCD",
        true,
        Some(&vec![0; 9]),
        Some(&vec![0; 3]),
        true,
        Some('A'),
    )
    .unwrap();

    c.bench_function("validate", |b| {
        b.iter(|| try_validate_common_annotated_key(&data, "ABCD"))
    });
}

criterion_group! {
    name = id_secrets;
    config = Criterion::default().warm_up_time(Duration::from_millis(500));
    targets = id_secrets_benchmark,
}

criterion_main!(id_secrets);
