use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use microsoft_security_utilities_core::microsoft_security_utilities_core::marvin::compute_hash;

fn marvin_hash(data: &[u8]) {
    compute_hash(data, 0, 0, data.len() as i32);
}

fn marvin_benchmark(c: &mut Criterion) {
    let data_0 = [0u8; 0];
    let data_128 = [0u8; 128];
    let data_1024 = [0u8; 1024];
    let data_8192 = [0u8; 8192];
    let data_65535 = [0u8; 65535];

    c.bench_function("marvin 0", |b| b.iter(|| marvin_hash(&data_0)))
        .bench_function("marvin 128", |b| b.iter(|| marvin_hash(&data_128)))
        .bench_function("marvin 1024", |b| b.iter(|| marvin_hash(&data_1024)))
        .bench_function("marvin 8192", |b| b.iter(|| marvin_hash(&data_8192)))
        .bench_function("marvin 65535", |b| b.iter(|| marvin_hash(&data_65535)));
}

criterion_group! {
    name = marvin;
    config = Criterion::default().warm_up_time(Duration::from_millis(500));
    targets = marvin_benchmark,
}

criterion_main!(marvin);
