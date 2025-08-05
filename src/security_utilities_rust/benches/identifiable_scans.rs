use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use microsoft_security_utilities_core::microsoft_security_utilities_core::identifiable_scans::{
    ScanEngine, ScanState,
};

fn id_scans_benchmark(c: &mut Criterion) {
    let data_utf8 = include_str!("../test_files/bench_data.utf8");
    let engine = ScanEngine::new(Default::default());

    c.bench_function("scan utf8", |b| {
        let mut state = ScanState::default();
        b.iter(|| {
            state.reset();
            engine.parse_bytes(&mut state, data_utf8.as_bytes());
        })
    });
}

criterion_group! {
    name = id_scans;
    config = Criterion::default().warm_up_time(Duration::from_millis(500));
    targets = id_scans_benchmark,
}

criterion_main!(id_scans);
