use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use microsoft_security_utilities_core::microsoft_security_utilities_core::cross_company_correlating_id::generate_cross_company_correlating_id;

fn c3id_benchmark(c: &mut Criterion) {
    let data_0: String = std::iter::repeat('a').take(0).collect();
    let data_8: String = std::iter::repeat('a').take(8).collect();
    let data_16: String = std::iter::repeat('a').take(16).collect();
    let data_32: String = std::iter::repeat('a').take(32).collect();
    let data_64: String = std::iter::repeat('a').take(64).collect();
    let data_88: String = std::iter::repeat('a').take(64).collect();
    let data_1024: String = std::iter::repeat('a').take(1024).collect();

    let c3id = |data| generate_cross_company_correlating_id(data);

    c.bench_function("c3id 0", |b| b.iter(|| c3id(&data_0)))
        .bench_function("c3id 8", |b| b.iter(|| c3id(&data_8)))
        .bench_function("c3id 16", |b| b.iter(|| c3id(&data_16)))
        .bench_function("c3id 32", |b| b.iter(|| c3id(&data_32)))
        .bench_function("c3id 64", |b| b.iter(|| c3id(&data_64)))
        .bench_function("c3id 88", |b| b.iter(|| c3id(&data_88)))
        .bench_function("c3id 1024", |b| b.iter(|| c3id(&data_1024)));
}

criterion_group! {
    name = c3id;
    config = Criterion::default().warm_up_time(Duration::from_millis(500));
    targets = c3id_benchmark,
}

criterion_main!(c3id);
