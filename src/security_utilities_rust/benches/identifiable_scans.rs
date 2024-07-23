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

/*
pub fn write_data() {
    use rand::Rng;

    let mut rand = ChaCha20Rng::from_seed([1u8; 32]);

    let valid_signature = "ABCD";

    let valid_key =
        microsoft_security_utilities_core::identifiable_secrets::generate_common_annotated_key(
            valid_signature,
            true,
            Some(&vec![0; 9]),
            Some(&vec![0; 3]),
            true,
            Some('A'),
        )
        .unwrap();

    let random_chars: Vec<_> = (0..100).map(|_| rand.next_u32() % 1024).collect();

    let mut output: Vec<u8> = Vec::new();
    for random_char in random_chars {
        for _ in 0..random_char {
            let char: char = rand.gen();
            let len = output.len();
            output.extend([0u8; 8]);
            let bytes = char.encode_utf8(&mut output[len..]);

            for _ in 0..(8 - bytes.len()) {
                output.pop();
            }
        }

        output.extend(valid_key.as_bytes());
    }

    let output_data = std::str::from_utf8(&output).unwrap();

    std::fs::write("bench_data.utf8", output_data).unwrap();

    let mut scanner = Scan::new(Default::default());
    scanner.parse_bytes(output_data.as_bytes());
    assert_eq!(100, scanner.possible_matches().len());

    // TODO: write utf16 data
}
*/
