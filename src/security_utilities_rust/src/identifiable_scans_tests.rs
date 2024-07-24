#![cfg(test)]

use crate::microsoft_security_utilities_core::identifiable_scans::{ScanEngine, ScanState};

// Static functions to assert trait bounds on some type.
// (not actually unused)
#[allow(unused)]
const fn assert_send_and_sync<T: Send + Sync>() {}

// Assert that ScanEngine is Send + Sync, otherwise
// fail to compile.
const _: () = assert_send_and_sync::<ScanEngine>();

#[test]

fn his_v2_concurrency() {
    let scan_engine = ScanEngine::new(Default::default());

    // Type-level test: if sync/send is missing,
    // this won't compile.
    std::thread::scope(|s| {
        for _ in 0..3 {
            s.spawn(|| {
                let data = b"some cred";
                let mut state = ScanState::default();
                scan_engine.parse_bytes(&mut state, data);
            });
        }
    });
}
