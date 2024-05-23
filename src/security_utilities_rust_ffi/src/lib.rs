use std::ffi::c_void;
use microsoft_security_utilities_core::{IdentifiableScan, IdentifiableScanOptions};

#[no_mangle]
extern "C" fn identifiable_scan_create() -> *mut c_void {
    let options = IdentifiableScanOptions::default();
    let scan = Box::new(IdentifiableScan::new(options));

    Box::into_raw(scan) as *mut c_void
}

#[no_mangle]
extern "C" fn identifiable_scan_destroy(
    scan: *mut c_void) {
    let scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };

    /* Drop */
    drop(scan);
}

#[no_mangle]
extern "C" fn identifiable_scan_start(
    scan: *mut c_void) {
    let mut scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };

    scan.reset();

    /* Don't drop */
    let _ = Box::into_raw(scan);
}

#[no_mangle]
extern "C" fn identifiable_scan_parse(
    scan: *mut c_void,
    data: *const u8,
    len: usize) -> bool {
    let mut scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };
    let data = unsafe { std::slice::from_raw_parts(data, len) };

    scan.parse_bytes(data);

    let result = scan.has_possible_matches();

    /* Don't drop */
    let _ = Box::into_raw(scan);

    result
}

#[no_mangle]
extern "C" fn identifiable_scan_match_count(
    scan: *mut c_void) -> u32 {
    let scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };

    let count = scan.possible_matches().len() as u32;

    /* Don't drop */
    let _ = Box::into_raw(scan);

    count
}

#[no_mangle]
extern "C" fn identifiable_scan_match_get(
    scan: *mut c_void,
    index: u32,
    start: *mut u64,
    len: *mut u64) -> bool {
    let scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };
    let matches = scan.possible_matches();
    let index = index as usize;

    /* Sanity checks */
    if index >= matches.len() ||
       start.is_null() ||
       len.is_null() {
        /* Don't drop */
        let _ = Box::into_raw(scan);

        return false;
    }

    let found = &matches[index];

    unsafe {
        *start = found.start();
        *len = found.len() as u64;
    }

    /* Don't drop */
    let _ = Box::into_raw(scan);

    true
}

fn ffi_string_copy(
    output: *mut u8,
    output_len: *mut usize,
    text: &str) {
    if output.is_null() || output_len.is_null() {
        return;
    }

    unsafe {
        if *output_len == 0 {
            return;
        }
    }

    let output = unsafe { std::slice::from_raw_parts_mut(output, *output_len) };
    let text = text.as_bytes();
    let mut length = text.len();

    if length >= output.len() {
        length = output.len() - 1;
    }

    output[0..length].copy_from_slice(&text[0..length]);
    output[length] = 0;

    unsafe {
        *output_len = length;
    }
}

#[no_mangle]
extern "C" fn identifiable_scan_match_check(
    scan: *mut c_void,
    index: u32,
    input: *const u8,
    input_len: usize,
    name: *mut u8,
    name_len: *mut usize,
    output: *mut u8,
    output_len: *mut usize) -> bool {
    let scan = unsafe { Box::from_raw(scan as *mut IdentifiableScan) };
    let matches = scan.possible_matches();
    let index = index as usize;

    /* Sanity checks */
    if index >= matches.len() || input.is_null() {
        /* Don't drop */
        let _ = Box::into_raw(scan);

        return false;
    }

    let found = &matches[index];

    let input = unsafe { std::slice::from_raw_parts(input, input_len as usize) };
    let want_text = !output.is_null() && !output_len.is_null();

    /* Check if we have a match */
    let result = if let Some(found) = found.matches_bytes(input, want_text) {
        /* Copy the UTF8 text out, if wanted */
        if want_text {
            ffi_string_copy(output, output_len, found.text());
        } else {
            if !output_len.is_null() {
                unsafe {
                    *output_len = 0;
                }
            }
        }

        /* Copy the name out */
        ffi_string_copy(name, name_len, found.name());

        /* Notify match */
        true
    } else {
        /* Notify miss */
        false
    };

    /* Don't drop */
    let _ = Box::into_raw(scan);

    result
}
