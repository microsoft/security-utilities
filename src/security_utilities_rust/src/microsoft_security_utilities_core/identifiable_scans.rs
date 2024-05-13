// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

const HIS2_UTF8_LEN: usize = 88;
const HIS2_UTF8_SHORT_LEN: usize = 84;

const HIS2_UTF16_LEN: usize = HIS2_UTF8_LEN * 2;
const HIS2_UTF16_SHORT_LEN: usize = HIS2_UTF8_SHORT_LEN * 2;
const HIS2_UTF16_SHORT_LEN_BE: usize = HIS2_UTF16_SHORT_LEN - 1;

const HIS_32_UTF8_LEN: usize = 44;
const HIS_64_UTF8_LEN: usize = 88;

const HIS_32_UTF16_LEN: usize = HIS_32_UTF8_LEN * 2;
const HIS_64_UTF16_LEN: usize = HIS_64_UTF8_LEN * 2;

trait Base64 {
    fn is_base64(&self) -> bool;
}

impl Base64 for u8 {
    fn is_base64(&self) -> bool {
        self.is_ascii_alphanumeric() ||
        *self == b'+' ||
        *self == b'/' ||
        *self == b'-' ||
        *self == b'_'
    }
}

/*
 * NOTE:
 * These are exposed for FFI, we must keep the numbers consistent.
 */
#[derive(Copy, Clone)]
pub enum ScanMatchType {
    His32Utf8 = 1,
    His32Utf16 = 2,
    His64Utf8 = 3,
    His64Utf16 = 4,
    His2Utf8 = 5,
    His2Utf16 = 6,
}

pub struct ScanMatch {
    start: u64,
    len: u64,
    mtype: ScanMatchType,
    text: Option<String>,
}

impl ScanMatch {
    fn new(
        mtype: ScanMatchType,
        start: u64,
        len: u64,
        data: &[u8],
        want_text: bool) -> Self {
        Self {
            mtype,
            start,
            len,
            text: match want_text {
                true => {
                    Some(std::str::from_utf8(data)
                         .expect("Already in UTF8")
                         .to_string())
                },
                false => { None }
            }
        }
    }

    pub fn start(&self) -> u64 { self.start }

    pub fn len(&self) -> u64 { self.len }

    pub fn match_type(&self) -> &ScanMatchType { &self.mtype }

    pub fn text(&self) -> &str {
        match &self.text {
            Some(text) => { &text },
            None => { "" },
        }
    }
}

pub struct PossibleScanMatch {
    start: u64,
    mtype: ScanMatchType,
}

impl PossibleScanMatch {
    fn new(
        start: u64,
        mtype: ScanMatchType) -> Self {
        Self {
            start,
            mtype,
        }
    }

    pub fn start(&self) -> u64 { self.start }

    pub fn len(&self) -> usize { 
        match &self.mtype {
            ScanMatchType::His2Utf8 => { HIS2_UTF8_LEN },
            ScanMatchType::His2Utf16 => { HIS2_UTF16_LEN },
            ScanMatchType::His32Utf8 => { HIS_32_UTF8_LEN },
            ScanMatchType::His32Utf16 => { HIS_32_UTF16_LEN },
            ScanMatchType::His64Utf8 => { HIS_64_UTF8_LEN },
            ScanMatchType::His64Utf16 => { HIS_64_UTF16_LEN },
        }
    }

    pub fn match_type(&self) -> &ScanMatchType { &self.mtype }

    fn his_32_matched_bytes(data: &[u8]) -> usize {
        /*
         * 33 Base64 + 4 signature + 1 [A-P] + 5 Base64 + optional 1 [=]
         */
        if data.len() < 43 {
            return 0;
        }

        for b in &data[0..33] {
            if !b.is_base64() {
                return 0;
            }
        }

        /* NOTE: We skip the signature since we already checked */

        if data[37] < b'A' || data[37] > b'P' {
            return 0;
        }

        for b in &data[38..43] {
            if !b.is_base64() {
                return 0;
            }
        }

        if data.len() >= HIS_32_UTF8_LEN {
            if data[43] == b'=' {
                return HIS_32_UTF8_LEN;
            }
        }

        43
    }

    fn his_64_matched_bytes(data: &[u8]) -> usize {
        /*
         * 76 Base64 + 4 signature + 5 Base64 + 1 [AQgw] + optional 2 [=]
         */
        if data.len() < 86 {
            return 0;
        }

        for b in &data[0..76] {
            if !b.is_base64() {
                return 0;
            }
        }

        /* NOTE: We skip the signature since we already checked */

        for b in &data[80..85] {
            if !b.is_base64() {
                return 0;
            }
        }

        if data[85] != b'A' && data[85] != b'Q' &&
           data[85] != b'g' && data[85] != b'w' {
               return 0;
        }

        if data.len() >= HIS_64_UTF8_LEN {
            for b in &data[86..88] {
                if *b != b'=' {
                    return 86;
                }
            }

            return HIS_64_UTF8_LEN;
        }

        86
    }

    fn his2_matched_bytes(data: &[u8]) -> usize {
        /* 
         * Checks are equivalent to this regex:
         * [A-Za-z0-9]{52}JQQJ99[A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}([A-Za-z0-9]{2}==)?
         */
        if data.len() < HIS2_UTF8_SHORT_LEN {
            return 0;
        }

        for b in &data[0..52] {
            if !b.is_ascii_alphanumeric() {
                return 0;
            }
        }

        if &data[52..58] != b"JQQJ99" {
            return 0;
        }

        if !data[58].is_ascii_alphanumeric() {
            return 0;
        }

        if data[59] < b'A' || data[59] > b'L' {
            return 0;
        }

        for b in &data[60..76] {
            if !b.is_ascii_alphanumeric() {
                return 0;
            }
        }

        if !data[76].is_ascii_alphabetic() {
            return 0;
        }

        for b in &data[77..84] {
            if !b.is_ascii_alphanumeric() {
                return 0;
            }
        }

        if data.len() < HIS2_UTF8_LEN {
            return HIS2_UTF8_SHORT_LEN;
        }

        for b in &data[84..86] {
            if !b.is_ascii_alphanumeric() {
                return HIS2_UTF8_SHORT_LEN;
            }
        }

        for b in &data[86..] {
            if *b != b'=' {
                return HIS2_UTF8_SHORT_LEN;
            }
        }

        HIS2_UTF8_LEN
    }

    fn convert_utf16(
        utf16: &[u8],
        utf8: &mut [u8]) -> usize {
        let len = utf16.len() / 2;
        let mut u = 0;

        /* Check once */
        if utf8.len() < len || len == 0 {
            return 0;
        }

        /* Validate and convert to UTF8 */
        for i in 0..len {
            if utf16[u+1] != 0 {
                return i;
            }
            utf8[i] = utf16[u];
            u += 2;
        }

        len
    }

    fn check_bytes_v1(
        mtype: &ScanMatchType,
        start: u64,
        data: &[u8],
        want_text: bool) -> Option<ScanMatch> {
        match mtype {
            ScanMatchType::His32Utf8 => {
                let len = Self::his_32_matched_bytes(&data);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His32Utf8,
                        start,
                        len as u64,
                        &data[0..len],
                        want_text))
            },

            ScanMatchType::His64Utf8 => {
                let len = Self::his_64_matched_bytes(&data);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His64Utf8,
                        start,
                        len as u64,
                        &data[0..len],
                        want_text))
            },

            ScanMatchType::His32Utf16 => {
                let mut bytes: [u8; HIS_32_UTF8_LEN] = [0; HIS_32_UTF8_LEN];
                let mut count = Self::convert_utf16(data, &mut bytes);

                if data.len() & 1 == 1 {
                    /* Add trailing unaligned byte edge case */
                    bytes[count] = data[data.len()-1];
                    count += 1;
                }

                let len = Self::his_32_matched_bytes(&bytes);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His32Utf8,
                        start,
                        (count * 2) as u64,
                        &bytes[0..count],
                        want_text))
            },

            ScanMatchType::His64Utf16 => {
                let mut bytes: [u8; HIS_64_UTF8_LEN] = [0; HIS_64_UTF8_LEN];
                let mut count = Self::convert_utf16(data, &mut bytes);

                if data.len() & 1 == 1 {
                    /* Add trailing unaligned byte edge case */
                    bytes[count] = data[data.len()-1];
                    count += 1;
                }

                let len = Self::his_64_matched_bytes(&bytes);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His64Utf8,
                        start,
                        (count * 2) as u64,
                        &bytes[0..count],
                        want_text))
            },

            /* Unknown */
            _ => { None }
        }
    }

    fn check_bytes_v2(
        mtype: &ScanMatchType,
        start: u64,
        data: &[u8],
        want_text: bool) -> Option<ScanMatch> {
        match mtype {
            ScanMatchType::His2Utf8 => {
                let len = Self::his2_matched_bytes(&data);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His2Utf8,
                        start,
                        len as u64,
                        &data[0..len],
                        want_text))
            },

            ScanMatchType::His2Utf16 => {
                let mut bytes: [u8; HIS2_UTF8_LEN] = [0; HIS2_UTF8_LEN];
                let mut count = Self::convert_utf16(data, &mut bytes);

                if data.len() & 1 == 1 {
                    /* Add trailing unaligned byte edge case */
                    bytes[count] = data[data.len()-1];
                    count += 1;
                }

                let len = Self::his2_matched_bytes(&bytes[..count]);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        ScanMatchType::His2Utf16,
                        start,
                        (count * 2) as u64,
                        &bytes[..count],
                        want_text))
            },
            
            /* Unknown */
            _ => { None },
        }
    }

    pub fn matches_reader(
        &self,
        reader: &mut (impl std::io::Read + std::io::Seek),
        buf: &mut [u8],
        want_text: bool) -> std::io::Result<Option<ScanMatch>> {
        if buf.len() < self.len() {
            return Err(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Buffer not big enough"));
        }

        reader.seek(std::io::SeekFrom::Start(self.start()))?;

        let len = self.len();
        let mut read = 0;
        let mut slice = &mut buf[read..len];

        while read < len {
            let count = reader.read(slice)?;

            if count == 0 {
                break;
            }

            read += count;
            slice = &mut slice[read..len];
        }

        match self.mtype {
            ScanMatchType::His2Utf8 |
            ScanMatchType::His2Utf16 => {
                Ok(Self::check_bytes_v2(
                    &self.mtype,
                    self.start,
                    &buf[..read],
                    want_text))
            },
            _ => {
                Ok(Self::check_bytes_v1(
                    &self.mtype,
                    self.start,
                    &buf[..read],
                    want_text))
            }
        }
    }

    pub fn matches_bytes(
        &self,
        data: &[u8],
        want_text: bool) -> Option<ScanMatch> {
        let mut end = self.len();

        /* Partial read or truncation case */
        if data.len() < end {
            /* Scan up to end */
            end = data.len();
        }

        match self.mtype {
            ScanMatchType::His2Utf8 |
            ScanMatchType::His2Utf16 => {
                Self::check_bytes_v2(
                    &self.mtype,
                    self.start,
                    &data[..end],
                    want_text)
            },
            _ => {
                Self::check_bytes_v1(
                    &self.mtype,
                    self.start,
                    &data[..end],
                    want_text)
            }
        }
    }
}

pub struct ScanOptions {
    v1: bool,
    v2: bool,
}

impl ScanOptions {
    pub fn without_v1(self) -> Self {
        let mut clone = self;
        clone.v1 = false;
        clone
    }

    pub fn without_v2(self) -> Self {
        let mut clone = self;
        clone.v2 = false;
        clone
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            v1: true,
            v2: true,
        }
    }
}

pub struct Scan {
    options: ScanOptions,
    accum: u64,
    index: u64,
    last_a_index: u64,
    checks: Vec<PossibleScanMatch>,
}

impl Scan {
    pub fn new(options: ScanOptions) -> Self {
        Self {
            options,
            accum: 0,
            index: 0,
            last_a_index: 0,
            checks: Vec::new(),
        }
    }

    pub fn has_possible_matches(&self) -> bool { !self.checks.is_empty() }

    pub fn possible_matches(&self) -> &Vec<PossibleScanMatch> { &self.checks }

    pub fn reset(&mut self) {
        self.accum = 0;
        self.index = 0;
        self.last_a_index = 0;
        self.checks.clear();
    }

    #[cfg(target_endian = "little")] // If run on BE, need to update
    #[inline(always)]
    fn match_sig_v1(&mut self) {
        /*
         * We have many signatures, but they all have A at certain
         * distances in the accumulator. We use that to speed up
         * the comparison branch checks.
         */
        let a_dist = self.a_distance();

        /* UTF8 */
        if a_dist == 4 || a_dist == 3 {
            match self.accum & 0xFFFFFFFF {
                /* 32-byte signatures */
                /* AIoT */
                0x41496F54 |
                /* +ASb */
                0x2B415362 |
                /* +AEh */
                0x2B414568 |
                /* +ARm */
                0x2B41526D => {
                    if self.index >= 37 {
                        /* Signature Detection */
                        self.checks.push(
                            PossibleScanMatch::new(
                                self.index - 37,
                                ScanMatchType::His32Utf8));
                    }
                },

                /* 64-byte signatures */
                /* APIM */
                0x4150494D |
                /* /AM7 */
                0x2F414D37 |
                /* ACDb */
                0x41434462 |
                /* +ABa */
                0x2B414261 |
                /* +AMC */
                0x2B414D43 |
                /* +ASt */
                0x2B415374 => {
                    if self.index >= 80 {
                        /* Signature Detection */
                        self.checks.push(
                            PossibleScanMatch::new(
                                self.index - 80,
                                ScanMatchType::His64Utf8));
                    }
                }
                _ => {},
            }
        }

        /* UTF16 */
        if a_dist == 7 || a_dist == 5 {
            match self.accum {
                /* 32-byte signatures */
                /* AIoT */
                0x00410049006F0054 |
                /* +ASb */
                0x002B004100530062 |
                /* +AEh */
                0x002B004100450068 |
                /* +ARm */
                0x002B00410052006D => {
                    if self.index >= 73 {
                        /* Signature Detection */
                        self.checks.push(
                            PossibleScanMatch::new(
                                self.index - 73,
                                ScanMatchType::His32Utf16));
                    }
                },

                /* 64-byte signatures */
                /* APIM */
                0x004100500049004D |
                /* /AM7 */
                0x002F0041004D0037 |
                /* ACDb */
                0x0041004300440062 |
                /* +ABa */
                0x002B004100420061 |
                /* +AMC */
                0x002B0041004D0043 |
                /* +ASt */
                0x002B004100530074 => {
                    if self.index >= 159 {
                        /* Signature Detection */
                        self.checks.push(
                            PossibleScanMatch::new(
                                self.index - 159,
                                ScanMatchType::His64Utf16));
                    }
                }
                _ => {},
            }
        }
    }

    #[cfg(target_endian = "little")] // If run on BE, need to update
    #[inline(always)]
    fn match_sig_v2(&mut self) {
        /* Detect "JQQJ" in either UTF8 or UTF16 (LE or BE) */
        if self.accum & 0xFFFFFFFF == 0x4A51514A {
            if self.index >= 56 {
                /* Signature Detection */
                self.checks.push(
                    PossibleScanMatch::new(
                        self.index - 56,
                        ScanMatchType::His2Utf8));
            }
        } else if self.accum == 0x004A00510051004A {
            if self.index >= 111 {
                /* Signature Detection */
                self.checks.push(
                    PossibleScanMatch::new(
                        self.index - 111,
                        ScanMatchType::His2Utf16));
            }
        }
    }

    #[inline(always)]
    #[cold]
    fn byte_scan_v1(
        &mut self,
        data: &[u8]) {
        for b in data {
            let b = *b;
            if b == b'A' {
                self.last_a_index = self.index;
            }
            self.accum = self.accum << 8 | b as u64;
            self.index += 1;

            self.match_sig_v1();
        }
    }

    #[inline(always)]
    #[cold]
    fn byte_scan_v2(
        &mut self,
        data: &[u8]) {
        for b in data {
            let b = *b;
            self.accum = self.accum << 8 | b as u64;
            self.index += 1;

            /* Only need to check accumulator on J */
            if b != b'J' {
                continue;
            }

            self.match_sig_v2();
        }
    }

    #[inline(always)]
    #[cold]
    fn byte_scan_all(
        &mut self,
        data: &[u8]) {
        for b in data {
            let b = *b;
            if b == b'A' {
                self.last_a_index = self.index;
            }
            self.accum = self.accum << 8 | b as u64;
            self.index += 1;

            if b != b'J' {
                self.match_sig_v1();
            } else {
                self.match_sig_v2();
            }
        }
    }

    #[inline(always)]
    fn a_distance(&self) -> u64 {
        self.index - self.last_a_index
    }

    #[inline(always)]
    fn a_in_accum(&self) -> bool {
        self.a_distance() < 8
    }

    pub fn parse_bytes(
        &mut self,
        data: &[u8]) {
        let chunks = data.chunks_exact(16);
        let rem = chunks.remainder();

        if self.options.v1 && self.options.v2 {
            /* Both V1 and V2 */
            for chunk in chunks {
                /* Check if last bytes in accum have an A */
                if !self.a_in_accum() {
                    /* Vectorized (SIMD) check for J or A */
                    let mut count = 0;
                    for i in 0..16 {
                        count |= (chunk[i] == b'J') as usize;
                    }
                    for i in 0..16 {
                        count |= (chunk[i] == b'A') as usize;
                    }

                    /* No J's or A's, set accumulator and continue */
                    if count == 0 {
                        self.index += 16;
                        self.accum = u64::from_ne_bytes(chunk[8..16].try_into().unwrap());
                        continue;
                    }
                }

                /* Scan for signature */
                self.byte_scan_all(chunk);
            }

            /* Scan remaining bytes */
            self.byte_scan_all(rem);
        } else if self.options.v1 {
            for chunk in chunks {
                /* Check if last bytes in accum have an A */
                if !self.a_in_accum() {
                    /* Vectorized (SIMD) check for A */
                    let mut count = 0;
                    for i in 0..16 {
                        count |= (chunk[i] == b'A') as usize;
                    }

                    /* No A's, set accumulator and continue */
                    if count == 0 {
                        self.index += 16;
                        self.accum = u64::from_ne_bytes(chunk[8..16].try_into().unwrap());
                        continue;
                    }
                }

                /* Scan for signature */
                self.byte_scan_v1(chunk);
            }

            /* Scan remaining bytes */
            self.byte_scan_v1(rem);
        } else {
            /* V2 Only */
            for chunk in chunks {
                /* Vectorized (SIMD) check for J */
                let mut count = 0;
                for i in 0..16 {
                    count |= (chunk[i] == b'J') as usize;
                }

                /* No J's, set accumulator and continue */
                if count == 0 {
                    self.index += 16;
                    self.accum = u64::from_ne_bytes(chunk[8..16].try_into().unwrap());
                    continue;
                }

                /* Scan for signature */
                self.byte_scan_v2(chunk);
            }

            /* Scan remaining bytes */
            self.byte_scan_v2(rem);
        }
    }

    pub fn parse_reader(
        &mut self,
        reader: &mut impl std::io::Read,
        buf: &mut [u8]) -> std::io::Result<()> {
        /* Reset for caller */
        self.reset();

        /* Parse all blocks of the reader */
        loop {
            let len = reader.read(buf)?;

            if len == 0 {
                break;
            }

            self.parse_bytes(&buf[..len]);
        }

        /* Scanned all blocks */
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn his_v2_scan_files() {
        let mut scan = Scan::new(ScanOptions::default());
        let mut buf: [u8; 4096] = [0; 4096];

        /* 50 long, 50 short, UTF8 */
        let mut reader = std::fs::File::open("test_files/his2_utf8.bin").unwrap();

        scan.parse_reader(&mut reader, &mut buf).unwrap();
        assert!(scan.has_possible_matches());
        assert_eq!(100, scan.possible_matches().len());

        let mut case = 1;
        for m in scan.possible_matches() {
            let result = m.matches_reader(&mut reader, &mut buf, true).unwrap();

            assert!(result.is_some(), "Case {}", case);
            let result = result.unwrap();

            if case > 50 {
                assert_eq!(HIS2_UTF8_SHORT_LEN as u64, result.len());
            } else {
                assert_eq!(HIS2_UTF8_LEN as u64, result.len());
            }

            case += 1;
        }
    }

    #[test]
    fn his_v1_scan_bytes() {
        let mut scan = Scan::new(ScanOptions::default());
        let empty: [u8; 0] = [0; 0];

        /* Less than 16 bytes */
        scan.parse_bytes(" ".as_bytes());
        assert!(scan.checks.is_empty());
        scan.reset();

        /* Empty */
        scan.parse_bytes(&empty);
        scan.reset();

        /* Valid Cases */
        let mut cases = Vec::new();

        /* 32-byte cases */
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo=");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w=");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI=");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco=");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco");

        /* 64-byte cases */
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASt5mnCaw==");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaACDbOpqrYA==");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ABa13FZVQ==");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/AM71lnmRw==");
        cases.push("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ==");

        for (i, case) in cases.iter().enumerate() {
            let match_str = if case.len() > HIS_32_UTF8_LEN && case.len() < (HIS_64_UTF8_LEN - 2) {
                &case[0..HIS_32_UTF8_LEN]
            } else if case.len() > HIS_64_UTF8_LEN {
                &case[0..HIS_64_UTF8_LEN]
            }else {
                &case[0..]
            };

            /* UTF8 */
            let data = case.as_bytes();
            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF8 Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF8 Case {}: Scan Offset", i);

            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF8 Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF8 Case {}: Text Match", i);

            /* UTF16 LE */
            let mut data = Vec::new();
            for b in case.as_bytes() {
                data.push(*b);
                data.push(0);
            }
            let data = data.as_slice();

            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF16 LE Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF16 LE Case {}: Scan Offset", i);
            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF16 Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF16 Case {}: Text Match", i);

            /* UTF16 BE */
            let mut data = Vec::new();
            for b in case.as_bytes() {
                data.push(0);
                data.push(*b);
            }
            let data = data.as_slice();

            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF16 BE Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();

            assert_eq!(1, check.start(), "UTF16 BE Case {}: Scan Offset", i);
            let scan_match = check.matches_bytes(&data[1..], true);
            assert!(scan_match.is_some(), "UTF16 BE Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF16 BE Case {}: Text Match", i);

            /* Multi-buffer (per-byte extreme case) */
            let data = case.as_bytes();
            scan.reset();
            for i in 0..data.len() {
                scan.parse_bytes(&data[i..i+1]);
            }
            assert_eq!(1, scan.checks.len(), "UTF8 per-byte Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF8 per-byte Case {}: Scan Offset", i);

            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF8 per-byte Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF8 per-byte Case {}: Text Match", i);
        }
    }

    #[test]
    fn his_v2_scan_bytes() {
        let mut scan = Scan::new(ScanOptions::default());
        let empty: [u8; 0] = [0; 0];

        /* Less than 16 bytes */
        scan.parse_bytes(" ".as_bytes());
        assert!(scan.checks.is_empty());
        scan.reset();

        /* Empty */
        scan.parse_bytes(&empty);
        scan.reset();

        /* Valid Cases */
        let mut cases = Vec::new();
        cases.push("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHJQQJ99AEAAAAAAAAAAAAAAAAAZFU03Ml");
        cases.push("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIJQQJ99AEAAAAAAAAAAAAAAAAAZFUq6gN");
        cases.push("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKJQQJ99AEAAAAAAAAAAAAAAAAAZFUtUkH");
        cases.push("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLJQQJ99AEAAAAAAAAAAAAAAAAAZFUcfkX");
        cases.push("6666666666666666666666666666666666666666666666666666JQQJ99AEAAAAAAAAAAAAAAAAAZFUrS9sdA==");
        cases.push("7777777777777777777777777777777777777777777777777777JQQJ99AEAAAAAAAAAAAAAAAAAZFUSHua5Q==");
        cases.push("8888888888888888888888888888888888888888888888888888JQQJ99AEAAAAAAAAAAAAAAAAAZFUT8jEyQ==ZZZZ");

        for (i, case) in cases.iter().enumerate() {
            let match_str = if case.len() < HIS2_UTF8_LEN {
                &case[0..HIS2_UTF8_SHORT_LEN]
            } else {
                &case[0..HIS2_UTF8_LEN]
            };

            /* UTF8 */
            let data = case.as_bytes();
            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF8 Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF8 Case {}: Scan Offset", i);

            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF8 Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF8 Case {}: Text Match", i);

            /* UTF16 LE */
            let mut data = Vec::new();
            for b in case.as_bytes() {
                data.push(*b);
                data.push(0);
            }
            let data = data.as_slice();

            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF16 LE Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF16 LE Case {}: Scan Offset", i);
            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF16 Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF16 Case {}: Text Match", i);

            /* UTF16 BE */
            let mut data = Vec::new();
            for b in case.as_bytes() {
                data.push(0);
                data.push(*b);
            }
            let data = data.as_slice();

            scan.reset();
            scan.parse_bytes(data);
            assert_eq!(1, scan.checks.len(), "UTF16 BE Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();

            assert_eq!(1, check.start(), "UTF16 BE Case {}: Scan Offset", i);
            let scan_match = check.matches_bytes(&data[1..], true);
            assert!(scan_match.is_some(), "UTF16 BE Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF16 BE Case {}: Text Match", i);

            /* Multi-buffer (per-byte extreme case) */
            let data = case.as_bytes();
            scan.reset();
            for i in 0..data.len() {
                scan.parse_bytes(&data[i..i+1]);
            }
            assert_eq!(1, scan.checks.len(), "UTF8 per-byte Case {}: Scan Check", i);

            let check = scan.checks.pop().unwrap();
            assert_eq!(0, check.start(), "UTF8 per-byte Case {}: Scan Offset", i);

            let scan_match = check.matches_bytes(data, true);
            assert!(scan_match.is_some(), "UTF8 per-byte Case {}: Matches", i);
            let scan_match = scan_match.unwrap();
            assert_eq!(match_str, scan_match.text(), "UTF8 per-byte Case {}: Text Match", i);
        }
    }
}
