// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

/* Indicates the char is part of a small mask */
const MASK_SMALL: u8 = 1 << 0;

/* Indicates the char is part of a large mask */
const MASK_LARGE: u8 = 1 << 1;

/* Indicates the char is a special sig character */
const MASK_SIG: u8 = 1 << 2;

/* We don't expect patterns larger than this */
const HIS_UTF8_MAX_LEN: usize = 256;

const HIS2_UTF8_LEN: usize = 88;
const HIS2_UTF8_SHORT_LEN: usize = 84;

const HIS_A7_UTF8_LEN: usize = 37;
const HIS_A8_UTF8_LEN: usize = 40;
const HIS_32_UTF8_LEN: usize = 44;
const HIS_39_UTF8_LEN: usize = 52;
const HIS_40_UTF8_LEN: usize = 56;
const HIS_64_UTF8_LEN: usize = 88;

trait Base64 {
    fn is_base64(&self) -> bool;
}

trait UrlUnreserved {
    fn is_url_unreserved(&self) -> bool;
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

impl UrlUnreserved for u8 {
    fn is_url_unreserved(&self) -> bool {
        self.is_base64() ||
        *self == b'~' ||
        *self == b'.'
    }
}

pub struct ScanMatch {
    name: &'static str,
    def_index: u32,
    start: u64,
    len: u64,
    text: Option<String>,
}

impl ScanMatch {
    fn new(
        name: &'static str,
        def_index: u32,
        start: u64,
        len: u64,
        data: &[u8],
        want_text: bool) -> Self {
        Self {
            name,
            def_index,
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

    pub fn name(&self) -> &'static str { self.name }

    pub fn def_index(&self) -> u32 { self.def_index }

    pub fn text(&self) -> &str {
        match &self.text {
            Some(text) => { &text },
            None => { "" },
        }
    }
}

#[derive(Clone)]
pub struct PossibleScanMatch {
    name: &'static str,
    def_index: u32,
    start: u64,
    len: usize,
    utf8: bool,
    validator: fn(&[u8]) -> usize,
}

impl PossibleScanMatch {
    fn new(
        name: &'static str,
        def_index: u32,
        start: u64,
        len: usize,
        utf8: bool,
        validator: fn(&[u8]) -> usize) -> Self {
        Self {
            name,
            def_index,
            start,
            len,
            utf8,
            validator,
        }
    }

    pub fn start(&self) -> u64 { self.start }

    pub fn len(&self) -> usize { self.len }

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

        Ok(self.matches_bytes(
            &buf[..read],
            want_text))
    }

    pub fn matches_bytes(
        &self,
        data: &[u8],
        want_text: bool) -> Option<ScanMatch> {
        match self.utf8 {
            true => {
                /* UTF8 */
                let len = (self.validator)(data);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        self.name,
                        self.def_index,
                        self.start,
                        len as u64,
                        &data[..len],
                        want_text))
            },

            false => {
                /* UTF16 */
                let mut bytes: [u8; HIS_UTF8_MAX_LEN] = [0; HIS_UTF8_MAX_LEN];
                let mut count = Self::convert_utf16(data, &mut bytes);

                if data.len() & 1 == 1 {
                    /* Add trailing unaligned byte edge case */
                    bytes[count] = data[data.len()-1];
                    count += 1;
                }

                let len = (self.validator)(&bytes[..count]);

                if len == 0 {
                    return None;
                }

                Some(
                    ScanMatch::new(
                        self.name,
                        self.def_index,
                        self.start,
                        (len * 2) as u64,
                        &bytes[..len],
                        want_text))
            }
        }
    }
}

#[derive(Clone)]
pub struct ScanDefinition {
    name: &'static str,
    index: u32,
    sig_char: u8,
    check_char: u8,
    before_utf8: u64,
    len_utf8: u64,
    before_utf16: u64,
    len_utf16: u64,
    mask_size: u8,
    packed_utf8: u64,
    packed_utf16: u64,
    validator: fn(&[u8]) -> usize,
}

impl ScanDefinition {
    pub fn new(
        name: &'static str,
        sig: &[u8],
        sig_char: u8,
        before: u64,
        len: usize,
        validator: fn(&[u8]) -> usize) -> Self {
        match sig.len() {
            3 | 4 => { },
            _ => { panic!("Signature has to be 3 or 4 bytes"); }
        }

        let mut found = false;
        for b in sig {
            if *b == sig_char { found = true; }
        }

        if !found {
            panic!("Signature must have char in it");
        }

        let mask_size = match sig.len() {
            3 => { MASK_SMALL },
            4 => { MASK_LARGE },
            _ => { 0 },
        };

        let len = len as u64;

        Self {
            name,
            index: 0,
            sig_char,
            check_char: sig[sig.len()-1],
            before_utf8: before,
            len_utf8: len,
            before_utf16: (before * 2) - 1,
            len_utf16: len * 2,
            mask_size,
            packed_utf8: Self::pack_utf8(sig),
            packed_utf16: Self::pack_utf16(sig),
            validator,
        }
    }

    pub fn name(&self) -> &'static str { self.name }

    fn pack_utf8(sig: &[u8]) -> u64 {
        let mut packed = 0u64;

        for b in sig {
            packed <<= 8;
            packed |= *b as u64;
        }

        packed
    }

    fn pack_utf16(sig: &[u8]) -> u64 {
        let mut packed = 0u64;

        for b in sig {
            packed <<= 16;
            packed |= *b as u64;
        }

        packed
    }

    fn has_possible_utf8_match(&self, index: u64) -> Option<PossibleScanMatch> {
        if index >= self.before_utf8 {
            Some(PossibleScanMatch::new(
                self.name,
                self.index,
                index - self.before_utf8,
                self.len_utf8 as usize,
                true,
                self.validator,
            ))
        } else {
            None
        }
    }

    fn has_possible_utf16_match(&self, index: u64) -> Option<PossibleScanMatch> {
        if index >= self.before_utf16 {
            Some(PossibleScanMatch::new(
                self.name,
                self.index,
                index - self.before_utf16,
                self.len_utf16 as usize,
                false,
                self.validator,
            ))
        } else {
            None
        }
    }
}

pub struct ScanOptions {
    defs: Vec<ScanDefinition>,
}

impl ScanOptions {
    pub fn with_aad(self) -> Self {
        let a7_match_bytes = |data: &[u8]| -> usize {
            /*
             * 3 url unreserved + 3 signature + 31 url unreserved
             */
            if data.len() < HIS_A7_UTF8_LEN {
                return 0;
            }

            for b in &data[0..3] {
                if !b.is_url_unreserved() {
                    return 0;
                }
            }

            /* NOTE: We skip the signature since we already checked */

            for b in &data[6..37] {
                if !b.is_url_unreserved() {
                    return 0;
                }
            }

            HIS_A7_UTF8_LEN
        };

        let a8_match_bytes = |data: &[u8]| -> usize {
            /*
             * 3 url unreserved + 3 signature + 34 url unreserved
             */
            if data.len() < HIS_A8_UTF8_LEN {
                return 0;
            }

            for b in &data[0..3] {
                if !b.is_url_unreserved() {
                    return 0;
                }
            }

            /* NOTE: We skip the signature since we already checked */

            for b in &data[6..40] {
                if !b.is_url_unreserved() {
                    return 0;
                }
            }

            HIS_A8_UTF8_LEN
        };

        let mut clone = self;

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/156",
                b"7Q~",
                b'Q',
                6,
                37,
                a7_match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/156",
                b"8Q~",
                b'Q',
                6,
                40,
                a8_match_bytes));

        clone
    }

    pub fn with_his_v1_32byte(self) -> Self {
        let match_bytes = |data: &[u8]| -> usize {
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
        };

        let mut clone = self;

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/173",
                b"+ARm",
                b'A',
                37,
                44,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/172",
                b"+AEh",
                b'A',
                37,
                44,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/171",
                b"+ASb",
                b'A',
                37,
                44,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/178",
                b"AIoT",
                b'A',
                37,
                44,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/154",
                b"AzCa",
                b'A',
                37,
                44,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/190",
                b"AZEG",
                b'A',
                37,
                44,
                match_bytes));

        clone
    }

    pub fn with_his_v1_39byte(self) -> Self {
        let match_bytes = |data: &[u8]| -> usize {
            /*
             * 42 Base64 + 4 signature + 1 [A-D] + 5 Base64
             */
            if data.len() < HIS_39_UTF8_LEN {
                return 0;
            }

            for b in &data[0..42] {
                if !b.is_base64() {
                    return 0;
                }
            }

            /* NOTE: We skip the signature since we already checked */

            if data[46] < b'A' || data[46] > b'D' {
                return 0;
            }

            for b in &data[47..52] {
                if !b.is_base64() {
                    return 0;
                }
            }

            HIS_39_UTF8_LEN
        };

        let mut clone = self;

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/166",
                b"AzSe",
                b'A',
                46,
                52,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/176",
                b"+ACR",
                b'A',
                46,
                52,
                match_bytes));

        clone
    }

    pub fn with_his_v1_40byte(self) -> Self {
        let match_bytes = |data: &[u8]| -> usize {
            /*
             * 44 Base64 + 4 signature + 5 Base64 + [AQgw] + optional 2 [=]
             */
            if data.len() < 54 {
                return 0;
            }

            for b in &data[0..44] {
                if !b.is_base64() {
                    return 0;
                }
            }

            /* NOTE: We skip the signature since we already checked */

            for b in &data[48..53] {
                if !b.is_base64() {
                    return 0;
                }
            }

            match data[53] {
                b'A' | b'Q' | b'g' | b'w' => { },
                _ => { return 0; },
            }

            if data.len() >= HIS_40_UTF8_LEN {
                if data[54] == b'=' && data[55] == b'=' {
                    return HIS_40_UTF8_LEN;
                }
            }

            54
        };

        let mut clone = self;

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/158",
                b"AzFu",
                b'A',
                48,
                56,
                match_bytes));

        clone
    }

    pub fn with_his_v1_64byte(self) -> Self {
        let match_bytes = |data: &[u8]| -> usize {
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
        };

        let mut clone = self;

        /* HIS v1 64-byte */
        clone.defs.push(
            ScanDefinition::new(
                "SEC101/152",
                b"+ASt",
                b'A',
                80,
                88,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/160",
                b"ACDb",
                b'A',
                80,
                88,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/163",
                b"+ABa",
                b'A',
                80,
                88,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/170",
                b"+AMC",
                b'A',
                80,
                88,
                match_bytes));

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/181",
                b"APIM",
                b'A',
                80,
                88,
                match_bytes));

        clone
    }

    pub fn with_his_v2(self) -> Self {
        let match_bytes = |data: &[u8]| -> usize {
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

            for b in &data[86..88] {
                if *b != b'=' {
                    return HIS2_UTF8_SHORT_LEN;
                }
            }

            HIS2_UTF8_LEN
        };

        let mut clone = self;

        clone.defs.push(
            ScanDefinition::new(
                "SEC101/200",
                b"JQQJ",
                b'Q',
                56,
                HIS2_UTF8_LEN,
                match_bytes));

        clone
    }

    pub fn with_only(
        self,
        names: Vec<&str>) -> Self {

        let mut clone = self;
        let mut filtered = Vec::new();

        /* Filter to only the names passed in */
        for def in clone.defs {
            if names.contains(&def.name) {
                filtered.push(def);
            }
        }

        clone.defs = filtered;

        clone
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        /* Default gets all known definitions */
        Self {
            defs: Vec::new(),
        }
        .with_aad()
        .with_his_v1_32byte()
        .with_his_v1_39byte()
        .with_his_v1_40byte()
        .with_his_v1_64byte()
        .with_his_v2()
    }
}

pub struct Scan {
    options: ScanOptions,
    accum: u64,
    index: u64,
    checks: Vec<PossibleScanMatch>,
    utf8_lanes: [Vec<ScanDefinition>; 32],
    utf16_lanes: [Vec<ScanDefinition>; 32],
    sig_char_chunks: Vec<[u8; 16]>,
    char_map: [u8; 256],
    must_scan: bool,
}

impl Scan {
    pub fn new(options: ScanOptions) -> Self {
        let mut scan = Self {
            options,
            accum: 0,
            index: 0,
            checks: Vec::new(),
            utf8_lanes: Default::default(),
            utf16_lanes: Default::default(),
            sig_char_chunks: Vec::new(),
            char_map: [0; 256],
            must_scan: false,
        };

        scan.init();

        scan
    }

    pub fn scan_defs(&self) -> &Vec<ScanDefinition>
    {
        &self.options.defs
    }

    fn init(&mut self) {
        let mut unique_chars = [0; 256];
        let mut def_index = 0u32;

        /* Build lookup tables */
        for def in &mut self.options.defs {
            /* Update definition index */
            def.index = def_index;
            def_index += 1;

            /* Store unique characters to vectorize scan for */
            if unique_chars[def.sig_char as usize] == 0 {
                /*
                 * Create 16-byte chunk filled with the sig char
                 * which can be SIMD/vectorized compared with read
                 * data.
                 */
                let chunk: [u8; 16] = [def.sig_char; 16];
                self.sig_char_chunks.push(chunk);

                /* Mark we've seen it already */
                unique_chars[def.sig_char as usize] = 1;
            }

            /*
             * Store final characters of sig in lookup map. This tells
             * us when to check the accumulator for signatures.
             */
            self.char_map[def.check_char as usize] |= def.mask_size;

            /*
             * Store sig character in lookup map. This tells us if a
             * byte is a part of a sig check and how far it is away.
             * This is used to see if the accumulator has any sig chars.
             */
            self.char_map[def.sig_char as usize] |= MASK_SIG;

            let utf8_lane = def.packed_utf8 & 31;
            let utf16_lane = def.packed_utf16 & 31;

            self.utf8_lanes[utf8_lane as usize].push(def.clone());
            self.utf16_lanes[utf16_lane as usize].push(def.clone());
        }
    }

    pub fn has_possible_matches(&self) -> bool { !self.checks.is_empty() }

    pub fn possible_matches(&self) -> &Vec<PossibleScanMatch> { &self.checks }

    pub fn reset(&mut self) {
        self.accum = 0;
        self.index = 0;
        self.must_scan = false;
        self.checks.clear();
    }

    #[inline(always)]
    fn has_sig_chars(
        &self,
        chunk: &[u8]) -> bool {
        let mut count = 0;

        for c in &self.sig_char_chunks {
            for i in 0..16 {
                count |= (chunk[i] == c[i]) as usize;
            }
        }

        count != 0
    }

    #[inline(always)]
    fn check_utf8(
        &mut self,
        packed_utf8: u64) {
        let lane = (packed_utf8 & 31) as usize;

        for def in &self.utf8_lanes[lane] {
            if def.packed_utf8 == packed_utf8 {
                if let Some(possible_match) = def.has_possible_utf8_match(self.index) {
                    self.checks.push(possible_match);
                }
                break;
            }
        }
    }

    #[inline(always)]
    fn check_utf16(
        &mut self,
        packed_utf16: u64) {
        let lane = (packed_utf16 & 31) as usize;

        for def in &self.utf16_lanes[lane] {
            if def.packed_utf16 == packed_utf16 {
                if let Some(possible_match) = def.has_possible_utf16_match(self.index) {
                    self.checks.push(possible_match);
                }
                break;
            }
        }
    }

    /* Faster without any inline, oddly enough */
    #[cold]
    fn byte_scan(
        &mut self,
        data: &[u8]) {
        let mut sig_index = 0u64;

        for b in data {
            let b = *b;

            self.accum = self.accum << 8 | b as u64;
            self.index += 1;

            /* Determine what to do with the char */
            let check = self.char_map[b as usize];

            /* Char is a signature part */
            if (check & MASK_SIG) == MASK_SIG {
                /* Track where it was found */
                sig_index = self.index;
            }

            if (check & MASK_SMALL) == MASK_SMALL {
                let packed_utf16_small = self.accum & 0xFFFFFFFFFFFF;
                let packed_utf8_small = self.accum & 0xFFFFFF;

                self.check_utf8(packed_utf8_small);
                self.check_utf16(packed_utf16_small);
            }

            if (check & MASK_LARGE) == MASK_LARGE {
                let packed_utf16 = self.accum;
                let packed_utf8: u64 = self.accum & 0xFFFFFFFF;

                self.check_utf8(packed_utf8);
                self.check_utf16(packed_utf16);
            }
        }

        /*
         * If our signature char is within 7 bytes, we need to scan next time
         * without the SIMD/vectorized scan. The reason for this is if parts
         * of the 4 (or 3) byte signature are in the accumulator. If the first
         * part of the signature is in the accumulator and the last byte or two
         * are in the new data, it would miss if we omitted this.
         */
        self.must_scan = (self.index - sig_index) < 8;
    }

        /// Parse `data` without resetting the internal state, and appending
    /// any newly found possible matches to `checks`.
    ///
    /// If `data` points to a different stream than data previously processed
    /// by this [`Scan`], you _must_ call [`Scan::reset`] first.
    pub fn parse_bytes(
        &mut self,
        data: &[u8]) {
        let chunks = data.chunks_exact(16);
        let rem = chunks.remainder();

        for chunk in chunks {
            /* Check if anything of interest */
            if !self.must_scan && !self.has_sig_chars(chunk) {
                self.index += 16;
                self.accum = u64::from_be_bytes(chunk[8..16].try_into().unwrap());
                continue;
            }

            self.byte_scan(chunk);
        }

        self.byte_scan(rem);
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

    struct Case {
        test: &'static str,
        expected: &'static str,
    }

    impl Case {
        fn new(
            test: &'static str,
            expected: &'static str) -> Self {
            Self {
                test,
                expected,
            }
        }
    }

    #[test]
    fn his_v2_scan_files() {
        let options = ScanOptions::default();

        let mut scan = Scan::new(options);
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
        let options = ScanOptions::default();

        let mut scan = Scan::new(options);
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

        /* AAD cases */
        cases.push(Case::new(
            "zzz7Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "zzz7Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        cases.push(Case::new(
            "zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        cases.push(Case::new(
            "zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzZZZ",
            "zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));

        /* 32-byte cases */
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo=",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w=",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI=",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco=",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ARmD7h+qo"));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AEhG2s/8w"));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASbHpHeAI"));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAIoTOumzco"));
        cases.push(Case::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbng=",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbng="));
        cases.push(Case::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbng=ZZZZ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbng="));
        cases.push(Case::new(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbngZZZZ",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbAZEGLiQbng"));

        /* 39-byte cases */
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAzSeCjhzCu",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAzSeCjhzCu"));
        cases.push(Case::new(
            "dddddddddddddddddddddddddddddddddddddddddd+ACRCUDxQE",
            "dddddddddddddddddddddddddddddddddddddddddd+ACRCUDxQE"));
        cases.push(Case::new(
            "dddddddddddddddddddddddddddddddddddddddddd+ACRCUDxQEZZZZZ",
            "dddddddddddddddddddddddddddddddddddddddddd+ACRCUDxQE"));

        /* 40-byte cases */
        cases.push(Case::new(
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA",
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA"));
        cases.push(Case::new(
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA==",
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA=="));
        cases.push(Case::new(
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhAZZZZZ",
            "ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA"));

        /* 64-byte cases */
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASt5mnCaw==",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ASt5mnCaw=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaACDbOpqrYA==",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaACDbOpqrYA=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ABa13FZVQ==",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+ABa13FZVQ=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AMCFNqWyA==ZZZZ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa+AMCFNqWyA=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ==",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ==ZZZZZ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ=="));
        cases.push(Case::new(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQZZZZZ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAPIMHbKhsQ"));

        for (i, case) in cases.iter().enumerate() {
            let match_str = case.expected;
            let case = case.test;

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
        let options = ScanOptions::default();

        let mut scan = Scan::new(options);
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

    fn test_bytes(data: &[u8]) -> usize {
        data.len()
    }

    #[test]
    fn his_scan_definition() {
        let def = ScanDefinition::new("HISv2", b"JQQJ", b'J', 56, 88, test_bytes);
        assert_eq!(0x4A51514A, def.packed_utf8);
        assert_eq!(0x004A00510051004A, def.packed_utf16);
        assert_eq!(MASK_LARGE, def.mask_size);
        assert_eq!(56, def.before_utf8);
        assert_eq!(88, def.len_utf8);
        assert_eq!((56*2) - 1, def.before_utf16);
        assert_eq!(88*2, def.len_utf16);
    }
}
