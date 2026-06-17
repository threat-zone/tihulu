/// TLS cipher suite mode (matches Wireshark definitions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Stream,
    Cbc,
    Gcm,
    Ccm,
    Ccm8,
    Poly1305,
}

/// Key exchange algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Kex {
    Rsa,
    DhDss,
    DhRsa,
    DheDss,
    DheRsa,
    DhAnon,
    EcdhEcdsa,
    EcdheEcdsa,
    EcdhRsa,
    EcdheRsa,
    EcdhAnon,
    Psk,
    DhePsk,
    RsaPsk,
    EcdhePsk,
    SrpSha,
    SrpShaRsa,
    SrpShaDss,
    Krb5,
    Tls13,
    EcJpake,
}

/// Digest algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Digest {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Na,
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Enc {
    Des,
    TripleDes,
    Rc4,
    Rc2,
    Idea,
    Aes128,
    Aes256,
    Camellia128,
    Camellia256,
    Seed,
    Chacha20,
    Null,
}

/// A TLS cipher suite definition
#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    pub number: u16,
    pub kex: Kex,
    pub enc: Enc,
    pub dig: Digest,
    pub mode: CipherMode,
}

impl CipherSuite {
    pub fn is_tls13(&self) -> bool {
        self.kex == Kex::Tls13
    }

    /// Return the secret length for TLS 1.3 based on the digest algorithm.
    pub fn secret_len(&self) -> usize {
        match self.dig {
            Digest::Sha384 => 48,
            _ => 32,
        }
    }
}

/// Find a cipher suite by its numeric identifier.
pub fn find_cipher_suite(num: u16) -> Option<&'static CipherSuite> {
    CIPHER_SUITES.iter().find(|c| c.number == num)
}

/// TLS content types
pub const SSL_ID_HANDSHAKE: u8 = 0x16;
pub const SSL_ID_APP_DATA: u8 = 0x17;

/// TLS handshake types
pub const SSL_HND_CLIENT_HELLO: u8 = 1;
pub const SSL_HND_SERVER_HELLO: u8 = 2;

/// Master secret length (RFC 5246 section 8.1)
pub const SSL_MASTER_SECRET_LENGTH: usize = 48;

/// TLS versions
pub const TLSV1DOT2_VERSION: u16 = 0x0303;
pub const TLSV1DOT3_VERSION: u16 = 0x0304;

/// Data direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Direction {
    In,
    Out,
}

/// A parsed TLS record
#[derive(Debug, Clone)]
pub struct TlsRecord {
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

/// Partial state for reassembling a TLS record from a byte stream.
#[derive(Debug, Clone, Default)]
pub struct StreamChunk {
    pub bytes_read: u16,
    pub content_type: u8,
    pub version: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl StreamChunk {
    pub fn is_complete(&self) -> bool {
        self.bytes_read >= 5 && (self.bytes_read - 5) == self.length
    }

    pub fn take_record(&mut self) -> TlsRecord {
        let record = TlsRecord {
            content_type: self.content_type,
            version: self.version,
            length: self.length,
            data: std::mem::take(&mut self.data),
        };
        *self = Self::default();
        record
    }
}

// Complete cipher suite table (from Wireshark)
static CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite { number: 0x0001, kex: Kex::Rsa, enc: Enc::Null, dig: Digest::Md5, mode: CipherMode::Stream },
    CipherSuite { number: 0x0002, kex: Kex::Rsa, enc: Enc::Null, dig: Digest::Sha1, mode: CipherMode::Stream },
    CipherSuite { number: 0x0003, kex: Kex::Rsa, enc: Enc::Rc4, dig: Digest::Md5, mode: CipherMode::Stream },
    CipherSuite { number: 0x0004, kex: Kex::Rsa, enc: Enc::Rc4, dig: Digest::Md5, mode: CipherMode::Stream },
    CipherSuite { number: 0x0005, kex: Kex::Rsa, enc: Enc::Rc4, dig: Digest::Sha1, mode: CipherMode::Stream },
    CipherSuite { number: 0x000A, kex: Kex::Rsa, enc: Enc::TripleDes, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0x002F, kex: Kex::Rsa, enc: Enc::Aes128, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0x0033, kex: Kex::DheRsa, enc: Enc::Aes128, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0x0035, kex: Kex::Rsa, enc: Enc::Aes256, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0x0039, kex: Kex::DheRsa, enc: Enc::Aes256, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0x003C, kex: Kex::Rsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0x003D, kex: Kex::Rsa, enc: Enc::Aes256, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0x0067, kex: Kex::DheRsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0x006B, kex: Kex::DheRsa, enc: Enc::Aes256, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0x009C, kex: Kex::Rsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Gcm },
    CipherSuite { number: 0x009D, kex: Kex::Rsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Gcm },
    CipherSuite { number: 0x009E, kex: Kex::DheRsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Gcm },
    CipherSuite { number: 0x009F, kex: Kex::DheRsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Gcm },
    // TLS 1.3
    CipherSuite { number: 0x1301, kex: Kex::Tls13, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Gcm },
    CipherSuite { number: 0x1302, kex: Kex::Tls13, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Gcm },
    CipherSuite { number: 0x1303, kex: Kex::Tls13, enc: Enc::Chacha20, dig: Digest::Sha256, mode: CipherMode::Poly1305 },
    CipherSuite { number: 0x1304, kex: Kex::Tls13, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Ccm },
    CipherSuite { number: 0x1305, kex: Kex::Tls13, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Ccm8 },
    // ECDHE suites
    CipherSuite { number: 0xC009, kex: Kex::EcdheEcdsa, enc: Enc::Aes128, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC00A, kex: Kex::EcdheEcdsa, enc: Enc::Aes256, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC013, kex: Kex::EcdheRsa, enc: Enc::Aes128, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC014, kex: Kex::EcdheRsa, enc: Enc::Aes256, dig: Digest::Sha1, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC023, kex: Kex::EcdheEcdsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC024, kex: Kex::EcdheEcdsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC027, kex: Kex::EcdheRsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC028, kex: Kex::EcdheRsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Cbc },
    CipherSuite { number: 0xC02B, kex: Kex::EcdheEcdsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Gcm },
    CipherSuite { number: 0xC02C, kex: Kex::EcdheEcdsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Gcm },
    CipherSuite { number: 0xC02F, kex: Kex::EcdheRsa, enc: Enc::Aes128, dig: Digest::Sha256, mode: CipherMode::Gcm },
    CipherSuite { number: 0xC030, kex: Kex::EcdheRsa, enc: Enc::Aes256, dig: Digest::Sha384, mode: CipherMode::Gcm },
    CipherSuite { number: 0xCCA8, kex: Kex::EcdheRsa, enc: Enc::Chacha20, dig: Digest::Sha256, mode: CipherMode::Poly1305 },
    CipherSuite { number: 0xCCA9, kex: Kex::EcdheEcdsa, enc: Enc::Chacha20, dig: Digest::Sha256, mode: CipherMode::Poly1305 },
    CipherSuite { number: 0xCCAA, kex: Kex::DheRsa, enc: Enc::Chacha20, dig: Digest::Sha256, mode: CipherMode::Poly1305 },
];
