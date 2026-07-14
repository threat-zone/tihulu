use crate::tls_types::*;

/// State maintained for a TLS connection being tracked.
/// Parses the byte stream into TLS records and extracts handshake parameters.
pub struct TlsParser {
    pub up_chunk: StreamChunk,
    pub down_chunk: StreamChunk,

    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub cipher_suite_id: u16,
    pub cipher_suite: Option<&'static CipherSuite>,

    pub client_hello_seen: bool,
    pub server_hello_seen: bool,
    pub cipher_suite_set: bool,
    pub is_tls13: bool,

    // TLS 1.2 state
    pub has_data_record: bool,
    pub data_record: Option<TlsRecord>,

    // TLS 1.3 state
    pub tls13_out_app_count: usize,
    pub tls13_in_app_count: usize,
    pub tls13_client_finished: Option<TlsRecord>,
    pub tls13_client_app_data: Option<TlsRecord>,
    pub tls13_server_encrypted: Option<TlsRecord>,
    pub tls13_server_app_data: Option<TlsRecord>,

    /// Bitmask tracking which TLS 1.3 secrets have already been found.
    pub tls13_found_secrets: u8,

    pub finished: bool,
}

impl TlsParser {
    pub fn new() -> Self {
        Self {
            up_chunk: StreamChunk::default(),
            down_chunk: StreamChunk::default(),
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            cipher_suite_id: 0,
            cipher_suite: None,
            client_hello_seen: false,
            server_hello_seen: false,
            cipher_suite_set: false,
            is_tls13: false,
            has_data_record: false,
            data_record: None,
            tls13_out_app_count: 0,
            tls13_in_app_count: 0,
            tls13_client_finished: None,
            tls13_client_app_data: None,
            tls13_server_encrypted: None,
            tls13_server_app_data: None,
            tls13_found_secrets: 0,
            finished: false,
        }
    }

    /// Feed data into the parser from a read or write operation.
    pub fn handle_data(&mut self, data: &[u8], dir: Direction) -> Vec<(TlsRecord, Direction)> {
        let mut completed_records = Vec::new();
        let chunk = match dir {
            Direction::Out => &mut self.up_chunk,
            Direction::In => &mut self.down_chunk,
        };

        let mut offset = 0;
        while offset < data.len() {
            match chunk.bytes_read {
                0 => {
                    chunk.content_type = data[offset];
                    chunk.bytes_read += 1;
                    offset += 1;
                }
                1 => {
                    chunk.version = (data[offset] as u16) << 8;
                    chunk.bytes_read += 1;
                    offset += 1;
                }
                2 => {
                    chunk.version |= data[offset] as u16;
                    chunk.bytes_read += 1;
                    offset += 1;
                }
                3 => {
                    chunk.length = (data[offset] as u16) << 8;
                    chunk.bytes_read += 1;
                    offset += 1;
                }
                4 => {
                    chunk.length |= data[offset] as u16;
                    chunk.bytes_read += 1;
                    offset += 1;
                }
                _ => {
                    if chunk.data.is_empty() {
                        chunk.data.reserve(chunk.length as usize);
                    }
                    let remaining_record = chunk.length as usize - (chunk.bytes_read as usize - 5);
                    let available = data.len() - offset;
                    let to_copy = remaining_record.min(available);
                    chunk.data.extend_from_slice(&data[offset..offset + to_copy]);
                    chunk.bytes_read += to_copy as u16;
                    offset += to_copy;

                    if chunk.is_complete() {
                        let record = chunk.take_record();
                        completed_records.push((record, dir));
                    }
                }
            }
        }

        completed_records
    }

    /// Process a complete TLS record and update handshake state.
    pub fn process_record(&mut self, record: &TlsRecord, dir: Direction) {
        match record.content_type {
            SSL_ID_HANDSHAKE => {
                if record.data.is_empty() {
                    return;
                }
                let handshake_type = record.data[0];

                if handshake_type == SSL_HND_CLIENT_HELLO && record.data.len() >= 38 {
                    self.client_hello_seen = true;
                    self.client_random.copy_from_slice(&record.data[6..38]);
                    crate::logln!("[+] CLIENT RANDOM: {}", hex_string(&self.client_random));
                }

                if handshake_type == SSL_HND_SERVER_HELLO && record.data.len() >= 40 {
                    self.server_hello_seen = true;
                    self.server_random.copy_from_slice(&record.data[6..38]);
                    crate::logln!("[+] SERVER RANDOM: {}", hex_string(&self.server_random));

                    let session_id_length = record.data[38] as usize;
                    if record.data.len() > 38 + session_id_length + 2 {
                        self.cipher_suite_id = ((record.data[38 + session_id_length + 1] as u16) << 8)
                            | (record.data[38 + session_id_length + 2] as u16);
                        crate::logln!("[*] CIPHER SUITE: 0x{:04X}", self.cipher_suite_id);
                        self.cipher_suite = find_cipher_suite(self.cipher_suite_id);
                        self.cipher_suite_set = self.cipher_suite.is_some();

                        if let Some(cs) = self.cipher_suite {
                            if cs.is_tls13() {
                                self.is_tls13 = true;
                                crate::logln!("[*] TLS 1.3 detected");
                            }
                        }
                    }
                }
            }
            SSL_ID_APP_DATA => {
                if self.is_tls13 {
                    match dir {
                        Direction::Out => {
                            if self.tls13_out_app_count == 0 {
                                self.tls13_client_finished = Some(record.clone());
                                crate::logln!("[*] [TLS-1.3] captured client finished record ({} bytes)", record.length);
                            } else if self.tls13_out_app_count == 1 {
                                self.tls13_client_app_data = Some(record.clone());
                                crate::logln!("[*] [TLS-1.3] captured client application data record ({} bytes)", record.length);
                            }
                            self.tls13_out_app_count += 1;
                        }
                        Direction::In => {
                            if self.tls13_in_app_count == 0 {
                                self.tls13_server_encrypted = Some(record.clone());
                                crate::logln!("[*] [TLS-1.3] captured server encrypted handshake record ({} bytes)", record.length);
                            } else if self.tls13_server_app_data.is_none() {
                                self.tls13_server_app_data = Some(record.clone());
                                crate::logln!("[*] [TLS-1.3] captured server application data record ({} bytes)", record.length);
                            }
                            self.tls13_in_app_count += 1;
                        }
                    }
                } else {
                    if !self.has_data_record {
                        self.data_record = Some(record.clone());
                        self.has_data_record = true;
                    }
                }
            }
            _ => {}
        }
    }

    /// Check if TLS 1.2 decryption can be attempted.
    pub fn may_decrypt_tls12(&self) -> bool {
        self.client_hello_seen
            && self.server_hello_seen
            && self.cipher_suite_set
            && self.has_data_record
            && !self.is_tls13
    }

    /// Check if TLS 1.3 decryption can be attempted (all 4 records available).
    pub fn may_decrypt_tls13(&self) -> bool {
        self.is_tls13
            && self.client_hello_seen
            && self.server_hello_seen
            && self.cipher_suite_set
            && self.tls13_client_finished.is_some()
            && self.tls13_client_app_data.is_some()
            && self.tls13_server_encrypted.is_some()
            && self.tls13_server_app_data.is_some()
    }
}

/// Format bytes as a hex string.
pub fn hex_string(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// TLS 1.3 found-secrets bitmask constants.
pub const TLS13_CHTS: u8 = 1; // CLIENT_HANDSHAKE_TRAFFIC_SECRET
pub const TLS13_CTS0: u8 = 2; // CLIENT_TRAFFIC_SECRET_0
pub const TLS13_SHTS: u8 = 4; // SERVER_HANDSHAKE_TRAFFIC_SECRET
pub const TLS13_STS0: u8 = 8; // SERVER_TRAFFIC_SECRET_0
pub const TLS13_ALL:  u8 = TLS13_CHTS | TLS13_CTS0 | TLS13_SHTS | TLS13_STS0;
