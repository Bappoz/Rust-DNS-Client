//! Biblioteca do cliente DNS: montagem e leitura de mensagens DNS (RFC 1035)
//! desacopladas de I/O de rede. O binario `my-client` e um consumidor desta API.
//!
//! ```
//! use my_client::dns::message::{Header, Question, RecordType};
//!
//! let header = Header::new_query(0x1234);
//! let question = Question::new("unb.br").unwrap();
//!
//! let mut packet = header.to_bytes().to_vec();
//! packet.extend_from_slice(&question.to_bytes_for(RecordType::A));
//! assert_eq!(&packet[..2], &[0x12, 0x34]);
//! ```

pub mod dns;
