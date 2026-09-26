use super::name::{ParseError, encode_qname};

pub const QTYPE_MX: u16 = 15;
pub const QCLASS_IN: u16 = 1;

pub struct Question {
    qname: Vec<u8>,
}

// QNAME changes size according to the domain written
impl Question {
    pub fn new(domain: &str) -> Result<Self, String> {
        Ok(Question {
            qname: encode_qname(domain)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.qname.clone();
        buf.extend_from_slice(&QTYPE_MX.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        buf
    }
}

/// DNS message header
pub struct Header {
    pub id: u16,      // 16 bits identifier
    pub flags: u16,   // responsible for response status and query behavior
    pub qdcount: u16, // Number of questions in the Question section
    pub ancount: u16, // Number of answer in the Answers section
    pub nscount: u16, // Number of servers of authority
    pub arcount: u16, // Number of additional registries
}

pub const FLAGS_RECURSIVE_QUERY: u16 = 0x0100;

impl Header {
    pub fn new_query(id: u16) -> Self {
        Header {
            id,
            flags: FLAGS_RECURSIVE_QUERY,
            qdcount: 0x0001,
            ancount: 0x0000,
            nscount: 0x0000,
            arcount: 0x0000,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 12 {
            return Err(ParseError::TruncatedHeader { length: bytes.len() });
        }

        Ok(Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    pub fn rcode(&self) -> u16 {
        self.flags & 0x000F
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bytes_rfc() {
        let header = Header::new_query(0x1234);
        assert_eq!(
            header.to_bytes(),
            [0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn parses_response_header() {
        let header = Header::from_bytes(&[
            0x12, 0x34, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();

        assert_eq!(header.id, 0x1234);
        assert_eq!(header.flags, 0x8183);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
        assert_eq!(header.rcode(), 3);
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(matches!(
            Header::from_bytes(&[0; 11]),
            Err(ParseError::TruncatedHeader { length: 11 })
        ));
    }

    #[test]
    fn question_bytes_for_unb_br_mx() {
        let q = Question::new("unb.br").unwrap();
        assert_eq!(
            q.to_bytes(),
            vec![3, b'u', b'n', b'b', 2, b'b', b'r', 0, 0x00, 0x0F, 0x00, 0x01]
        );
    }
}
