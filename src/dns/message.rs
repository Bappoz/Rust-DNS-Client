use super::name::{ParseError, checked_offset, decode_name, encode_qname};

pub const QTYPE_MX: u16 = 15;
pub const QCLASS_IN: u16 = 1;

/// Um Resource Record da mensagem DNS. `rdata_offset` aponta para o inicio do
/// RDATA no pacote original, necessario pois nomes dentro dele podem usar
/// ponteiros de compressao.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata_offset: usize,
    pub rdlength: u16,
}

fn skip_questions(packet: &[u8], count: u16) -> Result<usize, ParseError> {
    let mut cursor = 12;

    for _ in 0..count {
        let (_, next_name_offset) = decode_name(packet, cursor)?;
        // QTYPE e QCLASS ocupam dois bytes cada apos o QNAME.
        let question_end = checked_offset(next_name_offset, 4)?;
        if packet.get(next_name_offset..question_end).is_none() {
            return Err(ParseError::TruncatedQuestion {
                offset: next_name_offset,
            });
        }
        cursor = question_end;
    }

    Ok(cursor)
}

/// Le um Resource Record e devolve tambem o cursor logo apos seu RDATA.
pub fn parse_resource_record(
    packet: &[u8],
    offset: usize,
) -> Result<(ResourceRecord, usize), ParseError> {
    let (name, fields_offset) = decode_name(packet, offset)?;
    let fields_end = checked_offset(fields_offset, 10)?;
    let fields =
        packet
            .get(fields_offset..fields_end)
            .ok_or(ParseError::TruncatedResourceRecord {
                offset: fields_offset,
            })?;

    let rr_type = u16::from_be_bytes([fields[0], fields[1]]);
    let class = u16::from_be_bytes([fields[2], fields[3]]);
    let ttl = u32::from_be_bytes([fields[4], fields[5], fields[6], fields[7]]);
    let rdlength = u16::from_be_bytes([fields[8], fields[9]]);
    let rdata_offset = fields_end;
    let next_offset = checked_offset(rdata_offset, rdlength as usize)?;

    if packet.get(rdata_offset..next_offset).is_none() {
        return Err(ParseError::TruncatedResourceRecord {
            offset: rdata_offset,
        });
    }

    Ok((
        ResourceRecord {
            name,
            rr_type,
            class,
            ttl,
            rdata_offset,
            rdlength,
        },
        next_offset,
    ))
}

/// Extrai o primeiro `EXCHANGE` de um registro MX na secao Answer.
///
/// Retorna `Ok(None)` quando a secao Answer esta vazia ou nao possui MX.
pub fn parse_mx_answer(packet: &[u8], header: &Header) -> Result<Option<String>, ParseError> {
    let mut cursor = skip_questions(packet, header.qdcount)?;

    for _ in 0..header.ancount {
        let (record, next_offset) = parse_resource_record(packet, cursor)?;
        cursor = next_offset;

        if record.rr_type != QTYPE_MX {
            continue;
        }
        if record.rdlength < 3 {
            return Err(ParseError::InvalidMxRdata {
                offset: record.rdata_offset,
                length: record.rdlength as usize,
            });
        }

        // MX RDATA: PREFERENCE (2 bytes) seguido por EXCHANGE (domain name).
        let exchange_offset = checked_offset(record.rdata_offset, 2)?;
        let (exchange, after_exchange) = decode_name(packet, exchange_offset)?;
        if after_exchange != next_offset {
            return Err(ParseError::InvalidMxRdata {
                offset: record.rdata_offset,
                length: record.rdlength as usize,
            });
        }
        return Ok(Some(exchange));
    }

    Ok(None)
}

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
            return Err(ParseError::TruncatedHeader {
                length: bytes.len(),
            });
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
            [
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
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
            vec![
                3, b'u', b'n', b'b', 2, b'b', b'r', 0, 0x00, 0x0F, 0x00, 0x01
            ]
        );
    }

    #[test]
    fn extracts_mx_exchange_from_answer() {
        let packet = [
            // Header: 1 question, 1 answer, NOERROR.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Question: unb.br IN MX. The QNAME begins at offset 12.
            3, b'u', b'n', b'b', 2, b'b', b'r', 0, 0x00, 0x0f, 0x00, 0x01,
            // Answer NAME points to unb.br, followed by an IN MX record.
            0xc0, 0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
            // MX RDATA: preference 10, exchange mail.unb.br.
            0x00, 0x0a, 4, b'm', b'a', b'i', b'l', 0xc0, 0x0c,
        ];
        let header = Header::from_bytes(&packet).unwrap();

        assert_eq!(
            parse_mx_answer(&packet, &header).unwrap(),
            Some("mail.unb.br".into())
        );
    }

    #[test]
    fn returns_none_when_answer_has_no_mx_record() {
        let packet = [
            // Header: 1 question, 1 answer, NOERROR.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // Question: unb.br IN MX.
            3, b'u', b'n', b'b', 2, b'b', b'r', 0, 0x00, 0x0f, 0x00, 0x01,
            // Answer: an IN A record for unb.br.
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 0, 2, 1,
        ];
        let header = Header::from_bytes(&packet).unwrap();

        assert_eq!(parse_mx_answer(&packet, &header).unwrap(), None);
    }
    #[test]
    fn rejects_truncated_question_name() {
        let packet = [
            // Header: uma Question e nenhuma Answer.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // QNAME declara três bytes, mas não possui terminador.
            3, b'u', b'n', b'b',
        ];

        let header = Header::from_bytes(&packet).unwrap();

        assert!(parse_mx_answer(&packet, &header).is_err());
    }

    #[test]
    fn rejects_truncated_resource_record_fields() {
        let packet = [
            // Header: nenhuma Question e uma Answer.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // NAME raiz seguido por somente nove bytes.
            0, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
        ];

        let header = Header::from_bytes(&packet).unwrap();

        assert!(matches!(
            parse_mx_answer(&packet, &header),
            Err(ParseError::TruncatedResourceRecord { .. })
        ));
    }

    #[test]
    fn rejects_rdlength_larger_than_remaining_packet() {
        let packet = [
            // Header: nenhuma Question e uma Answer.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // NAME raiz.
            0, // TYPE MX, CLASS IN, TTL 60.
            0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
            // Declara quatro bytes de RDATA.
            0x00, 0x04, // Mas fornece somente dois.
            0x00, 0x0a,
        ];

        let header = Header::from_bytes(&packet).unwrap();

        assert!(matches!(
            parse_mx_answer(&packet, &header),
            Err(ParseError::TruncatedResourceRecord { .. })
        ));
    }

    #[test]
    fn rejects_mx_rdata_without_exchange() {
        let packet = [
            // Header: nenhuma Question e uma Answer.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // NAME raiz.
            0, // TYPE MX, CLASS IN, TTL 60.
            0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
            // RDLENGTH = 2, contendo somente PREFERENCE.
            0x00, 0x02, 0x00, 0x0a,
        ];

        let header = Header::from_bytes(&packet).unwrap();

        assert!(matches!(
            parse_mx_answer(&packet, &header),
            Err(ParseError::InvalidMxRdata { .. })
        ));
    }

    #[test]
    fn rejects_mx_exchange_outside_rdata() {
        let packet = [
            // Header: nenhuma Question e uma Answer.
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            // NAME raiz.
            0, // TYPE MX, CLASS IN, TTL 60.
            0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, // RDLENGTH = 4.
            0x00, 0x04, // PREFERENCE e nome raiz.
            0x00, 0x0a, 0, // Byte extra que não pertence ao EXCHANGE.
            0xff,
        ];

        let header = Header::from_bytes(&packet).unwrap();

        assert!(matches!(
            parse_mx_answer(&packet, &header),
            Err(ParseError::InvalidMxRdata { .. })
        ));
    }
}
