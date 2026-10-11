use super::name::{ParseError, checked_offset, decode_name, encode_qname};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QCLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    NS,
    Cname,
    MX,
    Txt,
    Aaaa,
}

impl RecordType {
    pub fn code(self) -> u16 {
        match self {
            Self::A => QTYPE_A,
            Self::NS => QTYPE_NS,
            Self::Cname => QTYPE_CNAME,
            Self::MX => QTYPE_MX,
            Self::Txt => QTYPE_TXT,
            Self::Aaaa => QTYPE_AAAA,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::NS => "NS",
            Self::Cname => "CNAME",
            Self::MX => "MX",
            Self::Txt => "TXT",
            Self::Aaaa => "AAAA",
        }
    }
}

impl FromStr for RecordType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::Cname),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::Txt),
            "AAAA" => Ok(Self::Aaaa),
            _ => Err(format!(
                "tipo DNS invalido: {value} (use A, AAAA, CNAME, NS, TXT ou MX)"
            )),
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAnswer {
    pub value: String,
    pub ttl: u32,
}

/// Extrai todos os registros do tipo solicitado na secao Answer.
///
/// O valor retornado usa a representacao textual do respectivo tipo DNS.
pub fn parse_answers(
    packet: &[u8],
    header: &Header,
    record_type: RecordType,
) -> Result<Vec<RecordAnswer>, ParseError> {
    let mut cursor = skip_questions(packet, header.qdcount)?;
    let mut answers = Vec::new();

    for _ in 0..header.ancount {
        let (record, next_offset) = parse_resource_record(packet, cursor)?;
        cursor = next_offset;

        if record.rr_type != record_type.code() {
            continue;
        }

        answers.push(RecordAnswer {
            value: decode_record_value(packet, &record, next_offset, record_type)?,
            ttl: record.ttl,
        });
    }

    Ok(answers)
}

fn decode_record_value(
    packet: &[u8],
    record: &ResourceRecord,
    rdata_end: usize,
    record_type: RecordType,
) -> Result<String, ParseError> {
    let invalid_rdata = || ParseError::InvalidRecordRdata {
        rr_type: record.rr_type,
        offset: record.rdata_offset,
        length: record.rdlength as usize,
    };

    match record_type {
        RecordType::A => {
            let bytes = packet
                .get(record.rdata_offset..rdata_end)
                .ok_or_else(invalid_rdata)?;
            let address: [u8; 4] = bytes.try_into().map_err(|_| invalid_rdata())?;
            Ok(Ipv4Addr::from(address).to_string())
        }
        RecordType::Aaaa => {
            let bytes = packet
                .get(record.rdata_offset..rdata_end)
                .ok_or_else(invalid_rdata)?;
            let address: [u8; 16] = bytes.try_into().map_err(|_| invalid_rdata())?;
            Ok(Ipv6Addr::from(address).to_string())
        }
        RecordType::Cname | RecordType::NS => {
            let (name, after_name) = decode_name(packet, record.rdata_offset)?;
            if after_name != rdata_end {
                return Err(invalid_rdata());
            }
            Ok(name)
        }
        RecordType::MX => {
            if record.rdlength < 3 {
                return Err(ParseError::InvalidMxRdata {
                    offset: record.rdata_offset,
                    length: record.rdlength as usize,
                });
            }
            let exchange_offset = checked_offset(record.rdata_offset, 2)?;
            let (exchange, after_exchange) = decode_name(packet, exchange_offset)?;
            if after_exchange != rdata_end {
                return Err(ParseError::InvalidMxRdata {
                    offset: record.rdata_offset,
                    length: record.rdlength as usize,
                });
            }
            Ok(exchange)
        }
        RecordType::Txt => {
            let mut cursor = record.rdata_offset;
            let mut strings = Vec::new();
            while cursor < rdata_end {
                let length = packet[cursor] as usize;
                cursor = checked_offset(cursor, 1)?;
                let string_end = checked_offset(cursor, length)?;
                if string_end > rdata_end {
                    return Err(invalid_rdata());
                }
                strings.push(format_txt_string(&packet[cursor..string_end]));
                cursor = string_end;
            }
            if strings.is_empty() {
                return Err(invalid_rdata());
            }
            Ok(strings.join(" "))
        }
    }
}

fn format_txt_string(bytes: &[u8]) -> String {
    let mut value = String::from("\"");
    for byte in bytes {
        match byte {
            b'"' => value.push_str("\\\""),
            b'\\' => value.push_str("\\\\"),
            0x20..=0x7e => value.push(char::from(*byte)),
            _ => {
                value.push('\\');
                value.push(char::from(b'0' + byte / 100));
                value.push(char::from(b'0' + (byte / 10) % 10));
                value.push(char::from(b'0' + byte % 10));
            }
        }
    }
    value.push('"');
    value
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
        self.to_bytes_for(RecordType::MX)
    }

    pub fn to_bytes_for(&self, record_type: RecordType) -> Vec<u8> {
        let mut buf = self.qname.clone();
        buf.extend_from_slice(&record_type.code().to_be_bytes());
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
pub const FLAGS_TRUNCATED: u16 = 0x0200;

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

    pub fn is_truncated(&self) -> bool {
        self.flags & FLAGS_TRUNCATED != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_rdata(record_type: RecordType, rdatas: &[&[u8]]) -> (Vec<u8>, Header) {
        let mut header = Header::new_query(0x1234);
        header.flags = 0x8180;
        header.ancount = rdatas.len().try_into().unwrap();
        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(
            &Question::new("example.com")
                .unwrap()
                .to_bytes_for(record_type),
        );

        for rdata in rdatas {
            packet.extend_from_slice(&[0xc0, 0x0c]);
            packet.extend_from_slice(&record_type.code().to_be_bytes());
            packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
            packet.extend_from_slice(&60u32.to_be_bytes());
            packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            packet.extend_from_slice(rdata);
        }

        let header = Header::from_bytes(&packet).unwrap();
        (packet, header)
    }

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
        assert!(!header.is_truncated());
    }

    #[test]
    fn detects_truncated_response() {
        let header = Header::from_bytes(&[
            0x12, 0x34, 0x83, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();

        assert!(header.is_truncated());
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
    fn question_encodes_requested_record_type() {
        let question = Question::new("unb.br").unwrap();
        for (record_type, code) in [
            (RecordType::A, QTYPE_A),
            (RecordType::NS, QTYPE_NS),
            (RecordType::Cname, QTYPE_CNAME),
            (RecordType::MX, QTYPE_MX),
            (RecordType::Txt, QTYPE_TXT),
            (RecordType::Aaaa, QTYPE_AAAA),
        ] {
            assert!(
                question
                    .to_bytes_for(record_type)
                    .ends_with(&[code.to_be_bytes(), QCLASS_IN.to_be_bytes()].concat())
            );
        }
    }

    #[test]
    fn parses_all_a_records() {
        let first = [192, 0, 2, 1];
        let second = [198, 51, 100, 2];
        let (packet, header) = response_with_rdata(RecordType::A, &[&first, &second]);

        let answers = parse_answers(&packet, &header, RecordType::A).unwrap();

        assert_eq!(
            answers
                .iter()
                .map(|answer| answer.value.as_str())
                .collect::<Vec<_>>(),
            ["192.0.2.1", "198.51.100.2"]
        );
    }

    #[test]
    fn parses_aaaa_record() {
        let address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let (packet, header) = response_with_rdata(RecordType::Aaaa, &[&address]);

        let answers = parse_answers(&packet, &header, RecordType::Aaaa).unwrap();

        assert_eq!(answers[0].value, "2001:db8::1");
    }

    #[test]
    fn parses_cname_and_ns_names() {
        let name = [0xc0, 0x0c];
        for record_type in [RecordType::Cname, RecordType::NS] {
            let (packet, header) = response_with_rdata(record_type, &[&name]);

            let answers = parse_answers(&packet, &header, record_type).unwrap();

            assert_eq!(answers[0].value, "example.com");
        }
    }

    #[test]
    fn parses_txt_character_strings() {
        let txt = [3, b'f', b'o', b'o', 3, b'b', b'a', b'r'];
        let (packet, header) = response_with_rdata(RecordType::Txt, &[&txt]);

        let answers = parse_answers(&packet, &header, RecordType::Txt).unwrap();

        assert_eq!(answers[0].value, "\"foo\" \"bar\"");
    }

    #[test]
    fn rejects_invalid_a_and_txt_rdata() {
        let invalid_a = [192, 0, 2];
        let (packet, header) = response_with_rdata(RecordType::A, &[&invalid_a]);
        assert!(matches!(
            parse_answers(&packet, &header, RecordType::A),
            Err(ParseError::InvalidRecordRdata {
                rr_type: QTYPE_A,
                ..
            })
        ));

        let invalid_txt = [4, b'f', b'o', b'o'];
        let (packet, header) = response_with_rdata(RecordType::Txt, &[&invalid_txt]);
        assert!(matches!(
            parse_answers(&packet, &header, RecordType::Txt),
            Err(ParseError::InvalidRecordRdata {
                rr_type: QTYPE_TXT,
                ..
            })
        ));
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
            parse_answers(&packet, &header, RecordType::MX).unwrap(),
            vec![RecordAnswer {
                value: "mail.unb.br".into(),
                ttl: 60,
            }]
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

        assert!(
            parse_answers(&packet, &header, RecordType::MX)
                .unwrap()
                .is_empty()
        );
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

        assert!(parse_answers(&packet, &header, RecordType::MX).is_err());
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
            parse_answers(&packet, &header, RecordType::MX),
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
            parse_answers(&packet, &header, RecordType::MX),
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
            parse_answers(&packet, &header, RecordType::MX),
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
            parse_answers(&packet, &header, RecordType::MX),
            Err(ParseError::InvalidMxRdata { .. })
        ));
    }
}
