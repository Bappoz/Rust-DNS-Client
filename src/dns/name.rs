use std::collections::HashSet;
use std::fmt;

/// Erros encontrados ao ler um nome codificado em uma mensagem DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader { length: usize },
    TruncatedQuestion { offset: usize },
    TruncatedResourceRecord { offset: usize },
    InvalidMxRdata { offset: usize, length: usize },
    OffsetOutOfBounds { offset: usize },
    TruncatedPointer { offset: usize },
    TruncatedLabel { offset: usize, length: usize },
    InvalidLabelTag { offset: usize, tag: u8 },
    PointerLoop,
    InvalidLabelEncoding,
    TooManyPointerJumps { limit: usize },
    OffsetOverflow { offset: usize, length: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { length } => {
                write!(f, "header DNS truncado (tamanho {length})")
            }
            Self::TruncatedQuestion { offset } => {
                write!(f, "question DNS truncada no offset {offset}")
            }
            Self::TruncatedResourceRecord { offset } => {
                write!(f, "resource record DNS truncado no offset {offset}")
            }
            Self::InvalidMxRdata { offset, length } => {
                write!(f, "RDATA MX invalido no offset {offset} (tamanho {length})")
            }
            Self::OffsetOutOfBounds { offset } => write!(f, "offset DNS invalido: {offset}"),
            Self::TruncatedPointer { offset } => {
                write!(f, "ponteiro DNS truncado no offset {offset}")
            }
            Self::TruncatedLabel { offset, length } => {
                write!(
                    f,
                    "label DNS truncado no offset {offset} (tamanho {length})"
                )
            }
            Self::InvalidLabelTag { offset, tag } => {
                write!(
                    f,
                    "tag de label DNS invalida 0x{tag:02x} no offset {offset}"
                )
            }
            Self::PointerLoop => write!(f, "muitos saltos de ponteiro DNS (possivel ciclo)"),
            Self::InvalidLabelEncoding => write!(f, "label DNS nao e UTF-8 valido"),
            Self::TooManyPointerJumps { limit } => {
                write!(f, "nome DNS excedeu o limite de {limit} ponteiros")
            }
            Self::OffsetOverflow { offset, length } => {
                write!(f, "overflow ao calcular offset DNS: {offset} + {length}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

pub(crate) fn checked_offset(offset: usize, length: usize) -> Result<usize, ParseError> {
    offset
        .checked_add(length)
        .ok_or(ParseError::OffsetOverflow { offset, length })
}

/// Decodifica um nome DNS, incluindo ponteiros de compressao do RFC 1035 §4.1.4.
///
/// O segundo elemento retornado e o primeiro byte apos o nome na representacao
/// original. Assim, ao seguir um ponteiro, o cursor retornado fica logo apos os
/// dois bytes do ponteiro, e nao apos o nome para o qual ele aponta.
pub fn decode_name(packet: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
    if offset >= packet.len() {
        return Err(ParseError::OffsetOutOfBounds { offset });
    }

    const MAX_POINTER_JUMPS: usize = 20;

    let mut cursor = offset;
    let mut next_offset = None;
    let mut labels = Vec::new();
    let mut pointer_jumps = 0;
    let mut visited_offsets = HashSet::new();

    loop {
        let length = *packet
            .get(cursor)
            .ok_or(ParseError::OffsetOutOfBounds { offset: cursor })?;

        match length {
            0 => {
                let after_name = match next_offset {
                    Some(offset) => offset,
                    None => checked_offset(cursor, 1)?,
                };
                return Ok((labels.join("."), after_name));
            }
            0xC0..=0xFF => {
                let low_byte_offset = checked_offset(cursor, 1)?;
                let low_byte = *packet
                    .get(low_byte_offset)
                    .ok_or(ParseError::TruncatedPointer { offset: cursor })?;
                let pointer = (((length & 0x3F) as usize) << 8) | low_byte as usize;

                if pointer >= packet.len() {
                    return Err(ParseError::OffsetOutOfBounds { offset: pointer });
                }
                if !visited_offsets.insert(pointer) {
                    return Err(ParseError::PointerLoop);
                }
                if pointer_jumps >= MAX_POINTER_JUMPS {
                    return Err(ParseError::TooManyPointerJumps {
                        limit: MAX_POINTER_JUMPS,
                    });
                }
                pointer_jumps += 1;
                if next_offset.is_none() {
                    next_offset = Some(checked_offset(cursor, 2)?);
                }
                cursor = pointer;
            }
            0x40..=0xBF => {
                return Err(ParseError::InvalidLabelTag {
                    offset: cursor,
                    tag: length,
                });
            }
            label_length => {
                let label_start = checked_offset(cursor, 1)?;
                let label_end = checked_offset(label_start, label_length as usize)?;
                let label =
                    packet
                        .get(label_start..label_end)
                        .ok_or(ParseError::TruncatedLabel {
                            offset: cursor,
                            length: label_length as usize,
                        })?;
                let label =
                    std::str::from_utf8(label).map_err(|_| ParseError::InvalidLabelEncoding)?;
                labels.push(label.to_owned());
                cursor = label_end;
            }
        }
    }
}

/// Codifica um dominio no formato de labels do DNS (RFC 10135)
/// cada label prefixado por 1 byte de tamanho (0-63)
/// tamanho limitado a 63 já que 2 bits mais altos do byte de tamanho sao reservados
pub fn encode_qname(domain: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for label in domain.split('.').filter(|s| !s.is_empty()) {
        let ascii_label = idna::domain_to_ascii(label)
            .map_err(|error| format!("label '{label}' invalido para IDN: {error}"))?;
        if ascii_label.len() > 63 {
            return Err(format!("label '{label}' excede 63 bytes após Punycode"));
        }
        out.push(ascii_label.len() as u8);
        out.extend_from_slice(ascii_label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_two_labels_domain() {
        assert_eq!(
            encode_qname("unb.br").unwrap(),
            vec![3, b'u', b'n', b'b', 2, b'b', b'r', 0]
        );
    }

    #[test]
    fn trailing_dot_is_equivalent() {
        // "unb.br." deve gerar o mesmo qname que unb.br
        assert_eq!(
            encode_qname("unb.br").unwrap(),
            encode_qname("unb.br.").unwrap()
        );
    }

    #[test]
    fn encodes_internationalized_label_as_punycode() {
        assert_eq!(
            encode_qname("café.example").unwrap(),
            vec![
                11, b'x', b'n', b'-', b'-', b'c', b'a', b'f', b'-', b'd', b'm', b'a', 7, b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', 0
            ]
        );
    }

    #[test]
    fn decodes_a_compressed_name() {
        let packet = [
            3, b'u', b'n', b'b', 2, b'b', b'r', 0, // unb.br
            3, b'w', b'w', b'w', 0xC0, 0x00, // www + pointer to unb.br
        ];

        assert_eq!(
            decode_name(&packet, 8).unwrap(),
            ("www.unb.br".to_owned(), 14)
        );
    }

    #[test]
    fn rejects_a_pointer_cycle() {
        let packet = [0xC0, 0x00];

        assert_eq!(decode_name(&packet, 0), Err(ParseError::PointerLoop));
    }

    #[test]
    fn rejects_a_pointer_outside_the_packet() {
        let packet = [0xC0, 0x10];

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::OffsetOutOfBounds { offset: 16 })
        );
    }

    #[test]
    fn rejects_name_without_terminator() {
        let packet = [3, b'u', b'n', b'b'];

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::OffsetOutOfBounds { offset: 4 })
        );
    }

    #[test]
    fn rejects_truncated_pointer() {
        let packet = [0xC0];

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::TruncatedPointer { offset: 0 })
        );
    }

    #[test]
    fn rejects_invalid_label_tag() {
        let packet = [0x40, 0];

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::InvalidLabelTag {
                offset: 0,
                tag: 0x40,
            })
        );
    }

    #[test]
    fn rejects_invalid_utf8_label() {
        let packet = [1, 0xFF, 0];

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::InvalidLabelEncoding)
        );
    }

    #[test]
    fn rejects_long_non_cyclic_pointer_chain() {
        let mut packet = Vec::new();

        for index in 0..21 {
            let target = ((index + 1) * 2) as u8;
            packet.extend_from_slice(&[0xC0, target]);
        }

        packet.push(0);

        assert_eq!(
            decode_name(&packet, 0),
            Err(ParseError::TooManyPointerJumps { limit: 20 })
        );
    }
}
