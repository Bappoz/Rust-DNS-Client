use std::fmt;

/// Erros encontrados ao ler um nome codificado em uma mensagem DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader { length: usize },
    OffsetOutOfBounds { offset: usize },
    TruncatedPointer { offset: usize },
    TruncatedLabel { offset: usize, length: usize },
    InvalidLabelTag { offset: usize, tag: u8 },
    PointerLoop,
    InvalidLabelEncoding,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { length } => {
                write!(f, "header DNS truncado (tamanho {length})")
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
        }
    }
}

impl std::error::Error for ParseError {}

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

    loop {
        let length = *packet
            .get(cursor)
            .ok_or(ParseError::OffsetOutOfBounds { offset: cursor })?;

        match length {
            0 => {
                let after_name = next_offset.unwrap_or(cursor + 1);
                return Ok((labels.join("."), after_name));
            }
            0xC0..=0xFF => {
                let low_byte = *packet
                    .get(cursor + 1)
                    .ok_or(ParseError::TruncatedPointer { offset: cursor })?;
                let pointer = (((length & 0x3F) as usize) << 8) | low_byte as usize;

                if pointer >= packet.len() {
                    return Err(ParseError::OffsetOutOfBounds { offset: pointer });
                }
                if pointer_jumps >= MAX_POINTER_JUMPS {
                    return Err(ParseError::PointerLoop);
                }
                pointer_jumps += 1;
                next_offset.get_or_insert(cursor + 2);
                cursor = pointer;
            }
            0x40..=0xBF => {
                return Err(ParseError::InvalidLabelTag {
                    offset: cursor,
                    tag: length,
                });
            }
            label_length => {
                let label_start = cursor + 1;
                let label_end = label_start + label_length as usize;
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
        if label.len() > 63 {
            return Err(format!("label '{label}' excede 63 bytes"));
        }
        if !label.is_ascii() {
            return Err(format!(
                "label '{label}' have non-ascii chars (IDN not supported)"
            ));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
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
}
