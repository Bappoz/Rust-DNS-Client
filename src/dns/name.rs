use std::collections::HashSet;
use std::fmt;

/// Erros encontrados ao ler um nome codificado em uma mensagem DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    TruncatedHeader {
        length: usize,
    },
    TruncatedQuestion {
        offset: usize,
    },
    TruncatedResourceRecord {
        offset: usize,
    },
    InvalidMxRdata {
        offset: usize,
        length: usize,
    },
    InvalidRecordRdata {
        rr_type: u16,
        offset: usize,
        length: usize,
    },
    OffsetOutOfBounds {
        offset: usize,
    },
    TruncatedPointer {
        offset: usize,
    },
    TruncatedLabel {
        offset: usize,
        length: usize,
    },
    InvalidLabelTag {
        offset: usize,
        tag: u8,
    },
    PointerLoop,
    InvalidLabelEncoding,
    TooManyPointerJumps {
        limit: usize,
    },
    OffsetOverflow {
        offset: usize,
        length: usize,
    },
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
            Self::InvalidRecordRdata {
                rr_type,
                offset,
                length,
            } => write!(
                f,
                "RDATA DNS tipo {rr_type} invalido no offset {offset} (tamanho {length})"
            ),
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
pub(crate) fn decode_name(packet: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
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

/// Erros encontrados ao codificar um dominio em QNAME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    InvalidLabel { label: String, reason: String },
    LabelTooLong { label: String },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLabel { label, reason } => {
                write!(f, "label '{label}' invalido: {reason}")
            }
            Self::LabelTooLong { label } => {
                write!(f, "label '{label}' excede 63 bytes após Punycode")
            }
        }
    }
}

impl std::error::Error for NameError {}

/// Codifica um dominio no formato de labels do DNS (RFC 1035 §3.1): cada label
/// e precedida por 1 byte com seu tamanho. O tamanho fica limitado a 63 porque
/// os 2 bits mais altos do byte sao reservados para ponteiros de compressao.
pub(crate) fn encode_qname(domain: &str) -> Result<Vec<u8>, NameError> {
    let mut out = Vec::new();
    for label in domain.split('.').filter(|s| !s.is_empty()) {
        let ascii_label = to_ascii_label(label)?;
        if ascii_label.len() > 63 {
            return Err(NameError::LabelTooLong {
                label: label.to_owned(),
            });
        }
        out.push(ascii_label.len() as u8);
        out.extend_from_slice(ascii_label.as_bytes());
    }
    out.push(0);
    Ok(out)
}

/// Label ASCII segue como foi digitada; label com caractere fora do ASCII e
/// convertida para a forma `xn--<punycode>` (RFC 3490). A unica preparacao do
/// texto e passar para minusculas: nao ha normalizacao Unicode (NFC) nem o
/// mapeamento da UTS #46, que exigiriam tabelas de dados externas.
fn to_ascii_label(label: &str) -> Result<String, NameError> {
    if label.is_ascii() {
        return Ok(label.to_owned());
    }
    let encoded =
        punycode_encode(&label.to_lowercase()).ok_or_else(|| NameError::InvalidLabel {
            label: label.to_owned(),
            reason: "nao foi possivel converter para Punycode".to_owned(),
        })?;
    Ok(format!("xn--{encoded}"))
}

// Parametros do Bootstring para Punycode (RFC 3492 §5).
const PUNYCODE_BASE: u32 = 36;
const PUNYCODE_TMIN: u32 = 1;
const PUNYCODE_TMAX: u32 = 26;
const PUNYCODE_SKEW: u32 = 38;
const PUNYCODE_DAMP: u32 = 700;
const PUNYCODE_INITIAL_BIAS: u32 = 72;
const PUNYCODE_INITIAL_N: u32 = 128;

/// Codificador Punycode (RFC 3492 §6.3). Os caracteres ASCII sao copiados no
/// inicio; cada caractere restante vira um inteiro de tamanho variavel que
/// guarda o seu code point e a posicao em que deve ser inserido. Devolve `None`
/// se a aritmetica estourar 32 bits.
fn punycode_encode(input: &str) -> Option<String> {
    let code_points: Vec<u32> = input.chars().map(u32::from).collect();
    let mut output: String = input.chars().filter(char::is_ascii).collect();
    let basic_count = output.len() as u32;
    if basic_count > 0 {
        output.push('-');
    }

    let mut handled = basic_count;
    let mut n = PUNYCODE_INITIAL_N;
    let mut delta = 0u32;
    let mut bias = PUNYCODE_INITIAL_BIAS;

    while (handled as usize) < code_points.len() {
        // Menor code point ainda nao codificado.
        let next = code_points.iter().copied().filter(|&c| c >= n).min()?;
        delta = delta.checked_add((next - n).checked_mul(handled + 1)?)?;
        n = next;

        for &code_point in &code_points {
            if code_point < n {
                delta = delta.checked_add(1)?;
            }
            if code_point == n {
                let mut q = delta;
                let mut k = PUNYCODE_BASE;
                loop {
                    let threshold = if k <= bias {
                        PUNYCODE_TMIN
                    } else if k >= bias + PUNYCODE_TMAX {
                        PUNYCODE_TMAX
                    } else {
                        k - bias
                    };
                    if q < threshold {
                        break;
                    }
                    let digit = threshold + (q - threshold) % (PUNYCODE_BASE - threshold);
                    output.push(punycode_digit(digit));
                    q = (q - threshold) / (PUNYCODE_BASE - threshold);
                    k += PUNYCODE_BASE;
                }
                output.push(punycode_digit(q));
                bias = punycode_adapt(delta, handled + 1, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }

        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }

    Some(output)
}

/// Ajuste do bias apos cada caractere codificado (RFC 3492 §6.1).
fn punycode_adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time {
        delta / PUNYCODE_DAMP
    } else {
        delta / 2
    };
    delta += delta / num_points;

    let mut k = 0;
    while delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2 {
        delta /= PUNYCODE_BASE - PUNYCODE_TMIN;
        k += PUNYCODE_BASE;
    }
    k + (PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta / (delta + PUNYCODE_SKEW)
}

/// Digito 0..=35 como `a`-`z` (0 a 25) ou `0`-`9` (26 a 35).
fn punycode_digit(digit: u32) -> char {
    let byte = if digit < 26 {
        b'a' + digit as u8
    } else {
        b'0' + (digit - 26) as u8
    };
    char::from(byte)
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

    // Vetores conferidos contra o codec "punycode" do Python 3.
    #[test]
    fn punycode_matches_reference_vectors() {
        for (input, expected) in [
            ("café", "caf-dma"),
            ("münchen", "mnchen-3ya"),
            ("bücher", "bcher-kva"),
            ("ação", "ao-siap"),
            // RFC 3492 §7.1 (A) e (B): sem nenhum caractere ASCII.
            ("ليهمابتكلموشعربي؟", "egbpdaj6bu4bxfgehfvwxn"),
            ("他们为什么不说中文", "ihqwcrb4cv8a8dqg056pqjye"),
        ] {
            assert_eq!(punycode_encode(input).as_deref(), Some(expected), "{input}");
        }
    }

    #[test]
    fn idn_label_is_lowercased_before_encoding() {
        assert_eq!(
            encode_qname("CAFÉ.example").unwrap(),
            encode_qname("café.example").unwrap()
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
