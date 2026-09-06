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
}
