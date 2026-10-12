/// Gerador pseudoaleatorio usado apenas para escolher o TXID das consultas.
///
/// Nao e criptograficamente seguro: o objetivo e reduzir colisao acidental, nao
/// impedir que um atacante preveja o identificador.
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Semeia com o relogio e o PID. Um relogio anterior a 1970 cai para zero,
    /// o que so reduz a aleatoriedade da semente.
    pub fn seeded_from_clock() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        Rng {
            state: nanos ^ pid.wrapping_mul(0x9E3779B97F4A7C15),
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Proximo valor de 16 bits, adequado como TXID.
    pub fn next_u16(&mut self) -> u16 {
        (self.next_u64() >> 48) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_calls_differ() {
        let mut rng = Rng { state: 42 };
        let a = rng.next_u16();
        let b = rng.next_u16();
        assert_ne!(a, b)
    }

    #[test]
    fn seeded_from_clock_is_reasonably_spread() {
        let mut rng = Rng::seeded_from_clock();
        let ids: std::collections::HashSet<u16> = (0..50).map(|_| rng.next_u16()).collect();
        assert!(ids.len() > 40, "few distincts values: {ids:?}");
    }
}
