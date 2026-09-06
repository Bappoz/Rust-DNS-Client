// A server only for generating a transaction ID with low chance of trivial colision of previsibility
pub struct Rng {
    state: u64,
}

impl Rng {
    // Minimal PRNG based on SplitMix64 (Virginia) -- Not full secure
    pub fn seeded_from_clock() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("...")
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
