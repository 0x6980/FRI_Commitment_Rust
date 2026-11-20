#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriConfig {
    pub degree_bound: usize,
    pub query_count: usize,
    pub final_domain_size: usize,
}

impl FriConfig {
    pub fn new(degree_bound: usize, query_count: usize, final_domain_size: usize) -> Self {
        Self {
            degree_bound,
            query_count,
            final_domain_size,
        }
    }

    /// Returns the number of folding rounds.
    ///
    /// Example:
    /// initial_size = 32
    /// final_domain_size = 8
    /// rounds = 2
    pub fn rounds(&self, initial_size: usize) -> Result<usize, String> {
        if initial_size == 0 || !initial_size.is_power_of_two() {
            return Err("Initial domain size must be a power of two".into());
        }

        if self.final_domain_size == 0 || !self.final_domain_size.is_power_of_two() {
            return Err("Final domain size must be a power of two".into());
        }

        if self.final_domain_size > initial_size {
            return Err("Final domain cannot be larger than initial domain".into());
        }

        if initial_size % self.final_domain_size != 0 {
            return Err("Final domain size must divide initial domain size".into());
        }

        let ratio = initial_size / self.final_domain_size;

        if !ratio.is_power_of_two() {
            return Err("Folding ratio must be a power of two".into());
        }

        Ok(ratio.trailing_zeros() as usize)
    }

    /// Computes the degree bound after all folding rounds.
    ///
    /// Each folding round approximately halves the degree bound.
    pub fn final_degree_bound(&self, initial_size: usize) -> Result<usize, String> {
        let rounds = self.rounds(initial_size)?;

        if self.degree_bound >= initial_size {
            return Err("Degree bound must be smaller than initial domain size".into());
        }

        if self.query_count == 0 {
            return Err("Query count must be greater than zero".into());
        }

        // d_r =[d_0/2^r]
        let final_degree = self.degree_bound >> rounds;

        if final_degree >= self.final_domain_size {
            return Err("Final domain must contain more points than the final degree bound".into());
        }

        Ok(final_degree)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_of_folding_rounds() {
        let config = FriConfig::new(5, 5, 8);

        assert_eq!(config.rounds(32).unwrap(), 2);
    }

    #[test]
    fn test_final_degree_bound() {
        let config = FriConfig::new(5, 5, 8);

        assert_eq!(config.final_degree_bound(32).unwrap(), 1);
    }

    #[test]
    fn test_no_folding_rounds() {
        let config = FriConfig::new(5, 5, 32);

        assert_eq!(config.rounds(32).unwrap(), 0);
        assert_eq!(config.final_degree_bound(32).unwrap(), 5);
    }

    #[test]
    fn test_invalid_initial_domain_size() {
        let config = FriConfig::new(5, 5, 8);

        assert!(config.rounds(30).is_err());
    }

    #[test]
    fn test_final_domain_larger_than_initial() {
        let config = FriConfig::new(5, 5, 64);

        assert!(config.rounds(32).is_err());
    }

    #[test]
    fn test_invalid_degree_bound() {
        let config = FriConfig::new(32, 5, 8);

        assert!(config.final_degree_bound(32).is_err());
    }

    #[test]
    fn test_zero_query_count() {
        let config = FriConfig::new(5, 0, 8);

        assert!(config.final_degree_bound(32).is_err());
    }
}
