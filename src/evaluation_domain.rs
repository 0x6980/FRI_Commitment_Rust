use crate::field::{FieldElement, PrimeField};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationDomain {
    pub generator: FieldElement,
    pub size: usize,
}

impl EvaluationDomain {
    /// Creates a multiplicative subgroup evaluation domain.
    ///
    /// The domain is:
    /// H = {1, omega, omega^2, ..., omega^(size-1)}
    ///
    /// Requirements:
    /// - size must be a power of two.
    /// - generator must have exact order `size`.
    ///
    /// For size >= 2, exact order is checked using:
    /// omega^size = 1
    /// omega^(size/2) = -1
    pub fn new(generator: FieldElement, size: usize) -> Self {
        assert!(size.is_power_of_two(), "Domain size must be a power of two");

        let one = generator.field().one();
        let minus_one = -one;

        if size == 1 {
            assert_eq!(generator, one, "A domain of size 1 must have generator 1");
        } else {
            let size_u64 = u64::try_from(size).expect("Domain size does not fit into u64");

            assert_eq!(generator.pow(size_u64), one, "Generator^size must equal 1");

            assert_eq!(
                generator.pow(size_u64 / 2),
                minus_one,
                "Generator^(size/2) must equal -1"
            );
        }

        Self { generator, size }
    }

    pub fn modulus(&self) -> u64 {
        self.generator.modulus()
    }

    pub fn field(&self) -> PrimeField {
        self.generator.field()
    }

    /// Returns the domain points in natural exponent order:
    ///
    /// [1, omega, omega^2, ..., omega^(size-1)]
    pub fn points(&self) -> Vec<FieldElement> {
        let mut result = Vec::with_capacity(self.size);

        let mut current = self.generator.field().one();

        for _ in 0..self.size {
            result.push(current);
            current = current * self.generator;
        }

        result
    }

    /// Folds evaluations over the multiplicative subgroup.
    ///
    /// Input:
    /// evaluations[i] = f(omega^i)
    ///
    /// Pairing:
    /// evaluations[i]     = f(x)
    /// evaluations[i+n/2] = f(-x)
    ///
    /// Output:
    /// folded[i] = g(x^2)
    ///
    /// where:
    ///
    /// g(x^2) =
    /// (f(x) + f(-x))/2
    /// + alpha * (f(x) - f(-x))/(2x)
    ///
    /// The returned domain has generator omega^2
    /// and size n/2.
    pub fn fold_evaluations(
        &self,
        evaluations: &[FieldElement],
        alpha: FieldElement,
    ) -> (EvaluationDomain, Vec<FieldElement>) {
        assert!(self.size >= 2, "Cannot fold a domain of size less than 2");

        assert_eq!(
            evaluations.len(),
            self.size,
            "Number of evaluations must equal domain size"
        );

        assert_eq!(
            alpha.modulus(),
            self.modulus(),
            "Challenge belongs to a different field"
        );

        for evaluation in evaluations {
            assert_eq!(
                evaluation.modulus(),
                self.modulus(),
                "Evaluation belongs to a different field"
            );
        }

        let half_size = self.size / 2;

        let field = PrimeField::new(self.modulus()).unwrap();

        let two_inverse = field.element(2).inverse();

        let mut folded_evaluations = Vec::with_capacity(half_size);

        // x starts at 1 and advances as:
        // 1, omega, omega^2, ...
        let mut x = self.generator.field().one();

        for i in 0..half_size {
            let fx = evaluations[i];
            let f_minus_x = evaluations[i + half_size];

            // Even component:
            // (f(x) + f(-x)) / 2
            let even_part = (fx + f_minus_x) * two_inverse;

            // Odd component:
            // (f(x) - f(-x)) / (2x)
            let odd_part = (fx - f_minus_x) * two_inverse * x.inverse();

            // Fold:
            // g(x^2) = even_part + alpha * odd_part
            let folded_value = even_part + alpha * odd_part;

            folded_evaluations.push(folded_value);

            x = x * self.generator;
        }

        // The new domain is:
        // H^2 = <omega^2>
        let new_generator = self.generator * self.generator;

        let new_domain = EvaluationDomain::new(new_generator, half_size);

        (new_domain, folded_evaluations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::Polynomial;

    const P: u64 = 97;
    const OMEGA: u64 = 19;
    const N: usize = 32;

    fn fe(value: u64) -> FieldElement {
        let field = PrimeField::new(P).unwrap();
        field.element(value)
    }

    fn test_domain() -> EvaluationDomain {
        EvaluationDomain::new(fe(OMEGA), N)
    }

    #[test]
    fn test_domain_size() {
        let domain = test_domain();

        assert_eq!(domain.points().len(), N);
    }

    #[test]
    fn test_generator_has_exact_order_32() {
        let omega = fe(OMEGA);

        assert_eq!(omega.pow(32), fe(1));
        assert_eq!(omega.pow(16), fe(96));

        // Since the order is a power of two,
        // omega^16 != 1 establishes exact order 32.
        assert_ne!(omega.pow(16), fe(1));
    }

    #[test]
    fn test_domain_points_are_distinct() {
        let domain = test_domain();
        let points = domain.points();

        for i in 0..points.len() {
            for j in (i + 1)..points.len() {
                assert_ne!(
                    points[i], points[j],
                    "Duplicate domain points at indices {} and {}",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_opposite_points_are_half_a_domain_apart() {
        let domain = test_domain();
        let points = domain.points();

        for i in 0..(N / 2) {
            assert_eq!(points[i + N / 2], -points[i]);
        }
    }

    #[test]
    fn test_folded_domain_has_half_size() {
        let domain = test_domain();

        let evaluations = vec![fe(0); N];

        let (new_domain, _) = domain.fold_evaluations(&evaluations, fe(7));

        assert_eq!(new_domain.size, N / 2);
        assert_eq!(new_domain.generator, fe(OMEGA).pow(2));
    }

    #[test]
    fn test_folded_domain_points_are_squares() {
        let domain = test_domain();

        let evaluations = vec![fe(0); N];

        let old_points = domain.points();

        let (new_domain, _) = domain.fold_evaluations(&evaluations, fe(7));

        let new_points = new_domain.points();

        for i in 0..(N / 2) {
            assert_eq!(new_points[i], old_points[i] * old_points[i]);
        }
    }

    #[test]
    fn test_evaluation_folding_matches_polynomial_folding() {
        // f(X) = 3 + 2X + 5X^2 + 4X^3 + 7X^4 + 6X^5
        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let alpha = fe(7);

        let domain = test_domain();

        // Evaluate f over the original domain.
        let evaluations: Vec<FieldElement> =
            domain.points().iter().map(|x| f.evaluate(*x)).collect();

        // Fold the polynomial using its coefficients.
        let folded_polynomial = f.fold(alpha);

        // Fold the evaluation vector.
        let (new_domain, folded_evaluations) = domain.fold_evaluations(&evaluations, alpha);

        // Evaluate the folded polynomial over the new domain.
        let expected_evaluations: Vec<FieldElement> = new_domain
            .points()
            .iter()
            .map(|x| folded_polynomial.evaluate(*x))
            .collect();

        assert_eq!(folded_evaluations, expected_evaluations);
    }

    #[test]
    fn test_multiple_folding_rounds() {
        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let mut domain = test_domain();

        let mut evaluations: Vec<FieldElement> =
            domain.points().iter().map(|x| f.evaluate(*x)).collect();

        let alpha = fe(7);

        // First round: 32 -> 16
        let (domain_1, evaluations_1) = domain.fold_evaluations(&evaluations, alpha);

        assert_eq!(domain_1.size, 16);

        // Second round: 16 -> 8
        let (domain_2, evaluations_2) = domain_1.fold_evaluations(&evaluations_1, alpha);

        assert_eq!(domain_2.size, 8);

        // Third round: 8 -> 4
        let (domain_3, evaluations_3) = domain_2.fold_evaluations(&evaluations_2, alpha);

        assert_eq!(domain_3.size, 4);

        // Fourth round: 4 -> 2
        let (domain_4, evaluations_4) = domain_3.fold_evaluations(&evaluations_3, alpha);

        assert_eq!(domain_4.size, 2);

        // Fifth round: 2 -> 1
        let (domain_5, evaluations_5) = domain_4.fold_evaluations(&evaluations_4, alpha);

        assert_eq!(domain_5.size, 1);
        assert_eq!(evaluations_5.len(), 1);

        // The final singleton domain is {1}.
        assert_eq!(domain_5.points(), vec![fe(1)]);
    }
}
