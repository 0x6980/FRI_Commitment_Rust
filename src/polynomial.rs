use crate::field::FieldElement;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coefficients: Vec<FieldElement>,
}

impl Polynomial {
    /// Creates a polynomial from coefficients in ascending order.
    ///
    /// Example:
    /// [3, 2, 5, 4] represents:
    /// 3 + 2X + 5X^2 + 4X^3
    pub fn new(mut coefficients: Vec<FieldElement>) -> Self {
        if coefficients.is_empty() {
            panic!("A polynomial must have at least one coefficient");
        }

        let modulus = coefficients[0].modulus;

        for coefficient in &coefficients {
            assert_eq!(
                coefficient.modulus, modulus,
                "All coefficients must belong to the same field"
            );
        }

        // Remove unnecessary trailing zero coefficients.
        while coefficients.len() > 1 && coefficients.last().unwrap().is_zero() {
            coefficients.pop();
        }

        Self { coefficients }
    }

    pub fn zero(modulus: u64) -> Self {
        Self::new(vec![FieldElement::zero(modulus)])
    }

    pub fn one(modulus: u64) -> Self {
        Self::new(vec![FieldElement::one(modulus)])
    }

    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    pub fn modulus(&self) -> u64 {
        self.coefficients[0].modulus
    }

    /// Evaluates the polynomial using Horner's method.
    ///
    /// For:
    /// f(X) = c0 + c1*X + c2*X^2 + ...
    ///
    /// Horner's method evaluates it as:
    /// c0 + X*(c1 + X*(c2 + ...))
    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        assert_eq!(
            x.modulus,
            self.modulus(),
            "Evaluation point belongs to a different field"
        );

        let mut result = FieldElement::zero(self.modulus());

        for coefficient in self.coefficients.iter().rev() {
            result = result * x + *coefficient;
        }

        result
    }

    /// Splits:
    ///
    /// f(X) = f_even(X^2) + X * f_odd(X^2)
    ///
    /// Returns:
    /// (f_even, f_odd)
    pub fn split_even_odd(&self) -> (Polynomial, Polynomial) {
        let modulus = self.modulus();

        let mut even_coefficients = Vec::new();
        let mut odd_coefficients = Vec::new();

        for (i, coefficient) in self.coefficients.iter().enumerate() {
            if i % 2 == 0 {
                even_coefficients.push(*coefficient);
            } else {
                odd_coefficients.push(*coefficient);
            }
        }

        if even_coefficients.is_empty() {
            even_coefficients.push(FieldElement::zero(modulus));
        }

        if odd_coefficients.is_empty() {
            odd_coefficients.push(FieldElement::zero(modulus));
        }

        (
            Polynomial::new(even_coefficients),
            Polynomial::new(odd_coefficients),
        )
    }

    /// Folds the polynomial using challenge alpha.
    ///
    /// Given:
    /// f(X) = f_even(X^2) + X * f_odd(X^2)
    ///
    /// Computes:
    /// g(Y) = f_even(Y) + alpha * f_odd(Y)
    pub fn fold(&self, alpha: FieldElement) -> Polynomial {
        assert_eq!(
            alpha.modulus,
            self.modulus(),
            "Challenge belongs to a different field"
        );

        let (even_poly, odd_poly) = self.split_even_odd();

        let modulus = self.modulus();
        let zero = FieldElement::zero(modulus);

        let max_len = even_poly
            .coefficients
            .len()
            .max(odd_poly.coefficients.len());

        let mut folded_coefficients = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let even_coefficient = even_poly.coefficients.get(i).copied().unwrap_or(zero);

            let odd_coefficient = odd_poly.coefficients.get(i).copied().unwrap_or(zero);

            let folded_coefficient = even_coefficient + alpha * odd_coefficient;

            folded_coefficients.push(folded_coefficient);
        }

        Polynomial::new(folded_coefficients)
    }

    /// Constructs the unique polynomial of degree at most n - 1
    /// that interpolates n distinct points.
    ///
    /// Points must have distinct x-coordinates and all coordinates
    /// must belong to the same field.
    pub fn interpolate(points: &[(FieldElement, FieldElement)]) -> Self {
        assert!(
            !points.is_empty(),
            "Interpolation requires at least one point"
        );

        let modulus = points[0].0.modulus;

        // Check that all coordinates belong to the same field.
        for (x, y) in points {
            assert_eq!(
                x.modulus, modulus,
                "All x-coordinates must belong to the same field"
            );

            assert_eq!(
                y.modulus, modulus,
                "All y-coordinates must belong to the same field"
            );
        }

        let mut result = vec![FieldElement::zero(modulus); points.len()];

        for i in 0..points.len() {
            let (x_i, y_i) = points[i];

            // Construct the numerator:
            // product (X - x_j), for j != i.
            let mut basis = vec![FieldElement::one(modulus)];

            // Construct the denominator:
            // product (x_i - x_j), for j != i.
            let mut denominator = FieldElement::one(modulus);

            for j in 0..points.len() {
                if i == j {
                    continue;
                }

                let x_j = points[j].0;

                let mut next_basis = vec![FieldElement::zero(modulus); basis.len() + 1];

                // Multiply the current basis by (X - x_j).
                for k in 0..basis.len() {
                    next_basis[k] = next_basis[k] - basis[k] * x_j;

                    next_basis[k + 1] = next_basis[k + 1] + basis[k];
                }

                basis = next_basis;

                denominator = denominator * (x_i - x_j);
            }

            assert!(
                !denominator.is_zero(),
                "Interpolation points must have distinct x-coordinates"
            );

            // Scale the basis polynomial by:
            // y_i / denominator.
            let scale = y_i / denominator;

            for k in 0..basis.len() {
                result[k] = result[k] + basis[k] * scale;
            }
        }

        Self::new(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 97;

    fn fe(value: u64) -> FieldElement {
        FieldElement::new(value, P)
    }

    #[test]
    fn test_polynomial_evaluation() {
        // f(X) = 3 + 2X + 5X^2 + 4X^3
        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4)]);

        // f(2) = 3 + 4 + 20 + 32 = 59
        assert_eq!(f.evaluate(fe(2)), fe(59));
    }

    #[test]
    fn test_split_even_odd() {
        // f(X) = 3 + 2X + 5X^2 + 4X^3
        //
        // f_even(Y) = 3 + 5Y
        // f_odd(Y)  = 2 + 4Y

        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4)]);

        let (even, odd) = f.split_even_odd();

        assert_eq!(even, Polynomial::new(vec![fe(3), fe(5),]));

        assert_eq!(odd, Polynomial::new(vec![fe(2), fe(4),]));
    }

    #[test]
    fn test_fold_coefficients() {
        // f(X) = 3 + 2X + 5X^2 + 4X^3
        //
        // f_even(Y) = 3 + 5Y
        // f_odd(Y)  = 2 + 4Y
        //
        // alpha = 7
        //
        // g(Y) = (3 + 5Y) + 7(2 + 4Y)
        //      = 17 + 33Y

        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4)]);

        let alpha = fe(7);

        let folded = f.fold(alpha);

        let expected = Polynomial::new(vec![fe(17), fe(33)]);

        assert_eq!(folded, expected);
    }

    #[test]
    fn test_folding_identity_for_all_nonzero_x() {
        // This test compares two independent ways
        // of computing the folded polynomial.
        //
        // Method 1:
        // Fold the coefficients, then evaluate at x^2.
        //
        // Method 2:
        // Evaluate f(x) and f(-x), then use:
        //
        // g(x^2) =
        // (f(x) + f(-x))/2
        // + alpha * (f(x) - f(-x))/(2x)

        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let alpha = fe(7);

        let folded = f.fold(alpha);

        let two_inverse = fe(2).inverse();

        for x_value in 1..P {
            let x = fe(x_value);
            let minus_x = -x;

            let fx = f.evaluate(x);
            let f_minus_x = f.evaluate(minus_x);

            let x_squared = x * x;

            let even_part = (fx + f_minus_x) * two_inverse;

            let odd_part = (fx - f_minus_x) * two_inverse * x.inverse();

            let value_from_pairs = even_part + alpha * odd_part;

            let value_from_coefficients = folded.evaluate(x_squared);

            assert_eq!(
                value_from_pairs, value_from_coefficients,
                "Folding identity failed for x = {}",
                x_value
            );
        }
    }

    #[test]
    fn test_fold_constant_polynomial() {
        let f = Polynomial::new(vec![fe(42)]);

        let folded = f.fold(fe(7));

        assert_eq!(folded, Polynomial::new(vec![fe(42)]));
    }

    #[test]
    fn test_fold_polynomial_with_even_degree_only() {
        // f(X) = 3 + 5X^2
        //
        // f_even(Y) = 3 + 5Y
        // f_odd(Y) = 0
        //
        // Folding does not depend on alpha.

        let f = Polynomial::new(vec![fe(3), fe(0), fe(5)]);

        let folded = f.fold(fe(7));

        assert_eq!(folded, Polynomial::new(vec![fe(3), fe(5),]));
    }
}

#[cfg(test)]
mod interpolation_tests {
    use super::*;

    const P: u64 = 97;

    fn fe(value: u64) -> FieldElement {
        FieldElement::new(value, P)
    }

    #[test]
    fn test_interpolate_recovers_original_polynomial() {
        let original = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4)]);

        let points: Vec<(FieldElement, FieldElement)> = [1, 2, 3, 4]
            .iter()
            .map(|x| {
                let x = fe(*x);
                (x, original.evaluate(x))
            })
            .collect();

        let recovered = Polynomial::interpolate(&points);

        assert_eq!(recovered.coefficients, original.coefficients);
    }

    #[test]
    fn test_interpolate_matches_all_points() {
        let points = vec![
            (fe(1), fe(7)),
            (fe(2), fe(12)),
            (fe(3), fe(19)),
            (fe(4), fe(28)),
        ];

        let polynomial = Polynomial::interpolate(&points);

        for (x, y) in points {
            assert_eq!(polynomial.evaluate(x), y);
        }
    }

    #[test]
    fn test_interpolate_single_point() {
        let points = vec![(fe(5), fe(42))];

        let polynomial = Polynomial::interpolate(&points);

        assert_eq!(polynomial.coefficients, vec![fe(42)]);

        assert_eq!(polynomial.evaluate(fe(5)), fe(42));
    }

    #[test]
    #[should_panic(expected = "Interpolation points must have distinct x-coordinates")]
    fn test_interpolate_rejects_duplicate_x_coordinates() {
        let points = vec![(fe(2), fe(10)), (fe(2), fe(20))];

        Polynomial::interpolate(&points);
    }

    #[test]
    #[should_panic(expected = "Interpolation requires at least one point")]
    fn test_interpolate_rejects_empty_input() {
        let points: Vec<(FieldElement, FieldElement)> = vec![];

        Polynomial::interpolate(&points);
    }
}
