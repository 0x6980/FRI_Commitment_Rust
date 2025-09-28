use crate::field::FieldElement;

#[derive(Debug, Clone)]
pub struct Polynomial {
    coefficients: Vec<FieldElement>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<FieldElement>) -> Self {
        // Remove leading zeros
        let mut coeffs = coefficients;
        while coeffs.len() > 0 && coeffs.last().unwrap().value == 0 {
            coeffs.pop();
        }

        Self { coefficients: coeffs }
    }

    pub fn degree(&self) -> usize {
        if self.coefficients.len() <= 1 {
            // A polynomial of degree 0 is p(x) = a_0
            0
        } else {
            // A polynomial of degree n is p(x) = a_0+ a_1x^1 + a_2x^2 + ... + a_{n-1}x^{n-1}
            self.coefficients.len() - 1
        }
    }
}