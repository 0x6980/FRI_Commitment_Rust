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

    pub fn evaluate(&self, x: FieldElement) -> FieldElement {
        let mut result = FieldElement::zero(x.modulus);
        for &coeff in self.coefficients.iter().rev() {
            result = result * x + coeff;
        }

        result
    }

    pub fn fold(&self, alpha: FieldElement) -> Polynomial {
        // even_poly = a_nx^n+ ... a_1x+a_0
        // odd_poly = b_nx^n+ ... b_1x+b_0
        let (even_poly, odd_poly) = self.split_even_odd();
        
        // f'(x) = even(x) + alpha * odd(x)
        let mut new_coeffs = Vec::new();
        let max_len = even_poly.coefficients.len().max(odd_poly.coefficients.len());
        
        for i in 0..max_len {
            // a_i
            let even_val = even_poly.coefficients.get(i)
                .copied()
                .unwrap_or(FieldElement::zero(alpha.modulus));

            // b_i
            let odd_val = odd_poly.coefficients.get(i)
                .copied()
                .unwrap_or(FieldElement::zero(alpha.modulus));
            
            new_coeffs.push(even_val + alpha * odd_val);
        }
        
        Polynomial::new(new_coeffs)
    }

    pub fn split_even_odd(&self) -> (Polynomial, Polynomial) {
        let mut even_coeffs = Vec::new();
        let mut odd_coeffs = Vec::new();
        
        for (i, &coeff) in self.coefficients.iter().enumerate() {
            if i % 2 == 0 {
                even_coeffs.push(coeff);
            } else {
                odd_coeffs.push(coeff);
            }
        }
        
        (Polynomial::new(even_coeffs), Polynomial::new(odd_coeffs))
    }
}