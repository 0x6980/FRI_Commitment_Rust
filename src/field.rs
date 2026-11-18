
use std::ops::{
    Add,
    Sub,
    Mul,
    Div,
    Neg,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    pub value: u64,
    pub modulus: u64,
}

impl FieldElement {
    /// Creates a field element modulo p.
    ///
    /// IMPORTANT:
    /// This implementation assumes that modulus is prime.
    /// Primality is not checked here.
    pub fn new(value: u64, modulus: u64) -> Self {
        assert!(
            modulus > 1,
            "Modulus must be greater than 1"
        );

        Self {
            value: value % modulus,
            modulus,
        }
    }

    pub fn zero(modulus: u64) -> Self {
        Self::new(0, modulus)
    }

    pub fn one(modulus: u64) -> Self {
        Self::new(1, modulus)
    }

    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    /// Checks that two field elements belong to the same field.
    fn assert_same_field(&self, other: &Self) {
        assert_eq!(
            self.modulus,
            other.modulus,
            "Cannot operate on elements from different fields"
        );
    }

    /// Computes self^exponent using square-and-multiply.
    pub fn pow(self, mut exponent: u64) -> Self {
        let mut base = self;
        let mut result = Self::one(self.modulus);

        while exponent > 0 {
            if exponent % 2 == 1 {
                result = result * base;
            }

            base = base * base;
            exponent /= 2;
        }

        result
    }

    /// Computes the multiplicative inverse.
    ///
    /// Uses Fermat's little theorem:
    /// a^(-1) = a^(p - 2) mod p
    ///
    /// This is valid when p is prime and a != 0.
    pub fn inverse(self) -> Self {
        assert!(
            !self.is_zero(),
            "Zero has no multiplicative inverse"
        );

        self.pow(self.modulus - 2)
    }
}
// Implement the arithmetic operations
// Addition operation if additive group of field
impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let sum =
            (self.value as u128 + other.value as u128)
            % self.modulus as u128;

        Self::new(sum as u64, self.modulus)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let p = self.modulus as u128;
        let a = self.value as u128;
        let b = other.value as u128;

        let result = (a + p - b) % p;

        Self::new(result as u64, self.modulus)
    }
}

// Multiplication operation if multiplicative group of field
impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let product =
            (self.value as u128 * other.value as u128)
            % self.modulus as u128;

        Self::new(product as u64, self.modulus)
    }
}

impl Div for FieldElement {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self.assert_same_field(&other);

        self * other.inverse()
    }
}

impl Neg for FieldElement {
    type Output = Self;

    fn neg(self) -> Self {
        if self.is_zero() {
            return self;
        }

        Self::new(
            self.modulus - self.value,
            self.modulus,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 97;

    #[test]
    fn test_addition() {
        let a = FieldElement::new(80, P);
        let b = FieldElement::new(30, P);

        assert_eq!(a + b, FieldElement::new(13, P));
    }

    #[test]
    fn test_subtraction() {
        let a = FieldElement::new(10, P);
        let b = FieldElement::new(20, P);

        assert_eq!(a - b, FieldElement::new(87, P));
    }

    #[test]
    fn test_multiplication() {
        let a = FieldElement::new(20, P);
        let b = FieldElement::new(10, P);

        assert_eq!(a * b, FieldElement::new(6, P));
    }

    #[test]
    fn test_inverse() {
        let a = FieldElement::new(5, P);
        let inverse = a.inverse();

        assert_eq!(
            a * inverse,
            FieldElement::one(P)
        );

        assert_eq!(inverse, FieldElement::new(39, P));
    }

    #[test]
    fn test_division() {
        let a = FieldElement::new(20, P);
        let b = FieldElement::new(5, P);

        assert_eq!(
            a / b,
            FieldElement::new(4, P)
        );
    }

    #[test]
    fn test_negation() {
        let a = FieldElement::new(5, P);

        assert_eq!(
            -a,
            FieldElement::new(92, P)
        );
    }

    #[test]
    fn test_zero_and_one() {
        assert_eq!(
            FieldElement::zero(P).value,
            0
        );

        assert_eq!(
            FieldElement::one(P).value,
            1
        );
    }
}
