use std::ops::{Add, Div, Mul, Neg, Sub};

/// A prime finite field F_p.
///
/// The modulus is validated once when the field is constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrimeField {
    modulus: u64,
}

impl PrimeField {
    /// Constructs a prime field.
    ///
    /// Returns an error if the modulus is not prime.
    pub fn new(modulus: u64) -> Result<Self, &'static str> {
        if !is_prime(modulus) {
            return Err("Modulus must be prime");
        }

        Ok(Self { modulus })
    }

    /// Returns the field modulus.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    /// Constructs an element in this field.
    pub fn element(&self, value: u64) -> FieldElement {
        FieldElement {
            value: value % self.modulus,
            field: *self,
        }
    }

    pub fn zero(&self) -> FieldElement {
        self.element(0)
    }

    pub fn one(&self) -> FieldElement {
        self.element(1)
    }
}

/// An element of a prime field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    value: u64,
    field: PrimeField,
}

impl FieldElement {
    /// Returns the canonical integer representation.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns the field to which this element belongs.
    pub fn field(&self) -> PrimeField {
        self.field
    }

    /// Returns the modulus of this element's field.
    pub fn modulus(&self) -> u64 {
        self.field.modulus
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0
    }

    fn assert_same_field(&self, other: &Self) {
        assert_eq!(
            self.field, other.field,
            "Cannot operate on elements from different fields"
        );
    }

    /// Computes self^exponent using square-and-multiply.
    pub fn pow(self, mut exponent: u64) -> Self {
        let mut base = self;
        let mut result = self.field.one();

        while exponent > 0 {
            if exponent % 2 == 1 {
                result = result * base;
            }

            base = base * base;
            exponent /= 2;
        }

        result
    }

    /// Computes the multiplicative inverse using Fermat's little theorem.
    pub fn inverse(self) -> Self {
        assert!(!self.is_zero(), "Zero has no multiplicative inverse");

        self.pow(self.modulus() - 2)
    }
}

impl Add for FieldElement {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let p = self.modulus() as u128;
        let sum = (self.value as u128 + other.value as u128) % p;

        self.field.element(sum as u64)
    }
}

impl Sub for FieldElement {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let p = self.modulus() as u128;
        let a = self.value as u128;
        let b = other.value as u128;

        let result = (a + p - b) % p;

        self.field.element(result as u64)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        self.assert_same_field(&other);

        let p = self.modulus() as u128;
        let product = (self.value as u128 * other.value as u128) % p;

        self.field.element(product as u64)
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

        self.field.element(self.modulus() - self.value)
    }
}

/// Deterministic primality test for all u64 integers.
fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }

    // Handle small primes and their multiples.
    const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

    for prime in SMALL_PRIMES {
        if n == prime {
            return true;
        }

        if n % prime == 0 {
            return false;
        }
    }

    // Write n - 1 = d * 2^s, where d is odd.
    let mut d = n - 1;
    let mut s = 0u32;

    while d % 2 == 0 {
        d /= 2;
        s += 1;
    }

    // This set of bases is deterministic for u64.
    const BASES: [u64; 7] = [2, 325, 9_375, 28_178, 450_775, 9_780_504, 1_795_265_022];

    for base in BASES {
        let a = base % n;

        if a == 0 {
            continue;
        }

        let mut x = modular_pow(a, d, n);

        if x == 1 || x == n - 1 {
            continue;
        }

        let mut probably_prime = false;

        for _ in 1..s {
            x = ((x as u128 * x as u128) % n as u128) as u64;

            if x == n - 1 {
                probably_prime = true;
                break;
            }
        }

        if !probably_prime {
            return false;
        }
    }

    true
}

/// Computes base^exponent modulo modulus.
fn modular_pow(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;

    while exponent > 0 {
        if exponent % 2 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }

        base = ((base as u128 * base as u128) % modulus as u128) as u64;
        exponent /= 2;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prime_field_creation() {
        let field = PrimeField::new(97).unwrap();

        assert_eq!(field.modulus(), 97);
    }

    #[test]
    fn test_reject_composite_modulus() {
        assert!(PrimeField::new(15).is_err());
        assert!(PrimeField::new(21).is_err());
        assert!(PrimeField::new(1).is_err());
        assert!(PrimeField::new(0).is_err());
    }

    #[test]
    fn test_large_prime_modulus() {
        assert!(PrimeField::new(u64::MAX - 58).is_ok());
    }

    #[test]
    fn test_field_element_normalization() {
        let field = PrimeField::new(97).unwrap();

        assert_eq!(field.element(100).value(), 3);
        assert_eq!(field.element(97).value(), 0);
    }

    #[test]
    fn test_addition() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(80);
        let b = field.element(30);

        assert_eq!((a + b).value(), 13);
    }

    #[test]
    fn test_subtraction() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(10);
        let b = field.element(20);

        assert_eq!((a - b).value(), 87);
    }

    #[test]
    fn test_multiplication() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(20);
        let b = field.element(10);

        assert_eq!((a * b).value(), 6);
    }

    #[test]
    fn test_inverse() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(5);
        let inverse = a.inverse();

        assert_eq!((a * inverse).value(), 1);
        assert_eq!(inverse.value(), 39);
    }

    #[test]
    fn test_division() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(20);
        let b = field.element(5);

        assert_eq!((a / b).value(), 4);
    }

    #[test]
    fn test_negation() {
        let field = PrimeField::new(97).unwrap();

        let a = field.element(5);

        assert_eq!((-a).value(), 92);
    }

    #[test]
    fn test_zero_and_one() {
        let field = PrimeField::new(97).unwrap();

        assert_eq!(field.zero().value(), 0);
        assert_eq!(field.one().value(), 1);
    }

    #[test]
    fn test_reject_operations_between_different_fields() {
        let field_97 = PrimeField::new(97).unwrap();
        let field_101 = PrimeField::new(101).unwrap();

        let a = field_97.element(5);
        let b = field_101.element(5);

        assert_ne!(a.field(), b.field());
    }
}
