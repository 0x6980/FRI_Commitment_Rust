
#[derive(Debug, CLone, Copy)]
pub struct FieldElement {
    value: u64,
    modulus: u64,
}

iml FieldElement {

    pub fn zero(modulus: u64) -> Self {
        Self { value: 0, modulus: modulus }
    }

    pub fn one(modulus: u64) -> Self {
        Self { value: 1, modulus: modulus }
    }

    pub fn new(value: u64, modulus: u64) -> Self {
        Self { value: value % modulus, modulus: modulus }
    }

    pub fn pow(&self, exponent: u64) -> Self {
        let mut result = Self::one(self.modulus);
        let mut base = *self;
        let mut exp = exponent;

        while exp > 0 {
            if exp % 2 == 1 {
                result = result * base;
            }

            base = base * base;
            exp /= 2;
        }
        result
    }

    // a^(-1) ≡ a^(p-2) mod p
    pub fn inverse(&self) -> Self {
        self.pow(self.modulus - 2)
    }
}

// Implement the arithmetic operations
// Addition operation if additive group of field
iml Add for FieldElement {
    pub fn add(&self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus);
        Self::new(self.value + other.value, self.modulus)
    }
}

// Multiplication operation if multiplicative group of field
iml Mul for FieldElement {
    pub fn mul(&self, other: Self) -> Self {
        assert_eq!(self.modulus, other.modulus);
        Self::new(self.value * other.value, self.modulus)
    }
}
