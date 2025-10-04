
pub struct FRIProver {
    modulus: u64,
    original_poly: Polynomial,
    domain: Vec<FieldElement>,
}


impl FRIProver {
    pub fn new(poly: Polynomial, modulus: u64) -> Self {
        let domain_size = poly.degree() + 1;
        let domain = Self::generate_domain(domain_size, modulus);

        Self {
            modulus: modulus,
            original_poly: poly,
            domain: domain
        }
    }

    fn generate_domain(size: usize, modulus: u64)-> Vec<FieldElement> {
        (0..size).map(|i| FieldElement::new(i as u64, modulus)).collect()
    }

    pub fn commit(&self) -> (Vec<Vec<u8>>, Vec<Vec<FieldElement>>) { // outputs (all roots, all evaluations)
        let mut commitments = Vec::new();
        let mut all_evaluations = Vec::new();

        let mut current_poly = self.original_poly.clone(); // because in each folding round the polynomial will change
        let mut current_domain =self.domain.clone(); // because in each folding the domain will halve

        while current_poly.degree() > 0 {
            // Evaluate polynomail over current domain

            // Build Merkle tree for evaluations

            // Get challenge from verifier

            // Halve the Domain and fold the current polynomial
        }

        (commitments, all_evaluations)
    }
}