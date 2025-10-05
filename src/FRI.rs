use crate::field::FieldElement;
use crate::polynomial::Polynomial;
use crate::merkle::MerkleTree;
use rand::Rng;

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

    pub fn commit(&self) -> (Vec<[u8; 32]>, Vec<Vec<FieldElement>>) { // outputs (all roots, all evaluations)
        let mut commitments:Vec<[u8; 32]> = Vec::new();
        let mut all_evaluations = Vec::new();

        let mut current_poly = self.original_poly.clone(); // because in each folding round the polynomial will change
        let mut current_domain = self.domain.clone(); // because in each folding the domain will halve

        while current_poly.degree() > 0 {
            // Evaluate polynomail over current domain
            let evaluations: Vec<FieldElement> = current_domain.iter()
                .map(|&x| current_poly.evaluate(x))
                .collect();

            // Build Merkle tree for evaluations
            let tree = MerkleTree::new(&evaluations);
            let root = tree.get_root();


            commitments.push(*root);
            all_evaluations.push(evaluations);

            if current_poly.degree() > 1 {
                // Get challenge from verifier
                let mut rng = rand::rng();
                let r: u64 = rng.gen_range(0..self.modulus);
                let alpha = FieldElement::new(r, self.modulus);

                // Fold the current polynomial and generate new polynomial
                current_poly = current_poly.fold(alpha);
                
                // Halve the domain
                current_domain = current_domain.iter()
                    .map(|&x| x * x)
                    .collect();
            } else {
                break;
            }
        }

        (commitments, all_evaluations)
    }
}