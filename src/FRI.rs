use crate::field::FieldElement;
use crate::polynomial::Polynomial;
use crate::merkle::{ MerkleTree, FRIQueryProof, LayerQueryProof };
use rand::Rng;

pub struct FriProof {
    pub layer_roots: Vec<Hash>,
    pub final_value: FieldElement,
    pub queries: Vec<FriQueryProof>,
}

pub struct FriQueryProof {
    pub index: usize,
    pub round_proofs: Vec<FriRoundQueryProof>,
}

pub struct FriRoundQueryProof {
    pub value_x: FieldElement,
    pub value_minus_x: FieldElement,
    pub folded_value: FieldElement,

    pub proof_x: MerkleProof,
    pub proof_minus_x: MerkleProof,
    pub folded_proof: MerkleProof,
}

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
            domain: domain,
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

    pub fn generate_query_proof(
        &self,
        query_index: usize,
        all_evaluations: &[Vec<FieldElement>],
    ) -> FRIQueryProof {
        let mut layer_proofs = Vec::new();
        
        // Generate authentication path for each layer
        let mut current_index = query_index;
        let mut current_domain_size = self.domain.len();
        
        for (layer_index, evaluations) in all_evaluations.iter().enumerate() {
            if evaluations.len() <= 1 {
                break; // Reached constant layer
            }
            
            let layer_proof = self.generate_layer_query_proof(
                layer_index,
                current_index,
                evaluations,
                current_domain_size,
            );
            
            layer_proofs.push(layer_proof);
            
            // Move to next layer: square the index and halve domain
            current_index = (current_index * 2) % current_domain_size;
            current_domain_size /= 2;
        }
        
        let final_constant = self.get_final_constant(all_evaluations);
        
        FRIQueryProof {
            layer_proofs,
            final_constant,
        }
    }

    fn generate_layer_query_proof(
        &self,
        layer_index: usize,
        point_index: usize,
        evaluations: &[FieldElement],
        domain_size: usize,
    ) -> LayerQueryProof {
        // Get the opposite point and its value
        let opposite_index = (point_index + domain_size / 2) % domain_size;
        
        let merkle_proof = self.generate_merkle_proof(layer_index, point_index, evaluations);
        let opposite_merkle_proof = self.generate_merkle_proof(layer_index, opposite_index, evaluations);
        
        LayerQueryProof {
            layer_index,
            point: FieldElement::new(point_index as u64, self.modulus),
            value: evaluations[point_index],
            opposite_point: FieldElement::new(opposite_index as u64, self.modulus),
            opposite_value: evaluations[opposite_index],
            merkle_proof,
            opposite_merkle_proof,
        }
    }

    fn generate_merkle_proof(
        &self,
        layer_index: usize,
        index: usize,
        evaluations: &[FieldElement],
    ) -> MerkleProof {
        // In a real implementation, this would use the actual Merkle tree
        // For now, create a mock proof that includes necessary information
        
        let leaf_value = Self::hash_field_element(&evaluations[index]);
        
        // Generate sibling hashes for the proof
        let mut sibling_hashes = Vec::new();
        let mut current_index = index;
        let mut current_level_size = evaluations.len();
        
        while current_level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            // Handle case where sibling doesn't exist (odd level)
            let sibling_value = if sibling_index < evaluations.len() {
                evaluations[sibling_index]
            } else {
                evaluations[current_index] // Duplicate if odd
            };
            
            sibling_hashes.push(Self::hash_field_element(&sibling_value));
            
            current_index /= 2;
            current_level_size = (current_level_size + 1) / 2;
        }
        
        MerkleProof {
            leaf_index: index,
            leaf_value,
            sibling_hashes,
        }
    }
}


pub struct FRIVerifier {
    modulus: u64,
    committed_roots: Vec<Vec<u8>>,
    challenges: Vec<FieldElement>,
}

impl FRIVerifier {
    pub fn new(modulus: u64) -> Self {
        Self {
            modulus,
            committed_roots: Vec::new(),
            challenges: Vec::new(),
        }
    }

    pub fn query(&self, query_index: usize) -> FRIQueryProof {

        FRIQueryProof { 
            final_constant: FieldElement::new(0, self.modulus),
            layer_proofs: Vec::new(),
        }
    }
    
    pub fn verify_query(&self, query_index: usize, query_proof: &FRIQueryProof) -> bool {
        // Verify merkle proofs

        // Verify folding consistency
        true 
    }
}