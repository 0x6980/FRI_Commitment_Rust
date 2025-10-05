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


pub struct FRIVerifier {
    modulus: u64,
    committed_roots: Vec<Vec<u8>>,
    challenges: Vec<FieldElement>,
}

// What is Merkle proof?
// For every leaf in the leaves there is path in mrkle tree, start from that leaf to merkle root.
// Consider the below mrkle tree. 
//        Root
//       /     \
//    H0123    H4567
//    /   \     /  \
//  H01  H23   H45  H67
// / \   / \   / \   / \
// 0  1  2  3 4   5 6  7  ← Leaves
//For leaf 2, the proof is:
// Sibling at level 0: Leaf 3 (H3)
// Sibling at level 1: Node H01
// Sibling at level 2: Node H4567
// Thus, the path is: H3-> H01-> H4567
// this the sibling hashes for leaf 2.
// We construct the below struct for represting this proof
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_value: [u8; 32], 
    pub sibling_hashes: Vec<[u8; 32]>,
}

// If the verifier choose `index` as query parameter then:
// In layer 0 the prover must prepare
// f_{odd}(w^{index}) + Merkle proof of that, and
// f_{odd}(-w^{index}) + Merkle proof of that
// In layer 1 the prover must prepare
// f_{odd}(w^{2(index)}) + Merkle proof of that, and
// f_{odd}(-w^{2(index)}) + Merkle proof of that
// In layer 2 the prover must prepare
// f_{odd}(w^{4(index)}) + Merkle proof of that, and
// f_{odd}(-w^{4(index)}) + Merkle proof of that
// and so on. Thus
// In each layer `j` of folding the prover should generate
// f_{odd}(w^{2^j(index)}) + Merkle proof, and
// f_{odd}(-w^(2^j{index)}) + Merkle proof, and

// and in last layer should send the constant `c`, no proof need.
// Thus FRI Query proof need a list of layer query proof and a constant for last layer
// We construct the below two struct as Query Proof.
pub struct LayerQueryProof {
    pub layer_index: usize,
    pub point: FieldElement,
    pub value: FieldElement,
    pub opposite_point: FieldElement, 
    pub opposite_value: FieldElement,
    pub merkle_proof: MerkleProof,
    pub opposite_merkle_proof: MerkleProof,
}

pub struct FRIQueryProof {
    pub layer_proofs: Vec<LayerQueryProof>,
    pub final_constant: FieldElement,
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