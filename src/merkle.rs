
use sha2::{Sha256, Digest};
use crate::field::FieldElement;


pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    layers: Vec<[u8; 32]>,
}

impl MerkleTree {
    
    pub fn new(elements: &[FieldElement]) -> Self {
        let leaves: Vec<[u8; 32]> = elements.iter()
            .map(|elem| Self::hash_field_element(elem))
            .collect();
        t 
        let root = Self::build_tree(&leaves);
        Self { leaves, root }
    }
    
    fn hash_field_element(elem: &FieldElement) -> [u8; 32] {
        let mut hasher = Sha256::new();
        
        // Encode both value and modulus for safety
        hasher.update(&elem.value.to_le_bytes());
        hasher.update(&elem.modulus.to_le_bytes());
        
        hasher.finalize().into()
    }

    pub fn build_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(&chunk[0]);
            
            if chunk.len() == 2 {
                hasher.update(&chunk[1]);
            } else {
                // For odd trees, duplicate the last element
                hasher.update(&chunk[0]);
            }
            
            next_level.push(hasher.finalize().into());
        }

        Self::build_tree(&next_level)
    }

    pub fn get_root(&self) -> &[u8; 32] {
        &self.root
    }

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

