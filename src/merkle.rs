
use sha2::{Sha256, Digest};
use crate::field::FieldElement;


pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl MerkleTree {
    
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

    pub fn get_root(&self) -> &[u8] {
        &self.root
    }
}

pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_value: [u8; 32],
    pub sibling_hashes: Vec<[u8; 32]>,
}

impl MerkleProof {
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut current_hash = self.leaf_value;
        
        for sibling in &self.sibling_hashes {
            let mut hasher = Sha256::new();
            
            // Always hash in consistent order (left then right)
            if self.leaf_index % 2 == 0 {
                hasher.update(&current_hash);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current_hash);
            }
            
            current_hash = hasher.finalize().into();
        }
        
        &current_hash == root
    }
}