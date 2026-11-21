use crate::field::{FieldElement, PrimeField};
use sha2::{Digest, Sha256};

/// A SHA-256 digest.
pub type Hash = [u8; 32];

/// A Merkle authentication path for one leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Index of the leaf in the original vector.
    pub index: usize,

    /// Number of leaves in the original Merkle tree.
    pub leaf_count: usize,

    /// Sibling hashes, ordered from leaf level to root level.
    pub siblings: Vec<Hash>,
}

/// A binary Merkle tree.
///
/// levels[0] contains the leaf hashes.
/// levels[1] contains the hashes of pairs of leaves.
/// ...
/// The last level contains exactly one hash: the root.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Constructs a Merkle tree from field elements.
    ///
    /// Requirements:
    /// - The input must not be empty.
    /// - The number of leaves must be a power of two.
    /// - All elements must belong to the same field.
    pub fn new(values: &[FieldElement]) -> Self {
        assert!(!values.is_empty(), "Merkle tree cannot be empty");

        assert!(
            values.len().is_power_of_two(),
            "Number of leaves must be a power of two"
        );

        let modulus = values[0].modulus();

        for value in values {
            assert_eq!(
                value.modulus(),
                modulus,
                "All leaves must belong to the same field"
            );
        }

        // Level 0: hash every leaf.
        let leaf_hashes: Vec<Hash> = values.iter().map(hash_leaf).collect();

        let mut levels = vec![leaf_hashes];

        // Build parent levels until only one hash remains.
        while levels.last().unwrap().len() > 1 {
            let current_level = levels.last().unwrap();

            let mut next_level = Vec::with_capacity(current_level.len() / 2);

            for pair in current_level.chunks_exact(2) {
                let parent_hash = hash_node(&pair[0], &pair[1]);

                next_level.push(parent_hash);
            }

            levels.push(next_level);
        }

        Self { levels }
    }

    /// Returns the Merkle root.
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .expect("Merkle tree must have at least one level")[0]
    }

    /// Returns the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Generates a Merkle proof for the leaf at `index`.
    ///
    /// Returns None if the index is out of range.
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaf_count() {
            return None;
        }

        let mut current_index = index;
        let mut siblings = Vec::new();

        // The root level does not have a sibling.
        for level in self.levels.iter().take(self.levels.len() - 1) {
            // The sibling of an even index is index + 1.
            // The sibling of an odd index is index - 1.
            let sibling_index = current_index ^ 1;

            siblings.push(level[sibling_index]);

            // Move to the parent index.
            current_index /= 2;
        }

        Some(MerkleProof {
            index,
            leaf_count: self.leaf_count(),
            siblings,
        })
    }

    /// Verifies a Merkle proof against a trusted root.
    ///
    /// Returns true if the proof is valid.
    pub fn verify(value: FieldElement, proof: &MerkleProof, expected_root: &Hash) -> bool {
        // Reject invalid tree sizes.
        if proof.leaf_count == 0 || !proof.leaf_count.is_power_of_two() {
            return false;
        }

        // Reject an out-of-range leaf index.
        if proof.index >= proof.leaf_count {
            return false;
        }

        // A binary tree with N leaves has log2(N) sibling hashes.
        let expected_depth = proof.leaf_count.trailing_zeros() as usize;

        if proof.siblings.len() != expected_depth {
            return false;
        }

        let mut current_hash = hash_leaf(&value);
        let mut current_index = proof.index;

        for sibling_hash in &proof.siblings {
            if current_index % 2 == 0 {
                // Current node is the left child.
                current_hash = hash_node(&current_hash, sibling_hash);
            } else {
                // Current node is the right child.
                current_hash = hash_node(sibling_hash, &current_hash);
            }

            // Move from the current node to its parent.
            current_index /= 2;
        }

        current_hash == *expected_root
    }
}

/// Hashes a field element as a Merkle leaf.
///
/// Encoding:
/// SHA256(0x00 || modulus || value)
///
/// Both integers are encoded as fixed-width little-endian u64 values.
fn hash_leaf(value: &FieldElement) -> Hash {
    let mut hasher = Sha256::new();

    // Domain separation: 0x00 identifies a leaf.
    hasher.update([0x00]);

    hasher.update(value.modulus().to_le_bytes());
    hasher.update(value.value().to_le_bytes());

    hasher.finalize().into()
}
fn hash_leaf(value: &FieldElement) -> Hash {
    let mut hasher = Sha256::new();

    // Domain separation: 0x00 identifies a leaf.
    hasher.update([0x00]);

    hasher.update(value.modulus().to_le_bytes());
    hasher.update(value.value().to_le_bytes());

    hasher.finalize().into()
}
/// Hashes an internal Merkle node.
///
/// Encoding:
/// SHA256(0x01 || left || right)
fn hash_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();

    // Domain separation: 0x01 identifies an internal node.
    hasher.update([0x01]);

    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 97;

    fn fe(value: u64) -> FieldElement {
        let field = PrimeField::new(P).unwrap();
        field.element(value)
    }

    fn test_values(count: usize) -> Vec<FieldElement> {
        (0..count).map(|i| fe(i as u64 + 1)).collect()
    }

    #[test]
    fn test_tree_with_eight_leaves() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);

        assert_eq!(tree.leaf_count(), 8);
        assert_eq!(tree.levels.len(), 4);

        assert_eq!(tree.levels[0].len(), 8);
        assert_eq!(tree.levels[1].len(), 4);
        assert_eq!(tree.levels[2].len(), 2);
        assert_eq!(tree.levels[3].len(), 1);
    }

    #[test]
    fn test_tree_with_thirty_two_leaves() {
        let values = test_values(32);

        let tree = MerkleTree::new(&values);

        assert_eq!(tree.leaf_count(), 32);
        assert_eq!(tree.levels.len(), 6);

        assert_eq!(tree.levels[0].len(), 32);
        assert_eq!(tree.levels[1].len(), 16);
        assert_eq!(tree.levels[2].len(), 8);
        assert_eq!(tree.levels[3].len(), 4);
        assert_eq!(tree.levels[4].len(), 2);
        assert_eq!(tree.levels[5].len(), 1);
    }

    #[test]
    fn test_proof_length() {
        let values = test_values(32);

        let tree = MerkleTree::new(&values);

        let proof = tree.prove(5).unwrap();

        assert_eq!(proof.siblings.len(), 5);
        assert_eq!(proof.leaf_count, 32);
    }

    #[test]
    fn test_verify_all_leaves() {
        let values = test_values(32);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        for (index, value) in values.iter().enumerate() {
            let proof = tree.prove(index).unwrap();

            assert!(
                MerkleTree::verify(*value, &proof, &root),
                "Proof verification failed for index {}",
                index
            );
        }
    }

    #[test]
    fn test_reject_modified_value() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let proof = tree.prove(5).unwrap();

        // The original value at index 5 is 6.
        // We try to verify a different value.
        let modified_value = fe(99);

        assert!(!MerkleTree::verify(modified_value, &proof, &root));
    }

    #[test]
    fn test_reject_modified_sibling() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let mut proof = tree.prove(5).unwrap();

        // Modify one sibling hash.
        proof.siblings[0] = hash_leaf(&fe(123));

        assert!(!MerkleTree::verify(values[5], &proof, &root));
    }

    #[test]
    fn test_reject_wrong_root() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);

        let proof = tree.prove(3).unwrap();

        let wrong_root = hash_leaf(&fe(123));

        assert!(!MerkleTree::verify(values[3], &proof, &wrong_root));
    }

    #[test]
    fn test_reject_invalid_index() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);

        assert!(tree.prove(8).is_none());
    }

    #[test]
    fn test_reject_incomplete_proof() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let mut proof = tree.prove(5).unwrap();

        // Remove one sibling.
        proof.siblings.pop();

        assert!(!MerkleTree::verify(values[5], &proof, &root));
    }

    #[test]
    fn test_reject_overlong_proof() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let mut proof = tree.prove(5).unwrap();

        proof.siblings.push(hash_leaf(&fe(123)));

        assert!(!MerkleTree::verify(values[5], &proof, &root));
    }

    #[test]
    fn test_reject_out_of_range_proof_index() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let mut proof = tree.prove(5).unwrap();

        proof.index = 8;

        assert!(!MerkleTree::verify(values[5], &proof, &root));
    }

    #[test]
    fn test_merkle_query_on_real_fri_evaluations() {
        use crate::evaluation_domain::EvaluationDomain;
        use crate::polynomial::Polynomial;

        const P: u64 = 97;
        const N: usize = 32;

        let field = PrimeField::new(P).unwrap();

        let fe = |value| field.element(value);

        // f(X) = 3 + 2X + 5X^2 + 4X^3 + 7X^4 + 6X^5
        let f = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        // Construct the multiplicative subgroup of size 32.
        let domain = EvaluationDomain::new(fe(19), N);

        // Evaluate f over the entire domain.
        let evaluations: Vec<FieldElement> =
            domain.points().iter().map(|x| f.evaluate(*x)).collect();

        assert_eq!(evaluations.len(), N);

        // Commit to the evaluation vector.
        let tree = MerkleTree::new(&evaluations);
        let root = tree.root();

        // The verifier queries index 5.
        let query_index = 5;

        // Its opposite point is located at index 5 + 16 = 21.
        let opposite_index = query_index + N / 2;

        // The prover generates both authentication paths.
        let proof_x = tree.prove(query_index).unwrap();
        let proof_minus_x = tree.prove(opposite_index).unwrap();

        // The verifier checks f(x).
        assert!(MerkleTree::verify(
            evaluations[query_index],
            &proof_x,
            &root
        ));

        // The verifier checks f(-x).
        assert!(MerkleTree::verify(
            evaluations[opposite_index],
            &proof_minus_x,
            &root
        ));

        // Check the opposite-point relationship in the domain.
        let points = domain.points();

        assert_eq!(points[opposite_index], -points[query_index]);

        // Now perform one FRI folding step.
        let alpha = fe(7);

        let (_, folded_evaluations) = domain.fold_evaluations(&evaluations, alpha);

        // The verifier can independently compute the folded
        // value associated with this query.
        let x = points[query_index];

        let two_inverse = fe(2).inverse();

        let fx = evaluations[query_index];
        let f_minus_x = evaluations[opposite_index];

        let even_part = (fx + f_minus_x) * two_inverse;

        let odd_part = (fx - f_minus_x) * two_inverse * x.inverse();

        let folded_value = even_part + alpha * odd_part;

        // It must match the corresponding entry in the
        // folded evaluation vector.
        assert_eq!(folded_value, folded_evaluations[query_index]);
    }

    #[test]
    fn test_reject_modified_in_range_index() {
        let values = test_values(8);

        let tree = MerkleTree::new(&values);
        let root = tree.root();

        let mut proof = tree.prove(2).unwrap();

        proof.index = 3;

        assert!(!MerkleTree::verify(values[2], &proof, &root));
    }
}
