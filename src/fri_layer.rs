use crate::evaluation_domain::EvaluationDomain;
use crate::field::{FieldElement, PrimeField};
use crate::merkle::{Hash, MerkleProof, MerkleTree};

#[derive(Clone, Debug)]
pub struct FriLayer {
    domain: EvaluationDomain,
    evaluations: Vec<FieldElement>,
    merkle_tree: MerkleTree,
}

impl FriLayer {
    /// Creates a FRI layer from an evaluation vector.
    ///
    /// The vector must contain exactly one evaluation
    /// for each point in the domain.
    pub fn new(domain: EvaluationDomain, evaluations: Vec<FieldElement>) -> Self {
        assert_eq!(
            evaluations.len(),
            domain.size,
            "Evaluation count must match domain size"
        );

        for value in &evaluations {
            assert_eq!(
                value.modulus(),
                domain.modulus(),
                "Evaluation belongs to a different field"
            );
        }

        let merkle_tree = MerkleTree::new(&evaluations);

        Self {
            domain,
            evaluations,
            merkle_tree,
        }
    }

    /// Returns a reference to the evaluation domain.
    pub fn domain(&self) -> &EvaluationDomain {
        &self.domain
    }

    /// Returns all evaluations in this layer.
    pub fn evaluations(&self) -> &[FieldElement] {
        &self.evaluations
    }

    /// Returns the Merkle root of this layer.
    pub fn root(&self) -> Hash {
        self.merkle_tree.root()
    }

    /// Returns the number of evaluations.
    pub fn size(&self) -> usize {
        self.evaluations.len()
    }

    /// Returns the evaluation at a given index.
    pub fn evaluation(&self, index: usize) -> Option<FieldElement> {
        self.evaluations.get(index).copied()
    }

    /// Generates a Merkle proof for an evaluation.
    pub fn prove(&self, index: usize) -> Option<MerkleProof> {
        self.merkle_tree.prove(index)
    }

    /// Constructs the next FRI layer by folding this layer.
    ///
    /// The challenge alpha must be selected independently
    /// after this layer's commitment has been fixed.
    pub fn fold(&self, alpha: FieldElement) -> Self {
        assert_eq!(
            alpha.modulus(),
            self.domain.modulus(),
            "Folding challenge belongs to a different field"
        );

        let (next_domain, next_evaluations) =
            self.domain.fold_evaluations(&self.evaluations, alpha);

        FriLayer::new(next_domain, next_evaluations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::polynomial::Polynomial;

    const P: u64 = 97;

    fn fe(value: u64) -> FieldElement {
        let field = PrimeField::new(P).unwrap();
        field.element(value)
    }

    fn initial_layer() -> FriLayer {
        let polynomial = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let domain = EvaluationDomain::new(fe(19), 32);

        let evaluations: Vec<FieldElement> = domain
            .points()
            .iter()
            .map(|x| polynomial.evaluate(*x))
            .collect();

        FriLayer::new(domain, evaluations)
    }

    #[test]
    fn test_layer_construction() {
        let layer = initial_layer();

        assert_eq!(layer.size(), 32);
        assert_eq!(layer.domain.size, 32);
    }

    #[test]
    fn test_layer_has_merkle_root() {
        let layer = initial_layer();

        let root = layer.root();

        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_layer_evaluation_access() {
        let layer = initial_layer();

        assert_eq!(layer.evaluation(5), Some(layer.evaluations[5]));

        assert_eq!(layer.evaluation(32), None);
    }

    #[test]
    fn test_layer_generates_valid_merkle_proof() {
        let layer = initial_layer();

        let index = 5;

        let proof = layer.prove(index).unwrap();

        assert!(MerkleTree::verify(
            layer.evaluations[index],
            &proof,
            &layer.root()
        ));
    }

    #[test]
    fn test_layer_folding() {
        let layer = initial_layer();

        let alpha = fe(7);

        let next_layer = layer.fold(alpha);

        assert_eq!(layer.size(), 32);
        assert_eq!(next_layer.size(), 16);

        assert_eq!(
            next_layer.domain.generator,
            layer.domain.generator * layer.domain.generator
        );
    }

    #[test]
    fn test_next_layer_has_its_own_commitment() {
        let layer = initial_layer();

        let next_layer = layer.fold(fe(7));

        assert_ne!(layer.root(), next_layer.root());

        assert_eq!(next_layer.merkle_tree.leaf_count(), 16);
    }

    #[test]
    fn test_multiple_layer_folding() {
        let mut layer = initial_layer();

        let challenges = [fe(7), fe(11), fe(13), fe(17), fe(19)];

        let expected_sizes = [16, 8, 4, 2, 1];

        for (challenge, expected_size) in challenges.iter().zip(expected_sizes.iter()) {
            layer = layer.fold(*challenge);

            assert_eq!(layer.size(), *expected_size);

            assert_eq!(layer.domain.size, *expected_size);
        }
    }

    #[test]
    #[should_panic(expected = "Folding challenge belongs to a different field")]
    fn test_fold_rejects_challenge_from_different_field() {
        let layer = initial_layer();

        let other_field = PrimeField::new(101).unwrap();
        let alpha = other_field.element(7);

        layer.fold(alpha);
    }
}
