use crate::evaluation_domain::EvaluationDomain;
use crate::field::FieldElement;
use crate::fri_layer::FriLayer;
use crate::merkle::{Hash, MerkleProof, MerkleTree};

#[derive(Clone, Debug)]
pub struct FriQueryProof {
    pub index: usize,

    pub value_x: FieldElement,
    pub value_minus_x: FieldElement,
    pub folded_value: FieldElement,

    pub proof_x: MerkleProof,
    pub proof_minus_x: MerkleProof,
    pub folded_proof: MerkleProof,
}

/// Creates a query proof for one position in two consecutive FRI layers.
///
/// The query index must belong to the first half of the original domain.
pub fn create_query_proof(
    current_layer: &FriLayer,
    next_layer: &FriLayer,
    index: usize,
) -> Option<FriQueryProof> {
    let n = current_layer.size();

    if n < 2 || n % 2 != 0 {
        return None;
    }

    if index >= n / 2 {
        return None;
    }

    if next_layer.size() != n / 2 {
        return None;
    }

    if current_layer.domain.modulus() != next_layer.domain.modulus() {
        return None;
    }

    let expected_generator = current_layer.domain.generator * current_layer.domain.generator;

    if next_layer.domain.generator != expected_generator {
        return None;
    }

    let opposite_index = index + n / 2;

    let value_x = current_layer.evaluation(index)?;
    let value_minus_x = current_layer.evaluation(opposite_index)?;

    let folded_value = next_layer.evaluation(index)?;

    let proof_x = current_layer.prove(index)?;
    let proof_minus_x = current_layer.prove(opposite_index)?;

    let folded_proof = next_layer.prove(index)?;

    Some(FriQueryProof {
        index,
        value_x,
        value_minus_x,
        folded_value,
        proof_x,
        proof_minus_x,
        folded_proof,
    })
}

/// Verifies one FRI query between two consecutive committed layers.
///
/// This checks Merkle authentication and local folding consistency.
/// It does NOT by itself establish the global low-degree property.
pub fn verify_query(
    domain: &EvaluationDomain,
    alpha: FieldElement,
    current_root: &Hash,
    next_root: &Hash,
    proof: &FriQueryProof,
) -> bool {
    let n = domain.size;

    if n < 2 || n % 2 != 0 {
        return false;
    }

    if proof.index >= n / 2 {
        return false;
    }

    let modulus = domain.modulus();

    if alpha.modulus != modulus
        || proof.value_x.modulus != modulus
        || proof.value_minus_x.modulus != modulus
        || proof.folded_value.modulus != modulus
    {
        return false;
    }

    let expected_opposite_index = proof.index + n / 2;

    // Bind each Merkle proof to the expected query position.
    if proof.proof_x.index != proof.index {
        return false;
    }

    if proof.proof_minus_x.index != expected_opposite_index {
        return false;
    }

    if proof.folded_proof.index != proof.index {
        return false;
    }

    // Bind the proofs to the expected layer sizes.
    if proof.proof_x.leaf_count != n
        || proof.proof_minus_x.leaf_count != n
        || proof.folded_proof.leaf_count != n / 2
    {
        return false;
    }

    // Authenticate the two original evaluations.
    if !MerkleTree::verify(proof.value_x, &proof.proof_x, current_root) {
        return false;
    }

    if !MerkleTree::verify(proof.value_minus_x, &proof.proof_minus_x, current_root) {
        return false;
    }

    // Authenticate the folded evaluation.
    if !MerkleTree::verify(proof.folded_value, &proof.folded_proof, next_root) {
        return false;
    }

    // Reconstruct x from the public domain and query index.
    // Do not trust a point supplied by the prover.
    let x = domain.generator.pow(proof.index as u64);

    if x.is_zero() {
        return false;
    }

    let two_inverse = FieldElement::new(2, modulus).inverse();

    // Compute:
    //
    // g(x^2) = (f(x) + f(-x))/2
    //        + alpha * (f(x) - f(-x))/(2x)

    let even_part = (proof.value_x + proof.value_minus_x) * two_inverse;

    let odd_part = (proof.value_x - proof.value_minus_x) * two_inverse * x.inverse();

    let expected_folded_value = even_part + alpha * odd_part;

    expected_folded_value == proof.folded_value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polynomial::Polynomial;

    const P: u64 = 97;
    const N: usize = 32;

    fn fe(value: u64) -> FieldElement {
        FieldElement::new(value, P)
    }

    fn initial_layer() -> FriLayer {
        let polynomial = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let domain = EvaluationDomain::new(fe(19), N);

        let evaluations: Vec<FieldElement> = domain
            .points()
            .iter()
            .map(|x| polynomial.evaluate(*x))
            .collect();

        FriLayer::new(domain, evaluations)
    }

    fn setup() -> (FriLayer, FriLayer, FriQueryProof, FieldElement) {
        let alpha = fe(7);

        let current_layer = initial_layer();
        let next_layer = current_layer.fold(alpha);

        let query_index = 5;

        let proof = create_query_proof(&current_layer, &next_layer, query_index).unwrap();

        (current_layer, next_layer, proof, alpha)
    }

    #[test]
    fn test_create_query_proof() {
        let (_, _, proof, _) = setup();

        assert_eq!(proof.index, 5);
        assert_eq!(proof.proof_x.index, 5);
        assert_eq!(proof.proof_minus_x.index, 21);
        assert_eq!(proof.folded_proof.index, 5);
    }

    #[test]
    fn test_valid_query_verification() {
        let (current, next, proof, alpha) = setup();

        assert!(verify_query(
            &current.domain,
            alpha,
            &current.root(),
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_wrong_challenge_is_rejected() {
        let (current, next, proof, _) = setup();

        let wrong_alpha = fe(11);

        assert!(!verify_query(
            &current.domain,
            wrong_alpha,
            &current.root(),
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_tampered_original_value_is_rejected() {
        let (current, next, mut proof, alpha) = setup();

        proof.value_x = proof.value_x + fe(1);

        assert!(!verify_query(
            &current.domain,
            alpha,
            &current.root(),
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_tampered_folded_value_is_rejected() {
        let (current, next, mut proof, alpha) = setup();

        proof.folded_value = proof.folded_value + fe(1);

        assert!(!verify_query(
            &current.domain,
            alpha,
            &current.root(),
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_wrong_current_root_is_rejected() {
        let (current, next, proof, alpha) = setup();

        let wrong_root = [0u8; 32];

        assert!(!verify_query(
            &current.domain,
            alpha,
            &wrong_root,
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_wrong_query_index_is_rejected() {
        let (current, next, mut proof, alpha) = setup();

        // The Merkle proofs still refer to the original indices.
        // Changing the claimed query index must not be accepted.
        proof.index = 6;

        assert!(!verify_query(
            &current.domain,
            alpha,
            &current.root(),
            &next.root(),
            &proof,
        ));
    }

    #[test]
    fn test_out_of_range_query_cannot_be_created() {
        let current = initial_layer();
        let next = current.fold(fe(7));

        assert!(create_query_proof(&current, &next, 16).is_none());
    }
}
