use crate::evaluation_domain::EvaluationDomain;
use crate::field::FieldElement;
use crate::fri_proof::FriProof;
use crate::merkle::MerkleTree;
use crate::transcript::Transcript;

/// Verifies an educational FRI proof.
///
/// The verifier does not access the prover's internal evaluation layers.
pub struct FriVerifier;

impl FriVerifier {
    /// Verifies a proof using the public initial evaluation domain
    /// and the expected number of queries.
    pub fn verify(
        proof: &FriProof,
        initial_domain: &EvaluationDomain,
        expected_query_count: usize,
    ) -> bool {
        let initial_size = initial_domain.size;
        let modulus = initial_domain.modulus();
        let generator = initial_domain.generator;

        // This implementation requires a power-of-two domain
        // with at least two elements.
        if initial_size < 2 || !initial_size.is_power_of_two() {
            return false;
        }

        // A nonempty query set is required.
        if expected_query_count == 0 {
            return false;
        }

        if proof.queries.len() != expected_query_count {
            return false;
        }

        // Validate the initial subgroup generator.
        if generator.pow(initial_size as u64) != FieldElement::one(modulus) {
            return false;
        }

        if generator.pow((initial_size / 2) as u64) != -FieldElement::one(modulus) {
            return false;
        }

        // This educational version folds until the domain
        // contains exactly one element.
        let rounds = initial_size.trailing_zeros() as usize;

        if proof.layer_roots.len() != rounds + 1 {
            return false;
        }

        if proof.final_value.modulus != modulus {
            return false;
        }

        // Reconstruct the Fiat-Shamir transcript.
        let mut transcript = Transcript::new();

        transcript.absorb(b"FRI_PROTOCOL_V1");
        transcript.absorb(&modulus.to_le_bytes());
        transcript.absorb(&(initial_size as u64).to_le_bytes());
        transcript.absorb(&generator.value.to_le_bytes());

        let mut challenges = Vec::with_capacity(rounds);

        let mut current_size = initial_size;
        let mut current_generator = generator;

        // Absorb the initial commitment before deriving alpha_0.
        Self::absorb_layer_commitment(
            &mut transcript,
            0,
            current_size,
            current_generator,
            &proof.layer_roots[0],
        );

        for round in 0..rounds {
            let label = format!("FRI_FOLD_CHALLENGE_ROUND_{}", round);

            let alpha = transcript.challenge(label.as_bytes(), modulus);

            challenges.push(alpha);

            current_size /= 2;
            current_generator = current_generator * current_generator;

            // Absorb the next layer commitment after deriving
            // the challenge and folding.
            Self::absorb_layer_commitment(
                &mut transcript,
                round + 1,
                current_size,
                current_generator,
                &proof.layer_roots[round + 1],
            );
        }

        // Derive query indices only after all layer roots
        // have been absorbed.
        let query_domain_size = initial_size / 2;

        let mut expected_indices = Vec::with_capacity(expected_query_count);

        for query_number in 0..expected_query_count {
            let label = format!("FRI_QUERY_INDEX_{}", query_number);

            let index = transcript.challenge_index(label.as_bytes(), query_domain_size);

            expected_indices.push(index);
        }

        let two_inverse = FieldElement::new(2, modulus).inverse();

        // Verify every query.
        for (query, expected_index) in proof.queries.iter().zip(expected_indices.iter()) {
            if query.index != *expected_index {
                return false;
            }

            if query.round_proofs.len() != rounds {
                return false;
            }

            for round in 0..rounds {
                let opening = &query.round_proofs[round];

                let half_size = initial_size >> (round + 1);

                let expected_current_index = expected_index % half_size;

                let expected_opposite_index = expected_current_index + half_size;

                // The next layer stores the folded value
                // at the representative index.
                let expected_folded_index = expected_current_index;

                let current_layer_size = initial_size >> round;

                let next_layer_size = current_layer_size / 2;

                // Check field consistency.
                if opening.value_x.modulus != modulus
                    || opening.value_minus_x.modulus != modulus
                    || opening.folded_value.modulus != modulus
                {
                    return false;
                }

                // Bind each Merkle proof to the expected position.
                if opening.proof_x.index != expected_current_index
                    || opening.proof_minus_x.index != expected_opposite_index
                    || opening.folded_proof.index != expected_folded_index
                {
                    return false;
                }

                if opening.proof_x.leaf_count != current_layer_size
                    || opening.proof_minus_x.leaf_count != current_layer_size
                    || opening.folded_proof.leaf_count != next_layer_size
                {
                    return false;
                }

                // Authenticate f(x) against the current layer root.
                if !MerkleTree::verify(opening.value_x, &opening.proof_x, &proof.layer_roots[round])
                {
                    return false;
                }

                // Authenticate f(-x) against the current layer root.
                if !MerkleTree::verify(
                    opening.value_minus_x,
                    &opening.proof_minus_x,
                    &proof.layer_roots[round],
                ) {
                    return false;
                }

                // Authenticate the folded value against the next root.
                if !MerkleTree::verify(
                    opening.folded_value,
                    &opening.folded_proof,
                    &proof.layer_roots[round + 1],
                ) {
                    return false;
                }

                // Compute x independently from the public domain.
                let round_generator = generator.pow(1u64 << round);

                let x = round_generator.pow(expected_current_index as u64);

                // Verify the FRI folding equation.
                let even_part = (opening.value_x + opening.value_minus_x) * two_inverse;

                let odd_part =
                    (opening.value_x - opening.value_minus_x) * two_inverse * x.inverse();

                let expected_folded_value = even_part + challenges[round] * odd_part;

                if opening.folded_value != expected_folded_value {
                    return false;
                }

                // The last folded value must equal the
                // publicly supplied final value.
                if round + 1 == rounds && opening.folded_value != proof.final_value {
                    return false;
                }
            }
        }

        true
    }

    /// Reproduces the exact layer-commitment encoding used by FriProver.
    fn absorb_layer_commitment(
        transcript: &mut Transcript,
        layer_index: usize,
        layer_size: usize,
        generator: FieldElement,
        root: &[u8; 32],
    ) {
        transcript.absorb(b"FRI_LAYER_COMMITMENT_V1");

        transcript.absorb(&(layer_index as u64).to_le_bytes());

        transcript.absorb(&(layer_size as u64).to_le_bytes());

        transcript.absorb(&generator.value.to_le_bytes());

        transcript.absorb(root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation_domain::EvaluationDomain;
    use crate::field::FieldElement;
    use crate::fri_layer::FriLayer;
    use crate::fri_prover::FriProver;
    use crate::polynomial::Polynomial;

    const P: u64 = 97;
    const QUERY_COUNT: usize = 5;

    fn fe(value: u64) -> FieldElement {
        FieldElement::new(value, P)
    }

    fn initial_domain() -> EvaluationDomain {
        EvaluationDomain::new(fe(19), 32)
    }

    fn initial_layer() -> FriLayer {
        let polynomial = Polynomial::new(vec![fe(3), fe(2), fe(5), fe(4), fe(7), fe(6)]);

        let domain = initial_domain();

        let evaluations: Vec<FieldElement> = domain
            .points()
            .iter()
            .map(|x| polynomial.evaluate(*x))
            .collect();

        FriLayer::new(domain, evaluations)
    }

    fn valid_proof() -> FriProof {
        let mut prover = FriProver::run(initial_layer(), 5);
        prover.build_proof(QUERY_COUNT)
    }

    #[test]
    fn test_valid_proof_is_accepted() {
        let proof = valid_proof();
        let domain = initial_domain();

        assert!(FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_wrong_query_count_is_rejected() {
        let proof = valid_proof();
        let domain = initial_domain();

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT + 1,));
    }

    #[test]
    fn test_modified_query_index_is_rejected() {
        let mut proof = valid_proof();
        let domain = initial_domain();

        proof.queries[0].index = (proof.queries[0].index + 1) % 16;

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_modified_evaluation_is_rejected() {
        let mut proof = valid_proof();
        let domain = initial_domain();

        proof.queries[0].round_proofs[0].value_x = fe(42);

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_modified_merkle_root_is_rejected() {
        let mut proof = valid_proof();
        let domain = initial_domain();

        proof.layer_roots[0][0] ^= 1;

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_modified_final_value_is_rejected() {
        let mut proof = valid_proof();
        let domain = initial_domain();

        proof.final_value = fe(42);

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_modified_merkle_sibling_is_rejected() {
        let mut proof = valid_proof();
        let domain = initial_domain();

        proof.queries[0].round_proofs[0].proof_x.siblings[0][0] ^= 1;

        assert!(!FriVerifier::verify(&proof, &domain, QUERY_COUNT,));
    }

    #[test]
    fn test_final_layer_opening_has_empty_merkle_path() {
        let proof = valid_proof();

        let last_round = proof.queries[0].round_proofs.last().unwrap();

        assert_eq!(last_round.folded_proof.leaf_count, 1);

        assert!(last_round.folded_proof.siblings.is_empty());
    }
}
