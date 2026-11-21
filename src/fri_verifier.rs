use crate::evaluation_domain::EvaluationDomain;
use crate::field::{FieldElement, PrimeField};
use crate::fri_config::FriConfig;
use crate::fri_proof::FriProof;
use crate::merkle::MerkleTree;
use crate::polynomial::Polynomial;
use crate::transcript::Transcript;

/// Verifies an educational FRI proof.
///
/// The verifier does not access the prover's internal evaluation layers.
pub struct FriVerifier;

impl FriVerifier {
    /// Verifies a proof using the public initial domain and FRI configuration.
    pub fn verify(
        proof: &FriProof,
        initial_domain: &EvaluationDomain,
        expected_initial_root: &[u8; 32],
        config: &FriConfig,
    ) -> bool {
        let initial_size = initial_domain.size;
        let field = initial_domain.field();
        let generator = initial_domain.generator;

        // Validate the initial domain.
        if initial_size < 2 || !initial_size.is_power_of_two() {
            return false;
        }

        if generator.pow(initial_size as u64) != generator.field().one() {
            return false;
        }

        if generator.pow((initial_size / 2) as u64) != -generator.field().one() {
            return false;
        }

        // Determine the number of rounds from the public configuration.
        let rounds = match config.rounds(initial_size) {
            Ok(rounds) => rounds,
            Err(_) => return false,
        };

        match config.final_degree_bound(initial_size) {
            Ok(bound) => bound,
            Err(_) => return false,
        };

        if proof.queries.len() != config.query_count {
            return false;
        }

        if proof.layer_roots.len() != rounds + 1 {
            return false;
        }

        if &proof.layer_roots[0] != expected_initial_root {
            return false;
        }

        // Validate the final evaluation vector.
        if proof.final_evaluations.len() != config.final_domain_size {
            return false;
        }

        if proof
            .final_evaluations
            .iter()
            .any(|value| value.modulus() != field.modulus())
        {
            return false;
        }

        // Keep the compatibility field consistent with the final vector.
        if proof.final_evaluations.first() != Some(&proof.final_value) {
            return false;
        }

        // Reconstruct the final Merkle commitment from all final evaluations.
        let final_tree = MerkleTree::new(&proof.final_evaluations.clone());

        if final_tree.root() != proof.layer_roots[rounds] {
            return false;
        }

        // Verify the degree bound of the final polynomial.
        if !Self::verify_final_degree(&proof.final_evaluations, initial_domain, config) {
            return false;
        }

        // Reconstruct the Fiat-Shamir transcript.
        let mut transcript = Transcript::new();

        transcript.absorb(b"FRI_PROTOCOL_V1");
        transcript.absorb(&field.modulus().to_le_bytes());
        transcript.absorb(&(initial_size as u64).to_le_bytes());
        transcript.absorb(&generator.value().to_le_bytes());

        // FRI configuration
        transcript.absorb(b"FRI_CONFIG_V1");
        transcript.absorb(&(config.degree_bound as u64).to_le_bytes());
        transcript.absorb(&(config.query_count as u64).to_le_bytes());
        transcript.absorb(&(config.final_domain_size as u64).to_le_bytes());

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

            let alpha = transcript.challenge(label.as_bytes(), field);

            challenges.push(alpha);

            current_size /= 2;
            current_generator = current_generator * current_generator;

            // Absorb the next commitment after deriving the challenge.
            Self::absorb_layer_commitment(
                &mut transcript,
                round + 1,
                current_size,
                current_generator,
                &proof.layer_roots[round + 1],
            );
        }

        // Derive query indices after all commitments have been absorbed.
        let query_domain_size = initial_size / 2;

        let mut expected_indices = Vec::with_capacity(config.query_count);

        for query_number in 0..config.query_count {
            let label = format!("FRI_QUERY_INDEX_{}", query_number);

            let index = transcript.challenge_index(label.as_bytes(), query_domain_size);

            expected_indices.push(index);
        }

        let two_inverse = field.element(2).inverse();

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
                let expected_folded_index = expected_current_index;

                let current_layer_size = initial_size >> round;
                let next_layer_size = current_layer_size / 2;

                // Check field consistency.
                if opening.value_x.modulus() != field.modulus()
                    || opening.value_minus_x.modulus() != field.modulus()
                    || opening.folded_value.modulus() != field.modulus()
                {
                    return false;
                }

                // Check the positions authenticated by Merkle proofs.
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

                // Authenticate f(x).
                if !MerkleTree::verify(opening.value_x, &opening.proof_x, &proof.layer_roots[round])
                {
                    return false;
                }

                // Authenticate f(-x).
                if !MerkleTree::verify(
                    opening.value_minus_x,
                    &opening.proof_minus_x,
                    &proof.layer_roots[round],
                ) {
                    return false;
                }

                // Authenticate the folded value.
                if !MerkleTree::verify(
                    opening.folded_value,
                    &opening.folded_proof,
                    &proof.layer_roots[round + 1],
                ) {
                    return false;
                }

                // Compute x independently from the public domain.
                let exponent = match 1u64.checked_shl(round as u32) {
                    Some(value) => value,
                    None => return false,
                };

                let round_generator = generator.pow(exponent);
                let x = round_generator.pow(expected_current_index as u64);

                // Verify the FRI folding equation.
                let even_part = (opening.value_x + opening.value_minus_x) * two_inverse;

                let odd_part =
                    (opening.value_x - opening.value_minus_x) * two_inverse * x.inverse();

                let expected_folded_value = even_part + challenges[round] * odd_part;

                if opening.folded_value != expected_folded_value {
                    return false;
                }

                // Explicitly link this round to the next round.
                if round + 1 < rounds {
                    let next_opening = &query.round_proofs[round + 1];

                    let next_half_size = initial_size >> (round + 2);

                    let next_current_index = expected_index % next_half_size;
                    let next_opposite_index = next_current_index + next_half_size;

                    let linked_value = if expected_folded_index == next_current_index {
                        next_opening.value_x
                    } else if expected_folded_index == next_opposite_index {
                        next_opening.value_minus_x
                    } else {
                        return false;
                    };

                    if opening.folded_value != linked_value {
                        return false;
                    }
                }

                // On the final round, check the exact final evaluation.
                if round + 1 == rounds {
                    if opening.folded_value != proof.final_evaluations[expected_folded_index] {
                        return false;
                    }
                }
            }
        }

        // The proof passed all checks.

        true
    }

    /// Reproduces the layer-commitment encoding used by the prover.
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
        transcript.absorb(&generator.value().to_le_bytes());
        transcript.absorb(root);
    }

    /// Checks whether the final evaluation vector represents
    /// a polynomial within the configured degree bound.
    fn verify_final_degree(
        final_evaluations: &[FieldElement],
        initial_domain: &EvaluationDomain,
        config: &FriConfig,
    ) -> bool {
        let initial_size = initial_domain.size;

        let rounds = match config.rounds(initial_size) {
            Ok(rounds) => rounds,
            Err(_) => return false,
        };

        if final_evaluations.len() != config.final_domain_size {
            return false;
        }

        let modulus = initial_domain.modulus();

        if final_evaluations
            .iter()
            .any(|value| value.modulus() != modulus)
        {
            return false;
        }

        // The final domain generator is omega^(2^rounds).
        let exponent = match 1u64.checked_shl(rounds as u32) {
            Some(value) => value,
            None => return false,
        };

        let final_generator = initial_domain.generator.pow(exponent);

        let final_domain = EvaluationDomain::new(final_generator, config.final_domain_size);

        let domain_points = final_domain.points();

        let interpolation_points: Vec<(FieldElement, FieldElement)> = domain_points
            .into_iter()
            .zip(final_evaluations.iter().copied())
            .collect();

        let final_polynomial = Polynomial::interpolate(&interpolation_points);

        let degree_bound = match config.final_degree_bound(initial_size) {
            Ok(bound) => bound,
            Err(_) => return false,
        };

        // Coefficients are stored in ascending order.
        final_polynomial
            .coefficients
            .iter()
            .skip(degree_bound + 1)
            .all(|coefficient| coefficient.is_zero())
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
        let field = PrimeField::new(P).unwrap();
        field.element(value)
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

    fn test_config() -> FriConfig {
        FriConfig::new(
            5, // initial degree bound
            QUERY_COUNT,
            8, // final domain size
        )
    }

    fn valid_proof() -> FriProof {
        let mut prover = FriProver::run(initial_layer(), test_config());

        prover.build_proof()
    }

    #[test]
    fn test_valid_proof_is_accepted() {
        let proof = valid_proof();
        let expected_root = initial_layer().root();

        assert!(FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_wrong_query_count_is_rejected() {
        let proof = valid_proof();

        let config = FriConfig::new(5, QUERY_COUNT + 1, 8);

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &config
        ));
    }

    #[test]
    fn test_modified_query_index_is_rejected() {
        let mut proof = valid_proof();

        proof.queries[0].index = (proof.queries[0].index + 1) % 16;

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_modified_evaluation_is_rejected() {
        let mut proof = valid_proof();

        proof.queries[0].round_proofs[0].value_x = fe(42);

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_modified_merkle_root_is_rejected() {
        let mut proof = valid_proof();

        proof.layer_roots[0][0] ^= 1;

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_modified_final_value_is_rejected() {
        let mut proof = valid_proof();

        proof.final_value = fe(42);

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_modified_final_evaluation_is_rejected() {
        let mut proof = valid_proof();

        proof.final_evaluations[0] = proof.final_evaluations[0] + fe(1);

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_modified_merkle_sibling_is_rejected() {
        let mut proof = valid_proof();

        proof.queries[0].round_proofs[0].proof_x.siblings[0][0] ^= 1;

        let expected_root = initial_layer().root();

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &expected_root,
            &test_config()
        ));
    }

    #[test]
    fn test_final_layer_opening_has_correct_merkle_path() {
        let proof = valid_proof();

        let last_round = proof.queries[0].round_proofs.last().unwrap();

        assert_eq!(last_round.folded_proof.leaf_count, 8);
        assert_eq!(last_round.folded_proof.siblings.len(), 3);
    }

    #[test]
    fn test_verify_final_degree_accepts_valid_linear_polynomial() {
        let domain = initial_domain();
        let config = test_config();

        let final_generator = fe(19).pow(4);

        let final_domain = EvaluationDomain::new(final_generator, 8);

        // g(X) = 7 + 3X
        let final_evaluations: Vec<FieldElement> = final_domain
            .points()
            .iter()
            .map(|x| fe(7) + fe(3) * *x)
            .collect();

        assert!(FriVerifier::verify_final_degree(
            &final_evaluations,
            &domain,
            &config,
        ));
    }

    #[test]
    fn test_verify_final_degree_rejects_quadratic_polynomial() {
        let domain = initial_domain();
        let config = test_config();

        let final_generator = fe(19).pow(4);

        let final_domain = EvaluationDomain::new(final_generator, 8);

        // g(X) = 7 + 3X + 2X^2
        let final_evaluations: Vec<FieldElement> = final_domain
            .points()
            .iter()
            .map(|x| fe(7) + fe(3) * *x + fe(2) * *x * *x)
            .collect();

        assert!(!FriVerifier::verify_final_degree(
            &final_evaluations,
            &domain,
            &config,
        ));
    }

    #[test]
    fn test_wrong_initial_commitment_is_rejected() {
        let proof = valid_proof();

        let mut wrong_root = initial_layer().root();
        wrong_root[0] ^= 1;

        assert!(!FriVerifier::verify(
            &proof,
            &initial_domain(),
            &wrong_root,
            &test_config(),
        ));
    }
}
