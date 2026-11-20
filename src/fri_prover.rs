use crate::field::FieldElement;
use crate::fri_layer::FriLayer;
use crate::fri_proof::{FriProof, FriQueryProof, FriRoundQueryProof};
use crate::transcript::Transcript;
/// Coordinates the educational FRI folding process.
///
/// For each round:
/// 1. The current layer commitment is already in the transcript.
/// 2. A challenge is derived.
/// 3. The current layer is folded.
/// 4. The next layer commitment is absorbed.
#[derive(Clone, Debug)]
pub struct FriProver {
    pub layers: Vec<FriLayer>,
    pub challenges: Vec<FieldElement>,
    transcript: Transcript,
}

impl FriProver {
    /// Runs the requested number of FRI folding rounds.
    ///
    /// The initial layer commitment is absorbed before the first challenge.
    pub fn run(initial_layer: FriLayer, rounds: usize) -> Self {
        let initial_size = initial_layer.size();

        assert!(
            initial_size.is_power_of_two(),
            "Initial layer size must be a power of two"
        );

        assert!(
            rounds <= initial_size.trailing_zeros() as usize,
            "Cannot fold more rounds than the domain allows"
        );

        let modulus = initial_layer.domain.modulus();

        let mut transcript = Transcript::new();

        // Absorb public protocol parameters.
        transcript.absorb(b"FRI_PROTOCOL_V1");

        transcript.absorb(&modulus.to_le_bytes());

        transcript.absorb(&(initial_size as u64).to_le_bytes());

        transcript.absorb(&initial_layer.domain.generator.value.to_le_bytes());

        // Crucial: commit to the initial layer before deriving alpha_0.
        Self::absorb_layer_commitment(&mut transcript, 0, &initial_layer);

        let mut layers = vec![initial_layer];
        let mut challenges = Vec::with_capacity(rounds);

        for round in 0..rounds {
            let current_layer = layers.last().unwrap();

            // Derive a fresh challenge from the current transcript.
            let label = format!("FRI_FOLD_CHALLENGE_ROUND_{}", round);

            let alpha = transcript.challenge(label.as_bytes(), modulus);

            challenges.push(alpha);

            // Fold only after the challenge has been derived.
            let next_layer = current_layer.fold(alpha);

            // Absorb the new commitment before the next round.
            Self::absorb_layer_commitment(&mut transcript, round + 1, &next_layer);

            layers.push(next_layer);
        }

        Self {
            layers,
            challenges,
            transcript,
        }
    }

    /// Adds a layer's metadata and Merkle root to the transcript.
    fn absorb_layer_commitment(transcript: &mut Transcript, layer_index: usize, layer: &FriLayer) {
        transcript.absorb(b"FRI_LAYER_COMMITMENT_V1");

        transcript.absorb(&(layer_index as u64).to_le_bytes());

        transcript.absorb(&(layer.size() as u64).to_le_bytes());

        transcript.absorb(&layer.domain.generator.value.to_le_bytes());

        transcript.absorb(&layer.root());
    }

    pub fn final_layer(&self) -> &FriLayer {
        self.layers.last().unwrap()
    }

    pub fn transcript_state(&self) -> [u8; 32] {
        self.transcript.state()
    }

    /// Samples query indices after all layer commitments have
    /// been absorbed into the transcript.
    ///
    /// Each initial query index belongs to the first half
    /// of the initial evaluation domain.
    pub fn sample_query_indices(&mut self, query_count: usize) -> Vec<usize> {
        let initial_size = self.layers[0].size();

        assert!(
            initial_size >= 2,
            "Initial domain must contain at least two elements"
        );

        let query_domain_size = initial_size / 2;

        let mut indices = Vec::with_capacity(query_count);

        for query_number in 0..query_count {
            let label = format!("FRI_QUERY_INDEX_{}", query_number);

            let index = self
                .transcript
                .challenge_index(label.as_bytes(), query_domain_size);

            indices.push(index);
        }

        indices
    }

    /// Builds a proof by opening the sampled positions in every layer.
    ///
    /// This educational version requires the folding process to end
    /// in a one-element final layer.
    pub fn build_proof(&mut self, query_count: usize) -> FriProof {
        assert_eq!(
            self.final_layer().size(),
            1,
            "Proof generation requires a one-element final layer"
        );

        let query_indices = self.sample_query_indices(query_count);

        let layer_roots: Vec<_> = self.layers.iter().map(|layer| layer.root()).collect();

        let final_layer = self.final_layer();

        let final_value = final_layer.evaluations[0];

        let final_evaluations = final_layer.evaluations.clone();

        let mut queries = Vec::with_capacity(query_count);

        for initial_index in query_indices {
            let mut round_proofs = Vec::with_capacity(self.challenges.len());

            for round in 0..self.challenges.len() {
                let current_layer = &self.layers[round];
                let next_layer = &self.layers[round + 1];

                let half_size = current_layer.size() / 2;

                // The representative index is reduced modulo
                // the first half of the current layer.
                let current_index = initial_index % half_size;

                let opposite_index = current_index + half_size;

                // The folded value is stored at current_index
                // in the next layer.
                let folded_index = current_index;

                let value_x = current_layer
                    .evaluation(current_index)
                    .expect("Query index out of range");

                let value_minus_x = current_layer
                    .evaluation(opposite_index)
                    .expect("Opposite query index out of range");

                let folded_value = next_layer
                    .evaluation(folded_index)
                    .expect("Folded query index out of range");

                let proof_x = current_layer
                    .prove(current_index)
                    .expect("Could not create Merkle proof for x");

                let proof_minus_x = current_layer
                    .prove(opposite_index)
                    .expect("Could not create Merkle proof for -x");

                let folded_proof = next_layer
                    .prove(folded_index)
                    .expect("Could not create Merkle proof for folded value");

                round_proofs.push(FriRoundQueryProof {
                    value_x,
                    value_minus_x,
                    folded_value,
                    proof_x,
                    proof_minus_x,
                    folded_proof,
                });
            }

            queries.push(FriQueryProof {
                index: initial_index,
                round_proofs,
            });
        }

        FriProof {
            layer_roots,
            final_value,
            final_evaluations,
            queries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation_domain::EvaluationDomain;
    use crate::polynomial::Polynomial;

    const P: u64 = 97;
    const QUERY_COUNT: usize = 5;

    fn fe(value: u64) -> FieldElement {
        FieldElement::new(value, P)
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
    fn test_run_one_round() {
        let prover = FriProver::run(initial_layer(), 1);

        assert_eq!(prover.layers.len(), 2);
        assert_eq!(prover.challenges.len(), 1);

        assert_eq!(prover.layers[0].size(), 32);
        assert_eq!(prover.layers[1].size(), 16);
    }

    #[test]
    fn test_run_multiple_rounds() {
        let prover = FriProver::run(initial_layer(), 5);

        let expected_sizes = [32, 16, 8, 4, 2, 1];

        assert_eq!(prover.layers.len(), expected_sizes.len());
        assert_eq!(prover.challenges.len(), 5);

        for (layer, expected_size) in prover.layers.iter().zip(expected_sizes) {
            assert_eq!(layer.size(), expected_size);
        }
    }

    #[test]
    fn test_each_round_uses_a_field_challenge() {
        let prover = FriProver::run(initial_layer(), 5);

        for alpha in &prover.challenges {
            assert_eq!(alpha.modulus, P);
            assert!(alpha.value < P);
        }
    }

    #[test]
    fn test_round_challenges_are_deterministic() {
        let first = FriProver::run(initial_layer(), 5);
        let second = FriProver::run(initial_layer(), 5);

        assert_eq!(first.challenges, second.challenges);
    }

    #[test]
    fn test_each_round_has_a_new_commitment() {
        let prover = FriProver::run(initial_layer(), 5);

        for pair in prover.layers.windows(2) {
            assert_ne!(pair[0].root(), pair[1].root());
        }
    }

    #[test]
    fn test_final_layer_has_size_one() {
        let prover = FriProver::run(initial_layer(), 5);

        assert_eq!(prover.final_layer().size(), 1);
    }

    #[test]
    fn test_zero_rounds_preserves_initial_layer() {
        let initial = initial_layer();
        let initial_root = initial.root();

        let prover = FriProver::run(initial, 0);

        assert_eq!(prover.layers.len(), 1);
        assert!(prover.challenges.is_empty());
        assert_eq!(prover.final_layer().root(), initial_root);
    }

    #[test]
    fn test_transcript_state_is_deterministic() {
        let first = FriProver::run(initial_layer(), 5);
        let second = FriProver::run(initial_layer(), 5);

        assert_eq!(first.transcript_state(), second.transcript_state());
    }

    #[test]
    fn test_query_indices_are_in_first_half() {
        let mut prover = FriProver::run(initial_layer(), 5);

        let indices = prover.sample_query_indices(20);

        assert_eq!(indices.len(), 20);

        for index in indices {
            assert!(index < 16);
        }
    }

    #[test]
    fn test_query_indices_are_deterministic() {
        let mut first = FriProver::run(initial_layer(), 5);
        let mut second = FriProver::run(initial_layer(), 5);

        let first_indices = first.sample_query_indices(10);
        let second_indices = second.sample_query_indices(10);

        assert_eq!(first_indices, second_indices);
    }

    #[test]
    fn test_query_sampling_advances_transcript() {
        let mut prover = FriProver::run(initial_layer(), 5);

        let initial_state = prover.transcript_state();

        prover.sample_query_indices(5);

        assert_ne!(prover.transcript_state(), initial_state);
    }

    #[test]
    fn test_zero_query_count_returns_empty_vector() {
        let mut prover = FriProver::run(initial_layer(), 5);

        let indices = prover.sample_query_indices(0);

        assert!(indices.is_empty());
    }

    #[test]
    fn test_query_indices_can_be_sampled_for_different_counts() {
        let mut first = FriProver::run(initial_layer(), 5);
        let mut second = FriProver::run(initial_layer(), 5);

        let first_indices = first.sample_query_indices(3);
        let second_indices = second.sample_query_indices(7);

        assert_eq!(first_indices.len(), 3);
        assert_eq!(second_indices.len(), 7);
    }

    #[test]
    fn test_build_proof_has_all_layer_roots() {
        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(4);

        assert_eq!(proof.layer_roots.len(), 6);
        assert_eq!(
            proof.final_value,
            prover.final_layer().evaluation(0).unwrap()
        );
    }

    #[test]
    fn test_build_proof_has_requested_query_count() {
        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(7);

        assert_eq!(proof.queries.len(), 7);
    }

    #[test]
    fn test_each_query_has_one_opening_per_round() {
        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(4);

        for query in &proof.queries {
            assert_eq!(query.round_proofs.len(), 5);
            assert!(query.index < 16);
        }
    }

    #[test]
    fn test_query_openings_verify_against_layer_roots() {
        use crate::merkle::MerkleTree;

        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(4);

        for query in &proof.queries {
            for (round, opening) in query.round_proofs.iter().enumerate() {
                assert!(MerkleTree::verify(
                    opening.value_x,
                    &opening.proof_x,
                    &proof.layer_roots[round],
                ));

                assert!(MerkleTree::verify(
                    opening.value_minus_x,
                    &opening.proof_minus_x,
                    &proof.layer_roots[round],
                ));

                assert!(MerkleTree::verify(
                    opening.folded_value,
                    &opening.folded_proof,
                    &proof.layer_roots[round + 1],
                ));
            }
        }
    }

    #[test]
    fn test_query_folded_values_match_fold_equation() {
        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(4);

        let two_inverse = fe(2).inverse();

        for query in &proof.queries {
            for (round, opening) in query.round_proofs.iter().enumerate() {
                let current_layer = &prover.layers[round];
                let half_size = current_layer.size() / 2;
                let current_index = query.index % half_size;

                let x = current_layer.domain.points()[current_index];

                let alpha = prover.challenges[round];

                let even_part = (opening.value_x + opening.value_minus_x) * two_inverse;

                let odd_part =
                    (opening.value_x - opening.value_minus_x) * two_inverse * x.inverse();

                let expected_folded = even_part + alpha * odd_part;

                assert_eq!(opening.folded_value, expected_folded);
            }
        }
    }

    #[test]
    fn test_final_value_is_authenticated_by_last_round() {
        use crate::merkle::MerkleTree;

        let mut prover = FriProver::run(initial_layer(), 5);
        let proof = prover.build_proof(3);

        let last_root = *proof.layer_roots.last().unwrap();

        for query in &proof.queries {
            let last_opening = query.round_proofs.last().unwrap();

            assert_eq!(last_opening.folded_value, proof.final_value);

            assert!(MerkleTree::verify(
                proof.final_value,
                &last_opening.folded_proof,
                &last_root,
            ));
        }
    }

    #[test]
    fn test_proof_contains_all_final_evaluations() {
        let mut prover = FriProver::run(initial_layer(), 5);

        let proof = prover.build_proof(QUERY_COUNT);

        assert_eq!(proof.final_evaluations.len(), 1);

        assert_eq!(proof.final_evaluations[0], proof.final_value);
    }
}
