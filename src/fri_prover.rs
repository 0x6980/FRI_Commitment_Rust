use crate::field::{FieldElement, PrimeField};
use crate::fri_config::FriConfig;
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
    config: FriConfig,
    transcript: Transcript,
}

impl FriProver {
    /// Runs the requested number of FRI folding rounds.
    ///
    /// The initial layer commitment is absorbed before the first challenge.
    pub fn run(initial_layer: FriLayer, config: FriConfig) -> Self {
        let initial_size = initial_layer.size();

        config
            .final_degree_bound(initial_size)
            .expect("Invalid FRI configuration");

        let rounds = config
            .rounds(initial_size)
            .expect("Invalid FRI configuration");

        let field = initial_layer.domain.field();
        let modulus = field.modulus();
        let generator = initial_layer.domain.generator;

        let mut transcript = Transcript::new();

        // Protocol parameters
        transcript.absorb(b"FRI_PROTOCOL_V1");
        transcript.absorb(&modulus.to_le_bytes());
        transcript.absorb(&(initial_size as u64).to_le_bytes());
        transcript.absorb(&generator.value().to_le_bytes());

        // FRI configuration
        transcript.absorb(b"FRI_CONFIG_V1");
        transcript.absorb(&(config.degree_bound as u64).to_le_bytes());
        transcript.absorb(&(config.query_count as u64).to_le_bytes());
        transcript.absorb(&(config.final_domain_size as u64).to_le_bytes());

        let mut layers = vec![initial_layer];

        let mut challenges = Vec::with_capacity(rounds);

        Self::absorb_layer_commitment(&mut transcript, 0, &layers[0]);

        for round in 0..rounds {
            let label = format!("FRI_FOLD_CHALLENGE_ROUND_{}", round);

            let alpha = transcript.challenge(label.as_bytes(), field);

            challenges.push(alpha);

            let next_layer = layers.last().unwrap().fold(alpha);

            Self::absorb_layer_commitment(&mut transcript, round + 1, &next_layer);

            layers.push(next_layer);
        }

        Self {
            layers,
            challenges,
            config,
            transcript,
        }
    }

    /// Adds a layer's metadata and Merkle root to the transcript.
    fn absorb_layer_commitment(transcript: &mut Transcript, layer_index: usize, layer: &FriLayer) {
        transcript.absorb(b"FRI_LAYER_COMMITMENT_V1");

        transcript.absorb(&(layer_index as u64).to_le_bytes());

        transcript.absorb(&(layer.size() as u64).to_le_bytes());

        transcript.absorb(&layer.domain.generator.value().to_le_bytes());

        transcript.absorb(&layer.root());
    }

    pub fn final_layer(&self) -> &FriLayer {
        self.layers.last().unwrap()
    }

    pub fn transcript_state(&self) -> [u8; 32] {
        self.transcript.state()
    }
    /// Samples query indices using the provided transcript.
    ///
    /// Each initial query index belongs to the first half
    /// of the initial evaluation domain.
    fn sample_query_indices(
        transcript: &mut Transcript,
        initial_size: usize,
        query_count: usize,
    ) -> Vec<usize> {
        assert!(
            initial_size >= 2,
            "Initial domain must contain at least two elements"
        );

        let query_domain_size = initial_size / 2;

        let mut indices = Vec::with_capacity(query_count);

        for query_number in 0..query_count {
            let label = format!("FRI_QUERY_INDEX_{}", query_number);

            let index = transcript.challenge_index(label.as_bytes(), query_domain_size);

            indices.push(index);
        }

        indices
    }
    /// Builds a proof by opening the sampled positions in every layer.
    ///
    /// This educational version requires the folding process to end
    /// in a one-element final layer.
    pub fn build_proof(&self) -> FriProof {
        // Use a local transcript copy for query sampling.
        let mut query_transcript = self.transcript.clone();

        let query_indices = Self::sample_query_indices(
            &mut query_transcript,
            self.layers[0].size(),
            self.config.query_count,
        );

        let layer_roots: Vec<_> = self.layers.iter().map(|layer| layer.root()).collect();

        let final_layer = self.final_layer();

        let final_value = final_layer.evaluations[0];

        let final_evaluations = final_layer.evaluations.clone();

        let mut queries = Vec::with_capacity(query_indices.len());

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
        let field = PrimeField::new(P).unwrap();
        field.element(value)
    }

    fn test_config(final_domain_size: usize) -> FriConfig {
        FriConfig::new(
            5,           // degree_bound
            QUERY_COUNT, // query_count
            final_domain_size,
        )
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
        let config: FriConfig = FriConfig::new(5, 5, 8);

        let prover = FriProver::run(initial_layer(), test_config(16));

        assert_eq!(prover.layers.len(), 2);
        assert_eq!(prover.challenges.len(), 1);

        assert_eq!(prover.layers[0].size(), 32);
        assert_eq!(prover.layers[1].size(), 16);
    }

    #[test]
    fn test_run_multiple_rounds() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let expected_sizes = [32, 16, 8, 4, 2, 1];

        assert_eq!(prover.layers.len(), expected_sizes.len());
        assert_eq!(prover.challenges.len(), 5);

        for (layer, expected_size) in prover.layers.iter().zip(expected_sizes) {
            assert_eq!(layer.size(), expected_size);
        }
    }

    #[test]
    fn test_each_round_uses_a_field_challenge() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        for alpha in &prover.challenges {
            assert_eq!(alpha.modulus(), P);
            assert!(alpha.value() < P);
        }
    }

    #[test]
    fn test_round_challenges_are_deterministic() {
        let first = FriProver::run(initial_layer(), test_config(1));
        let second = FriProver::run(initial_layer(), test_config(1));

        assert_eq!(first.challenges, second.challenges);
    }

    #[test]
    fn test_each_round_has_a_new_commitment() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        for pair in prover.layers.windows(2) {
            assert_ne!(pair[0].root(), pair[1].root());
        }
    }

    #[test]
    fn test_final_layer_has_size_one() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        assert_eq!(prover.final_layer().size(), 1);
    }

    #[test]
    fn test_zero_rounds_preserves_initial_layer() {
        let initial = initial_layer();
        let initial_root = initial.root();

        let prover = FriProver::run(initial, test_config(32));

        assert_eq!(prover.layers.len(), 1);
        assert!(prover.challenges.is_empty());
        assert_eq!(prover.final_layer().root(), initial_root);
    }

    #[test]
    fn test_transcript_state_is_deterministic() {
        let first = FriProver::run(initial_layer(), test_config(1));
        let second = FriProver::run(initial_layer(), test_config(1));

        assert_eq!(first.transcript_state(), second.transcript_state());
    }

    #[test]
    fn test_query_indices_are_in_first_half() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let mut transcript = prover.transcript.clone();

        let indices = FriProver::sample_query_indices(&mut transcript, prover.layers[0].size(), 20);

        assert_eq!(indices.len(), 20);

        for index in indices {
            assert!(index < 16);
        }
    }

    #[test]
    fn test_query_indices_are_deterministic() {
        let first = FriProver::run(initial_layer(), test_config(1));
        let second = FriProver::run(initial_layer(), test_config(1));

        let mut first_transcript = first.transcript.clone();
        let mut second_transcript = second.transcript.clone();

        let first_indices =
            FriProver::sample_query_indices(&mut first_transcript, first.layers[0].size(), 10);

        let second_indices =
            FriProver::sample_query_indices(&mut second_transcript, second.layers[0].size(), 10);

        assert_eq!(first_indices, second_indices);
    }

    #[test]
    fn test_query_sampling_does_not_modify_prover_transcript() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let initial_state = prover.transcript_state();

        let mut query_transcript = prover.transcript.clone();

        FriProver::sample_query_indices(&mut query_transcript, prover.layers[0].size(), 5);

        assert_ne!(query_transcript.state(), initial_state);

        assert_eq!(prover.transcript_state(), initial_state);
    }

    #[test]
    fn test_zero_query_count_returns_empty_vector() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let mut transcript = prover.transcript.clone();

        let indices = FriProver::sample_query_indices(&mut transcript, prover.layers[0].size(), 0);

        assert!(indices.is_empty());
    }

    #[test]
    fn test_query_indices_can_be_sampled_for_different_counts() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let mut first_transcript = prover.transcript.clone();
        let mut second_transcript = prover.transcript.clone();

        let first_indices =
            FriProver::sample_query_indices(&mut first_transcript, prover.layers[0].size(), 3);

        let second_indices =
            FriProver::sample_query_indices(&mut second_transcript, prover.layers[0].size(), 7);

        assert_eq!(first_indices.len(), 3);
        assert_eq!(second_indices.len(), 7);
    }

    #[test]
    fn test_build_proof_is_deterministic_and_does_not_modify_transcript() {
        let prover = FriProver::run(initial_layer(), test_config(1));

        let initial_state = prover.transcript_state();

        let first_proof = prover.build_proof();
        let second_proof = prover.build_proof();

        let first_indices: Vec<usize> = first_proof
            .queries
            .iter()
            .map(|query| query.index)
            .collect();

        let second_indices: Vec<usize> = second_proof
            .queries
            .iter()
            .map(|query| query.index)
            .collect();

        assert_eq!(first_indices, second_indices);

        assert_eq!(first_proof.layer_roots, second_proof.layer_roots);

        assert_eq!(prover.transcript_state(), initial_state);
    }

    #[test]
    fn test_build_proof_has_all_layer_roots() {
        let mut prover = FriProver::run(initial_layer(), test_config(1));
        let proof = prover.build_proof();

        assert_eq!(proof.layer_roots.len(), 6);
        assert_eq!(
            proof.final_value,
            prover.final_layer().evaluation(0).unwrap()
        );
    }

    #[test]
    fn test_build_proof_uses_configured_query_count() {
        let config = FriConfig::new(5, 7, 1);

        let mut prover = FriProver::run(initial_layer(), config);

        let proof = prover.build_proof();

        assert_eq!(proof.queries.len(), 7);
    }

    #[test]
    fn test_each_query_has_one_opening_per_round() {
        let mut prover = FriProver::run(initial_layer(), test_config(1));
        let proof = prover.build_proof();

        for query in &proof.queries {
            assert_eq!(query.round_proofs.len(), 5);
            assert!(query.index < 16);
        }
    }

    #[test]
    fn test_query_openings_verify_against_layer_roots() {
        use crate::merkle::MerkleTree;

        let mut prover = FriProver::run(initial_layer(), test_config(1));
        let proof = prover.build_proof();

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
        let mut prover = FriProver::run(initial_layer(), test_config(1));
        let proof = prover.build_proof();

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

        let mut prover = FriProver::run(initial_layer(), test_config(1));
        let proof = prover.build_proof();

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
        let mut prover = FriProver::run(initial_layer(), test_config(1));

        let proof = prover.build_proof();

        assert_eq!(proof.final_evaluations.len(), 1);

        assert_eq!(proof.final_evaluations[0], proof.final_value);
    }

    #[test]
    fn test_prover_stops_at_configured_final_domain_size() {
        let config = FriConfig::new(5, 5, 8);

        let prover = FriProver::run(initial_layer(), config);

        assert_eq!(prover.layers.len(), 3);
        assert_eq!(prover.challenges.len(), 2);

        assert_eq!(prover.layers[0].size(), 32);
        assert_eq!(prover.layers[1].size(), 16);
        assert_eq!(prover.layers[2].size(), 8);

        assert_eq!(prover.final_layer().size(), 8);
    }

    #[test]
    fn test_final_degree_bound_after_two_rounds() {
        let config = FriConfig::new(5, 5, 8);

        let final_degree = config.final_degree_bound(32).unwrap();

        assert_eq!(final_degree, 1);
    }

    #[test]
    fn test_build_proof_contains_all_final_evaluations() {
        let config = FriConfig::new(5, 5, 8);

        let mut prover = FriProver::run(initial_layer(), config);

        let proof = prover.build_proof();

        assert_eq!(proof.final_evaluations.len(), 8);

        assert_eq!(proof.final_value, proof.final_evaluations[0]);
    }

    #[test]
    fn test_final_evaluations_match_committed_root() {
        use crate::merkle::MerkleTree;

        let config = FriConfig::new(5, 5, 8);

        let mut prover = FriProver::run(initial_layer(), config);

        let proof = prover.build_proof();

        let final_evaluations = proof.final_evaluations.clone();

        let reconstructed_tree = MerkleTree::new(&final_evaluations);

        let reconstructed_root = reconstructed_tree.root();

        let committed_root = *proof.layer_roots.last().unwrap();

        assert_eq!(reconstructed_root, committed_root);
    }

    #[test]
    fn test_final_layer_size_matches_config() {
        let config = FriConfig::new(5, 5, 8);

        let mut prover = FriProver::run(initial_layer(), config);

        let proof = prover.build_proof();

        assert_eq!(proof.final_evaluations.len(), prover.final_layer().size());

        assert_eq!(proof.final_evaluations.len(), 8);
    }

    #[test]
    fn test_transcript_depends_on_fri_config() {
        let config_a = FriConfig::new(5, 5, 8);
        let config_b = FriConfig::new(5, 6, 8);

        let prover_a = FriProver::run(initial_layer(), config_a);
        let prover_b = FriProver::run(initial_layer(), config_b);

        assert_ne!(prover_a.transcript_state(), prover_b.transcript_state());
    }
}
