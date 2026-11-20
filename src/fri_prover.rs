use crate::field::FieldElement;
use crate::fri_layer::FriLayer;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluation_domain::EvaluationDomain;
    use crate::polynomial::Polynomial;

    const P: u64 = 97;

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
}
