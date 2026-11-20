use crate::field::FieldElement;
use sha2::{Digest, Sha256};

/// A simple hash-chain transcript for the educational FRI implementation.
///
/// This is not intended to be a production-ready Fiat-Shamir implementation.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: [u8; 32],
}

impl Transcript {
    /// Creates a new transcript with a domain-separated initial state.
    pub fn new() -> Self {
        let initial_state = Sha256::digest(b"FRI_TRANSCRIPT_INITIAL_STATE_V1");

        let mut state = [0u8; 32];
        state.copy_from_slice(&initial_state);

        Self { state }
    }

    /// Adds a byte message to the transcript.
    ///
    /// Length-prefixing makes the message encoding unambiguous.
    pub fn absorb(&mut self, message: &[u8]) {
        let mut hasher = Sha256::new();

        hasher.update(b"FRI_TRANSCRIPT_ABSORB_V1");
        hasher.update(self.state);
        hasher.update((message.len() as u64).to_le_bytes());
        hasher.update(message);

        let digest = hasher.finalize();
        self.state.copy_from_slice(&digest);
    }

    /// Derives a field challenge using rejection sampling.
    ///
    /// The challenge is derived from the current transcript state
    /// and the supplied label.
    ///
    /// After deriving it, the challenge is absorbed into the transcript.
    pub fn challenge(&mut self, label: &[u8], modulus: u64) -> FieldElement {
        assert!(modulus > 1, "Modulus must be greater than 1");

        let range = 1u128 << 64;
        let limit = range - (range % modulus as u128);

        let mut counter = 0u64;

        let value = loop {
            let mut hasher = Sha256::new();

            hasher.update(b"FRI_TRANSCRIPT_CHALLENGE_V1");
            hasher.update(self.state);
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label);
            hasher.update(counter.to_le_bytes());

            let digest = hasher.finalize();

            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);

            let candidate = u64::from_le_bytes(bytes) as u128;

            if candidate < limit {
                break (candidate % modulus as u128) as u64;
            }

            counter = counter
                .checked_add(1)
                .expect("Challenge rejection counter overflow");
        };

        // Absorb the derived challenge so the transcript state advances.
        let mut encoded_challenge = Vec::new();

        encoded_challenge.extend_from_slice(b"FRI_TRANSCRIPT_CHALLENGE_RESULT_V1");

        encoded_challenge.extend_from_slice(&(label.len() as u64).to_le_bytes());

        encoded_challenge.extend_from_slice(label);
        encoded_challenge.extend_from_slice(&modulus.to_le_bytes());
        encoded_challenge.extend_from_slice(&value.to_le_bytes());

        self.absorb(&encoded_challenge);

        FieldElement::new(value, modulus)
    }

    /// Returns the current transcript state.
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// Derives a uniformly distributed index in [0, upper_bound).
    ///
    /// The result is derived from the current transcript state.
    /// After deriving the index, the result is absorbed into the transcript.
    pub fn challenge_index(&mut self, label: &[u8], upper_bound: usize) -> usize {
        assert!(upper_bound > 0, "Upper bound must be greater than zero");

        let bound = upper_bound as u128;
        let range = 1u128 << 64;
        let limit = range - (range % bound);

        let mut counter = 0u64;

        let index = loop {
            let mut hasher = Sha256::new();

            hasher.update(b"FRI_TRANSCRIPT_INDEX_CHALLENGE_V1");
            hasher.update(self.state);
            hasher.update((label.len() as u64).to_le_bytes());
            hasher.update(label);
            hasher.update(counter.to_le_bytes());

            let digest = hasher.finalize();

            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&digest[..8]);

            let candidate = u64::from_le_bytes(bytes) as u128;

            if candidate < limit {
                break (candidate % bound) as usize;
            }

            counter = counter
                .checked_add(1)
                .expect("Index rejection counter overflow");
        };

        let mut encoded_result = Vec::new();

        encoded_result.extend_from_slice(b"FRI_TRANSCRIPT_INDEX_RESULT_V1");

        encoded_result.extend_from_slice(&(label.len() as u64).to_le_bytes());

        encoded_result.extend_from_slice(label);
        encoded_result.extend_from_slice(&(upper_bound as u64).to_le_bytes());
        encoded_result.extend_from_slice(&(index as u64).to_le_bytes());

        self.absorb(&encoded_result);

        index
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u64 = 97;

    #[test]
    fn test_new_transcripts_have_same_initial_state() {
        let first = Transcript::new();
        let second = Transcript::new();

        assert_eq!(first.state(), second.state());
    }

    #[test]
    fn test_absorb_changes_transcript_state() {
        let mut transcript = Transcript::new();
        let initial_state = transcript.state();

        transcript.absorb(b"merkle-root");

        assert_ne!(transcript.state(), initial_state);
    }

    #[test]
    fn test_same_transcript_produces_same_challenge() {
        let mut first = Transcript::new();
        let mut second = Transcript::new();

        first.absorb(b"root-0");
        second.absorb(b"root-0");

        let alpha_first = first.challenge(b"alpha-0", P);
        let alpha_second = second.challenge(b"alpha-0", P);

        assert_eq!(alpha_first, alpha_second);
    }

    #[test]
    fn test_challenge_belongs_to_field() {
        let mut transcript = Transcript::new();

        let alpha = transcript.challenge(b"alpha-0", P);

        assert_eq!(alpha.modulus, P);
        assert!(alpha.value < P);
    }

    #[test]
    fn test_different_labels_produce_different_challenges() {
        let mut first = Transcript::new();
        let mut second = Transcript::new();

        first.absorb(b"root-0");
        second.absorb(b"root-0");

        let alpha = first.challenge(b"alpha-0", P);
        let beta = second.challenge(b"beta-0", P);

        assert_ne!(alpha, beta);
    }

    #[test]
    fn test_challenge_advances_transcript_state() {
        let mut transcript = Transcript::new();
        let initial_state = transcript.state();

        transcript.challenge(b"alpha-0", P);

        assert_ne!(transcript.state(), initial_state);
    }

    #[test]
    fn test_absorbing_different_messages_changes_challenges() {
        let mut first = Transcript::new();
        let mut second = Transcript::new();

        first.absorb(b"root-A");
        second.absorb(b"root-B");

        let alpha = first.challenge(b"alpha-0", P);
        let beta = second.challenge(b"alpha-0", P);

        assert_ne!(alpha, beta);
    }

    #[test]
    fn test_challenges_in_sequence_are_different() {
        let mut transcript = Transcript::new();

        let alpha_0 = transcript.challenge(b"alpha-0", P);
        let alpha_1 = transcript.challenge(b"alpha-1", P);

        assert_ne!(alpha_0, alpha_1);
    }

    #[test]
    fn test_query_index_is_in_range() {
        let mut transcript = Transcript::new();

        transcript.absorb(b"layer-root");

        let index = transcript.challenge_index(b"query-0", 16);

        assert!(index < 16);
    }

    #[test]
    fn test_same_state_produces_same_query_index() {
        let mut first = Transcript::new();
        let mut second = Transcript::new();

        first.absorb(b"root-0");
        second.absorb(b"root-0");

        let index_first = first.challenge_index(b"query-0", 16);

        let index_second = second.challenge_index(b"query-0", 16);

        assert_eq!(index_first, index_second);
    }

    #[test]
    fn test_different_labels_produce_different_query_indices() {
        let mut first = Transcript::new();
        let mut second = Transcript::new();

        first.absorb(b"root-0");
        second.absorb(b"root-0");

        let index_first = first.challenge_index(b"query-0", 1024);

        let index_second = second.challenge_index(b"query-1", 1024);

        assert_ne!(index_first, index_second);
    }

    #[test]
    fn test_query_index_advances_transcript() {
        let mut transcript = Transcript::new();

        let initial_state = transcript.state();

        transcript.challenge_index(b"query-0", 16);

        assert_ne!(transcript.state(), initial_state);
    }

    #[test]
    fn test_query_index_with_bound_one() {
        let mut transcript = Transcript::new();

        let index = transcript.challenge_index(b"query-0", 1);

        assert_eq!(index, 0);
    }
}
