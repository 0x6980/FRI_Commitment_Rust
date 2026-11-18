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
}
