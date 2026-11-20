use crate::field::FieldElement;
use crate::merkle::{Hash, MerkleProof};

/// Query information for one FRI folding round.
#[derive(Clone, Debug)]
pub struct FriRoundQueryProof {
    /// Evaluation at x.
    pub value_x: FieldElement,

    /// Evaluation at -x.
    pub value_minus_x: FieldElement,

    /// Evaluation of the next folded layer at x^2.
    pub folded_value: FieldElement,

    /// Merkle authentication path for value_x.
    pub proof_x: MerkleProof,

    /// Merkle authentication path for value_minus_x.
    pub proof_minus_x: MerkleProof,

    /// Merkle authentication path for folded_value.
    ///
    /// In the final round, this authenticates the single-element
    /// final layer and therefore has an empty sibling list.
    pub folded_proof: MerkleProof,
}

/// All round openings associated with one sampled query index.
#[derive(Clone, Debug)]
pub struct FriQueryProof {
    /// Query index in the first half of the initial domain.
    pub index: usize,

    /// One opening record per folding round.
    pub round_proofs: Vec<FriRoundQueryProof>,
}

/// The complete educational FRI proof.
#[derive(Clone, Debug)]
pub struct FriProof {
    /// Merkle roots of all layers, including the final layer.
    pub layer_roots: Vec<Hash>,

    // Temporary compatibility field.
    // Will be removed when the verifier is updated.
    pub final_value: FieldElement,

    // All evaluations in the final FRI layer.
    pub final_evaluations: Vec<FieldElement>,

    /// Query openings.
    pub queries: Vec<FriQueryProof>,
}
