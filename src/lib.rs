// UBTC Protocol — Client-Side Validation
// Quantum-Resistant Bitcoin-Native Monetary Primitive
// World Local Bank — 2026

pub mod proof;
pub mod signing;
pub mod nullifier;
pub mod transfer;
pub mod verify;
pub mod collateral;
pub mod bitcoin_anchor;
pub mod commitment;
pub mod wallet;
pub mod adaptor;
pub mod dleq;
pub mod errors;

pub use proof::{UBTCProof, UBTCState, SignedStateTransition};
pub use signing::{QuantumKeypair, QuantumSignature, sign_state, verify_state_signature};
pub use nullifier::{Nullifier, NullifierRegistry, NullifierBatch};
pub use transfer::{transfer_proof, split_proof, merge_proof};
pub use verify::{verify_proof, verify_collateral_chain, VerificationResult};
pub use collateral::{CollateralProof, CollateralAnchor};
pub use bitcoin_anchor::{post_nullifier_to_bitcoin, BatchCommitment};
pub use commitment::{AmountCommitment, commit_amount, verify_amount_commitment};
pub use wallet::{UBTCWallet, ProofStore};
pub use adaptor::{
    KyberKeypair, KyberCiphertext, SchnorrAdaptor, CompletedSignature,
    RedemptionTree, EncryptedRedemptionPath, CompleteQuantumKeypair,
    create_adaptor, complete_adaptor,
};
pub use dleq::{DLEQProof, CoSignRequest, CoSignResponse, LamportOneTimeSig, VDFProof};
pub use errors::UBTCError;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MIN_COLLATERAL_RATIO: f64 = 1.5;
pub const MAX_CHAIN_LENGTH: usize = 1000;
pub const OP_RETURN_PREFIX: &[u8] = b"UBTCN1:";
