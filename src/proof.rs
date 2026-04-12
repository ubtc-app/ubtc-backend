// proof.rs — The UBTC Proof Object
//
// A UBTCProof is not a token. It is not a database record.
// It is a self-contained cryptographic object that IS the money.
// It carries inside it proof of everything:
// - The BTC collateral it is backed by
// - Every state transition in its history
// - The current owner's quantum public key
// - A nullifier that prevents double-spending
//
// To transfer UBTC: transform the proof. No server needed.
// To verify UBTC: check the proof locally. No trust needed.
// To redeem UBTC: present the proof. BTC releases.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use chrono::{DateTime, Utc};
use crate::collateral::CollateralProof;
use crate::signing::QuantumSignature;
use crate::nullifier::Nullifier;
use crate::commitment::AmountCommitment;
use crate::errors::UBTCError;
use crate::PROTOCOL_VERSION;

/// The core state of a UBTC unit
/// This is what gets transferred between parties
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UBTCState {
    /// Unique identifier for this state
    pub state_id: [u8; 32],

    /// Protocol version this state was created under
    pub protocol_version: u8,

    /// Amount commitment — hides the amount while allowing verification
    /// Full Pedersen commitments in Phase 2
    /// For now: SHA3-256(amount_sats || blinding_factor)
    pub amount_commitment: AmountCommitment,

    /// The actual amount in satoshis
    /// Will be replaced by ZK proof in Phase 3
    /// Kept for MVP — blinded in commitment above
    pub amount_sats: u64,

    /// Current owner's Dilithium3 public key
    pub owner_dilithium_pk: Vec<u8>,

    /// Current owner's SPHINCS+ public key (backup quantum signing)
    pub owner_sphincs_pk: Vec<u8>,

    /// Nullifier — posted to Bitcoin when this state is spent
    /// Prevents double-spending without revealing transfer details
    pub nullifier: Nullifier,

    /// Hash of the previous state — None for freshly minted UBTC
    pub prev_state_hash: Option<[u8; 32]>,

    /// The Bitcoin UTXO this UBTC is backed by
    pub collateral_txid: String,
    pub collateral_vout: u32,
    pub collateral_amount_sats: u64,

    /// Bitcoin block this state was anchored in
    pub bitcoin_anchor_height: u64,
    pub bitcoin_anchor_hash: String,

    /// Timestamp this state was created
    pub created_at: DateTime<Utc>,
}

impl UBTCState {
    /// Create a new state (called during minting)
    pub fn new_minted(
        amount_sats: u64,
        owner_dilithium_pk: Vec<u8>,
        owner_sphincs_pk: Vec<u8>,
        collateral_txid: String,
        collateral_vout: u32,
        collateral_amount_sats: u64,
        bitcoin_anchor_height: u64,
        bitcoin_anchor_hash: String,
    ) -> Result<Self, UBTCError> {
        use crate::commitment::commit_amount;

        let (amount_commitment, _blinding) = commit_amount(amount_sats)?;
        let nullifier = Nullifier::generate(&owner_dilithium_pk, amount_sats)?;
        let state_id = Self::generate_state_id(
            &owner_dilithium_pk,
            amount_sats,
            &collateral_txid,
            collateral_vout,
        );

        Ok(Self {
            state_id,
            protocol_version: PROTOCOL_VERSION,
            amount_commitment,
            amount_sats,
            owner_dilithium_pk,
            owner_sphincs_pk,
            nullifier,
            prev_state_hash: None,
            collateral_txid,
            collateral_vout,
            collateral_amount_sats,
            bitcoin_anchor_height,
            bitcoin_anchor_hash,
            created_at: Utc::now(),
        })
    }

    /// Create a new state for a recipient (called during transfer)
    pub fn new_transferred(
        amount_sats: u64,
        recipient_dilithium_pk: Vec<u8>,
        recipient_sphincs_pk: Vec<u8>,
        prev_state: &UBTCState,
    ) -> Result<Self, UBTCError> {
        use crate::commitment::commit_amount;

        let (amount_commitment, _blinding) = commit_amount(amount_sats)?;
        let nullifier = Nullifier::generate(&recipient_dilithium_pk, amount_sats)?;
        let prev_hash = prev_state.hash();
        let state_id = Self::generate_state_id(
            &recipient_dilithium_pk,
            amount_sats,
            &prev_state.collateral_txid,
            prev_state.collateral_vout,
        );

        Ok(Self {
            state_id,
            protocol_version: PROTOCOL_VERSION,
            amount_commitment,
            amount_sats,
            owner_dilithium_pk: recipient_dilithium_pk,
            owner_sphincs_pk: recipient_sphincs_pk,
            nullifier,
            prev_state_hash: Some(prev_hash),
            collateral_txid: prev_state.collateral_txid.clone(),
            collateral_vout: prev_state.collateral_vout,
            collateral_amount_sats: prev_state.collateral_amount_sats,
            bitcoin_anchor_height: prev_state.bitcoin_anchor_height,
            bitcoin_anchor_hash: prev_state.bitcoin_anchor_hash.clone(),
            created_at: Utc::now(),
        })
    }

    /// Hash this state — used to chain states together
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.state_id);
        hasher.update(&self.amount_sats.to_le_bytes());
        hasher.update(&self.owner_dilithium_pk);
        hasher.update(&self.nullifier.bytes);
        if let Some(prev) = &self.prev_state_hash {
            hasher.update(prev);
        }
        hasher.update(self.collateral_txid.as_bytes());
        hasher.update(&self.collateral_vout.to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Generate a unique state ID
    fn generate_state_id(
        owner_pk: &[u8],
        amount_sats: u64,
        collateral_txid: &str,
        collateral_vout: u32,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(owner_pk);
        hasher.update(&amount_sats.to_le_bytes());
        hasher.update(collateral_txid.as_bytes());
        hasher.update(&collateral_vout.to_le_bytes());
        hasher.update(&Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Serialise to bytes for signing or transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, UBTCError> {
        bincode::serialize(self).map_err(|e| UBTCError::Serialization(e.to_string()))
    }

    /// The message that gets signed during a transfer
    /// "I am transferring amount_sats from state prev_hash to recipient"
    pub fn transfer_message(
        prev_state_hash: &[u8; 32],
        recipient_dilithium_pk: &[u8],
        amount_sats: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"UBTC_TRANSFER_V1:");
        msg.extend_from_slice(prev_state_hash);
        msg.extend_from_slice(b":");
        msg.extend_from_slice(recipient_dilithium_pk);
        msg.extend_from_slice(b":");
        msg.extend_from_slice(&amount_sats.to_le_bytes());
        msg
    }
}

/// A signed state transition — proof that a transfer was authorised
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedStateTransition {
    /// Hash of the state being spent
    pub from_state_hash: [u8; 32],

    /// Hash of the new state being created
    pub to_state_hash: [u8; 32],

    /// Amount being transferred in satoshis
    pub amount_sats: u64,

    /// Dilithium3 signature from the sender
    pub dilithium_signature: Vec<u8>,

    /// SPHINCS+ signature from the sender (backup quantum signing)
    /// Both must be valid — hybrid quantum security
    pub sphincs_signature: Vec<u8>,

    /// Sender's public keys (for verification)
    pub sender_dilithium_pk: Vec<u8>,
    pub sender_sphincs_pk: Vec<u8>,

    /// Timestamp of the transfer
    pub transferred_at: DateTime<Utc>,
}

impl SignedStateTransition {
    /// The signing payload — what both signatures are over
    pub fn signing_payload(
        from_hash: &[u8; 32],
        to_hash: &[u8; 32],
        amount_sats: u64,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"UBTC_TRANSITION_V1:");
        payload.extend_from_slice(from_hash);
        payload.extend_from_slice(b":");
        payload.extend_from_slice(to_hash);
        payload.extend_from_slice(b":");
        payload.extend_from_slice(&amount_sats.to_le_bytes());
        payload
    }
}

/// The complete UBTC proof object
/// This IS the money. Hold this, you hold UBTC.
/// Lose this, you lose UBTC. (Recovery via vault if linked)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UBTCProof {
    /// The current state of this UBTC unit
    pub current_state: UBTCState,

    /// Complete chain of state transitions from mint to now
    /// Each entry proves one valid transfer in the history
    pub state_chain: Vec<SignedStateTransition>,

    /// Proof that BTC collateral exists on Bitcoin
    pub collateral_proof: CollateralProof,

    /// Proof size in bytes — used to determine if compression needed
    pub proof_size_bytes: usize,
}

impl UBTCProof {
    /// Create a new proof at mint time
    pub fn new_minted(state: UBTCState, collateral_proof: CollateralProof) -> Self {
        let mut proof = Self {
            current_state: state,
            state_chain: Vec::new(),
            collateral_proof,
            proof_size_bytes: 0,
        };
        proof.proof_size_bytes = proof.estimate_size();
        proof
    }

    /// Estimate the serialised size of this proof
    pub fn estimate_size(&self) -> usize {
        // Approximate: state + chain entries + collateral
        1024 + (self.state_chain.len() * 4096) + 512
    }

    /// Serialise to bytes for transmission to recipient
    pub fn to_bytes(&self) -> Result<Vec<u8>, UBTCError> {
        bincode::serialize(self).map_err(|e| UBTCError::Serialization(e.to_string()))
    }

    /// Deserialise from bytes received from sender
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UBTCError> {
        bincode::deserialize(bytes).map_err(|e| UBTCError::Serialization(e.to_string()))
    }

    /// Serialise to JSON (human readable, larger)
    pub fn to_json(&self) -> Result<String, UBTCError> {
        serde_json::to_string_pretty(self).map_err(|e| UBTCError::Serialization(e.to_string()))
    }

    /// Check if this proof needs compression
    /// After MAX_CHAIN_LENGTH transitions, compress with ZK proof
    pub fn needs_compression(&self) -> bool {
        self.state_chain.len() >= crate::MAX_CHAIN_LENGTH
    }

    /// Get the chain depth (number of transfers this UBTC has made)
    pub fn chain_depth(&self) -> usize {
        self.state_chain.len()
    }

    /// Amount in UBTC (satoshis / 100_000_000)
    pub fn amount_ubtc(&self) -> f64 {
        self.current_state.amount_sats as f64 / 100_000_000.0
    }

    /// Amount in USD equivalent (requires BTC price)
    pub fn amount_usd(&self, btc_price_usd: f64) -> f64 {
        self.amount_ubtc() * btc_price_usd
    }
}
