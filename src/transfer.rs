// transfer.rs — Proof Transformation
//
// Transferring UBTC = transforming a proof object
// No server needed. No blockchain per transfer.
// Just: Alice creates a new proof for Bob and gives it to him directly.
// Alice's old proof becomes invalid (nullifier posted to Bitcoin).
//
// The transfer produces:
// 1. A new UBTCProof for the recipient
// 2. A signed state transition proving Alice authorised it
// 3. Alice's nullifier (to be posted to Bitcoin to prevent double-spend)

use crate::proof::{UBTCProof, UBTCState, SignedStateTransition};
use crate::signing::{sign_hybrid, QuantumSignature};
use crate::nullifier::Nullifier;
use crate::collateral::CollateralProof;
use crate::errors::UBTCError;
use chrono::Utc;

/// Transfer a complete UBTC proof to a new owner
/// Called by the sender client-side — no server required
///
/// Arguments:
/// - proof: The sender's current UBTC proof
/// - recipient_dilithium_pk: Recipient's Dilithium3 public key
/// - recipient_sphincs_pk: Recipient's SPHINCS+ public key  
/// - sender_dilithium_sk_hex: Sender's Dilithium3 secret key (never stored)
/// - sender_sphincs_sk_hex: Sender's SPHINCS+ secret key (never stored)
///
/// Returns:
/// - new_proof: The proof package to send to the recipient
/// - spent_nullifier: Alice's nullifier to post to Bitcoin
pub fn transfer_proof(
    proof: &UBTCProof,
    recipient_dilithium_pk: &[u8],
    recipient_sphincs_pk: &[u8],
    sender_dilithium_sk_hex: &str,
    sender_sphincs_sk_hex: &str,
) -> Result<(UBTCProof, Nullifier), UBTCError> {
    let current_state = &proof.current_state;

    // Verify this proof is valid before transferring
    // (prevents passing on invalid proofs)
    let from_hash = current_state.hash();

    // Create new state for recipient
    let new_state = UBTCState::new_transferred(
        current_state.amount_sats,
        recipient_dilithium_pk.to_vec(),
        recipient_sphincs_pk.to_vec(),
        current_state,
    )?;

    let to_hash = new_state.hash();

    // Sign the state transition with sender's quantum keys
    let payload = SignedStateTransition::signing_payload(
        &from_hash,
        &to_hash,
        current_state.amount_sats,
    );

    let dilithium_sk_bytes = hex::decode(sender_dilithium_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 key".to_string()))?;
    let sphincs_sk_bytes = hex::decode(sender_sphincs_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ key".to_string()))?;

    let sig = sign_hybrid(&payload, &dilithium_sk_bytes, &sphincs_sk_bytes)?;

    // Build the signed state transition
    let transition = SignedStateTransition {
        from_state_hash: from_hash,
        to_state_hash: to_hash,
        amount_sats: current_state.amount_sats,
        dilithium_signature: sig.dilithium_sig,
        sphincs_signature: sig.sphincs_sig,
        sender_dilithium_pk: current_state.owner_dilithium_pk.clone(),
        sender_sphincs_pk: current_state.owner_sphincs_pk.clone(),
        transferred_at: Utc::now(),
    };

    // Build new proof for recipient
    // Includes complete history so recipient can verify everything
    let mut new_chain = proof.state_chain.clone();
    new_chain.push(transition);

    let mut new_proof = UBTCProof {
        current_state: new_state,
        state_chain: new_chain,
        collateral_proof: proof.collateral_proof.clone(),
        proof_size_bytes: 0,
    };
    new_proof.proof_size_bytes = new_proof.estimate_size();

    // The spent nullifier — to be posted to Bitcoin
    let spent_nullifier = current_state.nullifier.clone();

    Ok((new_proof, spent_nullifier))
}

/// Split a UBTC proof into two proofs
/// e.g., Split $1000 UBTC into $300 and $700
/// Both outputs must be backed by same collateral
/// Total must equal input (conservation of value)
pub fn split_proof(
    proof: &UBTCProof,
    amount_a_sats: u64,
    recipient_a_dilithium_pk: &[u8],
    recipient_a_sphincs_pk: &[u8],
    recipient_b_dilithium_pk: &[u8],
    recipient_b_sphincs_pk: &[u8],
    sender_dilithium_sk_hex: &str,
    sender_sphincs_sk_hex: &str,
) -> Result<(UBTCProof, UBTCProof, Nullifier), UBTCError> {
    let total = proof.current_state.amount_sats;
    let amount_b_sats = total.checked_sub(amount_a_sats)
        .ok_or(UBTCError::InsufficientBalance {
            available: total,
            requested: amount_a_sats,
        })?;

    if amount_a_sats == 0 || amount_b_sats == 0 {
        return Err(UBTCError::InvalidAmount("Split amounts must be non-zero".to_string()));
    }

    let current_state = &proof.current_state;
    let from_hash = current_state.hash();

    // Create state A
    let state_a = UBTCState::new_transferred(
        amount_a_sats,
        recipient_a_dilithium_pk.to_vec(),
        recipient_a_sphincs_pk.to_vec(),
        current_state,
    )?;

    // Create state B
    let state_b = UBTCState::new_transferred(
        amount_b_sats,
        recipient_b_dilithium_pk.to_vec(),
        recipient_b_sphincs_pk.to_vec(),
        current_state,
    )?;

    let to_hash_a = state_a.hash();
    let to_hash_b = state_b.hash();

    // Sign both transitions
    let dilithium_sk_bytes = hex::decode(sender_dilithium_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 key".to_string()))?;
    let sphincs_sk_bytes = hex::decode(sender_sphincs_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ key".to_string()))?;

    // Sign split operation
    let mut split_payload = Vec::new();
    split_payload.extend_from_slice(b"UBTC_SPLIT_V1:");
    split_payload.extend_from_slice(&from_hash);
    split_payload.extend_from_slice(&to_hash_a);
    split_payload.extend_from_slice(&to_hash_b);
    split_payload.extend_from_slice(&amount_a_sats.to_le_bytes());
    split_payload.extend_from_slice(&amount_b_sats.to_le_bytes());

    let sig = sign_hybrid(&split_payload, &dilithium_sk_bytes, &sphincs_sk_bytes)?;

    let transition_a = SignedStateTransition {
        from_state_hash: from_hash,
        to_state_hash: to_hash_a,
        amount_sats: amount_a_sats,
        dilithium_signature: sig.dilithium_sig.clone(),
        sphincs_signature: sig.sphincs_sig.clone(),
        sender_dilithium_pk: current_state.owner_dilithium_pk.clone(),
        sender_sphincs_pk: current_state.owner_sphincs_pk.clone(),
        transferred_at: Utc::now(),
    };

    let transition_b = SignedStateTransition {
        from_state_hash: from_hash,
        to_state_hash: to_hash_b,
        amount_sats: amount_b_sats,
        dilithium_signature: sig.dilithium_sig,
        sphincs_signature: sig.sphincs_sig,
        sender_dilithium_pk: current_state.owner_dilithium_pk.clone(),
        sender_sphincs_pk: current_state.owner_sphincs_pk.clone(),
        transferred_at: Utc::now(),
    };

    let mut chain_a = proof.state_chain.clone();
    chain_a.push(transition_a);

    let mut chain_b = proof.state_chain.clone();
    chain_b.push(transition_b);

    let mut proof_a = UBTCProof {
        current_state: state_a,
        state_chain: chain_a,
        collateral_proof: proof.collateral_proof.clone(),
        proof_size_bytes: 0,
    };
    proof_a.proof_size_bytes = proof_a.estimate_size();

    let mut proof_b = UBTCProof {
        current_state: state_b,
        state_chain: chain_b,
        collateral_proof: proof.collateral_proof.clone(),
        proof_size_bytes: 0,
    };
    proof_b.proof_size_bytes = proof_b.estimate_size();

    let spent_nullifier = current_state.nullifier.clone();

    Ok((proof_a, proof_b, spent_nullifier))
}

/// Merge two UBTC proofs into one
/// Both must be backed by the same collateral
/// Used to consolidate small amounts
pub fn merge_proof(
    proof_a: &UBTCProof,
    proof_b: &UBTCProof,
    recipient_dilithium_pk: &[u8],
    recipient_sphincs_pk: &[u8],
    sender_a_dilithium_sk_hex: &str,
    sender_a_sphincs_sk_hex: &str,
    sender_b_dilithium_sk_hex: &str,
    sender_b_sphincs_sk_hex: &str,
) -> Result<(UBTCProof, Nullifier, Nullifier), UBTCError> {
    // Both proofs must reference the same collateral
    if proof_a.current_state.collateral_txid != proof_b.current_state.collateral_txid {
        return Err(UBTCError::CollateralMismatch(
            "Cannot merge proofs from different collateral UTXOs".to_string()
        ));
    }

    let total_sats = proof_a.current_state.amount_sats
        .checked_add(proof_b.current_state.amount_sats)
        .ok_or(UBTCError::InvalidAmount("Overflow in merge".to_string()))?;

    // Create merged state
    let merged_state = UBTCState::new_transferred(
        total_sats,
        recipient_dilithium_pk.to_vec(),
        recipient_sphincs_pk.to_vec(),
        &proof_a.current_state, // Use proof_a as the "primary" parent
    )?;

    let merged_hash = merged_state.hash();

    // Sign from both senders
    let dil_sk_a = hex::decode(sender_a_dilithium_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 key A".to_string()))?;
    let sph_sk_a = hex::decode(sender_a_sphincs_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ key A".to_string()))?;

    let dil_sk_b = hex::decode(sender_b_dilithium_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 key B".to_string()))?;
    let sph_sk_b = hex::decode(sender_b_sphincs_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ key B".to_string()))?;

    let hash_a = proof_a.current_state.hash();
    let hash_b = proof_b.current_state.hash();

    let payload_a = SignedStateTransition::signing_payload(&hash_a, &merged_hash, proof_a.current_state.amount_sats);
    let payload_b = SignedStateTransition::signing_payload(&hash_b, &merged_hash, proof_b.current_state.amount_sats);

    let sig_a = sign_hybrid(&payload_a, &dil_sk_a, &sph_sk_a)?;
    let sig_b = sign_hybrid(&payload_b, &dil_sk_b, &sph_sk_b)?;

    let transition_a = SignedStateTransition {
        from_state_hash: hash_a,
        to_state_hash: merged_hash,
        amount_sats: proof_a.current_state.amount_sats,
        dilithium_signature: sig_a.dilithium_sig,
        sphincs_signature: sig_a.sphincs_sig,
        sender_dilithium_pk: proof_a.current_state.owner_dilithium_pk.clone(),
        sender_sphincs_pk: proof_a.current_state.owner_sphincs_pk.clone(),
        transferred_at: Utc::now(),
    };

    let transition_b = SignedStateTransition {
        from_state_hash: hash_b,
        to_state_hash: merged_hash,
        amount_sats: proof_b.current_state.amount_sats,
        dilithium_signature: sig_b.dilithium_sig,
        sphincs_signature: sig_b.sphincs_sig,
        sender_dilithium_pk: proof_b.current_state.owner_dilithium_pk.clone(),
        sender_sphincs_pk: proof_b.current_state.owner_sphincs_pk.clone(),
        transferred_at: Utc::now(),
    };

    // Combine chains from both inputs
    let mut merged_chain = proof_a.state_chain.clone();
    merged_chain.extend(proof_b.state_chain.clone());
    merged_chain.push(transition_a);
    merged_chain.push(transition_b);

    let mut merged_proof = UBTCProof {
        current_state: merged_state,
        state_chain: merged_chain,
        collateral_proof: proof_a.collateral_proof.clone(),
        proof_size_bytes: 0,
    };
    merged_proof.proof_size_bytes = merged_proof.estimate_size();

    let spent_a = proof_a.current_state.nullifier.clone();
    let spent_b = proof_b.current_state.nullifier.clone();

    Ok((merged_proof, spent_a, spent_b))
}
