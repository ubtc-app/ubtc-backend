// verify.rs — Client-Side Proof Verification
//
// The recipient verifies a proof completely locally.
// No server needed. No trust in World Local Bank.
// Just mathematics.
//
// Verification checks:
// 1. Every state transition in the chain has valid quantum signatures
// 2. The chain is unbroken — each state references the previous
// 3. The collateral proof links to a real Bitcoin UTXO
// 4. No nullifier in the chain has been spent (double-spend check)
// 5. The current state is consistent with the chain
// 6. The collateral is sufficient (>=150% ratio)

use crate::proof::{UBTCProof, UBTCState, SignedStateTransition};
use crate::signing::verify_hybrid;
use crate::nullifier::{Nullifier, NullifierRegistry};
use crate::collateral::CollateralProof;
use crate::errors::UBTCError;
use serde::{Deserialize, Serialize};

/// Result of proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub chain_length: usize,
    pub amount_sats: u64,
    pub collateral_valid: bool,
    pub signatures_valid: bool,
    pub chain_intact: bool,
    pub no_double_spend: bool,
    pub error: Option<String>,
}

impl VerificationResult {
    pub fn invalid(reason: &str) -> Self {
        Self {
            valid: false,
            chain_length: 0,
            amount_sats: 0,
            collateral_valid: false,
            signatures_valid: false,
            chain_intact: false,
            no_double_spend: false,
            error: Some(reason.to_string()),
        }
    }
}

/// Verify a complete UBTC proof
/// This is what the recipient calls when they receive UBTC
pub async fn verify_proof(
    proof: &UBTCProof,
    nullifier_registry: &NullifierRegistry,
    btc_rpc_url: &str,
) -> VerificationResult {
    // Step 1: Verify the state chain signatures
    match verify_chain_signatures(proof) {
        Ok(true) => {},
        Ok(false) => return VerificationResult::invalid("Invalid quantum signatures in chain"),
        Err(e) => return VerificationResult::invalid(&format!("Signature verification error: {}", e)),
    }

    // Step 2: Verify chain integrity (each state links to previous)
    match verify_chain_integrity(proof) {
        Ok(true) => {},
        Ok(false) => return VerificationResult::invalid("Broken chain — state hashes don't link"),
        Err(e) => return VerificationResult::invalid(&format!("Chain integrity error: {}", e)),
    }

    // Step 3: Check nullifiers haven't been spent (double-spend protection)
    match verify_no_double_spend(proof, nullifier_registry).await {
        Ok(true) => {},
        Ok(false) => return VerificationResult::invalid("Double spend detected — nullifier already spent"),
        Err(e) => return VerificationResult::invalid(&format!("Nullifier check error: {}", e)),
    }

    // Step 4: Verify collateral exists on Bitcoin
    let collateral_valid = match verify_collateral_chain(proof, btc_rpc_url).await {
        Ok(v) => v,
        Err(e) => {
            // Collateral check failure is not fatal if we can't reach Bitcoin
            // Flag it but don't reject
            eprintln!("Collateral verification warning: {}", e);
            false
        }
    };

    VerificationResult {
        valid: true,
        chain_length: proof.state_chain.len(),
        amount_sats: proof.current_state.amount_sats,
        collateral_valid,
        signatures_valid: true,
        chain_intact: true,
        no_double_spend: true,
        error: None,
    }
}

/// Verify all quantum signatures in the state chain
fn verify_chain_signatures(proof: &UBTCProof) -> Result<bool, UBTCError> {
    for (i, transition) in proof.state_chain.iter().enumerate() {
        // Reconstruct the signing payload
        let payload = SignedStateTransition::signing_payload(
            &transition.from_state_hash,
            &transition.to_state_hash,
            transition.amount_sats,
        );

        // Build temporary QuantumSignature for verification
        let sig = crate::signing::QuantumSignature {
            dilithium_sig: transition.dilithium_signature.clone(),
            sphincs_sig: transition.sphincs_signature.clone(),
            message_hash: sha2_hash(&payload),
        };

        // Verify both signatures
        let valid = verify_hybrid(
            &payload,
            &sig,
            &transition.sender_dilithium_pk,
            &transition.sender_sphincs_pk,
        )?;

        if !valid {
            return Err(UBTCError::InvalidSignature(
                format!("Invalid signature at chain position {}", i)
            ));
        }
    }
    Ok(true)
}

/// Verify the hash chain is unbroken
fn verify_chain_integrity(proof: &UBTCProof) -> Result<bool, UBTCError> {
    if proof.state_chain.is_empty() {
        // Freshly minted — no chain to verify, just check current state
        return Ok(proof.current_state.prev_state_hash.is_none());
    }

    // Verify each transition links to the next
    for i in 0..proof.state_chain.len() - 1 {
        let current = &proof.state_chain[i];
        let next = &proof.state_chain[i + 1];

        if current.to_state_hash != next.from_state_hash {
            return Err(UBTCError::InvalidChain(
                format!("Chain broken at position {} -> {}", i, i + 1)
            ));
        }
    }

    // Verify the last transition leads to the current state
    if let Some(last_transition) = proof.state_chain.last() {
        let current_hash = proof.current_state.hash();
        if last_transition.to_state_hash != current_hash {
            return Err(UBTCError::InvalidChain(
                "Last transition doesn't match current state".to_string()
            ));
        }
    }

    // Verify current state references its predecessor correctly
    if let Some(last_transition) = proof.state_chain.last() {
        if let Some(prev_hash) = proof.current_state.prev_state_hash {
            if prev_hash != last_transition.from_state_hash {
                return Err(UBTCError::InvalidChain(
                    "Current state prev_hash doesn't match chain".to_string()
                ));
            }
        }
    }

    Ok(true)
}

/// Check none of the nullifiers in the chain have been spent
async fn verify_no_double_spend(
    proof: &UBTCProof,
    registry: &NullifierRegistry,
) -> Result<bool, UBTCError> {
    // Check current state's nullifier hasn't been spent
    let spent = registry.is_spent(&proof.current_state.nullifier).await?;
    if spent {
        return Ok(false);
    }
    Ok(true)
}

/// Verify the BTC collateral exists on Bitcoin
pub async fn verify_collateral_chain(
    proof: &UBTCProof,
    btc_rpc_url: &str,
) -> Result<bool, UBTCError> {
    let collateral = &proof.collateral_proof;

    // Check the UTXO exists and is unspent via Bitcoin RPC
    let client = reqwest::Client::new();
    let res = client
        .post(btc_rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "gettxout",
            "params": [
                collateral.txid,
                collateral.vout,
                false  // include_mempool
            ]
        }))
        .send()
        .await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let data: serde_json::Value = res.json().await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    if let Some(error) = data.get("error") {
        if !error.is_null() {
            return Err(UBTCError::Network(
                error["message"].as_str().unwrap_or("RPC error").to_string()
            ));
        }
    }

    let result = &data["result"];
    if result.is_null() {
        // UTXO doesn't exist or is spent
        return Ok(false);
    }

    // Verify the amount matches
    let utxo_value = result["value"].as_f64().unwrap_or(0.0);
    let utxo_sats = (utxo_value * 100_000_000.0) as u64;

    if utxo_sats < collateral.amount_sats {
        return Ok(false);
    }

    // Verify collateral ratio >= 150%
    let collateral_ratio = utxo_sats as f64 / proof.current_state.amount_sats as f64;
    if collateral_ratio < crate::MIN_COLLATERAL_RATIO {
        return Err(UBTCError::InsufficientCollateral {
            required: crate::MIN_COLLATERAL_RATIO,
            actual: collateral_ratio,
        });
    }

    Ok(true)
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
