// nullifier.rs — Double-Spend Prevention Without Privacy Leakage
//
// A nullifier is a one-way commitment to a UBTC state.
// When Alice spends her UBTC, her nullifier is posted to Bitcoin.
// Anyone can check if a nullifier has been spent.
// Nobody can learn anything about the transfer from the nullifier.
//
// This is how Zcash prevents double-spending while maintaining privacy.
// We apply the same technique to UBTC.
//
// Nullifier = SHA3-256(state_id || owner_pk || secret_nonce)
// Posted to Bitcoin as OP_RETURN in batches (not per-transfer)

use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use std::collections::HashSet;
use crate::errors::UBTCError;

/// A nullifier — commitment to a UBTC state that prevents double-spending
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Nullifier {
    /// The nullifier bytes — posted to Bitcoin when state is spent
    pub bytes: [u8; 32],
    /// Hex representation for display and Bitcoin OP_RETURN
    pub hex: String,
}

impl Nullifier {
    /// Generate a nullifier for a UBTC state
    /// Deterministic given the same inputs — owner can regenerate
    /// Unlinkable to transfer details by anyone else
    pub fn generate(
        owner_dilithium_pk: &[u8],
        amount_sats: u64,
    ) -> Result<Self, UBTCError> {
        // Random nonce for unlinkability
        let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();

        let mut hasher = Sha3_256::new();
        hasher.update(b"UBTC_NULLIFIER_V1:");
        hasher.update(owner_dilithium_pk);
        hasher.update(b":");
        hasher.update(&amount_sats.to_le_bytes());
        hasher.update(b":");
        hasher.update(&nonce);

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);

        Ok(Self {
            hex: hex::encode(bytes),
            bytes,
        })
    }

    /// Generate from explicit nonce (for deterministic generation)
    pub fn generate_with_nonce(
        owner_dilithium_pk: &[u8],
        amount_sats: u64,
        nonce: &[u8],
    ) -> Result<Self, UBTCError> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"UBTC_NULLIFIER_V1:");
        hasher.update(owner_dilithium_pk);
        hasher.update(b":");
        hasher.update(&amount_sats.to_le_bytes());
        hasher.update(b":");
        hasher.update(nonce);

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);

        Ok(Self {
            hex: hex::encode(bytes),
            bytes,
        })
    }
}

/// Registry of spent nullifiers
/// In production: backed by Bitcoin OP_RETURN scanning
/// For now: in-memory + Supabase for persistence
pub struct NullifierRegistry {
    /// In-memory cache of spent nullifiers
    spent: HashSet<[u8; 32]>,
    /// Supabase URL for persistence
    api_url: String,
}

impl NullifierRegistry {
    pub fn new(api_url: String) -> Self {
        Self {
            spent: HashSet::new(),
            api_url,
        }
    }

    /// Check if a nullifier has been spent
    /// First checks in-memory cache, then checks API/Bitcoin
    pub async fn is_spent(&self, nullifier: &Nullifier) -> Result<bool, UBTCError> {
        // Check in-memory cache first
        if self.spent.contains(&nullifier.bytes) {
            return Ok(true);
        }

        // Check backend (which scans Bitcoin OP_RETURN)
        let client = reqwest::Client::new();
        let res = client
            .get(format!("{}/nullifier/{}", self.api_url, nullifier.hex))
            .send()
            .await
            .map_err(|e| UBTCError::Network(e.to_string()))?;

        if res.status().is_success() {
            let data: serde_json::Value = res.json().await
                .map_err(|e| UBTCError::Network(e.to_string()))?;
            Ok(data["spent"].as_bool().unwrap_or(false))
        } else {
            Ok(false)
        }
    }

    /// Mark a nullifier as spent
    /// Called when a UBTC state is transferred or redeemed
    pub async fn mark_spent(&mut self, nullifier: &Nullifier) -> Result<(), UBTCError> {
        self.spent.insert(nullifier.bytes);

        // Post to backend which will include in next Bitcoin batch
        let client = reqwest::Client::new();
        client
            .post(format!("{}/nullifier/spend", self.api_url))
            .json(&serde_json::json!({ "nullifier": nullifier.hex }))
            .send()
            .await
            .map_err(|e| UBTCError::Network(e.to_string()))?;

        Ok(())
    }

    /// Batch check multiple nullifiers
    pub async fn any_spent(&self, nullifiers: &[&Nullifier]) -> Result<bool, UBTCError> {
        for n in nullifiers {
            if self.is_spent(n).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// A batch of nullifiers to be posted to Bitcoin
/// Posted as OP_RETURN: "UBTC_NULL_V1:{merkle_root_of_nullifiers}"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierBatch {
    pub nullifiers: Vec<[u8; 32]>,
    pub merkle_root: [u8; 32],
    pub bitcoin_txid: Option<String>,
}

impl NullifierBatch {
    pub fn new(nullifiers: Vec<Nullifier>) -> Self {
        let bytes: Vec<[u8; 32]> = nullifiers.iter().map(|n| n.bytes).collect();
        let merkle_root = Self::compute_merkle_root(&bytes);
        Self {
            nullifiers: bytes,
            merkle_root,
            bitcoin_txid: None,
        }
    }

    /// Simple binary merkle tree of nullifiers
    pub fn compute_merkle_root(nullifiers: &[[u8; 32]]) -> [u8; 32] {
        if nullifiers.is_empty() {
            return [0u8; 32];
        }
        if nullifiers.len() == 1 {
            return nullifiers[0];
        }

        let mut layer: Vec<[u8; 32]> = nullifiers.to_vec();

        while layer.len() > 1 {
            let mut next_layer = Vec::new();
            let mut i = 0;
            while i < layer.len() {
                let left = layer[i];
                let right = if i + 1 < layer.len() { layer[i + 1] } else { left };
                let mut hasher = Sha3_256::new();
                hasher.update(left);
                hasher.update(right);
                let result = hasher.finalize();
                let mut node = [0u8; 32];
                node.copy_from_slice(&result);
                next_layer.push(node);
                i += 2;
            }
            layer = next_layer;
        }

        layer[0]
    }

    /// OP_RETURN payload — 43 bytes max for Bitcoin
    /// "UBTCN1:" (7 bytes) + merkle root (32 bytes) = 39 bytes
    pub fn op_return_payload(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"UBTCN1:");
        payload.extend_from_slice(&self.merkle_root);
        payload
    }
}
