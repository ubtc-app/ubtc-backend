use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::proof::UBTCProof;
use crate::errors::UBTCError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStore {
    pub proofs: HashMap<String, UBTCProof>,
    pub total_sats: u64,
}

impl ProofStore {
    pub fn new() -> Self {
        Self { proofs: HashMap::new(), total_sats: 0 }
    }

    pub fn add_proof(&mut self, proof: UBTCProof) {
        let key = hex::encode(proof.current_state.state_id);
        self.total_sats += proof.current_state.amount_sats;
        self.proofs.insert(key, proof);
    }

    pub fn remove_proof(&mut self, state_id: &[u8; 32]) -> Option<UBTCProof> {
        let key = hex::encode(state_id);
        if let Some(proof) = self.proofs.remove(&key) {
            self.total_sats -= proof.current_state.amount_sats;
            Some(proof)
        } else {
            None
        }
    }

    pub fn total_ubtc(&self) -> f64 {
        self.total_sats as f64 / 100_000_000.0
    }

    pub fn to_json(&self) -> Result<String, UBTCError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| UBTCError::Serialization(e.to_string()))
    }

    pub fn from_json(json: &str) -> Result<Self, UBTCError> {
        serde_json::from_str(json)
            .map_err(|e| UBTCError::Serialization(e.to_string()))
    }
}

pub struct UBTCWallet {
    pub store: ProofStore,
    pub dilithium_pk: Vec<u8>,
    pub sphincs_pk: Vec<u8>,
}

impl UBTCWallet {
    pub fn new(dilithium_pk: Vec<u8>, sphincs_pk: Vec<u8>) -> Self {
        Self { store: ProofStore::new(), dilithium_pk, sphincs_pk }
    }

    pub fn balance_sats(&self) -> u64 { self.store.total_sats }
    pub fn balance_ubtc(&self) -> f64 { self.store.total_ubtc() }
}
