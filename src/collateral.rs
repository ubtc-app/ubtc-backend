// collateral.rs — BTC Collateral Proof
use serde::{Deserialize, Serialize};
use crate::errors::UBTCError;

/// Proof that BTC collateral exists on Bitcoin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralProof {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub block_hash: String,
    pub block_height: u64,
    pub confirmations: u64,
}

/// Anchor linking UBTC to Bitcoin chain state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralAnchor {
    pub collateral_proof: CollateralProof,
    pub vault_address: String,
    pub vault_owner_pk: Vec<u8>,
}

impl CollateralProof {
    pub fn new(
        txid: String,
        vout: u32,
        amount_sats: u64,
        block_hash: String,
        block_height: u64,
        confirmations: u64,
    ) -> Self {
        Self { txid, vout, amount_sats, block_hash, block_height, confirmations }
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmations >= 1
    }

    pub fn is_deeply_confirmed(&self) -> bool {
        self.confirmations >= 6
    }
}
