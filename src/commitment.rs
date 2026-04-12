use serde::{Deserialize, Serialize};
use sha3::{Sha3_256, Digest};
use rand::RngCore;
use crate::errors::UBTCError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AmountCommitment {
    pub commitment: [u8; 32],
    pub blinding_factor: [u8; 32],
}

pub fn commit_amount(amount_sats: u64) -> Result<(AmountCommitment, [u8; 32]), UBTCError> {
    let mut blinding = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut blinding);

    let mut hasher = Sha3_256::new();
    hasher.update(b"UBTC_COMMIT_V1:");
    hasher.update(&amount_sats.to_le_bytes());
    hasher.update(b":");
    hasher.update(&blinding);
    let result = hasher.finalize();
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&result);

    Ok((AmountCommitment { commitment, blinding_factor: blinding }, blinding))
}

pub fn verify_amount_commitment(amount_sats: u64, commitment: &AmountCommitment) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(b"UBTC_COMMIT_V1:");
    hasher.update(&amount_sats.to_le_bytes());
    hasher.update(b":");
    hasher.update(&commitment.blinding_factor);
    let result = hasher.finalize();
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&result);
    expected == commitment.commitment
}
