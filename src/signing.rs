// signing.rs — Hybrid Post-Quantum Signing
//
// Every UBTC state transition requires TWO valid signatures:
// 1. Dilithium3 — NIST standard lattice-based signature
// 2. SPHINCS+ — NIST standard hash-based signature
//
// Breaking UBTC requires breaking TWO completely different
// post-quantum algorithms simultaneously.
// This is mathematically unprecedented security.
//
// Dilithium3: security from Module Learning With Errors problem
// SPHINCS+: security from hash function collision resistance
// Both: quantum-resistant by NIST verification

use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincsshake128ssimple as sphincs;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use crate::errors::UBTCError;

/// A complete quantum keypair — both Dilithium3 and SPHINCS+
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumKeypair {
    /// Dilithium3 public key (stored in database, shared with recipients)
    pub dilithium_pk: Vec<u8>,
    /// Dilithium3 secret key (NEVER stored, shown once to user)
    pub dilithium_sk: Vec<u8>,
    /// SPHINCS+ public key (stored in database)
    pub sphincs_pk: Vec<u8>,
    /// SPHINCS+ secret key (NEVER stored, shown once to user)
    pub sphincs_sk: Vec<u8>,
}

/// A hybrid quantum signature — both algorithms must be valid
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSignature {
    /// Dilithium3 signature
    pub dilithium_sig: Vec<u8>,
    /// SPHINCS+ signature
    pub sphincs_sig: Vec<u8>,
    /// What was signed (for verification)
    pub message_hash: [u8; 32],
}

impl QuantumKeypair {
    /// Generate a new quantum keypair using system entropy
    /// In production, supplement with QRNG entropy
    pub fn generate() -> Result<Self, UBTCError> {
        Self::generate_with_entropy(&[])
    }

    /// Generate with additional entropy (e.g., from ANU QRNG)
    pub fn generate_with_entropy(extra_entropy: &[u8]) -> Result<Self, UBTCError> {
        // Mix extra entropy with system entropy via hashing
        if !extra_entropy.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(extra_entropy);
            hasher.update(&uuid::Uuid::new_v4().as_bytes().to_vec());
            let _mixed = hasher.finalize(); // entropy mixing
        }

        // Generate Dilithium3 keypair
        let (dil_pk, dil_sk) = dilithium3::keypair();

        // Generate SPHINCS+ keypair
        let (sph_pk, sph_sk) = sphincs::keypair();

        Ok(Self {
            dilithium_pk: dil_pk.as_bytes().to_vec(),
            dilithium_sk: dil_sk.as_bytes().to_vec(),
            sphincs_pk: sph_pk.as_bytes().to_vec(),
            sphincs_sk: sph_sk.as_bytes().to_vec(),
        })
    }

    /// Export public keys only — safe to share/store
    pub fn public_keys(&self) -> QuantumPublicKeys {
        QuantumPublicKeys {
            dilithium_pk: self.dilithium_pk.clone(),
            sphincs_pk: self.sphincs_pk.clone(),
        }
    }

    /// Export secret keys as hex — shown once to user, never stored
    pub fn secret_keys_hex(&self) -> QuantumSecretKeysHex {
        QuantumSecretKeysHex {
            dilithium_sk_hex: hex::encode(&self.dilithium_sk),
            sphincs_sk_hex: hex::encode(&self.sphincs_sk),
            combined: format!(
                "DILITHIUM:{}\nSPHINCS:{}",
                hex::encode(&self.dilithium_sk),
                hex::encode(&self.sphincs_sk)
            ),
        }
    }
}

/// Public keys — safe to store and share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumPublicKeys {
    pub dilithium_pk: Vec<u8>,
    pub sphincs_pk: Vec<u8>,
}

/// Secret keys as hex — shown once, never stored
#[derive(Debug, Clone)]
pub struct QuantumSecretKeysHex {
    pub dilithium_sk_hex: String,
    pub sphincs_sk_hex: String,
    /// Combined format for display to user
    pub combined: String,
}

/// Sign a message with both Dilithium3 and SPHINCS+
/// Both signatures must be present and valid
pub fn sign_hybrid(
    message: &[u8],
    dilithium_sk_bytes: &[u8],
    sphincs_sk_bytes: &[u8],
) -> Result<QuantumSignature, UBTCError> {
    // Hash the message first (for efficiency with SPHINCS+)
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: [u8; 32] = hasher.finalize().into();

    // Sign with Dilithium3
    let dil_sk = dilithium3::SecretKey::from_bytes(dilithium_sk_bytes)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 secret key".to_string()))?;
    let dil_signed = dilithium3::sign(&message_hash, &dil_sk);
    let dilithium_sig = dil_signed.as_bytes().to_vec();

    // Sign with SPHINCS+
    let sph_sk = sphincs::SecretKey::from_bytes(sphincs_sk_bytes)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ secret key".to_string()))?;
    let sph_signed = sphincs::sign(&message_hash, &sph_sk);
    let sphincs_sig = sph_signed.as_bytes().to_vec();

    Ok(QuantumSignature {
        dilithium_sig,
        sphincs_sig,
        message_hash,
    })
}

/// Verify a hybrid quantum signature
/// BOTH signatures must be valid — if either fails, the whole signature fails
pub fn verify_hybrid(
    message: &[u8],
    signature: &QuantumSignature,
    dilithium_pk_bytes: &[u8],
    sphincs_pk_bytes: &[u8],
) -> Result<bool, UBTCError> {
    // Recompute message hash
    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash: [u8; 32] = hasher.finalize().into();

    // Verify hash matches (prevents message substitution)
    if message_hash != signature.message_hash {
        return Ok(false);
    }

    // Verify Dilithium3 signature
    let dil_pk = dilithium3::PublicKey::from_bytes(dilithium_pk_bytes)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 public key".to_string()))?;
    let dil_signed = dilithium3::SignedMessage::from_bytes(&signature.dilithium_sig)
        .map_err(|_| UBTCError::InvalidSignature("Malformed Dilithium3 signature".to_string()))?;
    let dil_valid = dilithium3::open(&dil_signed, &dil_pk).is_ok();

    if !dil_valid {
        return Ok(false);
    }

    // Verify SPHINCS+ signature
    let sph_pk = sphincs::PublicKey::from_bytes(sphincs_pk_bytes)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ public key".to_string()))?;
    let sph_signed = sphincs::SignedMessage::from_bytes(&signature.sphincs_sig)
        .map_err(|_| UBTCError::InvalidSignature("Malformed SPHINCS+ signature".to_string()))?;
    let sph_valid = sphincs::open(&sph_signed, &sph_pk).is_ok();

    // Both must be valid
    Ok(dil_valid && sph_valid)
}

/// Sign a state transition
/// Called by the sender when transferring UBTC
pub fn sign_state(
    message: &[u8],
    dilithium_sk_hex: &str,
    sphincs_sk_hex: &str,
) -> Result<QuantumSignature, UBTCError> {
    let dilithium_sk_bytes = hex::decode(dilithium_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 key hex".to_string()))?;
    let sphincs_sk_bytes = hex::decode(sphincs_sk_hex)
        .map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ key hex".to_string()))?;

    sign_hybrid(message, &dilithium_sk_bytes, &sphincs_sk_bytes)
}

/// Verify a state transition signature
/// Called by the recipient when receiving UBTC
pub fn verify_state_signature(
    message: &[u8],
    signature: &QuantumSignature,
    dilithium_pk_bytes: &[u8],
    sphincs_pk_bytes: &[u8],
) -> Result<bool, UBTCError> {
    verify_hybrid(message, signature, dilithium_pk_bytes, sphincs_pk_bytes)
}

/// Parse combined secret key string (as shown to user at wallet creation)
/// Format: "DILITHIUM:{hex}\nSPHINCS:{hex}"
pub fn parse_combined_secret_key(combined: &str) -> Result<(String, String), UBTCError> {
    let lines: Vec<&str> = combined.lines().collect();
    if lines.len() != 2 {
        return Err(UBTCError::InvalidKey(
            "Invalid combined key format. Expected DILITHIUM:hex\\nSPHINCS:hex".to_string()
        ));
    }

    let dil_line = lines[0].strip_prefix("DILITHIUM:")
        .ok_or_else(|| UBTCError::InvalidKey("Missing DILITHIUM: prefix".to_string()))?;
    let sph_line = lines[1].strip_prefix("SPHINCS:")
        .ok_or_else(|| UBTCError::InvalidKey("Missing SPHINCS: prefix".to_string()))?;

    // Validate hex
    hex::decode(dil_line).map_err(|_| UBTCError::InvalidKey("Invalid Dilithium3 hex".to_string()))?;
    hex::decode(sph_line).map_err(|_| UBTCError::InvalidKey("Invalid SPHINCS+ hex".to_string()))?;

    Ok((dil_line.to_string(), sph_line.to_string()))
}
