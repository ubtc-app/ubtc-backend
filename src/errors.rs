use thiserror::Error;

#[derive(Debug, Error)]
pub enum UBTCError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid chain: {0}")]
    InvalidChain(String),

    #[error("Insufficient balance: available {available}, requested {requested}")]
    InsufficientBalance { available: u64, requested: u64 },

    #[error("Insufficient collateral: required {required:.2}x, actual {actual:.2}x")]
    InsufficientCollateral { required: f64, actual: f64 },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Bitcoin error: {0}")]
    Bitcoin(String),

    #[error("Collateral mismatch: {0}")]
    CollateralMismatch(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Double spend detected")]
    DoubleSpend,

    #[error("Proof too large: {size} bytes")]
    ProofTooLarge { size: usize },

    #[error("Unknown error: {0}")]
    Unknown(String),
}
