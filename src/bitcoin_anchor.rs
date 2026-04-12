use serde::{Deserialize, Serialize};
use crate::nullifier::NullifierBatch;
use crate::errors::UBTCError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCommitment {
    pub merkle_root: [u8; 32],
    pub bitcoin_txid: Option<String>,
    pub block_height: Option<u64>,
    pub nullifier_count: usize,
}

pub async fn post_nullifier_to_bitcoin(
    batch: &NullifierBatch,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
) -> Result<String, UBTCError> {
    let payload = batch.op_return_payload();
    let payload_hex = hex::encode(&payload);

    let client = reqwest::Client::new();

    let res = client
        .post(rpc_url)
        .basic_auth(rpc_user, Some(rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "createrawtransaction",
            "params": [[], {"data": payload_hex}]
        }))
        .send()
        .await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let data: serde_json::Value = res.json().await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let raw_tx = data["result"].as_str()
        .ok_or_else(|| UBTCError::Bitcoin("Failed to create raw transaction".to_string()))?;

    let fund_res = client
        .post(rpc_url)
        .basic_auth(rpc_user, Some(rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "fundrawtransaction",
            "params": [raw_tx]
        }))
        .send()
        .await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let fund_data: serde_json::Value = fund_res.json().await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let funded_tx = fund_data["result"]["hex"].as_str()
        .ok_or_else(|| UBTCError::Bitcoin("Failed to fund transaction".to_string()))?;

    let sign_res = client
        .post(rpc_url)
        .basic_auth(rpc_user, Some(rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "signrawtransactionwithwallet",
            "params": [funded_tx]
        }))
        .send()
        .await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let sign_data: serde_json::Value = sign_res.json().await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let signed_hex = sign_data["result"]["hex"].as_str()
        .ok_or_else(|| UBTCError::Bitcoin("Failed to sign transaction".to_string()))?;

    let send_res = client
        .post(rpc_url)
        .basic_auth(rpc_user, Some(rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "sendrawtransaction",
            "params": [signed_hex]
        }))
        .send()
        .await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let send_data: serde_json::Value = send_res.json().await
        .map_err(|e| UBTCError::Network(e.to_string()))?;

    let txid = send_data["result"].as_str()
        .ok_or_else(|| UBTCError::Bitcoin("Failed to broadcast transaction".to_string()))?
        .to_string();

    Ok(txid)
}
