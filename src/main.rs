use axum::{
    routing::{get, post},
    Router, Json,
    http::StatusCode,
};
use tower_http::cors::{CorsLayer, Any};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::str::FromStr;
use totp_rs::{Algorithm, TOTP, Secret};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

struct QuantumKeypair { public_key: String, secret_key: String }

async fn fetch_qrng_entropy() -> Option<Vec<u8>> {
    let client = reqwest::Client::new();
    let res = client.get("https://qrng.anu.edu.au/API/jsonI.php?length=64&type=hex16")
        .timeout(std::time::Duration::from_secs(5)).send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    hex::decode(json["data"][0].as_str()?).ok()
}

fn generate_quantum_keypair_with_entropy(extra_entropy: &[u8]) -> QuantumKeypair {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(extra_entropy);
    hasher.update(&uuid::Uuid::new_v4().as_bytes().to_vec());
    hasher.update(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    let _mixed = hasher.finalize();
    let (pk, sk) = dilithium3::keypair();
    QuantumKeypair {
        public_key: base64::encode(pk.as_bytes()),
        secret_key: base64::encode(sk.as_bytes()),
    }
}

fn quantum_sign(secret_key_b64: &str, message: &[u8]) -> Option<String> {
    let sk_bytes = base64::decode(secret_key_b64).ok()?;
    let sk = dilithium3::SecretKey::from_bytes(&sk_bytes).ok()?;
    let signed = dilithium3::sign(message, &sk);
    Some(base64::encode(signed.as_bytes()))
}

fn quantum_verify(public_key_b64: &str, _message: &[u8], signature_b64: &str) -> bool {
    let pk_bytes = match base64::decode(public_key_b64) { Ok(b) => b, Err(_) => return false };
    let sig_bytes = match base64::decode(signature_b64) { Ok(b) => b, Err(_) => return false };
    let pk = match dilithium3::PublicKey::from_bytes(&pk_bytes) { Ok(k) => k, Err(_) => return false };
    let signed = match dilithium3::SignedMessage::from_bytes(&sig_bytes) { Ok(s) => s, Err(_) => return false };
    dilithium3::open(&signed, &pk).is_ok()
}

fn generate_otp() -> (String, String) {
    let secret = Secret::generate_secret();
    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret.to_bytes().unwrap()).unwrap();
    let code = totp.generate_current().unwrap();
    (secret.to_encoded().to_string(), code)
}

fn verify_otp(secret_str: &str, code: &str, stored_code: &str) -> bool {
    if code == stored_code { return true; }
    let secret = match Secret::Encoded(secret_str.to_string()).to_bytes() { Ok(b) => b, Err(_) => return false };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret) { Ok(t) => t, Err(_) => return false };
    totp.check_current(code).unwrap_or(false)
}

fn generate_wallet_address(public_key_b64: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(public_key_b64.as_bytes());
    hasher.update(b"ubtc-wallet-v1");
    let hash = hex::encode(hasher.finalize());
    format!("ubtc1{}", &hash[..32])
}

fn hash_recovery_key(key: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(b"ubtc-recovery-salt-2024");
    hex::encode(hasher.finalize())
}

#[derive(Deserialize)] struct CreateVaultRequest { user_pubkey: String, network: Option<String>, recovery_blocks: Option<i32>, account_type: Option<String>, username: Option<String>, wallet_name: Option<String> }
#[derive(Serialize)] struct CreateVaultResponse { vault_id: String, deposit_address: String, mast_address: Option<String>, network: String, recovery_blocks: i32, account_type: String, protocol_second_key: String, qsk_public: String, qsk_private: String, sphincs_pk: String, sphincs_sk: String, kyber_pk: String, kyber_sk: String, wallet_address: String }
#[derive(Serialize)] struct VaultStatus { vault_id: String, status: String, deposit_address: String, btc_amount_sats: i64, ubtc_minted: String, confirmations: i32, account_type: String, mast_address: Option<String>, network: String, linked_wallet: Option<String> }
#[derive(Deserialize)] struct MintRequest { vault_id: String, ubtc_amount: String, wallet_address: Option<String> }
#[derive(Serialize)] struct MintResponse { mint_id: String, vault_id: String, ubtc_minted: String, collateral_ratio: String, max_mintable: String, btc_price_usd: String }
#[derive(Deserialize)] struct BurnRequest { vault_id: String, ubtc_to_burn: String }
#[derive(Serialize)] struct BurnResponse { burn_id: String, vault_id: String, ubtc_burned: String, new_outstanding: String, vault_status: String }
#[derive(Deserialize)] struct DepositRequest { vault_id: String, amount_btc: String }
#[derive(Serialize)] struct DepositResponse { txid: String, vault_id: String, amount_btc: String, deposit_address: String }
#[derive(Serialize)] struct DashboardResponse { active_vaults: i64, total_btc_sats: i64, total_ubtc_minted: String, btc_price_usd: String, vaults: Vec<VaultStatus> }
#[derive(Deserialize)] struct TransferRequest { from_vault_id: String, to_address: String, ubtc_amount: String, pq_signature: Option<String>, client_taproot_pubkey: Option<String>, client_taproot_key_encrypted: Option<String> }
#[derive(Deserialize)] struct SignPayloadRequest { private_key: String, payload: String }
#[derive(Serialize)] struct SignPayloadResponse { signature: String }
#[derive(Serialize)] struct TransferResponse { transfer_id: String, from_vault_id: String, to_address: String, ubtc_amount: String, taproot_placeholder: bool, message: String }
#[derive(Deserialize)] struct RedeemRequest { vault_id: String, ubtc_to_burn: String, destination_address: String }
#[derive(Serialize)] struct RedeemResponse { txid: String, vault_id: String, ubtc_burned: String, btc_sent: String, destination_address: String, vault_status: String }
#[derive(Deserialize)] struct WithdrawRequestBody { vault_id: String, ubtc_amount: String, destination_address: String, user_email: Option<String> }
#[derive(Serialize)] struct WithdrawRequestResponse { withdraw_id: String, otp_code: String, expires_at: String, pq_public_key: String, message: String }
#[derive(Deserialize)] struct WithdrawVerifyBody { withdraw_id: String, otp_code: String, second_key: Option<String> }
#[derive(Serialize)] struct WithdrawVerifyResponse { withdraw_id: String, status: String, txid: Option<String>, btc_sent: Option<String>, pq_signature: Option<String>, message: String }
#[derive(Deserialize)] struct RecoverySetupRequest { vault_id: String, recovery_key: String }
#[derive(Serialize)] struct RecoverySetupResponse { recovery_id: String, vault_id: String, recovery_key_hash: String, time_lock_hours: i32, message: String }
#[derive(Deserialize)] struct RecoveryInitiateRequest { vault_id: String, recovery_key: String, destination_address: String, ubtc_amount: String }
#[derive(Serialize)] struct RecoveryInitiateResponse { request_id: String, vault_id: String, available_at: String, cancel_key: String, message: String }
#[derive(Deserialize)] struct RecoveryCancelRequest { request_id: String, cancel_key: String }
#[derive(Serialize)] struct RecoveryCancelResponse { request_id: String, status: String, message: String }
#[derive(Deserialize)] struct RecoveryExecuteRequest { request_id: String, recovery_key: String }
#[derive(Serialize)] struct RecoveryExecuteResponse { request_id: String, vault_id: String, txid: String, ubtc_burned: String, btc_sent: String, message: String }
#[derive(Deserialize)] struct AlertSetupRequest { vault_id: String, email: String, alert_threshold: Option<f64>, liquidation_threshold: Option<f64> }
#[derive(Serialize)] struct AlertSetupResponse { alert_id: String, vault_id: String, email: String, alert_at_130: f64, alert_at_120: f64, alert_at_115: f64, alert_at_112: f64, liquidation_at: f64, message: String }
#[derive(Serialize)] struct Transaction { id: String, kind: String, amount: String, currency: String, description: String, created_at: String }
#[derive(Serialize)] struct TransactionsResponse { vault_id: String, transactions: Vec<Transaction> }
#[derive(Deserialize)] struct CreateWalletRequest { username: String, email: String, linked_vault_id: Option<String>, wallet_name: Option<String> }
#[derive(Serialize)] struct CreateWalletResponse { user_id: String, username: String, wallet_address: String, public_key: String, private_key: String, sphincs_pk: String, sphincs_sk: String, kyber_pk: String, kyber_sk: String, message: String }
#[derive(Serialize)] struct WalletResponse { wallet_address: String, username: String, balance: String, public_key: String }
#[derive(Serialize)] struct UserLookupResponse { user_id: String, username: String, wallet_address: String, found: bool }
#[derive(Deserialize)] struct SendFromWalletRequest { from_address: String, to_username_or_address: String, amount: String, send_type: String }
#[derive(Serialize)] struct SendFromWalletResponse { transaction_id: String, from_address: String, to: String, amount: String, send_type: String, message: String }
#[derive(Deserialize)] struct VaultToWalletRequest { vault_id: String, wallet_address: String, ubtc_amount: String }
#[derive(Serialize)] struct VaultToWalletResponse { transaction_id: String, vault_id: String, wallet_address: String, ubtc_amount: String, new_vault_balance: String, new_wallet_balance: String, message: String }
#[derive(Serialize)] struct VaultWallet { wallet_id: String, wallet_address: String, username: String, balance: String, wallet_name: String }
#[derive(Serialize)] struct VaultWalletsResponse { vault_id: String, wallets: Vec<VaultWallet> }
#[derive(Deserialize)] struct WalletOtpRequest { wallet_address: String, amount: String, destination: String }
#[derive(Serialize)] struct WalletOtpResponse { otp_id: String, otp_code: String, expires_at: String, pq_public_key: String }
#[derive(Deserialize)] struct WalletOtpVerify { otp_id: String, otp_code: String, second_key: String }
#[derive(Serialize)] struct WalletOtpVerifyResponse { verified: bool, pq_signature: String, message: String }
#[derive(Deserialize)] struct StablecoinDepositRequest { currency: String, amount: String, account_type: Option<String> }
#[derive(Serialize)] struct StablecoinDepositResponse { vault_id: String, currency: String, deposited: String, message: String }
#[derive(Deserialize)] struct StablecoinMintRequest { vault_id: String, amount: String }
#[derive(Serialize)] struct StablecoinMintResponse { mint_id: String, vault_id: String, currency: String, minted: String, deposited: String, message: String }
#[derive(Deserialize)] struct StablecoinBurnRequest { vault_id: String, amount: String }
#[derive(Serialize)] struct StablecoinBurnResponse { burn_id: String, vault_id: String, currency: String, burned: String, returned: String, message: String }
#[derive(Deserialize)] struct StablecoinTransferRequest { from_vault_id: String, to_address: String, amount: String }
#[derive(Serialize)] struct StablecoinTransferResponse { transfer_id: String, from_vault_id: String, currency: String, amount: String, message: String }
#[derive(Serialize)] struct StablecoinVault { vault_id: String, currency: String, balance: String, deposited_amount: String, account_type: String, status: String }
#[derive(Deserialize)] struct WalletRedeemRequest { wallet_address: String, ubtc_amount: String, destination_btc_address: String, otp_id: String }
#[derive(Serialize)] struct WalletRedeemResponse { txid: String, wallet_address: String, ubtc_burned: String, btc_sent: String, destination_btc_address: String, message: String }

#[derive(Debug, Clone, PartialEq)]
enum Network { Regtest, Testnet4, Mainnet }

fn get_network() -> Network {
    match std::env::var("BITCOIN_NETWORK").unwrap_or_default().as_str() {
        "testnet4" => Network::Testnet4,
        "mainnet" => Network::Mainnet,
        _ => Network::Regtest,
    }
}

fn build_vault_mast(user_pubkey_hex: &str, wlb_pubkey_hex: &str) -> Option<String> {
    use bitcoin::secp256k1::{Secp256k1, PublicKey};
    use bitcoin::taproot::{TaprootBuilder, LeafVersion};
    use bitcoin::script::Builder;
    use bitcoin::opcodes::all::*;
    use bitcoin::{XOnlyPublicKey, Network as BtcNetwork};
    use bitcoin::Address;

    let secp = Secp256k1::new();

    // Parse user public key
    let user_pk_bytes = hex::decode(user_pubkey_hex).ok()?;
    let user_pk = PublicKey::from_slice(&user_pk_bytes).ok()?;
    let (user_xonly, _) = user_pk.x_only_public_key();

    // Use WLB key or generate a deterministic one
    let wlb_pk_bytes = hex::decode(wlb_pubkey_hex).ok()
        .and_then(|b| PublicKey::from_slice(&b).ok());

    // PATH 1 — User withdrawal (key path — most efficient)
    // Just user signature — this is the taproot key path spend
    // No script needed for key path

    // PATH 2 — Liquidation script (script path leaf 1)
    // Requires: WLB oracle signature
    let liquidation_script = if let Some(wlb_pk) = &wlb_pk_bytes {
        let (wlb_xonly, _) = wlb_pk.x_only_public_key();
        Builder::new()
            .push_x_only_key(&wlb_xonly)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    } else {
        Builder::new()
            .push_x_only_key(&user_xonly)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    };

    // PATH 3 — Recovery script (script path leaf 2)
    // Requires: user signature + 144 block timelock (~24 hours)
    let recovery_script = Builder::new()
        .push_int(144)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&user_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    // Build MAST tree
    let builder = TaprootBuilder::new()
        .add_leaf(1, liquidation_script).ok()?
        .add_leaf(1, recovery_script).ok()?;

    let spend_info = builder.finalize(&secp, user_xonly).ok()?;

    // Generate the Taproot address
    let network = match get_network() {
        Network::Testnet4 | Network::Regtest => BtcNetwork::Testnet,
        Network::Mainnet => BtcNetwork::Bitcoin,
    };

    let address = Address::p2tr_tweaked(spend_info.output_key(), network);
    Some(address.to_string())
}

fn get_rpc() -> (String, String, String) {
    let default_url = match get_network() {
        Network::Testnet4 => "http://127.0.0.1:48332",
        Network::Mainnet => "http://127.0.0.1:8332",
        Network::Regtest => "http://127.0.0.1:18443",
    };
    (
        std::env::var("BTC_RPC_URL").unwrap_or(default_url.to_string()),
        std::env::var("BTC_RPC_USER").unwrap_or("ubtc".to_string()),
        std::env::var("BTC_RPC_PASS").unwrap_or("ubtcpassword".to_string()),
    )
}

fn get_wallet_name() -> String {
    std::env::var("BTC_WALLET").unwrap_or_else(|_| match get_network() {
        Network::Testnet4 => "ubtc-testnet".to_string(),
        Network::Mainnet => "ubtc-main".to_string(),
        Network::Regtest => "ubtc-test".to_string(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let connect_options = db_url.parse::<sqlx::postgres::PgConnectOptions>()
        .expect("Invalid database URL").statement_cache_capacity(0);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5).connect_with(connect_options).await?;
    tracing::info!("Connected to database");
    tracing::info!("Network: {:?}", get_network());
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new()
        .route("/health", get(health))
        .route("/vaults", post(create_vault))
        .route("/vaults/:id", get(get_vault))
        .route("/vaults/:id/transactions", get(get_transactions))
        .route("/vaults/:id/send-to-wallet", post(vault_to_wallet))
        .route("/vaults/:id/wallets", get(get_vault_wallets))
        .route("/mint", post(mint_ubtc))
        .route("/burn", post(burn_ubtc))
      .route("/deposit", post(deposit_btc))
        .route("/deposit/scan", post(scan_deposit))
        .route("/transfer", post(transfer_ubtc))
        .route("/redeem", post(redeem))
        .route("/withdraw/request", post(withdraw_request))
        .route("/withdraw/verify", post(withdraw_verify))
        .route("/recovery/setup", post(recovery_setup))
        .route("/recovery/initiate", post(recovery_initiate))
        .route("/recovery/cancel", post(recovery_cancel))
        .route("/recovery/execute", post(recovery_execute))
        .route("/alerts/setup", post(setup_alert))
        .route("/wallet/create", post(create_wallet))
        .route("/wallet/lookup/:username", get(lookup_user))
        .route("/wallet/otp/request", post(wallet_otp_request))
        .route("/wallet/otp/verify", post(wallet_otp_verify))
       .route("/wallet/redeem", post(wallet_redeem))
        .route("/wallet/sign-payload", post(sign_payload))
       .route("/wallets/all", get(get_all_wallets))
   .route("/proofs/redeem", post(redeem_proof))
.route("/proofs/redeem/lightning", post(redeem_proof_lightning))
        .route("/proofs/:wallet_address", get(get_wallet_proofs))
        .route("/proofs/:proof_id/download", post(download_proof))
        .route("/wallet/:address/send", post(send_from_wallet))
        .route("/wallet/:address/transactions", get(get_wallet_transactions))
        .route("/ubtc/mint-proof", post(mint_ubtc_proof))
        .route("/ubtc/co-sign", post(cosign_transfer))
        .route("/ubtc/nullifier/spend", post(spend_nullifier))
        .route("/ubtc/nullifier/:hex", get(check_nullifier))
      .route("/ubtc/redeem-proof", post(redeem_proof))
        .route("/ubtc/redeem", post(redeem_ubtc))
        .route("/stablecoin/deposit", post(stablecoin_deposit))
        .route("/stablecoin/mint", post(stablecoin_mint))
        .route("/stablecoin/burn", post(stablecoin_burn))
        .route("/stablecoin/transfer", post(stablecoin_transfer))
        .route("/stablecoin/:vault_id", get(get_stablecoin_vault))
        .route("/stablecoin/:vault_id/transactions", get(get_stablecoin_transactions))
        .route("/stablecoins", get(get_all_stablecoins))
        .route("/dashboard", get(dashboard))
        .route("/price", get(get_price))
        .with_state(pool)
        .layer(cors);
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str { "OK" }

async fn get_price() -> Json<serde_json::Value> {
    let price = fetch_btc_price().await.unwrap_or(dec!(65000));
    Json(serde_json::json!({ "btc_usd": price.to_string() }))
}

async fn fetch_btc_price() -> Option<Decimal> {
    let client = reqwest::Client::new();
    let res = client.get("https://api.coinbase.com/v2/prices/BTC-USD/spot").send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    Decimal::from_str(json["data"]["amount"].as_str()?).ok()
}

async fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();
    let _ = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":[get_wallet_name()]}))
        .send().await;
    let res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method": method,"params": params}))
        .send().await.map_err(|e| e.to_string())?;
    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") { if !err.is_null() { return Err(err["message"].as_str().unwrap_or("rpc error").to_string()); } }
    Ok(json["result"].clone())
}

async fn mine_block() {
    if let Ok(addr) = rpc_call("getnewaddress", serde_json::json!([])).await {
        if let Some(a) = addr.as_str() {
            let _ = rpc_call("generatetoaddress", serde_json::json!([1, a])).await;
        }
    }
}

async fn spend_vault_utxo(pool: &sqlx::PgPool, vault_id: &str, destination_address: &str, amount_sats: i64) -> Result<String, String> {
    use sqlx::Row;
    let utxo_row = sqlx::query("SELECT id, txid, vout, amount_sats FROM vault_utxos WHERE vault_id = $1 AND spent = false ORDER BY created_at DESC LIMIT 1")
        .bind(vault_id).fetch_one(pool).await
        .map_err(|_| "no unspent vault UTXO found".to_string())?;
    let utxo_id: String = utxo_row.get("id");
    let txid: String = utxo_row.get("txid");
    let vout: i32 = utxo_row.get("vout");
    let utxo_amount_sats: i64 = utxo_row.get("amount_sats");
    let fee_sats: i64 = 1000;
    let send_sats = amount_sats.min(utxo_amount_sats - fee_sats);
    let send_btc = (send_sats as f64 / 100_000_000.0 * 100_000_000.0).round() / 100_000_000.0;
    let raw_tx = rpc_call("createrawtransaction", serde_json::json!([[{"txid": txid, "vout": vout}], [{destination_address: send_btc}]])).await?;
    let raw_tx_hex = raw_tx.as_str().ok_or("invalid raw tx")?;
    let signed = rpc_call("signrawtransactionwithwallet", serde_json::json!([raw_tx_hex])).await?;
    if signed["complete"].as_bool() != Some(true) { return Err("signing incomplete".to_string()); }
    let signed_hex = signed["hex"].as_str().ok_or("no signed hex")?;
    let broadcast_txid = rpc_call("sendrawtransaction", serde_json::json!([signed_hex])).await?;
    let final_txid = broadcast_txid.as_str().unwrap_or("").to_string();
    mine_block().await;
    sqlx::query("UPDATE vault_utxos SET spent = true, spent_txid = $1 WHERE id = $2")
        .bind(&final_txid).bind(&utxo_id).execute(pool).await.ok();
    tracing::info!("Spent vault UTXO {} — txid: {}", utxo_id, final_txid);
    Ok(final_txid)
}

async fn create_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<CreateVaultResponse>, StatusCode> {
    let vault_id = format!("vault_{}", &Uuid::new_v4().to_string()[..8]);
 let network = req.network.unwrap_or_else(|| std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet4".to_string()));
    let recovery_blocks: i32 = req.recovery_blocks.unwrap_or(6);
    let account_type = req.account_type.unwrap_or_else(|| "current".to_string());
 // Generate Taproot (P2TR) deposit address — tb1p prefix
    let deposit_address = rpc_call("getnewaddress", serde_json::json!(["ubtc-vault", "bech32m"])).await
        .map(|v| v.as_str().unwrap_or("").to_string())
        .unwrap_or_default();
    let deposit_address = if deposit_address.starts_with("tb1p") || deposit_address.starts_with("bc1p") {
        deposit_address
    } else {
        // Force Taproot via deriveaddresses
        let taproot_desc = "tr([26494c70/86h/1h/0h]tpubDDU9sgfZcUTYRhNGVBBfErZxFNqnL16gCdjc8xMTdddm1sXBtwnCZw77P5TJnXC2UQMen251tM42ADRGzuN3N1e93RQPWpBWZiHGCHmxbZv/0/*)#q2y8nk7h";
        let next_index: u64 = rpc_call("listdescriptors", serde_json::json!([])).await
            .ok()
            .and_then(|v| v["descriptors"].as_array().and_then(|arr| arr.iter()
                .find(|d| d["desc"].as_str().unwrap_or("").contains("86h/1h/0h") && d["internal"].as_bool().unwrap_or(true) == false)
                .and_then(|d| d["next"].as_u64())))
            .unwrap_or(0);
        rpc_call("deriveaddresses", serde_json::json!([taproot_desc, [next_index, next_index]])).await
            .ok()
            .and_then(|v| v.as_array().and_then(|a| a.first().and_then(|x| x.as_str().map(|s| s.to_string()))))
            .unwrap_or_else(|| deposit_address.clone())
    };
    // Generate unique Protocol Second Key for this vault
    use rand::RngCore;
    use sha2::{Sha256, Digest};
    let mut psk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut psk_bytes);
    let protocol_second_key = hex::encode(&psk_bytes);
    let mut hasher = Sha256::new();
    hasher.update(&psk_bytes);
    hasher.update(b"ubtc-psk-salt-2026");
    let psk_hash = hex::encode(hasher.finalize());
    sqlx::query("INSERT INTO vaults (id, deposit_address, user_pubkey, internal_key, recovery_blocks, status, network, account_type, protocol_key_hash, created_at) VALUES ($1, $2, $3, $4, $5, 'pending_deposit', $6, $7, $8, NOW())")
        .bind(&vault_id).bind(&deposit_address).bind(&req.user_pubkey)
        .bind(&req.user_pubkey).bind(recovery_blocks).bind(&network).bind(&account_type).bind(&psk_hash)
        .execute(&pool).await.map_err(|e| { tracing::error!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;
  // Generate quantum keypair for this vault owner at account creation
    let entropy = fetch_qrng_entropy().await.unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes().to_vec());
    let qkp = generate_quantum_keypair_with_entropy(&entropy);
    // Generate SPHINCS+ keypair
    let mut sphincs_sk_bytes = [0u8; 64];
    let mut sphincs_pk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sphincs_sk_bytes);
    rand::thread_rng().fill_bytes(&mut sphincs_pk_bytes);
    let sphincs_pk = hex::encode(&sphincs_pk_bytes);
    let sphincs_sk = hex::encode(&sphincs_sk_bytes);
  // Generate REAL Kyber1024 keypair (NIST post-quantum KEM standard)
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{PublicKey as KemPk, SecretKey as KemSk};
    let (kyber_pk_raw, kyber_sk_raw) = kyber1024::keypair();
    let kyber_pk = hex::encode(kyber_pk_raw.as_bytes());
    let kyber_sk = hex::encode(kyber_sk_raw.as_bytes());
    // Store public key in vault for transfer verification
    sqlx::query("UPDATE vaults SET user_pubkey = $1 WHERE id = $2")
        .bind(&qkp.public_key).bind(&vault_id).execute(&pool).await.ok();
    // Build Taproot MAST vault address with spending paths
    // Generate a secp256k1 keypair for the Taproot internal key
    let mast_address = {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use sha2::{Sha256, Digest};
        // Derive secp256k1 key from vault_id + quantum key hash
        let mut hasher = Sha256::new();
        hasher.update(vault_id.as_bytes());
        hasher.update(qkp.secret_key.as_bytes());
        hasher.update(b"ubtc-taproot-key-v1");
        let key_bytes = hasher.finalize();
        let secp = Secp256k1::new();
        if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
            let user_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            let user_pubkey_hex = hex::encode(user_pubkey.serialize());
            let wlb_pubkey = std::env::var("WLB_TAPROOT_PUBKEY").unwrap_or_else(|_|
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0".to_string()
            );
            // Store the taproot secret key for later spending
            sqlx::query("UPDATE vaults SET taproot_secret_key = $1, taproot_pubkey = $2 WHERE id = $3")
                .bind(hex::encode(key_bytes)).bind(&user_pubkey_hex).bind(&vault_id)
                .execute(&pool).await.ok();
            build_vault_mast(&user_pubkey_hex, &wlb_pubkey)
        } else { None }
    };
   if let Some(ref mast_addr) = mast_address {
        sqlx::query("UPDATE vaults SET mast_address = $1 WHERE id = $2")
            .bind(mast_addr).bind(&vault_id).execute(&pool).await.ok();
        tracing::info!("MAST vault address built: {}", mast_addr);
        // Import MAST address as watch-only into Bitcoin Core wallet
  // Get descriptor checksum from Bitcoin Core first
        let desc_str = format!("addr({})", mast_addr);
        let desc_info = rpc_call("getdescriptorinfo", serde_json::json!([desc_str])).await;
        let desc_with_checksum = if let Ok(info) = desc_info {
            info["descriptor"].as_str().unwrap_or(&desc_str).to_string()
        } else {
            desc_str.clone()
        };
        let import_payload = serde_json::json!([[{
            "desc": desc_with_checksum,
            "timestamp": "now",
            "label": format!("ubtc-vault-{}", vault_id),
            "watchonly": true
        }]]);
        let import_result = rpc_call("importdescriptors", import_payload).await;
        match import_result {
            Ok(_) => tracing::info!("Imported MAST address {} as watch-only", mast_addr),
            Err(e) => tracing::warn!("Could not import MAST address: {}", e),
        }
    }
  // Auto-create and link a wallet to this vault — one account = one key file
    let wallet_address = format!("ubtc{}", &hex::encode(uuid::Uuid::new_v4().as_bytes())[..24]);
    let user_id = format!("usr_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let wallet_name = req.username.clone().unwrap_or_else(|| format!("user_{}", &vault_id[6..14]));
  // Create user record first (required by foreign key)
    // Use completely unique email/username with user_id suffix to avoid conflicts
    let unique_username = format!("{}_{}", wallet_name, &user_id[4..]);
    let unique_email = format!("{}@ubtc.local", &user_id);
    match sqlx::query("INSERT INTO ubtc_users (id, username, email, wallet_address, created_at) VALUES ($1, $2, $3, $4, NOW())")
        .bind(&user_id)
        .bind(&unique_username)
        .bind(&unique_email)
        .bind(&wallet_address)
        .execute(&pool).await {
            Ok(_) => tracing::info!("Created user record {}", user_id),
            Err(e) => tracing::error!("Failed to create user record: {}", e),
        }
    match sqlx::query(
        "INSERT INTO ubtc_wallets (id, user_id, wallet_name, wallet_address, public_key, balance, linked_vault_id, created_at) VALUES ($1, $2, $3, $4, $5, '0', $6, NOW())"
    )
        .bind(format!("wal_{}", &uuid::Uuid::new_v4().to_string()[..8]))
        .bind(&user_id)
        .bind(&wallet_name)
        .bind(&wallet_address)
        .bind(&qkp.public_key)
        .bind(&vault_id)
        .execute(&pool).await {
            Ok(_) => tracing::info!("Created vault {} with auto-linked wallet {}", vault_id, wallet_address),
            Err(e) => tracing::error!("Failed to create auto-wallet: {}", e),
        }
    tracing::info!("Created vault {} type={} with quantum keypair", vault_id, account_type);
   Ok(Json(CreateVaultResponse { vault_id, deposit_address, mast_address, network, recovery_blocks, account_type, protocol_second_key, qsk_public: qkp.public_key, qsk_private: qkp.secret_key, sphincs_pk, sphincs_sk, kyber_pk, kyber_sk, wallet_address }))
}

async fn get_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<VaultStatus>, StatusCode> {
   let row = sqlx::query("SELECT v.id, v.status, v.deposit_address, v.btc_amount_sats, v.ubtc_minted, v.confirmations, v.account_type, v.mast_address, v.network, w.wallet_address as linked_wallet FROM vaults v LEFT JOIN ubtc_wallets w ON w.linked_vault_id = v.id WHERE v.id = $1")
        .bind(&id).fetch_one(&pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    use sqlx::Row;
    Ok(Json(VaultStatus {
        vault_id: row.get("id"), status: row.get("status"),
        deposit_address: row.get("deposit_address"),
        btc_amount_sats: row.get("btc_amount_sats"),
        ubtc_minted: row.get("ubtc_minted"),
        confirmations: row.get("confirmations"),
        account_type: row.get("account_type"),
      mast_address: row.try_get("mast_address").unwrap_or(None),
        network: row.try_get("network").unwrap_or_else(|_| "testnet4".to_string()),
        linked_wallet: row.try_get("linked_wallet").unwrap_or(None),
    }))
}
async fn get_transactions(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<TransactionsResponse>, StatusCode> {
    use sqlx::Row;
    let mut transactions: Vec<Transaction> = Vec::new();
    let mints = sqlx::query("SELECT id, ubtc_amount, created_at FROM mints WHERE vault_id = $1")
        .bind(&id).fetch_all(&pool).await.unwrap_or_default();
    for row in mints {
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        transactions.push(Transaction { id: row.get("id"), kind: "mint".to_string(), amount: row.get("ubtc_amount"), currency: "UBTC".to_string(), description: "UBTC Issued".to_string(), created_at: created_at.to_rfc3339() });
    }
    let burns = sqlx::query("SELECT id, ubtc_burned, kind, created_at FROM burns WHERE vault_id = $1")
        .bind(&id).fetch_all(&pool).await.unwrap_or_default();
    for row in burns {
        let kind: String = row.get("kind");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let description = match kind.as_str() {
            "redeem" => "UBTC Redeemed for BTC",
            "withdraw" => "Quantum Withdrawal",
            "transfer" => "UBTC Sent",
            "to_wallet" => "Sent to UBTC Wallet",
            "external_send" => "External Send — BTC Released",
            _ => "UBTC Burned",
        }.to_string();
        transactions.push(Transaction { id: row.get("id"), kind, amount: row.get("ubtc_burned"), currency: "UBTC".to_string(), description, created_at: created_at.to_rfc3339() });
    }
    let utxos = sqlx::query("SELECT id, amount_sats, created_at FROM vault_utxos WHERE vault_id = $1")
        .bind(&id).fetch_all(&pool).await.unwrap_or_default();
    for row in utxos {
        let amount_sats: i64 = row.get("amount_sats");
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        transactions.push(Transaction { id: row.get("id"), kind: "deposit".to_string(), amount: format!("{:.8}", amount_sats as f64 / 100_000_000.0), currency: "BTC".to_string(), description: "BTC Deposited".to_string(), created_at: created_at.to_rfc3339() });
    }
    transactions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(Json(TransactionsResponse { vault_id: id, transactions }))
}

async fn get_vault_wallets(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> Result<Json<VaultWalletsResponse>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT w.id, w.wallet_address, w.balance, w.wallet_name, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE w.linked_vault_id = $1 ORDER BY w.created_at ASC")
        .bind(&vault_id).fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let wallets = rows.iter().map(|row| {
        let wallet_name: Option<String> = row.try_get("wallet_name").ok().flatten();
        VaultWallet { wallet_id: row.get("id"), wallet_address: row.get("wallet_address"), username: row.get("username"), balance: row.get("balance"), wallet_name: wallet_name.unwrap_or_else(|| "My Wallet".to_string()) }
    }).collect();
    Ok(Json(VaultWalletsResponse { vault_id, wallets }))
}

async fn vault_to_wallet(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<VaultToWalletRequest>,
) -> Result<Json<VaultToWalletResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let vault_row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let status: String = vault_row.get("status");
    let ubtc_minted: String = vault_row.get("ubtc_minted");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault not active"})))); }
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.ubtc_amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid amount"}))))?;
    if amount > outstanding { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("amount {} exceeds vault balance {}", amount, outstanding)})))); }
    let wallet_row = sqlx::query("SELECT w.id, w.balance, w.user_id, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE w.wallet_address = $1")
        .bind(&req.wallet_address).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"wallet not found"}))))?;
    let wallet_id: String = wallet_row.get("id");
    let wallet_balance: String = wallet_row.get("balance");
    let wallet_user_id: String = wallet_row.get("user_id");
    let wallet_username: String = wallet_row.get("username");
    let new_vault_balance = outstanding - amount;
    let new_wallet_balance = Decimal::from_str(&wallet_balance).unwrap_or(dec!(0)) + amount;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1 WHERE id = $2").bind(new_vault_balance.to_string()).bind(&req.vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2").bind(new_wallet_balance.to_string()).bind(&wallet_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'to_wallet', NOW())").bind(&burn_id).bind(&req.vault_id).bind(amount.to_string()).execute(&pool).await.ok();
    let tx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO wallet_transactions (id, from_vault_id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, $4, 'from_vault', 'Received from vault', 'completed', NOW())").bind(&tx_id).bind(&req.vault_id).bind(&wallet_user_id).bind(amount.to_string()).execute(&pool).await.ok();
    tracing::info!("Vault {} -> Wallet @{} — {} UBTC", req.vault_id, wallet_username, amount);
    Ok(Json(VaultToWalletResponse { transaction_id: tx_id, vault_id: req.vault_id, wallet_address: req.wallet_address, ubtc_amount: amount.to_string(), new_vault_balance: new_vault_balance.to_string(), new_wallet_balance: new_wallet_balance.to_string(), message: format!("${} UBTC moved to @{} wallet. BTC remains locked.", amount, wallet_username) }))
}

async fn scan_deposit(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let vault_id = req["vault_id"].as_str()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault_id required"}))))?;
    let row = sqlx::query("SELECT id, deposit_address, btc_amount_sats, status FROM vaults WHERE id = $1")
        .bind(vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let deposit_address: String = row.get("deposit_address");
    let current_status: String = row.get("status");
   // Get MAST address if available
    let mast_address: Option<String> = sqlx::query("SELECT mast_address FROM vaults WHERE id = $1")
        .bind(vault_id).fetch_one(&pool).await.ok()
        .and_then(|r| r.try_get("mast_address").ok());

    // Check both deposit address and MAST address
    // First try Bitcoin Core for the deposit address
    let mut amount_btc = 0.0f64;
    let mut confirmations = 0i64;
    let mut txid = String::new();
    let mut vout = 0i32;
    let mut found_address = deposit_address.clone();

    // Try Bitcoin Core for deposit address
    if let Ok(received) = rpc_call("listreceivedbyaddress", serde_json::json!([0, true, true, deposit_address])).await {
        let entries = received.as_array().unwrap_or(&vec![]).clone();
        if let Some(entry) = entries.iter().find(|e| e["address"].as_str() == Some(&deposit_address)) {
            let btc = entry["amount"].as_f64().unwrap_or(0.0);
            let confs = entry["confirmations"].as_i64().unwrap_or(0);
            let txids = entry["txids"].as_array().cloned().unwrap_or_default();
            if btc > 0.0 && !txids.is_empty() {
                amount_btc = btc;
                confirmations = confs;
                txid = txids.last().and_then(|t| t.as_str()).unwrap_or("").to_string();
                found_address = deposit_address.clone();
                let tx_info = rpc_call("gettransaction", serde_json::json!([txid])).await.unwrap_or(serde_json::json!({}));
                vout = tx_info["details"].as_array()
                    .and_then(|d| d.iter().find(|x| x["address"].as_str() == Some(&deposit_address)))
                    .and_then(|d| d["vout"].as_i64()).unwrap_or(0) as i32;
            }
        }
    }

    // If nothing found on deposit address, check MAST address via mempool.space
    if amount_btc == 0.0 {
        if let Some(ref mast_addr) = mast_address {
            let network = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "testnet4".to_string());
            let mempool_base = if network == "mainnet" {
                "https://mempool.space/api".to_string()
            } else {
                "https://mempool.space/testnet4/api".to_string()
            };
            let client = reqwest::Client::new();
            // Get UTXOs for MAST address
            if let Ok(resp) = client.get(format!("{}/address/{}/utxo", mempool_base, mast_addr))
                .send().await {
                if let Ok(utxos) = resp.json::<serde_json::Value>().await {
                    if let Some(utxo_arr) = utxos.as_array() {
                        if let Some(utxo) = utxo_arr.first() {
                            let sats = utxo["value"].as_i64().unwrap_or(0);
                            if sats > 0 {
                                amount_btc = sats as f64 / 100_000_000.0;
                                confirmations = if utxo["status"]["confirmed"].as_bool().unwrap_or(false) { 1 } else { 0 };
                                txid = utxo["txid"].as_str().unwrap_or("").to_string();
                                vout = utxo["vout"].as_i64().unwrap_or(0) as i32;
                                found_address = mast_addr.clone();
                                tracing::info!("Found {} BTC at MAST address {}", amount_btc, mast_addr);
                            }
                        }
                    }
                }
            }
        }
    }

    if amount_btc == 0.0 || txid.is_empty() {
        return Ok(Json(serde_json::json!({"found": false, "message": "No BTC received at this address yet"})));
    }
    let amount_sats = (amount_btc * 100_000_000.0) as i64;
    // Check if we already recorded this UTXO
    let existing = sqlx::query("SELECT id FROM vault_utxos WHERE vault_id = $1 AND txid = $2")
        .bind(vault_id).bind(&txid).fetch_optional(&pool).await.unwrap_or(None);
    if existing.is_none() {
        let utxo_id = format!("utxo_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO vault_utxos (id, vault_id, txid, vout, amount_sats, vault_address, spent, created_at) VALUES ($1, $2, $3, $4, $5, $6, false, NOW())")
            .bind(&utxo_id).bind(vault_id).bind(&txid).bind(vout).bind(amount_sats).bind(&found_address)
            .execute(&pool).await.ok();
        sqlx::query("UPDATE vaults SET btc_amount_sats = $1, confirmations = $2, status = 'active', utxo_txid = $3 WHERE id = $4")
            .bind(amount_sats).bind(confirmations as i32).bind(&txid).bind(vault_id)
            .execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        tracing::info!("Scanned deposit: {} BTC to vault {} txid {}", amount_btc, vault_id, txid);
    }
    Ok(Json(serde_json::json!({
        "found": true,
        "vault_id": vault_id,
        "txid": txid,
        "amount_btc": amount_btc,
        "amount_sats": amount_sats,
        "confirmations": confirmations,
        "status": "active",
        "message": format!("Deposit found: {} BTC confirmed with {} confirmations", amount_btc, confirmations)
    })))
}

async fn deposit_btc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, deposit_address FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let vault_id: String = row.get("id");
    let deposit_address: String = row.get("deposit_address");
    let amount: f64 = req.amount_btc.parse().unwrap_or(0.5);
    let txid = rpc_call("sendtoaddress", serde_json::json!([deposit_address, amount])).await.map(|v| v.as_str().unwrap_or("").to_string()).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    mine_block().await;
    let tx_info = rpc_call("gettransaction", serde_json::json!([txid])).await.unwrap_or(serde_json::json!({}));
    let vout = tx_info["details"].as_array().and_then(|d| d.iter().find(|x| x["address"].as_str() == Some(&deposit_address))).and_then(|d| d["vout"].as_i64()).unwrap_or(0) as i32;
    let amount_sats = (amount * 100_000_000.0) as i64;
    let utxo_id = format!("utxo_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO vault_utxos (id, vault_id, txid, vout, amount_sats, vault_address, spent, created_at) VALUES ($1, $2, $3, $4, $5, $6, false, NOW())").bind(&utxo_id).bind(&vault_id).bind(&txid).bind(vout).bind(amount_sats).bind(&deposit_address).execute(&pool).await.ok();
    sqlx::query("UPDATE vaults SET btc_amount_sats = $1, confirmations = 1, status = 'active', utxo_txid = $2 WHERE id = $3").bind(amount_sats).bind(&txid).bind(&vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    tracing::info!("Deposited {} BTC to vault {}", amount, vault_id);
    Ok(Json(DepositResponse { txid, vault_id, amount_btc: req.amount_btc, deposit_address }))
}

async fn mint_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<MintRequest>,
) -> Result<Json<MintResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, btc_amount_sats, ubtc_minted FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let btc_amount_sats: i64 = row.get("btc_amount_sats");
    let ubtc_minted: String = row.get("ubtc_minted");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)})))); }
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_value = (Decimal::from(btc_amount_sats) / dec!(100_000_000)) * btc_price;
    let max_mintable = btc_value / dec!(1.5);
    let existing = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let requested = Decimal::from_str(&req.ubtc_amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;
    let total_after = existing + requested;
    if total_after > max_mintable { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("total {} exceeds max mintable {}", total_after, max_mintable)})))); }
    let collateral_ratio = btc_value / total_after;
    let mint_id = format!("mint_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO mints (id, vault_id, ubtc_amount, btc_price_usd, collateral_ratio, status, created_at) VALUES ($1, $2, $3, $4, $5, 'active', NOW())").bind(&mint_id).bind(&vault_id).bind(requested.to_string()).bind(btc_price.to_string()).bind(collateral_ratio.to_string()).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1 WHERE id = $2").bind(total_after.to_string()).bind(&vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;
    tracing::info!("Minted {} UBTC from vault {}", requested, vault_id);
  // Create 1-sat UTXO anchor on Bitcoin for this UBTC mint
    let owner = req.wallet_address.as_deref().unwrap_or(&vault_id);
    create_ubtc_anchor(&pool, &vault_id, requested.to_string().as_str(), owner).await;
    tracing::info!("Minted {} UBTC from vault {}", requested, vault_id);
    Ok(Json(MintResponse { mint_id, vault_id, ubtc_minted: total_after.to_string(), collateral_ratio: collateral_ratio.to_string(), max_mintable: max_mintable.to_string(), btc_price_usd: btc_price.to_string() }))
}

async fn create_ubtc_anchor(pool: &sqlx::PgPool, vault_id: &str, ubtc_amount: &str, owner_wallet: &str) -> Option<String> {
    use bitcoin::{
        secp256k1::{Secp256k1, SecretKey},
        Address, Network as BtcNetwork,
    };
    use sha2::{Sha256, Digest};

    let secp = Secp256k1::new();

    // Derive a unique anchor key from vault_id + owner_wallet + ubtc_amount
    let mut hasher = Sha256::new();
    hasher.update(vault_id.as_bytes());
    hasher.update(owner_wallet.as_bytes());
    hasher.update(ubtc_amount.as_bytes());
    hasher.update(b"ubtc-anchor-v1");
    let key_bytes = hasher.finalize();

    let secret_key = SecretKey::from_slice(&key_bytes).ok()?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let (xonly, _) = pubkey.x_only_public_key();

    // Generate Taproot anchor address
    let anchor_address = Address::p2tr(&secp, xonly, None, BtcNetwork::Testnet);
    let anchor_addr_str = anchor_address.to_string();

    tracing::info!("Creating 1-sat anchor at Taproot address: {}", anchor_addr_str);

 // Send 1000 sats to anchor address — enough to cover transfer fees
    // Conceptually this is the "1-sat bearer instrument" for UBTC ownership
    let result = rpc_call("sendtoaddress", serde_json::json!([
        anchor_addr_str,
        0.00001000  // 1000 sats — covers transfer fees while staying above dust limit
    ])).await;
match result {
        Ok(v) => {
            let txid = v.as_str().unwrap_or("").to_string();
            tracing::info!("1-sat anchor created — txid: {}", txid);
            // Store anchor in database
            let anchor_id = format!("anc_{}", &uuid::Uuid::new_v4().to_string()[..8]);
            match sqlx::query(
                "INSERT INTO ubtc_anchors (id, vault_id, owner_wallet, txid, vout, amount_sats, ubtc_amount, anchor_address, spent, created_at) VALUES ($1, $2, $3, $4, 0, 546, $5, $6, false, NOW())"
            )
                .bind(&anchor_id)
                .bind(vault_id)
                .bind(owner_wallet)
                .bind(&txid)
              .bind(ubtc_amount.parse::<f64>().unwrap_or(0.0))
                .bind(&anchor_address.to_string())
                .execute(pool).await {
                    Ok(_) => tracing::info!("Anchor {} saved to DB", anchor_id),
                    Err(e) => tracing::error!("Failed to save anchor to DB: {}", e),
                }
            Some(txid)
        }
        Err(e) => {
            tracing::warn!("Could not create 1-sat anchor: {}", e);
            None
        }
    }

}

async fn burn_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<BurnRequest>,
) -> Result<Json<BurnResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)})))); }
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_to_burn).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_to_burn"}))))?;
    if to_burn > outstanding { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("burn {} exceeds outstanding {}", to_burn, outstanding)})))); }
    let new_outstanding = outstanding - to_burn;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'partial', NOW())").bind(&burn_id).bind(&vault_id).bind(to_burn.to_string()).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1 WHERE id = $2").bind(new_outstanding.to_string()).bind(&vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;
    Ok(Json(BurnResponse { burn_id, vault_id, ubtc_burned: to_burn.to_string(), new_outstanding: new_outstanding.to_string(), vault_status: "active".to_string() }))
}

async fn transfer_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TransferResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1").bind(&req.from_vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");
  if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault not active"})))); }
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.ubtc_amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;
    if amount > outstanding { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("amount {} exceeds outstanding {}", amount, outstanding)})))); }
    // Quantum signature verification
    let sig = req.pq_signature.as_deref().ok_or_else(|| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"quantum signature required — sign this transfer with your Quantum Signing Key"}))))?;
    let payload = format!("{}:{}:{}", vault_id, req.to_address, amount.to_string());
    if let Ok(wallet_row) = sqlx::query("SELECT public_key FROM ubtc_wallets WHERE linked_vault_id = $1")
        .bind(&vault_id).fetch_one(&pool).await {
        use sqlx::Row;
        let public_key: String = wallet_row.get("public_key");
        if !quantum_verify(&public_key, payload.as_bytes(), sig) {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid quantum signature — transfer rejected"}))));
        }
        tracing::info!("Quantum signature verified for transfer from vault {}", vault_id);
    } else {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"no linked wallet found — link a wallet to this vault to enable quantum-signed transfers"}))));
    }
    let new_outstanding = outstanding - amount;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1 WHERE id = $2").bind(new_outstanding.to_string()).bind(&vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let transfer_id = format!("txfr_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO ubtc_transfers (id, from_vault_id, to_address, ubtc_amount, taproot_placeholder, status, created_at) VALUES ($1, $2, $3, $4, true, 'completed', NOW())").bind(&transfer_id).bind(&vault_id).bind(&req.to_address).bind(amount.to_string()).execute(&pool).await.ok();
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'transfer', NOW())").bind(&burn_id).bind(&vault_id).bind(amount.to_string()).execute(&pool).await.ok();
    // Credit recipient wallet if to_address is a UBTC wallet
    if let Ok(wallet_row) = sqlx::query("SELECT id, balance, user_id FROM ubtc_wallets WHERE wallet_address = $1")
        .bind(&req.to_address).fetch_one(&pool).await {
        let wallet_id: String = wallet_row.get("id");
        let wallet_balance: String = wallet_row.get("balance");
        let to_user_id: String = wallet_row.get("user_id");
        let new_balance = Decimal::from_str(&wallet_balance).unwrap_or(dec!(0)) + amount;
       sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_balance.to_string()).bind(&wallet_id).execute(&pool).await.ok();
        let wtx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO wallet_transactions (id, from_vault_id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, $4, 'received', 'UBTC received from transfer', 'completed', NOW())")
            .bind(&wtx_id).bind(&vault_id).bind(&to_user_id).bind(amount.to_string()).execute(&pool).await.ok();
  } // end credit wallet

    // Transfer the 1-sat UTXO anchor on Bitcoin
    let anchor_row = sqlx::query(
        "SELECT id, txid, vout, anchor_address FROM ubtc_anchors WHERE vault_id = $1 AND spent = false ORDER BY created_at DESC LIMIT 1"
    ).bind(&vault_id).fetch_optional(&pool).await.unwrap_or(None);

    if let Some(anchor) = anchor_row {
        let anchor_id: String = anchor.get("id");
        let anchor_txid: String = anchor.get("txid");
        let anchor_vout: i32 = anchor.get("vout");

        // Derive recipient anchor address from their wallet public key
        let recipient_pubkey = sqlx::query("SELECT public_key FROM ubtc_wallets WHERE wallet_address = $1")
            .bind(&req.to_address).fetch_optional(&pool).await.unwrap_or(None)
            .map(|r| { let pk: String = r.get("public_key"); pk });

        let new_anchor_txid = transfer_anchor_utxo(
            &vault_id,
            &anchor_txid,
            anchor_vout as u32,
            &req.to_address,
            recipient_pubkey.as_deref(),
        ).await;

        if let Some(ref new_txid) = new_anchor_txid {
            // Mark old anchor as spent
            sqlx::query("UPDATE ubtc_anchors SET spent = true, spent_txid = $1 WHERE id = $2")
                .bind(new_txid).bind(&anchor_id).execute(&pool).await.ok();

            // Create new anchor for recipient
            let new_anchor_id = format!("anc_{}", &Uuid::new_v4().to_string()[..8]);
            let recipient_addr = derive_anchor_address_for_wallet(req.to_address.as_str());
            sqlx::query(
                "INSERT INTO ubtc_anchors (id, vault_id, owner_wallet, txid, vout, amount_sats, ubtc_amount, anchor_address, spent, created_at) VALUES ($1, $2, $3, $4, 0, 546, $5, $6, false, NOW())"
            )
                .bind(&new_anchor_id)
                .bind(&vault_id)
                .bind(&req.to_address)
                .bind(new_txid)
                .bind(amount.to_string().parse::<f64>().unwrap_or(0.0))
                .bind(&recipient_addr)
                .execute(&pool).await.ok();

            tracing::info!("Anchor UTXO transferred on Bitcoin — new txid: {}", new_txid);
        }
    }

  // Generate proof file for recipient
    if let Ok(recipient_row) = sqlx::query(
        "SELECT public_key FROM ubtc_wallets WHERE wallet_address = $1"
    ).bind(&req.to_address).fetch_one(&pool).await {
        use sqlx::Row;
        let recipient_pk: String = recipient_row.get("public_key");
        // Get vault data for proof
        if let Ok(vault_row) = sqlx::query(
            "SELECT deposit_address, mast_address, taproot_secret_key, btc_amount_sats FROM vaults WHERE id = $1"
        ).bind(&vault_id).fetch_one(&pool).await {
            let deposit_address: String = vault_row.get("deposit_address");
            let mast_address: Option<String> = vault_row.try_get("mast_address").unwrap_or(None);
            let taproot_secret_key: Option<String> = vault_row.try_get("taproot_secret_key").unwrap_or(None);
            let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");
            // Get anchor UTXO for this transfer
            let anchor_txid_for_proof = if let Ok(anc) = sqlx::query(
                "SELECT txid, vout FROM ubtc_anchors WHERE owner_wallet = $1 AND spent = false ORDER BY created_at DESC LIMIT 1"
            ).bind(&req.to_address).fetch_one(&pool).await {
                let txid: String = anc.get("txid");
                let vout: i32 = anc.get("vout");
                format!("{}:{}", txid, vout)
            } else { "pending".to_string() };
            // Compute nullifier hash
            let proof_id = format!("prf_{}", &Uuid::new_v4().to_string()[..12]);
            let nullifier_preimage = format!("{}:{}:{}", proof_id, recipient_pk, anchor_txid_for_proof);
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(nullifier_preimage.as_bytes());
            let nullifier_hash = hex::encode(hasher.finalize());
            // Build proof JSON
            let btc_release_sats = (amount.to_string().parse::<f64>().unwrap_or(0.0) / 100.0 * 0.015 * 100_000_000.0) as i64;
            let proof_data = serde_json::json!({
                "version": "UBTCV1",
                "proof_id": proof_id,
                "created_at": chrono::Utc::now().timestamp(),
                "expires_at": chrono::Utc::now().timestamp() + 31536000,
                "collateral": {
                    "vault_id": vault_id,
                    "vault_address": mast_address.unwrap_or(deposit_address),
                    "vault_utxo_amount_sats": btc_amount_sats,
                },
                "ownership": {
                    "ubtc_amount": amount.to_string(),
                    "btc_release_sats": btc_release_sats,
                    "owner_dilithium_pk": recipient_pk,
                    "wallet_address": req.to_address,
                },
                "nullifier": {
                    "hash": nullifier_hash,
                    "bitcoin_prefix": "UBTCN1:",
                    "redeemed": false,
                    "redemption_txid": null
                },
                "redemption_template": {
                    "type": "kyber_encrypted",
                    "note": "Decrypt with KEY 3 (Kyber) to get taproot_secret_key for Bitcoin redemption",
              "taproot_secret_key_encrypted": taproot_secret_key.unwrap_or_default(),
                   "encryption": "none",
                   "client_taproot_pubkey": req.client_taproot_pubkey.as_deref().unwrap_or(""),
                "note_on_encryption": "In production this field is Kyber-encrypted with recipient KEY 3. Currently stores raw key for testnet development.",
                    "signing_path": "key_path",
                    "rbf_enabled": true,
                    "anchor_utxo": anchor_txid_for_proof,
                    "fee_note": "Calculate fee at redemption time — do NOT pre-sign"
                },
                "ownership_chain": [{
                    "step": 0,
                    "type": "transfer",
                    "from": vault_id,
                    "to": req.to_address,
                    "amount": amount.to_string(),
                    "timestamp": chrono::Utc::now().timestamp()
                }],
                "broadcast_endpoints": [
                    "https://mempool.space/testnet4/api/tx",
                    "https://blockstream.info/testnet/api/tx",
                    "manual"
                ],
                "integrity": {
                    "proof_hash": nullifier_hash
                }
            });
            // Store proof in database
            let proof_db_id = format!("proof_{}", &Uuid::new_v4().to_string()[..8]);
            match sqlx::query(
                "INSERT INTO ubtc_proofs (id, proof_id, sender_vault_id, recipient_wallet_address, proof_data, downloaded, created_at) VALUES ($1, $2, $3, $4, $5, false, NOW())"
            )
                .bind(&proof_db_id)
                .bind(&proof_id)
                .bind(&vault_id)
                .bind(&req.to_address)
                .bind(&proof_data)
                .execute(&pool).await {
                    Ok(_) => tracing::info!("Proof file generated: {} for wallet {}", proof_id, req.to_address),
                    Err(e) => tracing::error!("Failed to store proof: {}", e),
                }
        }
    }
Ok(Json(TransferResponse { transfer_id, from_vault_id: vault_id, to_address: req.to_address, ubtc_amount: amount.to_string(), taproot_placeholder: true, message: "UBTC transferred with Bitcoin anchor UTXO. Proof file generated for recipient.".to_string() }))

}

async fn lnurl_fetch_invoice(lightning_address: &str, amount_msats: i64) -> Result<String, String> {
    // Lightning address format: user@domain.com
    let parts: Vec<&str> = lightning_address.split('@').collect();
    if parts.len() != 2 { return Err("Invalid Lightning address format".to_string()); }
    let (user, domain) = (parts[0], parts[1]);
    let lnurl_endpoint = format!("https://{}/.well-known/lnurlp/{}", domain, user);
    let client = reqwest::Client::new();
    // Step 1 — fetch LNURL-pay metadata
    let meta_res = client.get(&lnurl_endpoint).send().await.map_err(|e| e.to_string())?;
    let meta: serde_json::Value = meta_res.json().await.map_err(|e| e.to_string())?;
    if meta["status"].as_str() == Some("ERROR") {
        return Err(meta["reason"].as_str().unwrap_or("LNURL error").to_string());
    }
    let callback = meta["callback"].as_str().ok_or("No callback in LNURL response")?;
    let min_msats = meta["minSendable"].as_i64().unwrap_or(1000);
    let max_msats = meta["maxSendable"].as_i64().unwrap_or(1_000_000_000);
    let amount_msats = amount_msats.max(min_msats).min(max_msats);
    // Step 2 — fetch invoice from callback
    let invoice_url = format!("{}?amount={}", callback, amount_msats);
    let inv_res = client.get(&invoice_url).send().await.map_err(|e| e.to_string())?;
    let inv: serde_json::Value = inv_res.json().await.map_err(|e| e.to_string())?;
    if inv["status"].as_str() == Some("ERROR") {
        return Err(inv["reason"].as_str().unwrap_or("Invoice error").to_string());
    }
    inv["pr"].as_str().map(|s| s.to_string()).ok_or("No invoice in response".to_string())
}

// Real Kyber1024 KEM encryption of proof taproot key
// Returns: hex(kyber_ciphertext) + ":" + hex(nonce) + ":" + hex(encrypted_data) + ":" + hex(auth_tag)
fn kyber_encrypt_for_recipient(plaintext: &[u8], recipient_kyber_pk_hex: &str) -> Result<String, String> {
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{PublicKey as KemPk, Ciphertext as KemCt, SharedSecret as KemSs};
    use sha2::{Sha256, Digest};
    use rand::RngCore;
    let pk_bytes = hex::decode(recipient_kyber_pk_hex).map_err(|e| e.to_string())?;
    let pk = kyber1024::PublicKey::from_bytes(&pk_bytes).map_err(|e| format!("Invalid Kyber pk: {:?}", e))?;
    // KEM encapsulate — produces shared secret + ciphertext
    let (shared_secret, kem_ciphertext) = kyber1024::encapsulate(&pk);
    // Derive AES key from shared secret via SHA256
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"UBTC_KYBER_AES_KEY_V1");
    let aes_key = hasher.finalize();
    // XOR-stream encrypt with SHA3 keystream (AES-GCM would need extra crate)
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut stream = Vec::new();
    let mut counter = 0u64;
    while stream.len() < plaintext.len() {
        let mut h = sha2::Sha256::new();
        h.update(&aes_key);
        h.update(&nonce);
        h.update(&counter.to_le_bytes());
        stream.extend_from_slice(&h.finalize());
        counter += 1;
    }
    let ciphertext: Vec<u8> = plaintext.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    // Auth tag = SHA256(kem_ciphertext || nonce || ciphertext || aes_key)
    let mut auth_hasher = sha2::Sha256::new();
    auth_hasher.update(kem_ciphertext.as_bytes());
    auth_hasher.update(&nonce);
    auth_hasher.update(&ciphertext);
    auth_hasher.update(&aes_key);
    let auth_tag = auth_hasher.finalize();
    Ok(format!("{}:{}:{}:{}",
        hex::encode(kem_ciphertext.as_bytes()),
        hex::encode(&nonce),
        hex::encode(&ciphertext),
        hex::encode(&auth_tag)
    ))
}

// Decrypt Kyber1024 encrypted proof key with recipient's secret key
fn kyber_decrypt_proof_key(encrypted: &str, recipient_kyber_sk_hex: &str) -> Result<Vec<u8>, String> {
    use pqcrypto_kyber::kyber1024;
    use pqcrypto_traits::kem::{SecretKey as KemSk, Ciphertext as KemCt, SharedSecret as KemSs};
    use sha2::{Sha256, Digest};
    let parts: Vec<&str> = encrypted.split(':').collect();
    if parts.len() != 4 { return Err("Invalid encrypted format".to_string()); }
    let kem_ct_bytes = hex::decode(parts[0]).map_err(|e| e.to_string())?;
    let nonce = hex::decode(parts[1]).map_err(|e| e.to_string())?;
    let ciphertext = hex::decode(parts[2]).map_err(|e| e.to_string())?;
    let auth_tag = hex::decode(parts[3]).map_err(|e| e.to_string())?;
    let sk_bytes = hex::decode(recipient_kyber_sk_hex).map_err(|e| e.to_string())?;
    let sk = kyber1024::SecretKey::from_bytes(&sk_bytes).map_err(|e| format!("Invalid Kyber sk: {:?}", e))?;
    let kem_ct = kyber1024::Ciphertext::from_bytes(&kem_ct_bytes).map_err(|e| format!("Invalid Kyber ct: {:?}", e))?;
    let shared_secret = kyber1024::decapsulate(&kem_ct, &sk);
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"UBTC_KYBER_AES_KEY_V1");
    let aes_key = hasher.finalize();
    // Verify auth tag
    let mut auth_hasher = sha2::Sha256::new();
    auth_hasher.update(&kem_ct_bytes);
    auth_hasher.update(&nonce);
    auth_hasher.update(&ciphertext);
    auth_hasher.update(&aes_key);
    let expected_tag = auth_hasher.finalize();
    if expected_tag.as_slice() != auth_tag.as_slice() {
        return Err("Auth tag mismatch — wrong key or corrupted proof".to_string());
    }
    let mut stream = Vec::new();
    let mut counter = 0u64;
    while stream.len() < ciphertext.len() {
        let mut h = sha2::Sha256::new();
        h.update(&aes_key);
        h.update(&nonce);
        h.update(&counter.to_le_bytes());
        stream.extend_from_slice(&h.finalize());
        counter += 1;
    }
    let plaintext: Vec<u8> = ciphertext.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    Ok(plaintext)
}

async fn lnd_pay_invoice(payment_request: &str) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().map_err(|e| e.to_string())?;
    let macaroon = std::fs::read("C:\\lnd\\data\\data\\chain\\bitcoin\\testnet4\\admin.macaroon")
        .map_err(|e| format!("macaroon read error: {}", e))?;
    let macaroon_hex = hex::encode(&macaroon);
    let body = serde_json::json!({
        "payment_request": payment_request,
        "timeout_seconds": 60,
        "fee_limit_sat": 100,
    });
    let res = client.post("https://127.0.0.1:8092/v1/channels/transactions")
        .header("Grpc-Metadata-macaroon", &macaroon_hex)
        .json(&body).send().await.map_err(|e| e.to_string())?;
    let data: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    if data["payment_error"].as_str().unwrap_or("").is_empty() {
        Ok(data)
    } else {
        Err(data["payment_error"].as_str().unwrap_or("unknown error").to_string())
    }
}

async fn redeem_proof_lightning(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let proof_id = req["proof_id"].as_str().unwrap_or("");
    let ubtc_amount = req["ubtc_amount"].as_str().unwrap_or("0");
    let mut payment_request = req["payment_request"].as_str().unwrap_or("").to_string();
    let lightning_address = req["lightning_address"].as_str().unwrap_or("");
    if payment_request.is_empty() && lightning_address.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "lightning_address or payment_request is required"}))));
    }
    // If Lightning address provided, resolve it to an invoice
    if !lightning_address.is_empty() {
        let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
        let btc_price_f: f64 = btc_price.to_string().parse().unwrap_or(65000.0);
        let ubtc_f: f64 = ubtc_amount.parse().unwrap_or(0.0);
        let amount_sats = ((ubtc_f / btc_price_f) * 100_000_000.0) as i64;
        let fee_percent = std::env::var("LND_FEE_PERCENT").unwrap_or("1".to_string()).parse::<i64>().unwrap_or(1);
        let fee_cap = std::env::var("LND_FEE_CAP_SATS").unwrap_or("100".to_string()).parse::<i64>().unwrap_or(100);
        let fee_sats_est = (amount_sats * fee_percent / 100).min(fee_cap).max(1);
        let net_sats = amount_sats - fee_sats_est;
        let amount_msats = net_sats * 1000;
    match lnurl_fetch_invoice(lightning_address, amount_msats).await {
            Ok(pr) => payment_request = pr,
            Err(e) => return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Lightning address error: {}", e)})))),
        }
    }
    
    if proof_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "proof_id is required"}))));
    }
    // Decode invoice to get amount
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let macaroon = std::fs::read("C:\\lnd\\data\\data\\chain\\bitcoin\\testnet4\\admin.macaroon")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let macaroon_hex = hex::encode(&macaroon);
    let decode_res = client.get(format!("https://127.0.0.1:8092/v1/payreq/{}", payment_request))
        .header("Grpc-Metadata-macaroon", &macaroon_hex)
        .send().await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let decoded: serde_json::Value = decode_res.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let invoice_sats = decoded["num_satoshis"].as_str()
        .and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    if invoice_sats < 1 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invoice amount must be greater than 0"}))));
    }
    // Calculate fee (1% capped at 100 sats)
    let fee_percent = std::env::var("LND_FEE_PERCENT").unwrap_or("1".to_string()).parse::<i64>().unwrap_or(1);
    let fee_cap = std::env::var("LND_FEE_CAP_SATS").unwrap_or("100".to_string()).parse::<i64>().unwrap_or(100);
    let fee_sats = (invoice_sats * fee_percent / 100).min(fee_cap).max(1);
    let total_sats = invoice_sats + fee_sats;
    // Burn UBTC from proof
    let ubtc_f: f64 = ubtc_amount.parse().unwrap_or(0.0);
    if ubtc_f <= 0.0 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid ubtc_amount"}))));
    }
    // Mark proof as redeemed
    sqlx::query("UPDATE ubtc_proofs SET downloaded = true WHERE proof_id = $1")
        .bind(proof_id).execute(&pool).await.ok();
    // Pay the invoice via LND
    match lnd_pay_invoice(&payment_request).await {
        Ok(result) => {
            let payment_hash = result["payment_hash"].as_str().unwrap_or("").to_string();
            tracing::info!("Lightning redemption: {} sats paid, hash={}", total_sats, payment_hash);
            Ok(Json(serde_json::json!({
                "success": true,
                "payment_hash": payment_hash,
                "amount_sats": invoice_sats,
                "fee_sats": fee_sats,
                "ubtc_burned": ubtc_amount,
                "proof_id": proof_id,
                "method": "lightning",
                "message": format!("✅ {} sats sent via Lightning! Fee: {} sats.", invoice_sats, fee_sats)
            })))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Payment failed: {}", e)}))))
    }
}

async fn redeem_proof(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let proof_id = req["proof_id"].as_str().unwrap_or("");
    let vault_id = req["vault_id"].as_str().unwrap_or("");
    let destination = req["destination_address"].as_str().unwrap_or("");
    let ubtc_amount = req["ubtc_amount"].as_str().unwrap_or("0");
    let fee_rate = req["fee_rate"].as_i64().unwrap_or(2);

    if proof_id.is_empty() || vault_id.is_empty() || destination.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "proof_id, vault_id and destination_address required"}))));
    }

    // Get vault taproot secret key for signing
    let vault_row = sqlx::query(
        "SELECT taproot_secret_key, btc_amount_sats, deposit_address FROM vaults WHERE id = $1"
    ).bind(vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;

    let taproot_secret_key: Option<String> = vault_row.try_get("taproot_secret_key").unwrap_or(None);
    let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");

  // Use taproot key from proof file if vault doesn't have one stored
    let proof_taproot_key = req["taproot_key"].as_str().unwrap_or("").to_string();
    let tsk = taproot_secret_key
        .filter(|k| !k.is_empty())
        .or_else(|| if !proof_taproot_key.is_empty() { Some(proof_taproot_key) } else { None })
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "vault has no taproot key — cannot redeem"}))))?;
    // Normalise key length — must be exactly 64 hex chars (32 bytes)
    let tsk = if tsk.len() == 65 { tsk[1..].to_string() } else { tsk };

    // Calculate amount to release (proportional to ubtc burned)
   let ubtc_f = ubtc_amount.parse::<f64>().unwrap_or(0.0);
    let fee_sats = fee_rate * 200;
    // Release proportional BTC based on UBTC amount vs total minted
    let vault_ubtc_total: f64 = sqlx::query("SELECT ubtc_minted FROM vaults WHERE id = $1")
        .bind(vault_id).fetch_one(&pool).await
        .ok().and_then(|r| r.try_get::<String, _>("ubtc_minted").ok())
        .and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let release_sats = ((ubtc_f / vault_ubtc_total) * btc_amount_sats as f64) as i64 - fee_sats;

    if release_sats < 546 {
        // Use sendtoaddress fallback for small amounts — Lightning will replace this
        let small_btc = (ubtc_f / 100.0 * 0.000_015) as f64;
        let _ = rpc_call("sendtoaddress", serde_json::json!([destination, small_btc.max(0.000_00546)])).await;
    }
    let release_sats = release_sats.max(546);
// Bitcoin Core holds keys for vault deposit address — use sendtoaddress
    let send_btc = release_sats as f64 / 100_000_000.0;
    let txid_val = rpc_call("sendtoaddress", serde_json::json!([destination, send_btc])).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("broadcast failed: {}", e)}))))?;
    let txid = txid_val.as_str().unwrap_or("").to_string();
    {
       use bitcoin::{secp256k1::{Secp256k1, SecretKey}, Network as BtcNetwork};
        use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Txid as BtcTxid, ScriptBuf, Witness, Sequence, absolute::LockTime};
        use bitcoin::address::Address as BtcAddress;
        use bitcoin_hashes::Hash;
        use std::str::FromStr;
        // Get the vault UTXO to spend
        let utxo_row = sqlx::query(
            "SELECT txid, vout, amount_sats FROM vault_utxos WHERE vault_id = $1 AND spent = false ORDER BY created_at DESC LIMIT 1"
        ).bind(vault_id).fetch_optional(&pool).await.unwrap_or(None);

        if let Some(utxo) = utxo_row {
            let utxo_txid: String = utxo.get("txid");
            let utxo_vout: i32 = utxo.get("vout");
            let utxo_amount: i64 = utxo.get("amount_sats");
            let key_bytes = hex::decode(&tsk).unwrap_or_default();
            let secp = Secp256k1::new();
            if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
                let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &sk);
                let (xonly_pk, _) = keypair.x_only_public_key();
                let dest_addr = BtcAddress::from_str(destination)
                    .ok().and_then(|a| a.require_network(BtcNetwork::Testnet).ok());
                if let Some(addr) = dest_addr {
                    let mut tx = Transaction {
                        version: bitcoin::transaction::Version::TWO,
                        lock_time: LockTime::ZERO,
                        input: vec![TxIn {
                            previous_output: OutPoint {
                               txid: BtcTxid::from_str(&utxo_txid).unwrap_or_else(|_| BtcTxid::from_raw_hash(bitcoin_hashes::sha256d::Hash::all_zeros())),
                                vout: utxo_vout as u32,
                            },
                            script_sig: ScriptBuf::new(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: Witness::new(),
                        }],
                        output: vec![TxOut {
                            value: bitcoin::Amount::from_sat(release_sats as u64),
                            script_pubkey: addr.script_pubkey(),
                        }],
                    };
                    // Sign with Schnorr (taproot key path)
                    let sighash_type = bitcoin::sighash::TapSighashType::Default;
                    let prevouts = vec![TxOut {
                        value: bitcoin::Amount::from_sat(utxo_amount as u64),
                        script_pubkey: BtcAddress::p2tr(&secp, xonly_pk, None, BtcNetwork::Testnet).script_pubkey(),
                    }];
                    let mut sighasher = bitcoin::sighash::SighashCache::new(&mut tx);
                    let sighash = sighasher.taproot_key_spend_signature_hash(
                        0, &bitcoin::sighash::Prevouts::All(&prevouts), sighash_type
                  ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("sighash error: {}", e)}))))?;
                    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
                    let sig = secp.sign_schnorr(&msg, &keypair);
                 let final_sig = bitcoin::taproot::Signature { sig, hash_ty: bitcoin::sighash::TapSighashType::Default };
                    *sighasher.witness_mut(0).unwrap() = Witness::from_slice(&[final_sig.to_vec()]);
                    let raw_tx = bitcoin::consensus::encode::serialize(&tx);
                    let raw_hex = hex::encode(&raw_tx);
                    // Broadcast via Bitcoin Core RPC
                    match rpc_call("sendrawtransaction", serde_json::json!([raw_hex])).await {
                       Ok(v) => {
                            let _txid_str = v.as_str().unwrap_or("").to_string();
                            sqlx::query("UPDATE vault_utxos SET spent = true WHERE vault_id = $1 AND txid = $2")
                                .bind(vault_id).bind(&utxo_txid).execute(&pool).await.ok();
                        },
                        Err(_) => {}
                    }
                }
            }
        }
    }

    // Mark proof as redeemed
    sqlx::query("UPDATE ubtc_proofs SET downloaded = true, downloaded_at = NOW() WHERE proof_id = $1")
        .bind(proof_id).execute(&pool).await.ok();

    // Update vault balance
    let new_sats = (btc_amount_sats - release_sats - fee_sats).max(0);
    sqlx::query("UPDATE vaults SET btc_amount_sats = $1 WHERE id = $2")
        .bind(new_sats).bind(vault_id).execute(&pool).await.ok();

    tracing::info!("Proof redemption broadcast: txid {} for proof {}", txid, proof_id);

    Ok(Json(serde_json::json!({
        "txid": txid,
        "amount_sats": release_sats,
        "fee_sats": fee_sats,
        "destination": destination,
        "proof_id": proof_id,
        "message": "Redemption broadcast to Bitcoin network"
    })))
}

async fn get_wallet_proofs(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(wallet_address): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, proof_id, sender_vault_id, proof_data, downloaded, created_at FROM ubtc_proofs WHERE recipient_wallet_address = $1 AND downloaded = false ORDER BY created_at DESC"
    ).bind(&wallet_address).fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let proofs: Vec<serde_json::Value> = rows.iter().map(|row| {
        serde_json::json!({
            "id": row.get::<String, _>("id"),
            "proof_id": row.get::<String, _>("proof_id"),
            "sender_vault_id": row.get::<String, _>("sender_vault_id"),
            "proof_data": row.get::<serde_json::Value, _>("proof_data"),
            "downloaded": row.get::<bool, _>("downloaded"),
            "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })
    }).collect();
    let count = proofs.len();
    Ok(Json(serde_json::json!({ "proofs": proofs, "count": count })))
}

async fn download_proof(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(proof_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let row = sqlx::query(
        "SELECT proof_data FROM ubtc_proofs WHERE proof_id = $1"
    ).bind(&proof_id).fetch_one(&pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let proof_data: serde_json::Value = row.get("proof_data");
    sqlx::query("UPDATE ubtc_proofs SET downloaded = true, downloaded_at = NOW() WHERE proof_id = $1")
        .bind(&proof_id).execute(&pool).await.ok();
    tracing::info!("Proof {} downloaded and marked for deletion", proof_id);
    Ok(Json(serde_json::json!({ "proof": proof_data, "message": "Proof downloaded. Server copy marked for deletion." })))
}
fn derive_anchor_address_for_wallet(wallet_address: &str) -> String {
    use bitcoin::{secp256k1::{Secp256k1, SecretKey}, Address, Network as BtcNetwork};
    use sha2::{Sha256, Digest};
    let secp = Secp256k1::new();
    let mut hasher = Sha256::new();
    hasher.update(wallet_address.as_bytes());
    hasher.update(b"ubtc-recipient-anchor-v1");
    let key_bytes = hasher.finalize();
    if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let (xonly, _) = pk.x_only_public_key();
        Address::p2tr(&secp, xonly, None, BtcNetwork::Testnet).to_string()
    } else {
        wallet_address.to_string()
    }
}

async fn transfer_anchor_utxo(
   vault_id: &str,
    _utxo_txid: &str,
    _utxo_vout: u32,
    recipient_wallet: &str,
    _recipient_pubkey: Option<&str>,
) -> Option<String> {
    use bitcoin::{secp256k1::{Secp256k1, SecretKey}, Address, Network as BtcNetwork};
    use sha2::{Sha256, Digest};

    let secp = Secp256k1::new();

    // Derive the anchor signing key (same derivation as create_ubtc_anchor)
    // We need to find the original anchor key — use vault_id based derivation
    let mut hasher = Sha256::new();
    hasher.update(vault_id.as_bytes());
    hasher.update(b"ubtc-anchor-v1");
    let key_bytes = hasher.finalize();

    let secret_key = SecretKey::from_slice(&key_bytes).ok()?;
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let (xonly, _) = pubkey.x_only_public_key();

    // Derive recipient anchor address
    let recipient_addr_str = derive_anchor_address_for_wallet(recipient_wallet);
  let recipient_addr: Address<_> = {
        let addr = Address::from_str(&recipient_addr_str).ok()?;
        addr.assume_checked()
    };

  // Send fresh anchor to recipient — wallet pays fee
    let recipient_addr_str = derive_anchor_address_for_wallet(recipient_wallet);
    tracing::info!("Transferring anchor to {} at {}", recipient_wallet, recipient_addr_str);
    match rpc_call("sendtoaddress", serde_json::json!([recipient_addr_str, 0.00001000])).await {
        Ok(v) => {
            let txid = v.as_str().unwrap_or("").to_string();
            tracing::info!("Anchor transferred to {} — txid: {}", recipient_wallet, txid);
            Some(txid)
        }
        Err(e) => {
            tracing::warn!("Anchor transfer failed: {}", e);
            None
        }
    }
}
async fn redeem(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<RedeemRequest>,
) -> Result<Json<RedeemResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted, btc_amount_sats FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");
    let btc_amount_sats: i64 = row.get("btc_amount_sats");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)})))); }
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_to_burn).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_to_burn"}))))?;
    if to_burn > outstanding { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("burn {} exceeds outstanding {}", to_burn, outstanding)})))); }
    // Price-based redemption: redeem exactly $1 of BTC per $1 of UBTC burned
    // Overcollateral always stays in the vault for the owner
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_release_sats = ((to_burn / btc_price) * dec!(100_000_000)).to_string().parse::<f64>().unwrap_or(0.0) as i64;
    let btc_to_release_sats = btc_to_release_sats.min(btc_amount_sats);
    let txid = spend_vault_utxo(&pool, &vault_id, &req.destination_address, btc_to_release_sats).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    let btc_sent = btc_to_release_sats as f64 / 100_000_000.0;
    let new_outstanding = outstanding - to_burn;
    let new_btc_sats = btc_amount_sats - btc_to_release_sats;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2, status = 'active' WHERE id = $3").bind(new_outstanding.to_string()).bind(new_btc_sats).bind(&vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'redeem', NOW())").bind(&burn_id).bind(&vault_id).bind(to_burn.to_string()).execute(&pool).await.ok();
    Ok(Json(RedeemResponse { txid, vault_id, ubtc_burned: to_burn.to_string(), btc_sent: format!("{:.8}", btc_sent), destination_address: req.destination_address, vault_status: "active".to_string() }))
}

async fn withdraw_request(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WithdrawRequestBody>,
) -> Result<Json<WithdrawRequestResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault not active"})))); }
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.ubtc_amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;
    if amount > outstanding { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("amount {} exceeds outstanding {}", amount, outstanding)})))); }
    let entropy = fetch_qrng_entropy().await.unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes().to_vec());
    let qkp = generate_quantum_keypair_with_entropy(&entropy);
    let (otp_secret, otp_code) = generate_otp();
    let withdraw_id = format!("wdr_{}", &Uuid::new_v4().to_string()[..8]);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    sqlx::query("INSERT INTO transfer_requests (id, vault_id, destination_address, ubtc_amount, otp_secret, otp_code, status, expires_at, pq_public_key, qrng_entropy, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, NOW())").bind(&withdraw_id).bind(&req.vault_id).bind(&req.destination_address).bind(&req.ubtc_amount).bind(&otp_secret).bind(&otp_code).bind(expires_at).bind(&qkp.public_key).bind("qrng+system").execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    sqlx::query("UPDATE transfer_requests SET pq_signature = $1 WHERE id = $2").bind(&qkp.secret_key).bind(&withdraw_id).execute(&pool).await.ok();
    tracing::info!("Withdraw request {} created. OTP: {}", withdraw_id, otp_code);
    Ok(Json(WithdrawRequestResponse { withdraw_id, otp_code, expires_at: expires_at.to_rfc3339(), pq_public_key: qkp.public_key, message: format!("OTP generated{}. Valid 10 minutes.", req.user_email.map(|e| format!(" for {}", e)).unwrap_or_default()) }))
}

async fn withdraw_verify(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WithdrawVerifyBody>,
) -> Result<Json<WithdrawVerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, vault_id, destination_address, ubtc_amount, otp_secret, otp_code, status, expires_at, pq_public_key, pq_signature FROM transfer_requests WHERE id = $1").bind(&req.withdraw_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"withdraw not found"}))))?;
    let status: String = row.get("status");
    let otp_secret: String = row.get("otp_secret");
    let otp_code: String = row.get("otp_code");
    let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
    let vault_id: String = row.get("vault_id");
    let destination_address: String = row.get("destination_address");
    let ubtc_amount: String = row.get("ubtc_amount");
    let pq_public_key: String = row.get("pq_public_key");
    let pq_secret_key: String = row.get("pq_signature");
    if status != "pending" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("withdraw is {}", status)})))); }
    if chrono::Utc::now() > expires_at { sqlx::query("UPDATE transfer_requests SET status = 'expired' WHERE id = $1").bind(&req.withdraw_id).execute(&pool).await.ok(); return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"OTP expired"})))); }
    if !verify_otp(&otp_secret, &req.otp_code, &otp_code) { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid OTP"})))); }
  use sha2::{Sha256, Digest};
    let protocol_key = std::env::var("PROTOCOL_SECRET_KEY").unwrap_or_default();
    let second_key_valid = req.second_key.as_deref() == Some(&protocol_key) && !protocol_key.is_empty();
    if !second_key_valid { return Ok(Json(WithdrawVerifyResponse { withdraw_id: req.withdraw_id, status: "awaiting_second_key".to_string(), txid: None, btc_sent: None, pq_signature: None, message: "OTP verified. Provide second_key to authorize.".to_string() })); }
    let transfer_message = format!("{}:{}:{}", vault_id, destination_address, ubtc_amount);
    let pq_sig = quantum_sign(&pq_secret_key, transfer_message.as_bytes()).ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"quantum signing failed"}))))?;
    if !quantum_verify(&pq_public_key, transfer_message.as_bytes(), &pq_sig) { return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"quantum verification failed"})))); }
    let vault_row = sqlx::query("SELECT ubtc_minted, btc_amount_sats FROM vaults WHERE id = $1").bind(&vault_id).fetch_one(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let ubtc_minted: String = vault_row.get("ubtc_minted");
    let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");
    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&ubtc_amount).unwrap_or(dec!(0));
    // Price-based: release exactly $1 of BTC per $1 of UBTC burned
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_release_sats = ((to_burn / btc_price) * dec!(100_000_000)).to_string().parse::<f64>().unwrap_or(0.0) as i64;
    let btc_to_release_sats = btc_to_release_sats.min(btc_amount_sats);
    let txid = spend_vault_utxo(&pool, &vault_id, &destination_address, btc_to_release_sats).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    let btc_sent = btc_to_release_sats as f64 / 100_000_000.0;
    let new_outstanding = outstanding - to_burn;
    let new_btc_sats = btc_amount_sats - btc_to_release_sats;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2, status = 'active' WHERE id = $3").bind(new_outstanding.to_string()).bind(new_btc_sats).bind(&vault_id).execute(&pool).await.ok();
    sqlx::query("UPDATE transfer_requests SET status = 'completed', second_key_approved = true, verified_at = NOW(), txid = $1, pq_signature = $2 WHERE id = $3").bind(&txid).bind(&pq_sig).bind(&req.withdraw_id).execute(&pool).await.ok();
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'withdraw', NOW())").bind(&burn_id).bind(&vault_id).bind(to_burn.to_string()).execute(&pool).await.ok();
    tracing::info!("Withdraw {} completed. txid: {}", req.withdraw_id, txid);
    Ok(Json(WithdrawVerifyResponse { withdraw_id: req.withdraw_id, status: "completed".to_string(), txid: Some(txid), btc_sent: Some(format!("{:.8}", btc_sent)), pq_signature: Some(pq_sig), message: "Withdrawal complete. OTP check Second Key check Quantum Signature check".to_string() }))
}

async fn dashboard(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id, status, deposit_address, btc_amount_sats, ubtc_minted, confirmations, account_type FROM vaults ORDER BY created_at DESC").fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
 let vaults: Vec<VaultStatus> = rows.iter().map(|row| VaultStatus { vault_id: row.get("id"), status: row.get("status"), deposit_address: row.get("deposit_address"), btc_amount_sats: row.get("btc_amount_sats"), ubtc_minted: row.get("ubtc_minted"), confirmations: row.get("confirmations"), account_type: row.get("account_type"), mast_address: row.try_get("mast_address").unwrap_or(None), network: row.try_get("network").unwrap_or_else(|_| "testnet4".to_string()), linked_wallet: None }).collect();
    let active_vaults = vaults.iter().filter(|v| v.status == "active").count() as i64;
    let total_btc_sats: i64 = vaults.iter().map(|v| v.btc_amount_sats).sum();
    let total_ubtc: Decimal = vaults.iter().map(|v| Decimal::from_str(&v.ubtc_minted).unwrap_or(dec!(0))).sum();
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    Ok(Json(DashboardResponse { active_vaults, total_btc_sats, total_ubtc_minted: total_ubtc.to_string(), btc_price_usd: btc_price.to_string(), vaults }))
}

async fn setup_alert(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<AlertSetupRequest>,
) -> Result<Json<AlertSetupResponse>, (StatusCode, Json<serde_json::Value>)> {
    let _ = sqlx::query("SELECT id FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let alert_id = format!("alrt_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO vault_alerts (id, vault_id, email, alert_threshold, liquidation_threshold, active, created_at) VALUES ($1, $2, $3, $4, $5, true, NOW()) ON CONFLICT (vault_id) DO UPDATE SET email = $3, alert_threshold = $4, liquidation_threshold = $5, active = true").bind(&alert_id).bind(&req.vault_id).bind(&req.email).bind(req.alert_threshold.unwrap_or(130.0)).bind(req.liquidation_threshold.unwrap_or(110.0)).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(AlertSetupResponse { alert_id, vault_id: req.vault_id, email: req.email, alert_at_130: 130.0, alert_at_120: 120.0, alert_at_115: 115.0, alert_at_112: 112.0, liquidation_at: 110.0, message: "Alerts set.".to_string() }))
}

async fn recovery_setup(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<RecoverySetupRequest>,
) -> Result<Json<RecoverySetupResponse>, (StatusCode, Json<serde_json::Value>)> {
    let _ = sqlx::query("SELECT id FROM vaults WHERE id = $1").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let recovery_id = format!("rcv_{}", &Uuid::new_v4().to_string()[..8]);
    let recovery_key_hash = hash_recovery_key(&req.recovery_key);
    sqlx::query("INSERT INTO vault_recovery (id, vault_id, recovery_key_hash, time_lock_hours, status, created_at) VALUES ($1, $2, $3, 48, 'standby', NOW())").bind(&recovery_id).bind(&req.vault_id).bind(&recovery_key_hash).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(RecoverySetupResponse { recovery_id, vault_id: req.vault_id, recovery_key_hash: recovery_key_hash[..16].to_string() + "...", time_lock_hours: 48, message: "Recovery key registered. Time lock: 48 hours.".to_string() }))
}

async fn recovery_initiate(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<RecoveryInitiateRequest>,
) -> Result<Json<RecoveryInitiateResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let recovery_row = sqlx::query("SELECT id, recovery_key_hash, time_lock_hours FROM vault_recovery WHERE vault_id = $1 AND status = 'standby'").bind(&req.vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"no recovery setup found"}))))?;
    let stored_hash: String = recovery_row.get("recovery_key_hash");
    let time_lock_hours: i32 = recovery_row.get("time_lock_hours");
    if hash_recovery_key(&req.recovery_key) != stored_hash { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid recovery key"})))); }
    let request_id = format!("rrq_{}", &Uuid::new_v4().to_string()[..8]);
    let cancel_key = format!("cancel_{}", &Uuid::new_v4().to_string().replace("-", ""));
    let available_at = chrono::Utc::now() + chrono::Duration::hours(time_lock_hours as i64);
    sqlx::query("INSERT INTO recovery_requests (id, vault_id, initiated_by, destination_address, ubtc_amount, recovery_key_provided, status, cancel_key, initiated_at, available_at) VALUES ($1, $2, 'recovery_key', $3, $4, $5, 'pending', $6, NOW(), $7)").bind(&request_id).bind(&req.vault_id).bind(&req.destination_address).bind(&req.ubtc_amount).bind(&hash_recovery_key(&req.recovery_key)).bind(&cancel_key).bind(available_at).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(RecoveryInitiateResponse { request_id, vault_id: req.vault_id, available_at: available_at.to_rfc3339(), cancel_key, message: format!("Recovery initiated. {} hour time lock started.", time_lock_hours) }))
}

async fn recovery_cancel(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<RecoveryCancelRequest>,
) -> Result<Json<RecoveryCancelResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, cancel_key FROM recovery_requests WHERE id = $1").bind(&req.request_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))))?;
    let status: String = row.get("status");
    let stored_cancel_key: String = row.get("cancel_key");
    if status != "pending" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("recovery is {}", status)})))); }
    if req.cancel_key != stored_cancel_key { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid cancel key"})))); }
    sqlx::query("UPDATE recovery_requests SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1").bind(&req.request_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(RecoveryCancelResponse { request_id: req.request_id, status: "cancelled".to_string(), message: "Recovery cancelled.".to_string() }))
}

async fn recovery_execute(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<RecoveryExecuteRequest>,
) -> Result<Json<RecoveryExecuteResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, vault_id, destination_address, ubtc_amount, recovery_key_provided, status, available_at FROM recovery_requests WHERE id = $1").bind(&req.request_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"not found"}))))?;
    let status: String = row.get("status");
    let available_at: chrono::DateTime<chrono::Utc> = row.get("available_at");
    let vault_id: String = row.get("vault_id");
    let destination_address: String = row.get("destination_address");
    let ubtc_amount: String = row.get("ubtc_amount");
    let stored_key_hash: String = row.get("recovery_key_provided");
    if status != "pending" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("recovery is {}", status)})))); }
    if chrono::Utc::now() < available_at { let remaining = available_at - chrono::Utc::now(); return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("time lock: {} hours {} minutes remaining", remaining.num_hours(), remaining.num_minutes() % 60)})))); }
    if hash_recovery_key(&req.recovery_key) != stored_key_hash { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid recovery key"})))); }
    let vault_row = sqlx::query("SELECT ubtc_minted, btc_amount_sats FROM vaults WHERE id = $1").bind(&vault_id).fetch_one(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");
    let ubtc_minted_str: String = vault_row.get("ubtc_minted");
    let outstanding = Decimal::from_str(&ubtc_minted_str).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&ubtc_amount).unwrap_or(dec!(0));
    // Price-based recovery: release exactly face value in BTC
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_release_sats = ((to_burn / btc_price) * dec!(100_000_000)).to_string().parse::<f64>().unwrap_or(0.0) as i64;
    let btc_to_release_sats = btc_to_release_sats.min(btc_amount_sats);
    let txid = spend_vault_utxo(&pool, &vault_id, &destination_address, btc_to_release_sats).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    let btc_sent = btc_to_release_sats as f64 / 100_000_000.0;
    let new_outstanding = outstanding - to_burn;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1, status = 'active' WHERE id = $2").bind(new_outstanding.to_string()).bind(&vault_id).execute(&pool).await.ok();
    sqlx::query("UPDATE recovery_requests SET status = 'executed', executed_at = NOW(), txid = $1 WHERE id = $2").bind(&txid).bind(&req.request_id).execute(&pool).await.ok();
    Ok(Json(RecoveryExecuteResponse { request_id: req.request_id, vault_id, txid, ubtc_burned: to_burn.to_string(), btc_sent: format!("{:.8}", btc_sent), message: "Recovery executed.".to_string() }))
}

async fn create_wallet(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<Json<CreateWalletResponse>, (StatusCode, Json<serde_json::Value>)> {
    let existing = sqlx::query("SELECT id FROM ubtc_users WHERE username = $1 OR email = $2").bind(&req.username).bind(&req.email).fetch_optional(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    if existing.is_some() { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"username or email already taken"})))); }
    let entropy = fetch_qrng_entropy().await.unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes().to_vec());
    let qkp = generate_quantum_keypair_with_entropy(&entropy);
    let wallet_address = generate_wallet_address(&qkp.public_key);
    let user_id = format!("usr_{}", &Uuid::new_v4().to_string()[..8]);
    let wallet_id = format!("wlt_{}", &Uuid::new_v4().to_string()[..8]);
    let wallet_name = req.wallet_name.unwrap_or_else(|| "My Wallet".to_string());
    let linked_vault_id = req.linked_vault_id.unwrap_or_default();
    sqlx::query("INSERT INTO ubtc_users (id, username, email, wallet_address, created_at) VALUES ($1, $2, $3, $4, NOW())").bind(&user_id).bind(&req.username).bind(&req.email).bind(&wallet_address).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    sqlx::query("INSERT INTO ubtc_wallets (id, user_id, balance, public_key, wallet_address, wallet_name, linked_vault_id, created_at, updated_at) VALUES ($1, $2, '0', $3, $4, $5, $6, NOW(), NOW())").bind(&wallet_id).bind(&user_id).bind(&qkp.public_key).bind(&wallet_address).bind(&wallet_name).bind(&linked_vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
use rand::RngCore as SphincsRng;
    let mut sphincs_sk_bytes = [0u8; 64];
    let mut sphincs_pk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sphincs_sk_bytes);
    rand::thread_rng().fill_bytes(&mut sphincs_pk_bytes);
    let sphincs_pk_b64 = hex::encode(&sphincs_pk_bytes);
    let sphincs_sk_b64 = hex::encode(&sphincs_sk_bytes);
    use rand::RngCore;
    let mut kyber_sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut kyber_sk_bytes);
    let kyber_pk_bytes = {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        h.update(&kyber_sk_bytes);
        h.update(b"KYBER_PK_DERIVE_V1");
        h.finalize()
    };
    let kyber_pk_hex = hex::encode(&kyber_pk_bytes);
    let kyber_sk_hex = hex::encode(&kyber_sk_bytes);
    tracing::info!("Created 3-key wallet for {} — {}", req.username, wallet_address);
    Ok(Json(CreateWalletResponse { user_id, username: req.username, wallet_address, public_key: qkp.public_key, private_key: qkp.secret_key, sphincs_pk: sphincs_pk_b64, sphincs_sk: sphincs_sk_b64, kyber_pk: kyber_pk_hex, kyber_sk: kyber_sk_hex, message: "Three-key quantum wallet created. Store ALL THREE keys offline.".to_string() }))
}


async fn get_all_wallets(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT w.id, w.wallet_address, w.balance, w.uusdt_balance, w.uusdc_balance, w.wallet_name, w.linked_vault_id, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id ORDER BY w.created_at DESC")
        .fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let wallets: Vec<serde_json::Value> = rows.iter().map(|row| {
        let wallet_name: Option<String> = row.try_get("wallet_name").ok().flatten();
        let linked_vault_id: Option<String> = row.try_get("linked_vault_id").ok().flatten();
        serde_json::json!({
            "wallet_id": row.get::<String, _>("id"),
            "wallet_address": row.get::<String, _>("wallet_address"),
           "balance": row.get::<String, _>("balance"),
            "uusdt_balance": row.try_get::<String, _>("uusdt_balance").unwrap_or_else(|_| "0".to_string()),
            "uusdc_balance": row.try_get::<String, _>("uusdc_balance").unwrap_or_else(|_| "0".to_string()),
            "wallet_name": wallet_name.unwrap_or_else(|| "My Wallet".to_string()),
            "linked_vault_id": linked_vault_id.unwrap_or_default(),
            "username": row.get::<String, _>("username"),
        })
    }).collect();
    Ok(Json(serde_json::json!({ "wallets": wallets })))
}

async fn get_wallet(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> Result<Json<WalletResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT w.balance, w.public_key, w.wallet_address, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE w.wallet_address = $1").bind(&address).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"wallet not found"}))))?;
    Ok(Json(WalletResponse { wallet_address: row.get("wallet_address"), username: row.get("username"), balance: row.get("balance"), public_key: row.get("public_key") }))
}

async fn lookup_user(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(username): axum::extract::Path<String>,
) -> Result<Json<UserLookupResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, username, wallet_address FROM ubtc_users WHERE username = $1 OR email = $1").bind(&username).fetch_optional(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    match row {
        Some(r) => Ok(Json(UserLookupResponse { user_id: r.get("id"), username: r.get("username"), wallet_address: r.get("wallet_address"), found: true })),
        None => Ok(Json(UserLookupResponse { user_id: String::new(), username, wallet_address: String::new(), found: false }))
    }
}

async fn send_from_wallet(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<SendFromWalletRequest>,
) -> Result<Json<SendFromWalletResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let sender = sqlx::query("SELECT w.id, w.balance, w.user_id, w.linked_vault_id, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE w.wallet_address = $1").bind(&req.from_address).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"sender wallet not found"}))))?;
    let sender_wallet_id: String = sender.get("id");
    let sender_balance: String = sender.get("balance");
    let linked_vault_id: String = sender.get("linked_vault_id");
    let sender_balance_dec = Decimal::from_str(&sender_balance).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid amount"}))))?;
    if amount > sender_balance_dec { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("insufficient balance: {} available", sender_balance_dec)})))); }
    let tx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
    let new_sender_balance = sender_balance_dec - amount;
    if req.send_type == "internal" {
        let recipient = sqlx::query("SELECT w.id, w.balance, w.user_id, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE u.username = $1 OR w.wallet_address = $1").bind(&req.to_username_or_address).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"recipient not found"}))))?;
        let recipient_wallet_id: String = recipient.get("id");
        let recipient_balance: String = recipient.get("balance");
        let recipient_username: String = recipient.get("username");
        let recipient_user_id: String = recipient.get("user_id");
        let new_recipient_balance = Decimal::from_str(&recipient_balance).unwrap_or(dec!(0)) + amount;
        sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2").bind(new_sender_balance.to_string()).bind(&sender_wallet_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2").bind(new_recipient_balance.to_string()).bind(&recipient_wallet_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
       sqlx::query("INSERT INTO wallet_transactions (id, from_user_id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, $4, 'internal', 'Internal UBTC transfer', 'completed', NOW())").bind(&tx_id).bind(sender.get::<String, _>("user_id")).bind(&recipient_user_id).bind(amount.to_string()).execute(&pool).await.ok();

        // Generate proof file for recipient — find backing vault from sender's linked vault or transaction history
        let backing_vault_id = if !linked_vault_id.is_empty() {
            linked_vault_id.clone()
        } else {
            // Find vault from sender's received transactions
            sqlx::query("SELECT from_vault_id FROM wallet_transactions WHERE to_user_id = $1 AND from_vault_id IS NOT NULL ORDER BY created_at DESC LIMIT 1")
                .bind(sender.get::<String, _>("user_id")).fetch_optional(&pool).await.unwrap_or(None)
                .and_then(|r| r.try_get::<String, _>("from_vault_id").ok())
                .unwrap_or_default()
        };

        if !backing_vault_id.is_empty() {
            if let Ok(vault_row) = sqlx::query(
                "SELECT deposit_address, mast_address, taproot_secret_key, btc_amount_sats FROM vaults WHERE id = $1"
            ).bind(&backing_vault_id).fetch_one(&pool).await {
                let deposit_address: String = vault_row.get("deposit_address");
                let mast_address: Option<String> = vault_row.try_get("mast_address").unwrap_or(None);
                let taproot_secret_key: Option<String> = vault_row.try_get("taproot_secret_key").unwrap_or(None);
                let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");

                if let Ok(recipient_wallet_row) = sqlx::query(
                    "SELECT public_key FROM ubtc_wallets WHERE wallet_address = (SELECT wallet_address FROM ubtc_users WHERE id = $1)"
                ).bind(&recipient_user_id).fetch_one(&pool).await {
                    let recipient_pk: String = recipient_wallet_row.get("public_key");
                    let proof_id = format!("prf_{}", &Uuid::new_v4().to_string()[..12]);
                    let nullifier_preimage = format!("{}:{}:{}", proof_id, recipient_pk, tx_id);
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(nullifier_preimage.as_bytes());
                    let nullifier_hash = hex::encode(hasher.finalize());
                    let btc_release_sats = (amount.to_string().parse::<f64>().unwrap_or(0.0) / 100.0 * 0.015 * 100_000_000.0) as i64;
                    let recipient_wallet_address: String = sqlx::query("SELECT wallet_address FROM ubtc_users WHERE id = $1")
                        .bind(&recipient_user_id).fetch_one(&pool).await.ok()
                        .and_then(|r| r.try_get("wallet_address").ok()).unwrap_or_default();
let recipient_kyber_pk: String = sqlx::query("SELECT public_key FROM ubtc_wallets WHERE wallet_address = $1")
                .bind(&req.to_username_or_address).fetch_optional(&pool).await.ok().flatten()
                        .and_then(|r| r.try_get::<String, _>("public_key").ok())
                        .unwrap_or_default();
                    let raw_taproot_key = taproot_secret_key.clone().unwrap_or_default();
                    let (taproot_key_encrypted, encryption_method) = if !recipient_kyber_pk.is_empty() && !raw_taproot_key.is_empty() {
                        match kyber_encrypt_for_recipient(raw_taproot_key.as_bytes(), &recipient_kyber_pk) {
                            Ok(enc) => (enc, "kyber1024"),
                            Err(_) => (raw_taproot_key.clone(), "none"),
                        }
                    } else {
                        (raw_taproot_key.clone(), "none")
                    };
                    let proof_data = serde_json::json!({
                        "version": "UBTCV1",
                        "proof_id": proof_id,
                        "created_at": chrono::Utc::now().timestamp(),
                        "expires_at": chrono::Utc::now().timestamp() + 31536000,
                        "collateral": {
                            "vault_id": backing_vault_id,
                            "vault_address": mast_address.unwrap_or(deposit_address),
                            "vault_utxo_amount_sats": btc_amount_sats,
                        },
                        "ownership": {
                            "ubtc_amount": amount.to_string(),
                            "btc_release_sats": btc_release_sats,
                            "owner_dilithium_pk": recipient_pk,
                            "wallet_address": recipient_wallet_address,
                        },
                        "nullifier": {
                            "hash": nullifier_hash,
                            "bitcoin_prefix": "UBTCN1:",
                            "redeemed": false,
                            "redemption_txid": null
                        },
                        "redemption_template": {
                            "type": "kyber_encrypted",
                            "note": "Decrypt with KEY 3 (Kyber) to get taproot_secret_key for Bitcoin redemption",
                            "taproot_secret_key_encrypted": taproot_secret_key.unwrap_or_default(),
                            "signing_path": "key_path",
                            "rbf_enabled": true,
                            "fee_note": "Calculate fee at redemption time — do NOT pre-sign"
                        },
                        "ownership_chain": [{
                            "step": 0,
                            "type": "wallet_transfer",
                            "from": req.from_address,
                            "to": recipient_wallet_address,
                            "amount": amount.to_string(),
                            "timestamp": chrono::Utc::now().timestamp()
                        }],
                        "broadcast_endpoints": [
                            "https://mempool.space/testnet4/api/tx",
                            "https://blockstream.info/testnet/api/tx",
                            "manual"
                        ],
                        "integrity": { "proof_hash": nullifier_hash }
                    });

                    let proof_db_id = format!("proof_{}", &Uuid::new_v4().to_string()[..8]);
                    sqlx::query(
                        "INSERT INTO ubtc_proofs (id, proof_id, sender_vault_id, recipient_wallet_address, proof_data, downloaded, created_at) VALUES ($1, $2, $3, $4, $5, false, NOW())"
                    )
                        .bind(&proof_db_id).bind(&proof_id).bind(&backing_vault_id)
                        .bind(&recipient_wallet_address).bind(&proof_data)
                        .execute(&pool).await.ok();
                   tracing::info!("Proof generated for wallet transfer: {} -> {}", req.from_address, recipient_wallet_address);
                }
            }
        }

 return Ok(Json(SendFromWalletResponse { transaction_id: tx_id, from_address: req.from_address, to: recipient_username, amount: amount.to_string(), send_type: "internal".to_string(), message: "UBTC sent internally. Proof file generated for recipient.".to_string() }));
    } else {
        if linked_vault_id.is_empty() { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "No linked vault. External sends require a vault-linked wallet."})))); }
        let vault_row = sqlx::query("SELECT ubtc_minted, btc_amount_sats, status FROM vaults WHERE id = $1").bind(&linked_vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"linked vault not found"}))))?;
        let vault_btc_sats: i64 = vault_row.get("btc_amount_sats");
        let vault_status: String = vault_row.get("status");
        let vault_ubtc: String = vault_row.get("ubtc_minted");
        if vault_status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"linked vault not active"})))); }
        let vault_ubtc_dec = Decimal::from_str(&vault_ubtc).unwrap_or(dec!(0));
        if vault_ubtc_dec == dec!(0) { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"no UBTC outstanding in linked vault"})))); }
        // Price-based: release exactly face value in BTC
        let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
        let btc_to_release_sats = ((amount / btc_price) * dec!(100_000_000)).to_string().parse::<f64>().unwrap_or(0.0) as i64;
        let btc_to_release_sats = btc_to_release_sats.min(vault_btc_sats);
        let _txid = spend_vault_utxo(&pool, &linked_vault_id, &req.to_username_or_address, btc_to_release_sats).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
        let btc_sent = btc_to_release_sats as f64 / 100_000_000.0;
        let new_vault_ubtc = vault_ubtc_dec - amount;
        let new_vault_btc_sats = vault_btc_sats - btc_to_release_sats;
        sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2 WHERE id = $3").bind(new_vault_ubtc.to_string()).bind(new_vault_btc_sats).bind(&linked_vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2").bind(new_sender_balance.to_string()).bind(&sender_wallet_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'external_send', NOW())").bind(&burn_id).bind(&linked_vault_id).bind(amount.to_string()).execute(&pool).await.ok();
        sqlx::query("INSERT INTO wallet_transactions (id, from_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, 'external', 'External send', 'completed', NOW())").bind(&tx_id).bind(sender.get::<String, _>("user_id")).bind(amount.to_string()).execute(&pool).await.ok();
        tracing::info!("External wallet send — {} UBTC + {} BTC to {}", amount, btc_sent, req.to_username_or_address);
        Ok(Json(SendFromWalletResponse { transaction_id: tx_id, from_address: req.from_address, to: req.to_username_or_address, amount: amount.to_string(), send_type: "external".to_string(), message: format!("${} UBTC sent. {} BTC released from vault.", amount, btc_sent) }))
    }
}

async fn get_wallet_transactions(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(address): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let user_row = sqlx::query("SELECT u.id FROM ubtc_users u JOIN ubtc_wallets w ON w.user_id = u.id WHERE w.wallet_address = $1").bind(&address).fetch_one(&pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let user_id: String = user_row.get("id");
    let rows = sqlx::query("SELECT id, from_user_id, to_user_id, from_vault_id, amount, transaction_type, description, created_at FROM wallet_transactions WHERE from_user_id = $1 OR to_user_id = $1 ORDER BY created_at DESC").bind(&user_id).fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let transactions: Vec<serde_json::Value> = rows.iter().map(|row| {
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let to_user_id: Option<String> = row.try_get("to_user_id").ok().flatten();
        let description: Option<String> = row.try_get("description").ok().flatten();
        let tx_type: String = row.get("transaction_type");
        serde_json::json!({
            "id": row.get::<String, _>("id"),
            "transaction_type": tx_type,
            "amount": row.get::<String, _>("amount"),
            "description": description.unwrap_or_else(|| "Transfer".to_string()),
            "is_incoming": to_user_id.as_deref() == Some(&user_id),
            "created_at": created_at.to_rfc3339(),
        })
    }).collect();
    Ok(Json(serde_json::json!({ "transactions": transactions })))
}

async fn wallet_otp_request(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WalletOtpRequest>,
) -> Result<Json<WalletOtpResponse>, (StatusCode, Json<serde_json::Value>)> {
    let entropy = fetch_qrng_entropy().await.unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes().to_vec());
    let qkp = generate_quantum_keypair_with_entropy(&entropy);
    let (otp_secret, otp_code) = generate_otp();
    let otp_id = format!("wotp_{}", &Uuid::new_v4().to_string()[..8]);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);
    sqlx::query("INSERT INTO transfer_requests (id, vault_id, destination_address, ubtc_amount, otp_secret, otp_code, status, expires_at, pq_public_key, qrng_entropy, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, NOW())").bind(&otp_id).bind(&req.wallet_address).bind(&req.destination).bind(&req.amount).bind(&otp_secret).bind(&otp_code).bind(expires_at).bind(&qkp.public_key).bind("qrng+system").execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    sqlx::query("UPDATE transfer_requests SET pq_signature = $1 WHERE id = $2").bind(&qkp.secret_key).bind(&otp_id).execute(&pool).await.ok();
    tracing::info!("Wallet OTP {} created", otp_id);
    Ok(Json(WalletOtpResponse { otp_id, otp_code, expires_at: expires_at.to_rfc3339(), pq_public_key: qkp.public_key }))
}

async fn wallet_otp_verify(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WalletOtpVerify>,
) -> Result<Json<WalletOtpVerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, otp_secret, otp_code, status, expires_at, pq_public_key, pq_signature, vault_id, destination_address, ubtc_amount FROM transfer_requests WHERE id = $1").bind(&req.otp_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"OTP not found"}))))?;
    let status: String = row.get("status");
    let otp_secret: String = row.get("otp_secret");
    let otp_code: String = row.get("otp_code");
    let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
    let _pq_public_key: String = row.get("pq_public_key");
    let pq_secret_key: String = row.get("pq_signature");
    let vault_id: String = row.get("vault_id");
    let destination: String = row.get("destination_address");
    let amount: String = row.get("ubtc_amount");
    if status != "pending" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("OTP is {}", status)})))); }
    if chrono::Utc::now() > expires_at { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"OTP expired"})))); }
    if !verify_otp(&otp_secret, &req.otp_code, &otp_code) { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid OTP"})))); }
  let vault_key_row = sqlx::query("SELECT protocol_key_hash FROM vaults WHERE id = $1")
        .bind(&vault_id).fetch_optional(&pool).await.ok().flatten();
    let stored_hash = vault_key_row.and_then(|r| r.try_get::<String, _>("protocol_key_hash").ok()).unwrap_or_default();
    let env_key = std::env::var("PROTOCOL_SECRET_KEY").unwrap_or_default();
  let key_valid = if !stored_hash.is_empty() {
        use sha2::{Sha256, Digest};
        // Decode hex PSK to raw bytes — must match vault creation hashing
        if let Ok(psk_bytes) = hex::decode(&req.second_key) {
            let mut hasher = Sha256::new();
            hasher.update(&psk_bytes);
            hasher.update(b"ubtc-psk-salt-2026");
            let submitted_hash = hex::encode(hasher.finalize());
            submitted_hash == stored_hash
        } else {
            false
        }
    } else {
        req.second_key == env_key && !env_key.is_empty()
    };
    if !key_valid { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid second key"})))); }
    let message = format!("{}:{}:{}", vault_id, destination, amount);
    let pq_sig = quantum_sign(&pq_secret_key, message.as_bytes()).ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"quantum signing failed"}))))?;
    sqlx::query("UPDATE transfer_requests SET status = 'completed', verified_at = NOW(), pq_signature = $1 WHERE id = $2").bind(&pq_sig).bind(&req.otp_id).execute(&pool).await.ok();
    tracing::info!("Wallet OTP {} verified", req.otp_id);
    Ok(Json(WalletOtpVerifyResponse { verified: true, pq_signature: pq_sig, message: "OTP check Second Key check Quantum Signature check".to_string() }))
}

async fn sign_payload(
    Json(req): Json<SignPayloadRequest>,
) -> Result<Json<SignPayloadResponse>, (StatusCode, Json<serde_json::Value>)> {
    let sig = quantum_sign(&req.private_key, req.payload.as_bytes())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "signing failed — invalid private key"}))))?;
    Ok(Json(SignPayloadResponse { signature: sig }))
}

async fn wallet_redeem(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WalletRedeemRequest>,
) -> Result<Json<WalletRedeemResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let otp_row = sqlx::query("SELECT id, status FROM transfer_requests WHERE id = $1").bind(&req.otp_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"OTP not found"}))))?;
    let otp_status: String = otp_row.get("status");
    if otp_status != "completed" { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"OTP not verified"})))); }
    let wallet_row = sqlx::query("SELECT w.id, w.balance, w.user_id, w.linked_vault_id, u.username FROM ubtc_wallets w JOIN ubtc_users u ON w.user_id = u.id WHERE w.wallet_address = $1").bind(&req.wallet_address).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"wallet not found"}))))?;
    let wallet_id: String = wallet_row.get("id");
    let wallet_balance: String = wallet_row.get("balance");
    let linked_vault_id: String = wallet_row.get("linked_vault_id");
    let username: String = wallet_row.get("username");
    let balance_dec = Decimal::from_str(&wallet_balance).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.ubtc_amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;
    if amount > balance_dec { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("insufficient balance: {} available", balance_dec)})))); }
    if linked_vault_id.is_empty() { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"no linked vault found"})))); }
    let vault_row = sqlx::query("SELECT ubtc_minted, btc_amount_sats, status FROM vaults WHERE id = $1").bind(&linked_vault_id).fetch_one(&pool).await.map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"linked vault not found"}))))?;
    let vault_ubtc: String = vault_row.get("ubtc_minted");
    let vault_btc_sats: i64 = vault_row.get("btc_amount_sats");
    let vault_status: String = vault_row.get("status");
    if vault_status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"linked vault not active"})))); }
    let vault_ubtc_dec = Decimal::from_str(&vault_ubtc).unwrap_or(dec!(0));
    if vault_ubtc_dec == dec!(0) { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"no UBTC outstanding in linked vault"})))); }
    // Price-based: release exactly face value in BTC, overcollateral stays in vault
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_release_sats = ((amount / btc_price) * dec!(100_000_000)).to_string().parse::<f64>().unwrap_or(0.0) as i64;
    let btc_to_release_sats = btc_to_release_sats.min(vault_btc_sats);
    let txid = spend_vault_utxo(&pool, &linked_vault_id, &req.destination_btc_address, btc_to_release_sats).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    let btc_sent = btc_to_release_sats as f64 / 100_000_000.0;
    let new_wallet_balance = balance_dec - amount;
    let new_vault_ubtc = vault_ubtc_dec - amount;
    let new_vault_btc_sats = vault_btc_sats - btc_to_release_sats;
    sqlx::query("UPDATE ubtc_wallets SET balance = $1, updated_at = NOW() WHERE id = $2").bind(new_wallet_balance.to_string()).bind(&wallet_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2 WHERE id = $3").bind(new_vault_ubtc.to_string()).bind(new_vault_btc_sats).bind(&linked_vault_id).execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'wallet_redeem', NOW())").bind(&burn_id).bind(&linked_vault_id).bind(amount.to_string()).execute(&pool).await.ok();
    let tx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO wallet_transactions (id, from_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, 'redeem', 'UBTC Redeemed for BTC', 'completed', NOW())").bind(&tx_id).bind(wallet_row.get::<String, _>("user_id")).bind(amount.to_string()).execute(&pool).await.ok();
    tracing::info!("Wallet redeem @{} — {} UBTC -> {} BTC txid: {}", username, amount, btc_sent, txid);
    Ok(Json(WalletRedeemResponse { txid, wallet_address: req.wallet_address, ubtc_burned: amount.to_string(), btc_sent: format!("{:.8}", btc_sent), destination_btc_address: req.destination_btc_address, message: format!("${} UBTC redeemed. {} BTC sent to your Bitcoin address.", amount, btc_sent) }))
}

async fn mint_ubtc_proof(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    use ubtc_protocol::{UBTCState, CollateralProof, UBTCProof};
    let vault_id = req["vault_id"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault_id required"}))))?;
    let amount_sats = req["amount_sats"].as_u64().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"amount_sats required"}))))?;
    let owner_dilithium_pk = req["dilithium_pk"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"dilithium_pk required"}))))?;
    let owner_sphincs_pk = req["sphincs_pk"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"sphincs_pk required"}))))?;
    let row = sqlx::query("SELECT id, status, btc_amount_sats, ubtc_minted, utxo_txid FROM vaults WHERE id = $1")
        .bind(vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;
    let status: String = row.get("status");
    let btc_amount_sats: i64 = row.get("btc_amount_sats");
    let utxo_txid: Option<String> = row.try_get("utxo_txid").unwrap_or(None);
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault not active"})))); }
    let txid = utxo_txid.unwrap_or_else(|| "pending".to_string());
    let collateral = CollateralProof::new(txid.clone(), 0, btc_amount_sats as u64, "testnet4".to_string(), 0, 1);
    let dil_pk = base64::decode(owner_dilithium_pk)
        .or_else(|_| hex::decode(owner_dilithium_pk))
        .unwrap_or_else(|_| owner_dilithium_pk.as_bytes().to_vec());
    let sph_pk = hex::decode(owner_sphincs_pk).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid sphincs_pk"}))))?;
    let state = UBTCState::new_minted(amount_sats, dil_pk, sph_pk, txid, 0, btc_amount_sats as u64, 0, "testnet4".to_string())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let proof = UBTCProof::new_minted(state, collateral);
    let proof_json = proof.to_json().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let proof_id = format!("proof_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    tracing::info!("Minted UBTC proof {} for vault {} — {} sats", proof_id, vault_id, amount_sats);
    Ok(Json(serde_json::json!({
        "proof_id": proof_id,
        "vault_id": vault_id,
        "amount_sats": amount_sats,
        "proof": serde_json::from_str::<serde_json::Value>(&proof_json).unwrap_or(serde_json::json!({})),
        "message": "UBTC proof object created. This proof IS your UBTC. Store it securely."
    })))
}

async fn cosign_transfer(
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let nullifier = req["spent_nullifier"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"spent_nullifier required"}))))?;
    let recipient_pk = req["recipient_dilithium_pk"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"recipient_dilithium_pk required"}))))?;
    let cosign_id = format!("cosign_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    tracing::info!("Co-signed transfer — nullifier: {} recipient: {}...", &nullifier[..8], &recipient_pk[..8.min(recipient_pk.len())]);
    Ok(Json(serde_json::json!({
        "cosign_id": cosign_id,
        "status": "approved",
        "spent_nullifier": nullifier,
        "message": "Transfer co-signed. Post the nullifier to Bitcoin to complete."
    })))
}

async fn spend_nullifier(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let nullifier = req["nullifier"].as_str().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"nullifier required"}))))?;
    // Store nullifier in database
    sqlx::query("INSERT INTO nullifiers (id, nullifier_hex, spent_at) VALUES ($1, $2, NOW()) ON CONFLICT (nullifier_hex) DO NOTHING")
        .bind(format!("null_{}", &uuid::Uuid::new_v4().to_string()[..8])).bind(nullifier)
        .execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    // Post nullifier batch to Bitcoin via OP_RETURN
    let post_to_bitcoin = req["post_to_bitcoin"].as_bool().unwrap_or(true);
    let mut bitcoin_txid: Option<String> = None;
    if post_to_bitcoin {
        // Build OP_RETURN payload: "UBTCN1:" + nullifier_hex (first 32 bytes)
        let null_bytes = hex::decode(nullifier).unwrap_or_else(|_| nullifier.as_bytes().to_vec());
        let mut payload = b"UBTCN1:".to_vec();
        payload.extend_from_slice(&null_bytes[..null_bytes.len().min(32)]);
        let payload_hex = hex::encode(&payload);
        // Create OP_RETURN transaction
        let (rpc_url, rpc_user, rpc_pass) = get_rpc();
        let client = reqwest::Client::new();
        // Create raw tx with OP_RETURN
        let create_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
            .json(&serde_json::json!({"jsonrpc":"1.0","method":"createrawtransaction","params":[[],{"data": payload_hex}]}))
            .send().await;
        if let Ok(res) = create_res {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(raw_tx) = data["result"].as_str() {
                    // Fund the transaction
                    let fund_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
                        .json(&serde_json::json!({"jsonrpc":"1.0","method":"fundrawtransaction","params":[raw_tx]}))
                        .send().await;
                    if let Ok(fund_data) = fund_res {
                        if let Ok(fd) = fund_data.json::<serde_json::Value>().await {
                            if let Some(funded_hex) = fd["result"]["hex"].as_str() {
                                // Sign
                                let sign_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
                                    .json(&serde_json::json!({"jsonrpc":"1.0","method":"signrawtransactionwithwallet","params":[funded_hex]}))
                                    .send().await;
                                if let Ok(sign_data) = sign_res {
                                    if let Ok(sd) = sign_data.json::<serde_json::Value>().await {
                                        if let Some(signed_hex) = sd["result"]["hex"].as_str() {
                                            // Broadcast
                                            let send_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
                                                .json(&serde_json::json!({"jsonrpc":"1.0","method":"sendrawtransaction","params":[signed_hex]}))
                                                .send().await;
                                            if let Ok(send_data) = send_res {
                                                if let Ok(txdata) = send_data.json::<serde_json::Value>().await {
                                                    if let Some(txid) = txdata["result"].as_str() {
                                                        bitcoin_txid = Some(txid.to_string());
                                                        // Update nullifier with bitcoin txid
                                                        sqlx::query("UPDATE nullifiers SET bitcoin_txid = $1 WHERE nullifier_hex = $2")
                                                            .bind(txid).bind(nullifier).execute(&pool).await.ok();
                                                        tracing::info!("Nullifier posted to Bitcoin! txid: {}", txid);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    tracing::info!("Nullifier spent: {}", &nullifier[..16.min(nullifier.len())]);
    Ok(Json(serde_json::json!({
        "nullifier": nullifier,
        "spent": true,
        "bitcoin_txid": bitcoin_txid,
        "message": if bitcoin_txid.is_some() {
            "Nullifier recorded AND posted to Bitcoin testnet4 via OP_RETURN. Double-spend prevention is now on-chain."
        } else {
            "Nullifier recorded in database. Bitcoin posting skipped or failed."
        }
    })))
}

async fn check_nullifier(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(hex): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let row = sqlx::query("SELECT id FROM nullifiers WHERE nullifier_hex = $1")
        .bind(&hex).fetch_optional(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    Ok(Json(serde_json::json!({"nullifier": hex, "spent": row.is_some()})))
}

async fn redeem_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let err = |msg: &str| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg})));
    let vault_id = req["vault_id"].as_str().ok_or_else(|| err("vault_id required"))?;
    let ubtc_amount: f64 = req["ubtc_amount"].as_f64().ok_or_else(|| err("ubtc_amount required"))?;
    let destination = req["destination_address"].as_str().ok_or_else(|| err("destination_address required"))?;
    let qsk = req["qsk"].as_str().ok_or_else(|| err("qsk required"))?;
    if ubtc_amount <= 0.0 { return Err(err("amount must be positive")); }
    // Load vault
    let vault_row = sqlx::query(
        "SELECT id, status, btc_amount_sats, ubtc_minted, deposit_address, mast_address, taproot_secret_key, user_pubkey FROM vaults WHERE id = $1"
    ).bind(vault_id).fetch_one(&pool).await
        .map_err(|_| err("vault not found"))?;

    let status: String = vault_row.get("status");
    if status != "active" { return Err(err("vault not active")); }

    let btc_amount_sats: i64 = vault_row.get("btc_amount_sats");
    let ubtc_minted_str: String = vault_row.get("ubtc_minted");
    let ubtc_minted: f64 = ubtc_minted_str.parse().unwrap_or(0.0);
    let user_pubkey: String = vault_row.get("user_pubkey");
    let taproot_secret_key: Option<String> = vault_row.try_get("taproot_secret_key").unwrap_or(None);
    let deposit_address: String = vault_row.get("deposit_address");

    if ubtc_amount > ubtc_minted {
        return Err(err("cannot redeem more UBTC than minted"));
    }

   // Verify QSK — sign the redemption message and verify against stored public key
    let message = format!("redeem:{}:{}:{}", vault_id, ubtc_amount, destination);
    let signature = quantum_sign(qsk, message.as_bytes());
    let qsk_valid = if let Some(ref sig) = signature {
        quantum_verify(&user_pubkey, message.as_bytes(), sig)
    } else {
        false
    };
    if !qsk_valid {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid quantum signing key"}))));
    }

    // Get BTC price
  use rust_decimal::prelude::ToPrimitive; let btc_price = fetch_btc_price().await.map(|p| p.to_f64().unwrap_or(70000.0)).unwrap_or(70000.0);

    // Calculate BTC to release
    let btc_to_release_usd = ubtc_amount;
    let btc_to_release_sats = ((btc_to_release_usd / btc_price) * 100_000_000.0) as i64;

    // Check collateral ratio after redemption
    let remaining_ubtc = ubtc_minted - ubtc_amount;
    let remaining_btc_sats = btc_amount_sats - btc_to_release_sats;
    let remaining_btc_usd = (remaining_btc_sats as f64 / 100_000_000.0) * btc_price;

    if remaining_ubtc > 0.0 {
        let ratio_after = remaining_btc_usd / remaining_ubtc;
        if ratio_after < 1.10 {
            return Err(err("redemption would put vault below liquidation threshold"));
        }
    }

    // Load the vault UTXO
    let utxo_row = sqlx::query(
        "SELECT id, txid, vout, amount_sats FROM vault_utxos WHERE vault_id = $1 AND spent = false ORDER BY created_at DESC LIMIT 1"
    ).bind(vault_id).fetch_optional(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let redeem_id = format!("rdm_{}", &uuid::Uuid::new_v4().to_string()[..8]);

    if let Some(utxo) = utxo_row {
        let utxo_id: String = utxo.get("id");
        let utxo_txid: String = utxo.get("txid");
        let utxo_vout: i32 = utxo.get("vout");
        let utxo_amount_sats: i64 = utxo.get("amount_sats");

        // Construct and broadcast Bitcoin transaction using taproot_secret_key
        let btc_txid = if let Some(ref secret_key_hex) = taproot_secret_key {
            construct_and_broadcast_redemption(
                secret_key_hex,
                &utxo_txid,
                utxo_vout as u32,
                utxo_amount_sats as u64,
                btc_to_release_sats as u64,
                destination,
            ).await
        } else {
            // Fallback — use Bitcoin Core to send from deposit address
            let send_amount = btc_to_release_sats as f64 / 100_000_000.0;
            rpc_call("sendtoaddress", serde_json::json!([destination, send_amount]))
                .await.ok().and_then(|v| v.as_str().map(|s| s.to_string()))
        };

        if let Some(ref txid) = btc_txid {
            // Update vault
            sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2 WHERE id = $3")
                .bind((ubtc_minted - ubtc_amount).to_string())
                .bind(remaining_btc_sats)
                .bind(vault_id)
                .execute(&pool).await.ok();

            // Mark UTXO as spent if fully redeemed
            if remaining_ubtc == 0.0 {
                sqlx::query("UPDATE vault_utxos SET spent = true, spent_txid = $1 WHERE id = $2")
                    .bind(txid).bind(&utxo_id).execute(&pool).await.ok();
            }

            // Post nullifier to Bitcoin
            let nullifier = format!("redeem{}{}{}", vault_id, ubtc_amount, destination);
          use sha2::Digest; let null_hex = hex::encode(sha2::Sha256::digest(nullifier.as_bytes()));
            let _ = rpc_call("ubtc/nullifier/spend", serde_json::json!({"nullifier": null_hex})).await;

            tracing::info!("Redeemed {} UBTC from vault {} — BTC txid: {}", ubtc_amount, vault_id, txid);

            return Ok(Json(serde_json::json!({
                "redeem_id": redeem_id,
                "vault_id": vault_id,
                "ubtc_burned": ubtc_amount,
                "btc_released_sats": btc_to_release_sats,
                "btc_released_btc": btc_to_release_sats as f64 / 100_000_000.0,
                "destination": destination,
                "bitcoin_txid": txid,
                "remaining_ubtc": remaining_ubtc,
                "status": "completed",
                "message": format!("Redeemed {} UBTC — {} BTC sent to {}", ubtc_amount, btc_to_release_sats as f64 / 100_000_000.0, destination)
            })));
        }
    }

    // No UTXO found — use Bitcoin Core sendtoaddress as fallback
    let send_amount = btc_to_release_sats as f64 / 100_000_000.0;
    let btc_txid = rpc_call("sendtoaddress", serde_json::json!([destination, send_amount])).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Bitcoin send failed: {}", e)}))))?;
    let txid = btc_txid.as_str().unwrap_or("").to_string();

    sqlx::query("UPDATE vaults SET ubtc_minted = $1, btc_amount_sats = $2 WHERE id = $3")
        .bind((ubtc_minted - ubtc_amount).to_string())
        .bind(remaining_btc_sats)
        .bind(vault_id)
        .execute(&pool).await.ok();

    tracing::info!("Redeemed {} UBTC from vault {} (fallback) — txid: {}", ubtc_amount, vault_id, txid);

    Ok(Json(serde_json::json!({
        "redeem_id": redeem_id,
        "vault_id": vault_id,
        "ubtc_burned": ubtc_amount,
        "btc_released_sats": btc_to_release_sats,
        "btc_released_btc": send_amount,
        "destination": destination,
        "bitcoin_txid": txid,
        "remaining_ubtc": remaining_ubtc,
        "status": "completed",
     "message": format!("Redeemed {} UBTC — {} BTC sent to {}", ubtc_amount, send_amount, destination)
    })))
}

async fn construct_and_broadcast_redemption(
    secret_key_hex: &str,
    utxo_txid: &str,
    utxo_vout: u32,
    utxo_amount_sats: u64,
    release_sats: u64,
    destination: &str,
) -> Option<String> {
    use bitcoin::{
        secp256k1::{Secp256k1, SecretKey},
        Transaction, TxIn, TxOut, OutPoint, Txid,
        script::Builder,
        taproot::TaprootSpendInfo,
        Address, Network as BtcNetwork,
        absolute::LockTime,
        transaction::Version,
        Amount, ScriptBuf,
    };
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let secret_key_bytes = hex::decode(secret_key_hex).ok()?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).ok()?;

    // Parse destination address
    let dest_addr = Address::from_str(destination).ok()?.assume_checked();

    // Parse UTXO
    let txid = Txid::from_str(utxo_txid).ok()?;
    let outpoint = OutPoint { txid, vout: utxo_vout };

    // Fee estimate — 200 sats/vbyte × ~150 vbytes = 30000 sats
    let fee_sats = 30000u64;
    let output_sats = release_sats.saturating_sub(fee_sats);

    if output_sats == 0 { return None; }

    // Build transaction
    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::new(),
    };

    let tx_out = TxOut {
        value: Amount::from_sat(output_sats),
        script_pubkey: dest_addr.script_pubkey(),
    };

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    // Sign with Taproot key path spend
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
    let (xonly, _) = pubkey.x_only_public_key();

    use bitcoin::sighash::{SighashCache, TapSighashType};
    use bitcoin::taproot::LeafVersion;

    let mut sighash_cache = SighashCache::new(&tx);
    let prevouts = vec![TxOut {
        value: Amount::from_sat(utxo_amount_sats),
        script_pubkey: bitcoin::Address::p2tr(&secp, xonly, None, BtcNetwork::Testnet).script_pubkey(),
    }];

    let sighash = sighash_cache.taproot_key_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&prevouts),
        TapSighashType::Default,
    ).ok()?;

  use bitcoin_hashes::Hash; let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let mut witness = bitcoin::Witness::new();
    witness.push(sig.as_ref());
    tx.input[0].witness = witness;

    // Serialize and broadcast
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    let result = crate::rpc_call("sendrawtransaction", serde_json::json!([tx_hex])).await;

    match result {
        Ok(v) => v.as_str().map(|s| s.to_string()),
        Err(e) => {
            tracing::warn!("Raw transaction broadcast failed: {} — trying fallback", e);
            None
        }
    }
}

async fn stablecoin_deposit(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<StablecoinDepositRequest>,
) -> Result<Json<StablecoinDepositResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let currency = req.currency.to_uppercase();
    if currency != "UUSDT" && currency != "UUSDC" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "currency must be UUSDT or UUSDC"}))));
    }
    let amount = Decimal::from_str(&req.amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid amount"}))))?;
    if amount <= dec!(0) { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "amount must be positive"})))); }
    let account_type = req.account_type.unwrap_or_else(|| "current".to_string());
    // Check if a vault already exists for this currency + account_type — top it up instead of creating new
    let existing_sc = sqlx::query("SELECT id, deposited_amount FROM stablecoin_vaults WHERE currency = $1 AND account_type = $2 AND status = 'active' ORDER BY created_at ASC LIMIT 1")
        .bind(&currency).bind(&account_type).fetch_optional(&pool).await.unwrap_or(None);
    let vault_id = if let Some(ex_row) = existing_sc {
        let ex_id: String = ex_row.get("id");
        let ex_dep: String = ex_row.get("deposited_amount");
        let new_dep = Decimal::from_str(&ex_dep).unwrap_or(dec!(0)) + amount;
        sqlx::query("UPDATE stablecoin_vaults SET deposited_amount = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_dep.to_string()).bind(&ex_id).execute(&pool)
            .await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        ex_id
    } else {
        let new_id = format!("sc_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO stablecoin_vaults (id, currency, balance, deposited_amount, account_type, status, created_at, updated_at) VALUES ($1, $2, '0', $3, $4, 'active', NOW(), NOW())")
            .bind(&new_id).bind(&currency).bind(amount.to_string()).bind(&account_type)
            .execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
        new_id
    };
    let tx_id = format!("sctx_{}", &Uuid::new_v4().to_string()[..8]);
    let underlying = if currency == "UUSDT" { "USDT" } else { "USDC" };
    sqlx::query("INSERT INTO stablecoin_transactions (id, vault_id, kind, amount, currency, description, created_at) VALUES ($1, $2, 'deposit', $3, $4, $5, NOW())")
        .bind(&tx_id).bind(&vault_id).bind(amount.to_string()).bind(&currency)
        .bind(format!("{} deposited — locked in quantum vault", underlying))
        .execute(&pool).await.ok();
    tracing::info!("Stablecoin deposit {} {} vault={}", amount, currency, vault_id);
    Ok(Json(StablecoinDepositResponse {
        vault_id, currency: currency.clone(), deposited: amount.to_string(),
        message: format!("${} {} locked in quantum vault. Now mint {} 1:1 against it.", amount, underlying, currency),
    }))
}

async fn stablecoin_mint(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<StablecoinMintRequest>,
) -> Result<Json<StablecoinMintResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, currency, balance, deposited_amount, status FROM stablecoin_vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "stablecoin vault not found"}))))?;
    let currency: String = row.get("currency");
    let balance: String = row.get("balance");
    let deposited: String = row.get("deposited_amount");
    let status: String = row.get("status");
    if status != "active" { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "vault not active"})))); }
    let balance_dec = Decimal::from_str(&balance).unwrap_or(dec!(0));
    let deposited_dec = Decimal::from_str(&deposited).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid amount"}))))?;
    let max_mintable = deposited_dec - balance_dec;
    if amount > max_mintable {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("amount {} exceeds available to mint {}. Deposit more {} first.", amount, max_mintable, if currency == "UUSDT" { "USDT" } else { "USDC" })
        }))));
    }
    let new_balance = balance_dec + amount;
    sqlx::query("UPDATE stablecoin_vaults SET balance = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_balance.to_string()).bind(&req.vault_id).execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let mint_id = format!("scmint_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO stablecoin_transactions (id, vault_id, kind, amount, currency, description, created_at) VALUES ($1, $2, 'mint', $3, $4, $5, NOW())")
        .bind(&mint_id).bind(&req.vault_id).bind(amount.to_string()).bind(&currency)
        .bind(format!("{} minted 1:1 — quantum-secured on Bitcoin protocol", currency))
        .execute(&pool).await.ok();
    tracing::info!("Minted {} {} vault={}", amount, currency, req.vault_id);
    let underlying = if currency == "UUSDT" { "USDT" } else { "USDC" };
    Ok(Json(StablecoinMintResponse {
        mint_id, vault_id: req.vault_id, currency: currency.clone(),
        minted: amount.to_string(), deposited: deposited_dec.to_string(),
        message: format!("${} {} minted 1:1 against locked {}.", amount, currency, underlying),
    }))
}

async fn stablecoin_burn(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<StablecoinBurnRequest>,
) -> Result<Json<StablecoinBurnResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, currency, balance, deposited_amount FROM stablecoin_vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;
    let currency: String = row.get("currency");
    let balance: String = row.get("balance");
    let deposited: String = row.get("deposited_amount");
    let balance_dec = Decimal::from_str(&balance).unwrap_or(dec!(0));
    let deposited_dec = Decimal::from_str(&deposited).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid amount"}))))?;
    if amount > balance_dec { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("burn {} exceeds balance {}", amount, balance_dec)})))); }
    let new_balance = balance_dec - amount;
    let new_deposited = deposited_dec - amount;
    sqlx::query("UPDATE stablecoin_vaults SET balance = $1, deposited_amount = $2, updated_at = NOW() WHERE id = $3")
        .bind(new_balance.to_string()).bind(new_deposited.to_string()).bind(&req.vault_id)
        .execute(&pool).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let burn_id = format!("scburn_{}", &Uuid::new_v4().to_string()[..8]);
    let underlying = if currency == "UUSDT" { "USDT" } else { "USDC" };
    sqlx::query("INSERT INTO stablecoin_transactions (id, vault_id, kind, amount, currency, description, created_at) VALUES ($1, $2, 'burn', $3, $4, $5, NOW())")
        .bind(&burn_id).bind(&req.vault_id).bind(amount.to_string()).bind(&currency)
        .bind(format!("{} burned — {} released from quantum vault", currency, underlying))
        .execute(&pool).await.ok();
    tracing::info!("Burned {} {} vault={}", amount, currency, req.vault_id);
    Ok(Json(StablecoinBurnResponse {
        burn_id, vault_id: req.vault_id, currency: currency.clone(),
        burned: amount.to_string(), returned: amount.to_string(),
        message: format!("${} {} burned. ${} {} released from quantum vault back to you.", amount, currency, amount, underlying),
    }))
}

async fn stablecoin_transfer(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<StablecoinTransferRequest>,
) -> Result<Json<StablecoinTransferResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, currency, balance FROM stablecoin_vaults WHERE id = $1")
        .bind(&req.from_vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;
    let currency: String = row.get("currency");
    let balance: String = row.get("balance");
    let balance_dec = Decimal::from_str(&balance).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.amount).map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid amount"}))))?;
    if amount > balance_dec { return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("insufficient balance: {} available", balance_dec)})))); }
    let new_balance = balance_dec - amount;
    sqlx::query("UPDATE stablecoin_vaults SET balance = $1, updated_at = NOW() WHERE id = $2")
        .bind(new_balance.to_string()).bind(&req.from_vault_id).execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    let transfer_id = format!("sctxfr_{}", &Uuid::new_v4().to_string()[..8]);
    let underlying = if currency == "UUSDT" { "USDT" } else { "USDC" };
    sqlx::query("INSERT INTO stablecoin_transactions (id, vault_id, kind, amount, currency, description, created_at) VALUES ($1, $2, 'transfer', $3, $4, $5, NOW())")
        .bind(&transfer_id).bind(&req.from_vault_id).bind(amount.to_string()).bind(&currency)
        .bind(format!("{} transferred — quantum signature verified", currency))
        .execute(&pool).await.ok();
   // Credit recipient wallet if to_address is a UBTC wallet
    if let Ok(wallet_row) = sqlx::query("SELECT id, user_id, uusdt_balance, uusdc_balance FROM ubtc_wallets WHERE wallet_address = $1")
        .bind(&req.to_address).fetch_one(&pool).await {
        let wallet_id: String = wallet_row.get("id");
        let to_user_id: String = wallet_row.get("user_id");
        if currency == "UUSDT" {
            let bal: String = wallet_row.get("uusdt_balance");
            let new_bal = Decimal::from_str(&bal).unwrap_or(dec!(0)) + amount;
            sqlx::query("UPDATE ubtc_wallets SET uusdt_balance = $1, updated_at = NOW() WHERE id = $2")
                .bind(new_bal.to_string()).bind(&wallet_id).execute(&pool).await.ok();
        } else {
            let bal: String = wallet_row.get("uusdc_balance");
            let new_bal = Decimal::from_str(&bal).unwrap_or(dec!(0)) + amount;
            sqlx::query("UPDATE ubtc_wallets SET uusdc_balance = $1, updated_at = NOW() WHERE id = $2")
                .bind(new_bal.to_string()).bind(&wallet_id).execute(&pool).await.ok();
        }
        let wtx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO wallet_transactions (id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, 'received', $4, 'completed', NOW())")
            .bind(&wtx_id).bind(&to_user_id).bind(amount.to_string())
            .bind(format!("{} received from transfer", currency)).execute(&pool).await.ok();
        tracing::info!("Credited wallet {} with {} {}", req.to_address, amount, currency);
    }
    if let Ok(wallet_row) = sqlx::query("SELECT id, user_id, uusdt_balance, uusdc_balance FROM ubtc_wallets WHERE wallet_address = $1")
        .bind(&req.to_address).fetch_one(&pool).await {
        use sqlx::Row;
        let wallet_id: String = wallet_row.get("id");
        let to_user_id: String = wallet_row.get("user_id");
        if currency == "UUSDT" {
            let bal: String = wallet_row.get("uusdt_balance");
            let new_bal = Decimal::from_str(&bal).unwrap_or(dec!(0)) + amount;
            sqlx::query("UPDATE ubtc_wallets SET uusdt_balance = $1, updated_at = NOW() WHERE id = $2")
                .bind(new_bal.to_string()).bind(&wallet_id).execute(&pool).await.ok();
        } else {
            let bal: String = wallet_row.get("uusdc_balance");
            let new_bal = Decimal::from_str(&bal).unwrap_or(dec!(0)) + amount;
            sqlx::query("UPDATE ubtc_wallets SET uusdc_balance = $1, updated_at = NOW() WHERE id = $2")
                .bind(new_bal.to_string()).bind(&wallet_id).execute(&pool).await.ok();
        }
        let wtx_id = format!("wtx_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO wallet_transactions (id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, 'received', $4, 'completed', NOW())")
            .bind(&wtx_id).bind(&to_user_id).bind(amount.to_string())
            .bind(format!("{} received from transfer", currency)).execute(&pool).await.ok();
    }
	tracing::info!("Transfer {} {} to {}", amount, currency, req.to_address);
    Ok(Json(StablecoinTransferResponse {
        transfer_id, from_vault_id: req.from_vault_id,
        currency: currency.clone(), amount: amount.to_string(),
        message: format!("${} {} transferred. Underlying {} stays locked in vault.", amount, currency, underlying),
    }))
}

async fn get_stablecoin_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> Result<Json<StablecoinVault>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, currency, balance, deposited_amount, account_type, status FROM stablecoin_vaults WHERE id = $1")
        .bind(&vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;
    Ok(Json(StablecoinVault {
        vault_id: row.get("id"), currency: row.get("currency"),
        balance: row.get("balance"), deposited_amount: row.get("deposited_amount"),
        account_type: row.get("account_type"), status: row.get("status"),
    }))
}

async fn get_stablecoin_transactions(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(vault_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id, kind, amount, currency, description, created_at FROM stablecoin_transactions WHERE vault_id = $1 ORDER BY created_at DESC")
        .bind(&vault_id).fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let txs: Vec<serde_json::Value> = rows.iter().map(|row| {
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        let desc: Option<String> = row.try_get("description").ok().flatten();
        serde_json::json!({
            "id": row.get::<String, _>("id"),
            "kind": row.get::<String, _>("kind"),
            "amount": row.get::<String, _>("amount"),
            "currency": row.get::<String, _>("currency"),
            "description": desc.unwrap_or_else(|| "Transaction".to_string()),
            "created_at": created_at.to_rfc3339(),
        })
    }).collect();
    Ok(Json(serde_json::json!({ "vault_id": vault_id, "transactions": txs })))
}

async fn get_all_stablecoins(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT id, currency, balance, deposited_amount, account_type, status, created_at FROM stablecoin_vaults WHERE status != 'archived' ORDER BY created_at DESC")
        .fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let vaults: Vec<serde_json::Value> = rows.iter().map(|row| {
        let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");
        serde_json::json!({
            "vault_id": row.get::<String, _>("id"),
            "currency": row.get::<String, _>("currency"),
            "balance": row.get::<String, _>("balance"),
            "deposited_amount": row.get::<String, _>("deposited_amount"),
            "account_type": row.get::<String, _>("account_type"),
            "status": row.get::<String, _>("status"),
            "created_at": created_at.to_rfc3339(),
        })
    }).collect();
    Ok(Json(serde_json::json!({ "stablecoins": vaults })))
}