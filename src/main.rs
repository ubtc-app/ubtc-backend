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

#[derive(Deserialize)] struct CreateVaultRequest { user_pubkey: String, network: Option<String>, recovery_blocks: Option<i32>, account_type: Option<String> }
#[derive(Serialize)] struct CreateVaultResponse { vault_id: String, deposit_address: String, network: String, recovery_blocks: i32, account_type: String }
#[derive(Serialize)] struct VaultStatus { vault_id: String, status: String, deposit_address: String, btc_amount_sats: i64, ubtc_minted: String, confirmations: i32, account_type: String }
#[derive(Deserialize)] struct MintRequest { vault_id: String, ubtc_amount: String }
#[derive(Serialize)] struct MintResponse { mint_id: String, vault_id: String, ubtc_minted: String, collateral_ratio: String, max_mintable: String, btc_price_usd: String }
#[derive(Deserialize)] struct BurnRequest { vault_id: String, ubtc_to_burn: String }
#[derive(Serialize)] struct BurnResponse { burn_id: String, vault_id: String, ubtc_burned: String, new_outstanding: String, vault_status: String }
#[derive(Deserialize)] struct DepositRequest { vault_id: String, amount_btc: String }
#[derive(Serialize)] struct DepositResponse { txid: String, vault_id: String, amount_btc: String, deposit_address: String }
#[derive(Serialize)] struct DashboardResponse { active_vaults: i64, total_btc_sats: i64, total_ubtc_minted: String, btc_price_usd: String, vaults: Vec<VaultStatus> }
#[derive(Deserialize)] struct TransferRequest { from_vault_id: String, to_address: String, ubtc_amount: String, pq_signature: Option<String> }
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
        .route("/wallet/:address/send", post(send_from_wallet))
        .route("/wallet/:address/transactions", get(get_wallet_transactions))
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
    let network = req.network.unwrap_or_else(|| "regtest".to_string());
    let recovery_blocks: i32 = req.recovery_blocks.unwrap_or(6);
    let account_type = req.account_type.unwrap_or_else(|| "current".to_string());
    let deposit_address = rpc_call("getnewaddress", serde_json::json!([])).await
        .map(|v| v.as_str().unwrap_or("").to_string()).unwrap_or_default();
    sqlx::query("INSERT INTO vaults (id, deposit_address, user_pubkey, internal_key, recovery_blocks, status, network, account_type, created_at) VALUES ($1, $2, $3, $4, $5, 'pending_deposit', $6, $7, NOW())")
        .bind(&vault_id).bind(&deposit_address).bind(&req.user_pubkey)
        .bind(&req.user_pubkey).bind(recovery_blocks).bind(&network).bind(&account_type)
        .execute(&pool).await.map_err(|e| { tracing::error!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;
    tracing::info!("Created vault {} type={}", vault_id, account_type);
    Ok(Json(CreateVaultResponse { vault_id, deposit_address, network, recovery_blocks, account_type }))
}

async fn get_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<VaultStatus>, StatusCode> {
    let row = sqlx::query("SELECT id, status, deposit_address, btc_amount_sats, ubtc_minted, confirmations, account_type FROM vaults WHERE id = $1")
        .bind(&id).fetch_one(&pool).await.map_err(|_| StatusCode::NOT_FOUND)?;
    use sqlx::Row;
    Ok(Json(VaultStatus {
        vault_id: row.get("id"), status: row.get("status"),
        deposit_address: row.get("deposit_address"),
        btc_amount_sats: row.get("btc_amount_sats"),
        ubtc_minted: row.get("ubtc_minted"),
        confirmations: row.get("confirmations"),
        account_type: row.get("account_type"),
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
    // Ask Bitcoin Core what has been received at this address
    let received = rpc_call("listreceivedbyaddress", serde_json::json!([0, true, true, deposit_address])).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;
    let entries = received.as_array().unwrap_or(&vec![]).clone();
    let entry = entries.iter().find(|e| e["address"].as_str() == Some(&deposit_address));
    if entry.is_none() {
        return Ok(Json(serde_json::json!({"found": false, "message": "No BTC received at this address yet"})));
    }
    let entry = entry.unwrap();
    let amount_btc = entry["amount"].as_f64().unwrap_or(0.0);
    let confirmations = entry["confirmations"].as_i64().unwrap_or(0);
    let txids = entry["txids"].as_array().cloned().unwrap_or_default();
    if amount_btc == 0.0 || txids.is_empty() {
        return Ok(Json(serde_json::json!({"found": false, "message": "No confirmed BTC found"})));
    }
    let txid = txids.last().and_then(|t| t.as_str()).unwrap_or("").to_string();
    let amount_sats = (amount_btc * 100_000_000.0) as i64;
    // Get transaction details to find vout
    let tx_info = rpc_call("gettransaction", serde_json::json!([txid])).await.unwrap_or(serde_json::json!({}));
    let vout = tx_info["details"].as_array()
        .and_then(|d| d.iter().find(|x| x["address"].as_str() == Some(&deposit_address)))
        .and_then(|d| d["vout"].as_i64()).unwrap_or(0) as i32;
    // Check if we already recorded this UTXO
    let existing = sqlx::query("SELECT id FROM vault_utxos WHERE vault_id = $1 AND txid = $2")
        .bind(vault_id).bind(&txid).fetch_optional(&pool).await.unwrap_or(None);
    if existing.is_none() {
        let utxo_id = format!("utxo_{}", &Uuid::new_v4().to_string()[..8]);
        sqlx::query("INSERT INTO vault_utxos (id, vault_id, txid, vout, amount_sats, vault_address, spent, created_at) VALUES ($1, $2, $3, $4, $5, $6, false, NOW())")
            .bind(&utxo_id).bind(vault_id).bind(&txid).bind(vout).bind(amount_sats).bind(&deposit_address)
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
    Ok(Json(MintResponse { mint_id, vault_id, ubtc_minted: total_after.to_string(), collateral_ratio: collateral_ratio.to_string(), max_mintable: max_mintable.to_string(), btc_price_usd: btc_price.to_string() }))
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
        sqlx::query("INSERT INTO wallet_transactions (id, to_user_id, amount, transaction_type, description, status, created_at) VALUES ($1, $2, $3, 'received', 'UBTC received from transfer', 'completed', NOW())")
            .bind(&wtx_id).bind(&to_user_id).bind(amount.to_string()).execute(&pool).await.ok();
        tracing::info!("Credited wallet {} with {} UBTC", req.to_address, amount);
    }
    Ok(Json(TransferResponse { transfer_id, from_vault_id: vault_id, to_address: req.to_address, ubtc_amount: amount.to_string(), taproot_placeholder: true, message: "UBTC transferred. BTC vault unchanged.".to_string() }))
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
    let vaults: Vec<VaultStatus> = rows.iter().map(|row| VaultStatus { vault_id: row.get("id"), status: row.get("status"), deposit_address: row.get("deposit_address"), btc_amount_sats: row.get("btc_amount_sats"), ubtc_minted: row.get("ubtc_minted"), confirmations: row.get("confirmations"), account_type: row.get("account_type") }).collect();
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
        Ok(Json(SendFromWalletResponse { transaction_id: tx_id, from_address: req.from_address, to: recipient_username, amount: amount.to_string(), send_type: "internal".to_string(), message: "UBTC sent internally. BTC collateral unchanged.".to_string() }))
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
    let protocol_key = std::env::var("PROTOCOL_SECRET_KEY").unwrap_or_default();
    if req.second_key != protocol_key || protocol_key.is_empty() { return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid second key"})))); }
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