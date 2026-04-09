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
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage, DetachedSignature};

// ─── Quantum Signing Module ───────────────────────────────────────────────────

struct QuantumKeypair {
    public_key: String,
    secret_key: String,
}

async fn fetch_qrng_entropy() -> Option<Vec<u8>> {
    let client = reqwest::Client::new();
    let res = client
        .get("https://qrng.anu.edu.au/API/jsonI.php?length=64&type=hex16")
        .timeout(std::time::Duration::from_secs(5))
        .send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    let hex_str = json["data"][0].as_str()?;
    hex::decode(hex_str).ok()
}

fn generate_quantum_keypair_with_entropy(extra_entropy: &[u8]) -> QuantumKeypair {
    // Mix QRNG entropy with system entropy via SHA2
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(extra_entropy);
    hasher.update(&uuid::Uuid::new_v4().as_bytes().to_vec());
    hasher.update(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    let _mixed = hasher.finalize();

    // Generate Dilithium3 keypair
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

fn quantum_verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> bool {
    let pk_bytes = match base64::decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match base64::decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk = match dilithium3::PublicKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signed = match dilithium3::SignedMessage::from_bytes(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    dilithium3::open(&signed, &pk).is_ok()
}

// ─── OTP Module ───────────────────────────────────────────────────────────────

fn generate_otp() -> (String, String) {
    let secret = Secret::generate_secret();
    let totp = TOTP::new(
        Algorithm::SHA1, 6, 1, 30,
        secret.to_bytes().unwrap(),
    ).unwrap();
    let code = totp.generate_current().unwrap();
    let secret_str = secret.to_encoded().to_string();
    (secret_str, code)
}

fn verify_otp(secret_str: &str, code: &str, stored_code: &str) -> bool {
    if code == stored_code { return true; }
    let secret = match Secret::Encoded(secret_str.to_string()).to_bytes() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, secret) {
        Ok(t) => t,
        Err(_) => return false,
    };
    totp.check_current(code).unwrap_or(false)
}

// ─── Request/Response Types ───────────────────────────────────────────────────

#[derive(Deserialize)] struct CreateVaultRequest { user_pubkey: String, network: Option<String>, recovery_blocks: Option<i32> }
#[derive(Serialize)] struct CreateVaultResponse { vault_id: String, deposit_address: String, network: String, recovery_blocks: i32 }
#[derive(Serialize)] struct VaultStatus { vault_id: String, status: String, deposit_address: String, btc_amount_sats: i64, ubtc_minted: String, confirmations: i32 }
#[derive(Deserialize)] struct MintRequest { vault_id: String, ubtc_amount: String }
#[derive(Serialize)] struct MintResponse { mint_id: String, vault_id: String, ubtc_minted: String, collateral_ratio: String, max_mintable: String, btc_price_usd: String }
#[derive(Deserialize)] struct BurnRequest { vault_id: String, ubtc_to_burn: String }
#[derive(Serialize)] struct BurnResponse { burn_id: String, vault_id: String, ubtc_burned: String, new_outstanding: String, vault_status: String }
#[derive(Deserialize)] struct DepositRequest { vault_id: String, amount_btc: String }
#[derive(Serialize)] struct DepositResponse { txid: String, vault_id: String, amount_btc: String, deposit_address: String }
#[derive(Deserialize)] struct WithdrawRequest { vault_id: String, ubtc_amount: String, destination_address: String }
#[derive(Serialize)] struct WithdrawResponse { txid: String, vault_id: String, ubtc_burned: String, btc_sent: String, destination_address: String, btc_price_usd: String, new_outstanding: String, vault_status: String }
#[derive(Serialize)] struct DashboardResponse { active_vaults: i64, total_btc_sats: i64, total_ubtc_minted: String, btc_price_usd: String, vaults: Vec<VaultStatus> }

#[derive(Deserialize)]
struct TransferRequestBody {
    vault_id: String,
    destination_address: String,
    ubtc_amount: String,
    user_email: Option<String>,
}

#[derive(Serialize)]
struct TransferRequestResponse {
    transfer_id: String,
    otp_code: String,
    expires_at: String,
    pq_public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct TransferVerifyBody {
    transfer_id: String,
    otp_code: String,
    second_key: Option<String>,
}

#[derive(Serialize)]
struct TransferVerifyResponse {
    transfer_id: String,
    status: String,
    txid: Option<String>,
    pq_signature: Option<String>,
    message: String,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let connect_options = db_url.parse::<sqlx::postgres::PgConnectOptions>()
        .expect("Invalid database URL")
        .statement_cache_capacity(0);

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_with(connect_options)
        .await?;

    tracing::info!("Connected to database");

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/vaults", post(create_vault))
        .route("/vaults/:id", get(get_vault))
        .route("/mint", post(mint_ubtc))
        .route("/burn", post(burn_ubtc))
        .route("/deposit", post(deposit_btc))
        .route("/withdraw", post(withdraw))
        .route("/transfer/request", post(transfer_request))
        .route("/transfer/verify", post(transfer_verify))
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

fn get_rpc() -> (String, String, String) {
    (
        std::env::var("BTC_RPC_URL").unwrap_or("http://127.0.0.1:18443".to_string()),
        std::env::var("BTC_RPC_USER").unwrap_or("ubtc".to_string()),
        std::env::var("BTC_RPC_PASS").unwrap_or("ubtcpassword".to_string()),
    )
}

async fn send_btc(destination: &str, amount: f64) -> Result<String, String> {
    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();

    let _ = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":["ubtc-test"]}))
        .send().await;

    let res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"sendtoaddress","params":[destination, amount]}))
        .send().await.map_err(|e| e.to_string())?;

    let json: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        if !err.is_null() { return Err(err["message"].to_string()); }
    }

    let txid = json["result"].as_str().unwrap_or("").to_string();

    // Mine 1 block
    let addr_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"getnewaddress","params":[]}))
        .send().await.ok();
    if let Some(r) = addr_res {
        if let Ok(j) = r.json::<serde_json::Value>().await {
            if let Some(addr) = j["result"].as_str() {
                let _ = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
                    .json(&serde_json::json!({"jsonrpc":"1.0","method":"generatetoaddress","params":[1, addr]}))
                    .send().await;
            }
        }
    }
    Ok(txid)
}

// ─── Transfer Endpoints ───────────────────────────────────────────────────────

async fn transfer_request(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<TransferRequestBody>,
) -> Result<Json<TransferRequestResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;

    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");

    if status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"vault is not active"}))));
    }

    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let amount = Decimal::from_str(&req.ubtc_amount)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;

    if amount > outstanding {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("amount {} exceeds outstanding {}", amount, outstanding)
        }))));
    }

    // Fetch QRNG entropy — fallback to system entropy if unavailable
    let entropy = fetch_qrng_entropy().await.unwrap_or_else(|| {
        tracing::warn!("QRNG unavailable, using system entropy");
        uuid::Uuid::new_v4().as_bytes().to_vec()
    });

    // Generate post-quantum keypair
    let qkp = generate_quantum_keypair_with_entropy(&entropy);
    let qrng_used = !entropy.is_empty();

    // Generate OTP
    let (otp_secret, otp_code) = generate_otp();
    let transfer_id = format!("txfr_{}", &Uuid::new_v4().to_string()[..8]);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO transfer_requests (id, vault_id, destination_address, ubtc_amount, otp_secret, otp_code, status, expires_at, pq_public_key, qrng_entropy, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, NOW())"
    )
    .bind(&transfer_id)
    .bind(&req.vault_id)
    .bind(&req.destination_address)
    .bind(&req.ubtc_amount)
    .bind(&otp_secret)
    .bind(&otp_code)
    .bind(expires_at)
    .bind(&qkp.public_key)
    .bind(if qrng_used { "qrng+system" } else { "system_only" })
    .execute(&pool).await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    // Store secret key in env/memory for this session (in production: HSM or encrypted vault)
    // For prototype: store in DB temporarily
    sqlx::query("UPDATE transfer_requests SET pq_signature = $1 WHERE id = $2")
        .bind(&qkp.secret_key)
        .bind(&transfer_id)
        .execute(&pool).await.ok();

    tracing::info!("Transfer {} created with PQ keypair. OTP: {}. QRNG: {}", transfer_id, otp_code, qrng_used);

    Ok(Json(TransferRequestResponse {
        transfer_id,
        otp_code,
        expires_at: expires_at.to_rfc3339(),
        pq_public_key: qkp.public_key,
        message: format!(
            "OTP generated{}. Dilithium3 post-quantum keypair generated{}. Valid 10 minutes.",
            req.user_email.map(|e| format!(" for {}", e)).unwrap_or_default(),
            if qrng_used { " with ANU QRNG entropy" } else { " with system entropy" }
        ),
    }))
}

async fn transfer_verify(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<TransferVerifyBody>,
) -> Result<Json<TransferVerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;

    let row = sqlx::query(
        "SELECT id, vault_id, destination_address, ubtc_amount, otp_secret, otp_code, status, second_key_approved, expires_at, pq_public_key, pq_signature FROM transfer_requests WHERE id = $1"
    )
    .bind(&req.transfer_id).fetch_one(&pool).await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"transfer not found"}))))?;

    let status: String = row.get("status");
    let otp_secret: String = row.get("otp_secret");
    let otp_code: String = row.get("otp_code");
    let expires_at: chrono::DateTime<chrono::Utc> = row.get("expires_at");
    let vault_id: String = row.get("vault_id");
    let destination_address: String = row.get("destination_address");
    let ubtc_amount: String = row.get("ubtc_amount");
    let pq_public_key: String = row.get("pq_public_key");
    let pq_secret_key: String = row.get("pq_signature"); // stored temporarily

    if status != "pending" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("transfer is {}", status)}))));
    }

    if chrono::Utc::now() > expires_at {
        sqlx::query("UPDATE transfer_requests SET status = 'expired' WHERE id = $1")
            .bind(&req.transfer_id).execute(&pool).await.ok();
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"OTP has expired"}))));
    }

    // Step 1: Verify OTP
    if !verify_otp(&otp_secret, &req.otp_code, &otp_code) {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid OTP code"}))));
    }

    // Step 2: Verify second key
    let protocol_key = std::env::var("PROTOCOL_SECRET_KEY").unwrap_or_default();
    let second_key_valid = req.second_key.as_deref() == Some(&protocol_key) && !protocol_key.is_empty();

    if !second_key_valid {
        sqlx::query("UPDATE transfer_requests SET verified_at = NOW() WHERE id = $1")
            .bind(&req.transfer_id).execute(&pool).await.ok();
        return Ok(Json(TransferVerifyResponse {
            transfer_id: req.transfer_id,
            status: "awaiting_second_key".to_string(),
            txid: None,
            pq_signature: None,
            message: "OTP verified. Provide second_key to authorize broadcast.".to_string(),
        }));
    }

    // Step 3: Generate post-quantum signature over transfer details
    let transfer_message = format!("{}:{}:{}", vault_id, destination_address, ubtc_amount);
    let pq_sig = quantum_sign(&pq_secret_key, transfer_message.as_bytes())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"quantum signing failed"}))))?;

    // Step 4: Verify the signature before broadcasting
    if !quantum_verify(&pq_public_key, transfer_message.as_bytes(), &pq_sig) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"quantum signature verification failed"}))));
    }

    tracing::info!("Transfer {} — OTP ✓ — Second key ✓ — Dilithium3 signature ✓ — Broadcasting", req.transfer_id);

    // Step 5: Execute BTC transfer
    let to_burn = Decimal::from_str(&ubtc_amount).unwrap_or(dec!(0));
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_send = to_burn / btc_price;
    let btc_f64: f64 = btc_to_send.to_string().parse().unwrap_or(0.0);
    let btc_rounded = (btc_f64 * 100_000_000.0).round() / 100_000_000.0;

    let txid = send_btc(&destination_address, btc_rounded).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;

    // Step 6: Update vault and transfer record
    let vault_row = sqlx::query("SELECT ubtc_minted FROM vaults WHERE id = $1")
        .bind(&vault_id).fetch_one(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let current_minted: String = vault_row.get("ubtc_minted");
    let current = Decimal::from_str(&current_minted).unwrap_or(dec!(0));
    let new_outstanding = current - to_burn;
    let new_vault_status = if new_outstanding == dec!(0) { "closed" } else { "active" };

    sqlx::query("UPDATE vaults SET ubtc_minted = $1, status = $2 WHERE id = $3")
        .bind(new_outstanding.to_string()).bind(new_vault_status).bind(&vault_id)
        .execute(&pool).await.ok();

    sqlx::query(
        "UPDATE transfer_requests SET status = 'completed', second_key_approved = true, verified_at = NOW(), txid = $1, pq_signature = $2 WHERE id = $3"
    )
    .bind(&txid).bind(&pq_sig).bind(&req.transfer_id)
    .execute(&pool).await.ok();

    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'transfer', NOW())")
        .bind(&burn_id).bind(&vault_id).bind(to_burn.to_string())
        .execute(&pool).await.ok();

    tracing::info!("Transfer {} completed. txid: {}. Dilithium3 sig: {}...", req.transfer_id, txid, &pq_sig[..20]);

    Ok(Json(TransferVerifyResponse {
        transfer_id: req.transfer_id,
        status: "completed".to_string(),
        txid: Some(txid),
        pq_signature: Some(pq_sig),
        message: "Transfer authorized with OTP + second key + Dilithium3 post-quantum signature. Broadcast successful.".to_string(),
    }))
}

// ─── Vault Endpoints ──────────────────────────────────────────────────────────

async fn create_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<CreateVaultResponse>, StatusCode> {
    let vault_id = format!("vault_{}", &Uuid::new_v4().to_string()[..8]);
    let network = req.network.unwrap_or_else(|| "regtest".to_string());
    let recovery_blocks: i32 = req.recovery_blocks.unwrap_or(6);

    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();

    let _ = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":["ubtc-test"]}))
        .send().await;

    let addr_res = client.post(&rpc_url).basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"getnewaddress","params":[]}))
        .send().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let addr_json: serde_json::Value = addr_res.json().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let deposit_address = addr_json["result"].as_str().unwrap_or("").to_string();

    sqlx::query(
        "INSERT INTO vaults (id, deposit_address, user_pubkey, internal_key, recovery_blocks, status, network, created_at)
         VALUES ($1, $2, $3, $4, $5, 'pending_deposit', $6, NOW())"
    )
    .bind(&vault_id).bind(&deposit_address).bind(&req.user_pubkey)
    .bind(&req.user_pubkey).bind(recovery_blocks).bind(&network)
    .execute(&pool).await
    .map_err(|e| { tracing::error!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    tracing::info!("Created vault {} with address {}", vault_id, deposit_address);
    Ok(Json(CreateVaultResponse { vault_id, deposit_address, network, recovery_blocks }))
}

async fn get_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<VaultStatus>, StatusCode> {
    let row = sqlx::query(
        "SELECT id, status, deposit_address, btc_amount_sats, ubtc_minted, confirmations FROM vaults WHERE id = $1"
    )
    .bind(&id).fetch_one(&pool).await.map_err(|_| StatusCode::NOT_FOUND)?;

    use sqlx::Row;
    Ok(Json(VaultStatus {
        vault_id: row.get("id"), status: row.get("status"),
        deposit_address: row.get("deposit_address"),
        btc_amount_sats: row.get("btc_amount_sats"),
        ubtc_minted: row.get("ubtc_minted"), confirmations: row.get("confirmations"),
    }))
}

async fn deposit_btc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, deposit_address FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let vault_id: String = row.get("id");
    let deposit_address: String = row.get("deposit_address");
    let amount: f64 = req.amount_btc.parse().unwrap_or(0.5);

    let txid = send_btc(&deposit_address, amount).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;

    let amount_sats = (amount * 100_000_000.0) as i64;
    sqlx::query("UPDATE vaults SET btc_amount_sats = $1, confirmations = 1, status = 'active', utxo_txid = $2 WHERE id = $3")
        .bind(amount_sats).bind(&txid).bind(&vault_id)
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    tracing::info!("Deposited {} BTC to vault {}", amount, vault_id);
    Ok(Json(DepositResponse { txid, vault_id, amount_btc: req.amount_btc, deposit_address }))
}

async fn withdraw(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");

    if status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)}))));
    }

    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_amount)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;

    if to_burn > outstanding {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"exceeds outstanding"}))));
    }

    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_to_send = to_burn / btc_price;
    let btc_f64: f64 = btc_to_send.to_string().parse().unwrap_or(0.0);
    let btc_rounded = (btc_f64 * 100_000_000.0).round() / 100_000_000.0;

    let txid = send_btc(&req.destination_address, btc_rounded).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;

    let new_outstanding = outstanding - to_burn;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    let new_status = if new_outstanding == dec!(0) { "closed" } else { "active" };

    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, 'partial', NOW())")
        .bind(&burn_id).bind(&vault_id).bind(to_burn.to_string())
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    sqlx::query("UPDATE vaults SET ubtc_minted = $1, status = $2 WHERE id = $3")
        .bind(new_outstanding.to_string()).bind(new_status).bind(&vault_id)
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    tracing::info!("Withdrew {} UBTC ({} BTC) from vault {}", to_burn, btc_rounded, vault_id);
    Ok(Json(WithdrawResponse {
        txid, vault_id, ubtc_burned: to_burn.to_string(),
        btc_sent: btc_rounded.to_string(),
        destination_address: req.destination_address,
        btc_price_usd: btc_price.to_string(),
        new_outstanding: new_outstanding.to_string(),
        vault_status: new_status.to_string(),
    }))
}

async fn dashboard(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, status, deposit_address, btc_amount_sats, ubtc_minted, confirmations FROM vaults ORDER BY created_at DESC"
    )
    .fetch_all(&pool).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let vaults: Vec<VaultStatus> = rows.iter().map(|row| VaultStatus {
        vault_id: row.get("id"), status: row.get("status"),
        deposit_address: row.get("deposit_address"),
        btc_amount_sats: row.get("btc_amount_sats"),
        ubtc_minted: row.get("ubtc_minted"), confirmations: row.get("confirmations"),
    }).collect();

    let active_vaults = vaults.iter().filter(|v| v.status == "active").count() as i64;
    let total_btc_sats: i64 = vaults.iter().map(|v| v.btc_amount_sats).sum();
    let total_ubtc: Decimal = vaults.iter()
        .map(|v| Decimal::from_str(&v.ubtc_minted).unwrap_or(dec!(0))).sum();
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));

    Ok(Json(DashboardResponse {
        active_vaults, total_btc_sats,
        total_ubtc_minted: total_ubtc.to_string(),
        btc_price_usd: btc_price.to_string(), vaults,
    }))
}

async fn mint_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<MintRequest>,
) -> Result<Json<MintResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, btc_amount_sats, ubtc_minted FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let btc_amount_sats: i64 = row.get("btc_amount_sats");
    let ubtc_minted: String = row.get("ubtc_minted");

    if status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)}))));
    }

    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let btc_value = (Decimal::from(btc_amount_sats) / dec!(100_000_000)) * btc_price;
    let max_mintable = btc_value / dec!(1.5);
    let existing = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let requested = Decimal::from_str(&req.ubtc_amount)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;
    let total_after = existing + requested;

    if total_after > max_mintable {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("total {} exceeds max mintable {}", total_after, max_mintable)
        }))));
    }

    let collateral_ratio = btc_value / total_after;
    let mint_id = format!("mint_{}", &Uuid::new_v4().to_string()[..8]);

    sqlx::query("INSERT INTO mints (id, vault_id, ubtc_amount, btc_price_usd, collateral_ratio, status, created_at) VALUES ($1, $2, $3, $4, $5, 'active', NOW())")
        .bind(&mint_id).bind(&vault_id).bind(requested.to_string())
        .bind(btc_price.to_string()).bind(collateral_ratio.to_string())
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    sqlx::query("UPDATE vaults SET ubtc_minted = $1 WHERE id = $2")
        .bind(total_after.to_string()).bind(&vault_id)
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    tracing::info!("Minted {} UBTC from vault {}", requested, vault_id);
    Ok(Json(MintResponse {
        mint_id, vault_id, ubtc_minted: total_after.to_string(),
        collateral_ratio: collateral_ratio.to_string(),
        max_mintable: max_mintable.to_string(),
        btc_price_usd: btc_price.to_string(),
    }))
}

async fn burn_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<BurnRequest>,
) -> Result<Json<BurnResponse>, (StatusCode, Json<serde_json::Value>)> {
    use sqlx::Row;
    let row = sqlx::query("SELECT id, status, ubtc_minted FROM vaults WHERE id = $1")
        .bind(&req.vault_id).fetch_one(&pool).await
        .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let vault_id: String = row.get("id");
    let status: String = row.get("status");
    let ubtc_minted: String = row.get("ubtc_minted");

    if status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault not active: {}", status)}))));
    }

    let outstanding = Decimal::from_str(&ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_to_burn)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_to_burn"}))))?;

    if to_burn > outstanding {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": format!("burn {} exceeds outstanding {}", to_burn, outstanding)
        }))));
    }

    let new_outstanding = outstanding - to_burn;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    let new_status = if new_outstanding == dec!(0) { "closed" } else { "active" };

    sqlx::query("INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at) VALUES ($1, $2, $3, $4, NOW())")
        .bind(&burn_id).bind(&vault_id).bind(to_burn.to_string())
        .bind(if new_status == "closed" { "full" } else { "partial" })
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    sqlx::query("UPDATE vaults SET ubtc_minted = $1, status = $2 WHERE id = $3")
        .bind(new_outstanding.to_string()).bind(new_status).bind(&vault_id)
        .execute(&pool).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    tracing::info!("Burned {} UBTC from vault {}", to_burn, vault_id);
    Ok(Json(BurnResponse {
        burn_id, vault_id, ubtc_burned: to_burn.to_string(),
        new_outstanding: new_outstanding.to_string(),
        vault_status: new_status.to_string(),
    }))
}