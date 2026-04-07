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

#[derive(Deserialize)]
struct CreateVaultRequest {
    user_pubkey: String,
    network: Option<String>,
    recovery_blocks: Option<i32>,
}

#[derive(Serialize)]
struct CreateVaultResponse {
    vault_id: String,
    deposit_address: String,
    network: String,
    recovery_blocks: i32,
}

#[derive(Serialize)]
struct VaultStatus {
    vault_id: String,
    status: String,
    deposit_address: String,
    btc_amount_sats: i64,
    ubtc_minted: String,
    confirmations: i32,
}

#[derive(Deserialize)]
struct MintRequest {
    vault_id: String,
    ubtc_amount: String,
}

#[derive(Serialize)]
struct MintResponse {
    mint_id: String,
    vault_id: String,
    ubtc_minted: String,
    collateral_ratio: String,
    max_mintable: String,
    btc_price_usd: String,
}

#[derive(Deserialize)]
struct BurnRequest {
    vault_id: String,
    ubtc_to_burn: String,
}

#[derive(Serialize)]
struct BurnResponse {
    burn_id: String,
    vault_id: String,
    ubtc_burned: String,
    new_outstanding: String,
    vault_status: String,
}

#[derive(Deserialize)]
struct DepositRequest {
    vault_id: String,
    amount_btc: String,
}

#[derive(Serialize)]
struct DepositResponse {
    txid: String,
    vault_id: String,
    amount_btc: String,
    deposit_address: String,
}

#[derive(Deserialize)]
struct WithdrawRequest {
    vault_id: String,
    ubtc_amount: String,
    destination_address: String,
}

#[derive(Serialize)]
struct WithdrawResponse {
    txid: String,
    vault_id: String,
    ubtc_burned: String,
    btc_sent: String,
    destination_address: String,
    btc_price_usd: String,
    new_outstanding: String,
    vault_status: String,
}

#[derive(Serialize)]
struct DashboardResponse {
    active_vaults: i64,
    total_btc_sats: i64,
    total_ubtc_minted: String,
    btc_price_usd: String,
    vaults: Vec<VaultStatus>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    tracing::info!("Connected to database");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health))
        .route("/vaults", post(create_vault))
        .route("/vaults/:id", get(get_vault))
        .route("/mint", post(mint_ubtc))
        .route("/burn", post(burn_ubtc))
        .route("/deposit", post(deposit_btc))
        .route("/withdraw", post(withdraw))
        .route("/dashboard", get(dashboard))
        .route("/price", get(get_price))
        .with_state(pool)
        .layer(cors);

    let addr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

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
    let res = client
        .get("https://api.coinbase.com/v2/prices/BTC-USD/spot")
        .send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    let price_str = json["data"]["amount"].as_str()?;
    Decimal::from_str(price_str).ok()
}

fn get_rpc() -> (String, String, String) {
    (
        std::env::var("BTC_RPC_URL").unwrap_or("http://127.0.0.1:18443".to_string()),
        std::env::var("BTC_RPC_USER").unwrap_or("ubtc".to_string()),
        std::env::var("BTC_RPC_PASS").unwrap_or("ubtcpassword".to_string()),
    )
}

async fn create_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<CreateVaultRequest>,
) -> Result<Json<CreateVaultResponse>, StatusCode> {
    let vault_id = format!("vault_{}", &Uuid::new_v4().to_string()[..8]);
    let network = req.network.unwrap_or_else(|| "regtest".to_string());
    let recovery_blocks: i32 = req.recovery_blocks.unwrap_or(6);

    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();

    let _ = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":["ubtc-test"]}))
        .send().await;

    let addr_res = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"getnewaddress","params":[]}))
        .send().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let addr_json: serde_json::Value = addr_res.json().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let deposit_address = addr_json["result"].as_str()
        .unwrap_or("").to_string();

    sqlx::query!(
        r#"INSERT INTO vaults
           (id, deposit_address, user_pubkey, internal_key,
            recovery_blocks, status, network, created_at)
           VALUES ($1, $2, $3, $4, $5, 'pending_deposit', $6, NOW())"#,
        vault_id, deposit_address, req.user_pubkey,
        req.user_pubkey, recovery_blocks, network,
    )
    .execute(&pool)
    .await
    .map_err(|e| { tracing::error!("DB error: {}", e); StatusCode::INTERNAL_SERVER_ERROR })?;

    tracing::info!("Created vault {} with address {}", vault_id, deposit_address);

    Ok(Json(CreateVaultResponse {
        vault_id, deposit_address, network, recovery_blocks,
    }))
}

async fn get_vault(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<VaultStatus>, StatusCode> {
    let row = sqlx::query!(
        r#"SELECT id, status, deposit_address,
                  btc_amount_sats, ubtc_minted, confirmations
           FROM vaults WHERE id = $1"#,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(VaultStatus {
        vault_id: row.id,
        status: row.status,
        deposit_address: row.deposit_address,
        btc_amount_sats: row.btc_amount_sats,
        ubtc_minted: row.ubtc_minted,
        confirmations: row.confirmations,
    }))
}

async fn deposit_btc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<DepositRequest>,
) -> Result<Json<DepositResponse>, (StatusCode, Json<serde_json::Value>)> {
    let vault = sqlx::query!(
        "SELECT id, deposit_address, status FROM vaults WHERE id = $1",
        req.vault_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();

    let _ = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":["ubtc-test"]}))
        .send().await;

    let amount: f64 = req.amount_btc.parse().unwrap_or(0.5);
    let send_res = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "sendtoaddress",
            "params": [vault.deposit_address, amount]
        }))
        .send().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let send_json: serde_json::Value = send_res.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    if let Some(err) = send_json.get("error") {
        if !err.is_null() {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": err["message"]}))));
        }
    }

    let txid = send_json["result"].as_str().unwrap_or("").to_string();

    let addr_res = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"getnewaddress","params":[]}))
        .send().await.ok();

    if let Some(r) = addr_res {
        if let Ok(j) = r.json::<serde_json::Value>().await {
            if let Some(addr) = j["result"].as_str() {
                let _ = client.post(&rpc_url)
                    .basic_auth(&rpc_user, Some(&rpc_pass))
                    .json(&serde_json::json!({"jsonrpc":"1.0","method":"generatetoaddress","params":[1, addr]}))
                    .send().await;
            }
        }
    }

    let amount_sats = (amount * 100_000_000.0) as i64;
    sqlx::query!(
        "UPDATE vaults SET btc_amount_sats = $1, confirmations = 1, status = 'active', utxo_txid = $2 WHERE id = $3",
        amount_sats, txid, vault.id
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    tracing::info!("Deposited {} BTC to vault {}", amount, vault.id);

    Ok(Json(DepositResponse {
        txid, vault_id: vault.id,
        amount_btc: req.amount_btc,
        deposit_address: vault.deposit_address,
    }))
}

async fn withdraw(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<WithdrawRequest>,
) -> Result<Json<WithdrawResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Load vault
    let vault = sqlx::query!(
        "SELECT id, status, ubtc_minted, btc_amount_sats FROM vaults WHERE id = $1",
        req.vault_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"vault not found"}))))?;

    if vault.status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault is not active (status: {})", vault.status)}))));
    }

    let outstanding = Decimal::from_str(&vault.ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_amount)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid ubtc_amount"}))))?;

    if to_burn > outstanding {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("withdraw {} exceeds outstanding {}", to_burn, outstanding)}))));
    }

    // Get live BTC price
    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));

    // Calculate BTC to send: ubtc_amount / btc_price
    let btc_to_send = to_burn / btc_price;
    let btc_to_send_f64: f64 = btc_to_send.to_string().parse().unwrap_or(0.0);
    // Round to 8 decimal places
    let btc_to_send_rounded = (btc_to_send_f64 * 100_000_000.0).round() / 100_000_000.0;

    // Send BTC to destination via Bitcoin Core RPC
    let (rpc_url, rpc_user, rpc_pass) = get_rpc();
    let client = reqwest::Client::new();

    let _ = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"loadwallet","params":["ubtc-test"]}))
        .send().await;

    let send_res = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({
            "jsonrpc": "1.0",
            "method": "sendtoaddress",
            "params": [req.destination_address, btc_to_send_rounded]
        }))
        .send().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let send_json: serde_json::Value = send_res.json().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    if let Some(err) = send_json.get("error") {
        if !err.is_null() {
            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": err["message"]}))));
        }
    }

    let txid = send_json["result"].as_str().unwrap_or("").to_string();

    // Mine 1 block to confirm
    let addr_res = client.post(&rpc_url)
        .basic_auth(&rpc_user, Some(&rpc_pass))
        .json(&serde_json::json!({"jsonrpc":"1.0","method":"getnewaddress","params":[]}))
        .send().await.ok();

    if let Some(r) = addr_res {
        if let Ok(j) = r.json::<serde_json::Value>().await {
            if let Some(addr) = j["result"].as_str() {
                let _ = client.post(&rpc_url)
                    .basic_auth(&rpc_user, Some(&rpc_pass))
                    .json(&serde_json::json!({"jsonrpc":"1.0","method":"generatetoaddress","params":[1, addr]}))
                    .send().await;
            }
        }
    }

    // Update DB
    let new_outstanding = outstanding - to_burn;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    let new_status = if new_outstanding == dec!(0) { "closed" } else { "active" };

    sqlx::query!(
        r#"INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at)
           VALUES ($1, $2, $3, 'partial', NOW())"#,
        burn_id, vault.id, to_burn.to_string(),
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    sqlx::query!(
        "UPDATE vaults SET ubtc_minted = $1, status = $2 WHERE id = $3",
        new_outstanding.to_string(), new_status, vault.id,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    tracing::info!("Withdrew {} UBTC ({} BTC) from vault {} to {}", to_burn, btc_to_send_rounded, vault.id, req.destination_address);

    Ok(Json(WithdrawResponse {
        txid,
        vault_id: vault.id,
        ubtc_burned: to_burn.to_string(),
        btc_sent: btc_to_send_rounded.to_string(),
        destination_address: req.destination_address,
        btc_price_usd: btc_price.to_string(),
        new_outstanding: new_outstanding.to_string(),
        vault_status: new_status.to_string(),
    }))
}

async fn dashboard(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
) -> Result<Json<DashboardResponse>, StatusCode> {
    let vaults = sqlx::query!(
        r#"SELECT id, status, deposit_address, btc_amount_sats, ubtc_minted, confirmations
           FROM vaults ORDER BY created_at DESC"#
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let active_vaults = vaults.iter().filter(|v| v.status == "active").count() as i64;
    let total_btc_sats: i64 = vaults.iter().map(|v| v.btc_amount_sats).sum();
    let total_ubtc: Decimal = vaults.iter()
        .map(|v| Decimal::from_str(&v.ubtc_minted).unwrap_or(dec!(0)))
        .sum();

    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));

    let vault_list = vaults.into_iter().map(|v| VaultStatus {
        vault_id: v.id, status: v.status,
        deposit_address: v.deposit_address,
        btc_amount_sats: v.btc_amount_sats,
        ubtc_minted: v.ubtc_minted,
        confirmations: v.confirmations,
    }).collect();

    Ok(Json(DashboardResponse {
        active_vaults, total_btc_sats,
        total_ubtc_minted: total_ubtc.to_string(),
        btc_price_usd: btc_price.to_string(),
        vaults: vault_list,
    }))
}

async fn mint_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<MintRequest>,
) -> Result<Json<MintResponse>, (StatusCode, Json<serde_json::Value>)> {
    let vault = sqlx::query!(
        "SELECT id, status, btc_amount_sats, ubtc_minted FROM vaults WHERE id = $1",
        req.vault_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;

    if vault.status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault is not active (status: {})", vault.status)}))));
    }

    let btc_price = fetch_btc_price().await.unwrap_or(dec!(65000));
    let sats = Decimal::from(vault.btc_amount_sats);
    let btc_value = (sats / dec!(100_000_000)) * btc_price;
    let max_mintable = btc_value / dec!(1.5);
    let existing = Decimal::from_str(&vault.ubtc_minted).unwrap_or(dec!(0));
    let requested = Decimal::from_str(&req.ubtc_amount)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid ubtc_amount"}))))?;
    let total_after = existing + requested;

    if total_after > max_mintable {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("total {} exceeds max mintable {}", total_after, max_mintable)}))));
    }

    let collateral_ratio = btc_value / total_after;
    let mint_id = format!("mint_{}", &Uuid::new_v4().to_string()[..8]);

    sqlx::query!(
        r#"INSERT INTO mints (id, vault_id, ubtc_amount, btc_price_usd, collateral_ratio, status, created_at)
           VALUES ($1, $2, $3, $4, $5, 'active', NOW())"#,
        mint_id, vault.id, requested.to_string(),
        btc_price.to_string(), collateral_ratio.to_string(),
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    sqlx::query!(
        "UPDATE vaults SET ubtc_minted = $1 WHERE id = $2",
        total_after.to_string(), vault.id,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    tracing::info!("Minted {} UBTC from vault {}", requested, vault.id);

    Ok(Json(MintResponse {
        mint_id, vault_id: vault.id,
        ubtc_minted: total_after.to_string(),
        collateral_ratio: collateral_ratio.to_string(),
        max_mintable: max_mintable.to_string(),
        btc_price_usd: btc_price.to_string(),
    }))
}

async fn burn_ubtc(
    axum::extract::State(pool): axum::extract::State<sqlx::PgPool>,
    Json(req): Json<BurnRequest>,
) -> Result<Json<BurnResponse>, (StatusCode, Json<serde_json::Value>)> {
    let vault = sqlx::query!(
        "SELECT id, status, ubtc_minted FROM vaults WHERE id = $1",
        req.vault_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "vault not found"}))))?;

    if vault.status != "active" {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("vault is not active (status: {})", vault.status)}))));
    }

    let outstanding = Decimal::from_str(&vault.ubtc_minted).unwrap_or(dec!(0));
    let to_burn = Decimal::from_str(&req.ubtc_to_burn)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid ubtc_to_burn"}))))?;

    if to_burn > outstanding {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("burn {} exceeds outstanding {}", to_burn, outstanding)}))));
    }

    let new_outstanding = outstanding - to_burn;
    let burn_id = format!("burn_{}", &Uuid::new_v4().to_string()[..8]);
    let new_status = if new_outstanding == dec!(0) { "closed" } else { "active" };

    sqlx::query!(
        r#"INSERT INTO burns (id, vault_id, ubtc_burned, kind, created_at)
           VALUES ($1, $2, $3, $4, NOW())"#,
        burn_id, vault.id, to_burn.to_string(),
        if new_status == "closed" { "full" } else { "partial" },
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    sqlx::query!(
        "UPDATE vaults SET ubtc_minted = $1, status = $2 WHERE id = $3",
        new_outstanding.to_string(), new_status, vault.id,
    )
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("db error: {}", e)}))))?;

    tracing::info!("Burned {} UBTC from vault {}", to_burn, vault.id);

    Ok(Json(BurnResponse {
        burn_id, vault_id: vault.id,
        ubtc_burned: to_burn.to_string(),
        new_outstanding: new_outstanding.to_string(),
        vault_status: new_status.to_string(),
    }))
}