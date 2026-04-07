//! Authentication Service (AS) for the MLS-SRTP demo.
//!
//! A minimal credential registry that maps client identities to their Ed25519
//! public signing keys. In the MLS architecture (RFC 9420 §5.3.1), the AS is
//! responsible for validating credentials so that group members can verify
//! each other's identities.
//!
//! This implementation contains an in-memory `HashMap``, 
//! with no persistence and no authentication on the registration endpoint. 
//! It is sufficient for demonstrating the credential verification flow.
//!
//! Endpoints:
//!   - `POST /register`            — store identity + public key
//!   - `GET  /lookup/{identity}`   — retrieve a client's public key

use actix_web::{web, App, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// ANSI escape: yellow text for AS prefix
const TAG: &str = "\x1b[33m[AS]\x1b[0m";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Application state holding the credential registry, shared across all
/// actix-web worker threads.
#[derive(Default)]
struct AsData {
    /// Maps identity (e.g. "sender-48231:sender") to base64-encoded Ed25519 public signing key.
    /// Wrapped in a `Mutex` because actix-web handlers run concurrently.
    credentials: Mutex<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Request/response types
// ---------------------------------------------------------------------------

/// JSON body for `POST /register`.
#[derive(Deserialize)]
struct RegisterRequest {
    identity: String,
    /// Ed25519 public signing key, standard-base64-encoded.
    public_key: String,
}

/// JSON response for `GET /lookup/{identity}`.
#[derive(Serialize)]
struct LookupResponse {
    identity: String,
    /// Ed25519 public signing key, standard-base64-encoded.
    public_key: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handles `POST /register`: stores a client's identity and public key.
///
/// Returns 409 Conflict if the identity is already registered.
async fn register(data: web::Data<AsData>, body: web::Json<RegisterRequest>) -> HttpResponse {
    let mut creds = data.credentials.lock().unwrap();

    // rejecting duplicate registrations to prevent identity takeover
    if creds.contains_key(&body.identity) {
        println!("{TAG} CONFLICT: \"{}\" already registered", body.identity);
        return HttpResponse::Conflict().body("identity already registered");
    }

    // logging a truncated key prefix for debugging
    println!(
        "{TAG} Registered \"{}\" (public_key: {}...)",
        body.identity,
        &body.public_key[..std::cmp::min(16, body.public_key.len())]
    );

    // inserting into the credential store
    creds.insert(body.identity.clone(), body.public_key.clone());
    HttpResponse::Ok().finish()
}

/// Handles `GET /lookup/{identity}`: returns a client's public key.
///
/// Returns 404 if the identity has not been registered.
async fn lookup(data: web::Data<AsData>, path: web::Path<String>) -> HttpResponse {
    let identity = path.into_inner();
    let creds = data.credentials.lock().unwrap();

    match creds.get(&identity) {
        Some(public_key) => {
            println!("{TAG} Lookup \"{}\" -> found", identity);
            HttpResponse::Ok().json(LookupResponse {
                identity,
                public_key: public_key.clone(),
            })
        }
        None => {
            println!("{TAG} Lookup \"{}\" -> NOT FOUND", identity);
            HttpResponse::NotFound().body("identity not found")
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("{TAG} === Authentication Service (AS) ===");
    println!("{TAG} Listening on http://127.0.0.1:8001");

    // wrapping in web::Data so all worker threads share one credential store
    let data = web::Data::new(AsData::default());

    // actix-web spawns multiple worker threads, 
    // but they all share the same data
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .route("/register", web::post().to(register))
            .route("/lookup/{identity}", web::get().to(lookup))
    })
    .bind("127.0.0.1:8001")?
    .run()
    .await
}
