//! HTTP client helpers for communicating with the Authentication Service (AS)
//! and the OpenMLS Delivery Service (DS).
//!
//! The AS uses a simple JSON API (our custom auth service). The DS uses the
//! OpenMLS binary protocol: all request and response bodies are TLS-serialized.
//!
//! Two different base64 encodings are used:
//!   - Standard base64 (`+/=`): for AS JSON payloads (public keys)
//!   - URL-safe base64 (`-_`): for DS URL path segments (client identity)

use base64::engine::general_purpose::URL_SAFE as BASE64_URL;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use ds_lib::messages::{AuthToken, RecvMessageRequest, RegisterClientRequest};
use ds_lib::ClientKeyPackages;
use openmls::prelude::tls_codec::{
    Deserialize as TlsDeserialize, Serialize as TlsSerialize, TlsByteVecU8, TlsVecU16, TlsVecU32,
};
use openmls::prelude::*;

// ---------------------------------------------------------------------------
// AS JSON types
// ---------------------------------------------------------------------------

/// JSON body for `POST /register` on the AS.
#[derive(Serialize)]
pub struct AsRegisterRequest {
    pub identity: String,
    /// Ed25519 public signing key, standard-base64-encoded.
    pub public_key: String,
}

/// JSON response from `GET /lookup/{identity}` on the AS.
#[derive(Deserialize)]
pub struct AsLookupResponse {
    pub identity: String,
    /// Ed25519 public signing key, standard-base64-encoded.
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// HTTP client for interacting with the AS and the OpenMLS DS.
pub struct DsClient {
    /// Base URL of the Authentication Service (e.g. "http://127.0.0.1:8001").
    as_url: String,
    /// Base URL of the Delivery Service (e.g. "http://127.0.0.1:8080").
    ds_url: String,
    /// HTTP client used to send requests to the AS and DS servers.
    http: Client,
    /// Auth token returned by the DS upon registration; required for
    /// subsequent DS requests (message retrieval).
    auth_token: Option<AuthToken>,
    /// Client identity bytes (the MLS basic credential content, e.g. b"sender-48231:sender").
    client_id: Option<Vec<u8>>,
}

impl DsClient {
    /// Creates a new client targeting the given AS and DS base URLs.
    pub fn new(as_url: &str, ds_url: &str) -> Self {
        Self {
            as_url: as_url.to_string(),
            ds_url: ds_url.to_string(),
            http: Client::new(),
            auth_token: None,
            client_id: None,
        }
    }

    /// Returns the base64-URL-safe encoding of the client identity,
    /// as required by the OpenMLS DS URL paths.
    fn id_b64(&self) -> String {
        BASE64_URL.encode(self.client_id.as_ref().expect("not registered with DS"))
    }

    /// Returns the auth token, panicking if not yet registered.
    fn auth_token(&self) -> &AuthToken {
        self.auth_token.as_ref().expect("not registered with DS")
    }

    // -- Authentication Service -----------------------------------------------

    /// Registers an identity and its public signing key with the AS.
    ///
    /// The public key bytes are base64-encoded for JSON transport.
    pub async fn register_with_as(
        &self,
        identity: &str,
        public_key: &[u8],
    ) -> Result<(), String> {

        // encoding the raw Ed25519 public key as standard base64 for JSON
        let resp = self
            .http
            .post(format!("{}/register", self.as_url))
            .json(&AsRegisterRequest {
                identity: identity.to_string(),
                public_key: BASE64.encode(public_key),
            })
            .send()
            .await
            .map_err(|e| format!("AS register request failed: {e}"))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("AS register failed: HTTP {}", resp.status()))
        }
    }

    /// Looks up a client's public signing key by identity from the AS.
    ///
    /// Decodes the base64 public key from the JSON response and returns
    /// the raw bytes.
    pub async fn lookup_as(&self, identity: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .http
            .get(format!("{}/lookup/{}", self.as_url, identity))
            .send()
            .await
            .map_err(|e| format!("AS lookup request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("AS lookup failed: HTTP {}", resp.status()));
        }

        // parsing the JSON response containing the base64-encoded public key
        let body: AsLookupResponse = resp
            .json()
            .await
            .map_err(|e| format!("AS lookup parse failed: {e}"))?;

        // decoding base64 back to raw Ed25519 public key bytes
        BASE64
            .decode(&body.public_key)
            .map_err(|e| format!("AS lookup base64 decode failed: {e}"))
    }

    // -- Delivery Service (OpenMLS DS) ----------------------------------------

    /// Registers with the OpenMLS DS, uploading KeyPackages.
    ///
    /// Sends a `RegisterClientRequest` containing KeyPackages paired with
    /// their hash references. The DS stores the KeyPackages and returns a
    /// `RegisterClientSuccessResponse` with an `AuthToken` that must be
    /// included in subsequent requests.
    pub async fn register_with_ds(
        &mut self,
        identity: &[u8],
        key_packages: Vec<(Vec<u8>, KeyPackageIn)>,
    ) -> Result<(), String> {
        // wrapping each (hash, key_package) pair into the ds-lib type
        let client_kps = ClientKeyPackages(
            key_packages
                .into_iter()
                .map(|(hash, kp)| (TlsByteVecU8::from(hash), kp))
                .collect::<Vec<_>>()
                .into(),
        );

        let req = RegisterClientRequest {
            key_packages: client_kps,
        };

        // serializing the request using the TLS presentation language (binary)
        let body = req
            .tls_serialize_detached()
            .map_err(|e| format!("TLS serialize RegisterClientRequest failed: {e}"))?;

        let resp = self
            .http
            .post(format!("{}/clients/register", self.ds_url))
            .body(body)
            .send()
            .await
            .map_err(|e| format!("DS register request failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("DS register failed: HTTP {}", resp.status()));
        }

        // deserializing the response to extract the auth token
        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("DS register response read failed: {e}"))?;

        let success =
            ds_lib::messages::RegisterClientSuccessResponse::tls_deserialize_exact(&resp_bytes)
                .map_err(|e| format!("DS register response parse failed: {e}"))?;

        // storing the auth token and identity for subsequent DS requests
        self.auth_token = Some(success.auth_token);
        self.client_id = Some(identity.to_vec());
        Ok(())
    }

    /// Lists all client identities currently registered on the DS.
    ///
    /// Uses `GET /clients/list` which returns a TLS-serialized
    /// `TlsVecU32<Vec<u8>>` of client identity byte vectors.
    pub async fn list_clients(&self) -> Result<Vec<Vec<u8>>, String> {
        let resp = self
            .http
            .get(format!("{}/clients/list", self.ds_url))
            .send()
            .await
            .map_err(|e| format!("DS list clients failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("DS list clients failed: HTTP {}", resp.status()));
        }

        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("DS list clients read failed: {e}"))?;

        if resp_bytes.is_empty() {
            return Ok(vec![]);
        }

        let clients: TlsVecU32<Vec<u8>> = TlsVecU32::tls_deserialize_exact(&resp_bytes)
            .map_err(|e| format!("DS list clients parse failed: {e}"))?;

        Ok(clients.into())
    }

    /// Consumes (pops) one KeyPackage for the given client identity.
    ///
    /// Returns `None` if no KeyPackage is available yet (the peer hasn't
    /// registered).
    ///
    /// Uses the OpenMLS DS endpoint: `GET /clients/key_package/{base64url(id)}`
    pub async fn consume_key_package(
        &self,
        client_identity: &[u8],
    ) -> Result<Option<Vec<u8>>, String> {
        // encoding the target client's identity as URL-safe base64 for the path
        let id_b64 = BASE64_URL.encode(client_identity);
        let resp = self
            .http
            .get(format!("{}/clients/key_package/{}", self.ds_url, id_b64))
            .send()
            .await
            .map_err(|e| format!("DS consume KP failed: {e}"))?;

        // 204 No Content means no KeyPackage available (peer not registered yet)
        if resp.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(format!("DS consume KP failed: HTTP {}", resp.status()));
        }

        // returning the raw TLS-serialized KeyPackage bytes
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("DS consume KP read failed: {e}"))?;

        Ok(Some(bytes.to_vec()))
    }

    /// Sends a Welcome message via the OpenMLS DS.
    ///
    /// `POST /send/welcome` with the TLS-serialized `MlsMessageIn` body.
    /// Each Welcome contains plaintext KeyPackage hash tags that identify
    /// the intended recipients. The DS matches these hashes against its
    /// stored KeyPackages to determine who should receive the message,
    /// then queues it in each matching client's inbox.
    pub async fn send_welcome(&self, welcome_bytes: &[u8]) -> Result<(), String> {
        let resp = self
            .http
            .post(format!("{}/send/welcome", self.ds_url))
            .body(welcome_bytes.to_vec())
            .send()
            .await
            .map_err(|e| format!("DS send welcome failed: {e}"))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("DS send welcome failed: HTTP {}", resp.status()))
        }
    }

    /// Receives all queued messages (Welcomes and group messages) from the DS.
    ///
    /// `GET /recv/{base64url(id)}` with a TLS-serialized `RecvMessageRequest`
    /// body containing the auth token. The DS empties the client's message
    /// queue and returns a `TlsSliceU16<MlsMessageIn>` (a 2-byte
    /// length-prefixed vector of MLS messages).
    pub async fn recv_messages(&self) -> Result<Vec<MlsMessageIn>, String> {
        // building the request with the auth token for server-side validation
        let recv_req = RecvMessageRequest {
            auth_token: self.auth_token().clone(),
        };
        let req_body = recv_req
            .tls_serialize_detached()
            .map_err(|e| format!("TLS serialize RecvMessageRequest failed: {e}"))?;

        let resp = self
            .http
            .get(format!("{}/recv/{}", self.ds_url, self.id_b64()))
            .body(req_body)
            .send()
            .await
            .map_err(|e| format!("DS recv messages failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("DS recv messages failed: HTTP {}", resp.status()));
        }

        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("DS recv messages read failed: {e}"))?;

        // empty body means no messages queued
        if resp_bytes.is_empty() {
            return Ok(vec![]);
        }

        // deserializing the TLS length-prefixed vector
        let msgs: TlsVecU16<MlsMessageIn> = TlsVecU16::tls_deserialize_exact(&resp_bytes)
            .map_err(|e| format!("DS recv messages parse failed: {e}"))?;

        Ok(msgs.into())
    }
}
