// src/ssl.rs
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{generate_simple_self_signed, CertificateParams};
use rustls::{Certificate, PrivateKey, ServerConfig as RustlsConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::config::{ServerConfig, SslProvider};

/// Global challenge store
pub type ChallengeStore = Arc<RwLock<HashMap<String, String>>>;

pub struct SslManager {
    config: ServerConfig,
    rustls_config: Option<Arc<RustlsConfig>>,
    challenge_store: ChallengeStore,
}

impl SslManager {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            rustls_config: None,
            challenge_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get challenge store for HTTP server
    pub fn get_challenge_store(&self) -> ChallengeStore {
        self.challenge_store.clone()
    }

    /// Add ACME challenge
    async fn add_challenge(&self, token: &str, key_auth: &str) {
        let mut store = self.challenge_store.write().await;
        store.insert(token.to_string(), key_auth.to_string());
        info!("Added ACME challenge for token: {}", token);
    }

    /// Remove ACME challenge
    async fn remove_challenge(&self, token: &str) {
        let mut store = self.challenge_store.write().await;
        store.remove(token);
        info!("Removed ACME challenge for token: {}", token);
    }

    /// Initialize SSL configuration
    pub async fn initialize(&mut self) -> Result<()> {
        if !self.config.ssl.enabled {
            info!("SSL disabled, running HTTP only");
            return Ok(());
        }

        info!("Initializing SSL for domain: {}", self.config.server.domain);

        let rustls_config = match self.config.ssl.provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await?,
            SslProvider::Manual => self.load_manual_certificates()?,
        };

        self.rustls_config = Some(Arc::new(rustls_config));
        info!("SSL configuration initialized successfully");
        Ok(())
    }

    /// Get rustls configuration
    pub fn get_rustls_config(&self) -> Option<Arc<RustlsConfig>> {
        self.rustls_config.clone()
    }

    /// Setup Let's Encrypt certificates
    async fn setup_letsencrypt(&self) -> Result<RustlsConfig> {
        let domain = &self.config.server.domain;
        let email = &self.config.ssl.email;
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);

        // Create cache directory
        fs::create_dir_all(cache_dir)?;

        let cert_path = cache_dir.join(format!("{}.pem", domain));
        let key_path = cache_dir.join(format!("{}.key", domain));

        // Check if certificates exist and are valid
        if cert_path.exists() && key_path.exists() {
            info!("Found existing certificates, checking validity...");
            if let Ok(config) = self.load_certificates(&cert_path, &key_path) {
                // TODO: Add certificate expiry check
                info!("Using existing certificates");
                return Ok(config);
            }
            warn!("Existing certificates invalid, obtaining new ones");
        }

        info!("Obtaining new Let's Encrypt certificate for {}", domain);

        // Get certificate from Let's Encrypt
        let (cert_pem, key_pem) = self.obtain_certificate(domain, email).await?;

        // Save certificates
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        info!("Certificates saved to cache directory");

        // Load into rustls
        self.load_certificates(&cert_path, &key_path)
    }

    /// Obtain certificate from Let's Encrypt
    async fn obtain_certificate(&self, domain: &str, email: &str) -> Result<(String, String)> {
        // Choose ACME directory based on staging flag
        let directory_url = if self.config.ssl.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        info!("Using ACME directory: {}", directory_url);

        // Create account
        let account = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
            .await?;

        info!("ACME account created");

        // Create order
        let identifier = Identifier::Dns(domain.to_string());
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[identifier],
            })
            .await?;

        info!("ACME order created");

        // Get order state and authorizations
        let _order_state = order.state();
        let authorizations = order.authorizations().await?;

        // Process authorizations
        for auth in authorizations {
            // Find HTTP-01 challenge
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow!("No HTTP-01 challenge found"))?;

            let key_authorization = order.key_authorization(challenge);
            let key_auth = key_authorization.as_str().to_string();

            info!("Setting up HTTP-01 challenge for {}", domain);
            info!("Challenge token: {}", challenge.token);

            // Add challenge to store for HTTP server to serve
            self.add_challenge(&challenge.token, &key_auth).await;

            // Validate challenge
            wait_for_http_server_ready(&self.config).await?;
            info!("Notifying Let's Encrypt that challenge is ready...");
            order.set_challenge_ready(&challenge.url).await?;

            // Wait for authorization - refresh authorizations
            let mut attempts = 0;
            const MAX_ATTEMPTS: u32 = 30; // 1 minute total

            loop {
                sleep(Duration::from_secs(2)).await;

                // Get fresh authorizations to check status
                let fresh_auths = order.authorizations().await?;

                // For single domain, take the first authorization
                let current_auth = fresh_auths.first()
                    .ok_or_else(|| anyhow!("No authorizations found"))?;

                match current_auth.status {
                    AuthorizationStatus::Valid => {
                        info!("✅ Authorization completed for {}", domain);
                        break;
                    }
                    AuthorizationStatus::Invalid => {
                        // Clean up challenge
                        self.remove_challenge(&challenge.token).await;
                        return Err(anyhow!("❌ Authorization failed for {}", domain));
                    }
                    AuthorizationStatus::Pending => {
                        attempts += 1;
                        if attempts >= MAX_ATTEMPTS {
                            self.remove_challenge(&challenge.token).await;
                            return Err(anyhow!("❌ Authorization timeout for {}", domain));
                        }
                        info!("⏳ Authorization pending for {} (attempt {}/{})", domain, attempts, MAX_ATTEMPTS);
                    }
                    status => {
                        info!("⏳ Authorization status: {:?} for {}", status, domain);
                    }
                }
            }

            // Clean up challenge after successful authorization
            self.remove_challenge(&challenge.token).await;
        }

        // Generate certificate signing request
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name.push(rcgen::DnType::CommonName, domain);

        let cert = rcgen::Certificate::from_params(params)?;
        let csr = cert.serialize_request_der()?;

        // Finalize order
        info!("Finalizing certificate order...");
        order.finalize(&csr).await?;

        // Wait for certificate
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 30;
        loop {
            sleep(Duration::from_secs(2)).await;
            let order_state = order.state();
            match order_state.status {
                OrderStatus::Valid => {
                    info!("✅ Certificate issued for {}", domain);
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(anyhow!("❌ Certificate order failed for {}", domain));
                }
                _ => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(anyhow!("❌ Certificate generation timeout for {}", domain));
                    }
                    info!("⏳ Certificate generation pending for {} (attempt {}/{})", domain, attempts, MAX_ATTEMPTS);
                }
            }
        }

        // Download certificate
        let cert_chain_pem = order.certificate().await?.ok_or_else(|| {
            anyhow!("Certificate not available")
        })?;

        let private_key_pem = cert.serialize_private_key_pem();

        info!("🎉 Successfully obtained certificate for {}", domain);
        Ok((cert_chain_pem, private_key_pem))
    }

    /// Load certificates from files
    fn load_certificates(&self, cert_path: &Path, key_path: &Path) -> Result<RustlsConfig> {
        info!("Loading certificates from files");

        // Read certificate file
        let cert_file = fs::read(cert_path)?;
        let cert_chain = certs(&mut cert_file.as_slice())?
            .into_iter()
            .map(Certificate)
            .collect();

        // Read private key file  
        let key_file = fs::read(key_path)?;
        let mut keys = pkcs8_private_keys(&mut key_file.as_slice())?;

        if keys.is_empty() {
            return Err(anyhow!("No private keys found"));
        }

        let private_key = PrivateKey(keys.remove(0));

        // Build rustls config
        let config = RustlsConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

    /// Load manual certificates
    fn load_manual_certificates(&self) -> Result<RustlsConfig> {
        // For manual certificates, user should provide cert and key files
        let cert_path = Path::new(&self.config.ssl.cert_cache_dir).join("cert.pem");
        let key_path = Path::new(&self.config.ssl.cert_cache_dir).join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            return Err(anyhow!(
                "Manual certificates not found. Please place cert.pem and key.pem in {}",
                self.config.ssl.cert_cache_dir
            ));
        }

        self.load_certificates(&cert_path, &key_path)
    }

    /// Generate self-signed certificate (for development)
    pub fn generate_self_signed(domain: &str) -> Result<RustlsConfig> {
        warn!("Generating self-signed certificate for {}", domain);
        warn!("This should only be used for development!");

        let subject_alt_names = vec![domain.to_string()];
        let cert = generate_simple_self_signed(subject_alt_names)?;

        let cert_der = cert.serialize_der()?;
        let private_key_der = cert.serialize_private_key_der();

        let cert_chain = vec![Certificate(cert_der)];
        let private_key = PrivateKey(private_key_der);

        let config = RustlsConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }
}

/// Get challenge response for ACME HTTP-01
pub async fn get_challenge_response(challenge_store: &ChallengeStore, token: &str) -> Option<String> {
    let store = challenge_store.read().await;
    store.get(token).cloned()
}

async fn wait_for_http_server_ready(config: &ServerConfig) -> Result<()> {
    let test_url = format!("http://127.0.0.1:{}/.well-known/acme-challenge/readiness-test",
                           config.server.http_port);

    info!("Waiting for HTTP server to be ready...");

    for attempt in 1..=10 {
        match reqwest::get(&test_url).await {
            Ok(response) => {
                info!("✅ HTTP server is ready (attempt {}, status: {})", attempt, response.status());
                return Ok(());
            }
            Err(e) => {
                if attempt < 10 {
                    info!("⏳ HTTP server not ready yet (attempt {}): {}", attempt, e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    return Err(anyhow!(format!("HTTP server failed to start after 10 attempts: {}", e)));
                }
            }
        }
    }

    Ok(())
}
