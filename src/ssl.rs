// src/ssl.rs
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig as RustlsConfig;
use rustls_pemfile::{read_one, Item};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn, error};
use x509_parser::parse_x509_certificate;

use crate::config::{ServerConfig, SslProvider};
use crate::dns::{DnsProvider, create_dns_provider};

/// Global challenge store
pub type ChallengeStore = Arc<RwLock<HashMap<String, String>>>;

pub struct SslManager {
    config: ServerConfig,
    rustls_config: Option<Arc<RustlsConfig>>,
    challenge_store: ChallengeStore,
    dns_provider: Option<Box<dyn DnsProvider>>,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub domain: String,
    pub exists: bool,
    pub expiry_date: Option<DateTime<Utc>>,
    pub days_until_expiry: Option<i64>,
    pub needs_renewal: bool,
}

impl SslManager {
    pub fn new(config: ServerConfig) -> Self {
        let dns_provider = if let Some(dns_config) = &config.ssl.dns_provider {
            // Pass TOML config to provider (if available)
            let toml_config = if dns_config.config.is_null() {
                None
            } else {
                Some(&dns_config.config)
            };

            // Just try to create the provider - no pre-validation
            match create_dns_provider(&dns_config.provider, toml_config) {
                Ok(provider) => {
                    info!("✅ DNS provider '{}' initialized", dns_config.provider);
                    Some(provider)
                }
                Err(e) => {
                    error!("❌ Failed to initialize DNS provider '{}': {}", dns_config.provider, e);
                    None
                }
            }
        } else {
            None
        };

        Self {
            config,
            rustls_config: None,
            challenge_store: Arc::new(RwLock::new(HashMap::new())),
            dns_provider,
        }
    }

    /// Get challenge store for HTTP server
    pub fn get_challenge_store(&self) -> ChallengeStore {
        self.challenge_store.clone()
    }

    /// Add ACME challenge for HTTP-01
    async fn add_challenge(&self, token: &str, key_auth: &str) {
        let mut store = self.challenge_store.write().await;
        store.insert(token.to_string(), key_auth.to_string());
        info!("Added ACME challenge for token: {}", token);
    }

    /// Remove ACME challenge for HTTP-01
    async fn remove_challenge(&self, token: &str) {
        let mut store = self.challenge_store.write().await;
        store.remove(token);
        info!("Removed ACME challenge for token: {}", token);
    }

    /// Initialize SSL configuration
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.ssl.enabled {
            info!("SSL disabled, running HTTP only");
            return Ok(());
        }

        info!("Initializing SSL for domain: {}", self.config.server.domain);

        let rustls_config = match self.config.ssl.provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await?,
            SslProvider::Manual => self.load_manual_certificates()?,
            SslProvider::SelfSigned => self.generate_self_signed()?,
        };

        self.rustls_config = Some(Arc::new(rustls_config));
        info!("SSL configuration initialized successfully");
        Ok(())
    }

    /// Get rustls configuration
    pub fn get_rustls_config(&self) -> Option<Arc<RustlsConfig>> {
        self.rustls_config.clone()
    }

    /// Setup Let's Encrypt certificates - COMPREHENSIVE FIX
    async fn setup_letsencrypt(&mut self) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let email = &self.config.ssl.email.clone();
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);

        // Create cache directory
        info!("Certificate cache directory: {:?}", fs::canonicalize(cache_dir)?);
        fs::create_dir_all(cache_dir)?;

        // Determine what domains to request
        let (cert_domains, cert_filename) = if self.config.ssl.wildcard {
            // For wildcard certificates, request both wildcard and base domain
            let wildcard_domain = format!("*.{}", domain);
            let domains = vec![wildcard_domain.clone(), domain.clone()];
            let filename = format!("wildcard-{}", domain.replace('.', "-"));
            (domains, filename)
        } else {
            // For regular certificates, just request the domain
            let domains = vec![domain.clone()];
            let filename = domain.replace('.', "-");
            (domains, filename)
        };

        let cert_path = cache_dir.join(format!("{}.pem", cert_filename));
        let key_path = cache_dir.join(format!("{}.key", cert_filename));

        // Check if certificates exist and are valid
        if cert_path.exists() && key_path.exists() {
            info!("Found existing certificates, checking validity...");
            if let Ok(config) = self.load_certificates(&cert_path, &key_path) {
                info!("Using existing certificates");
                return Ok(config);
            }
            warn!("Existing certificates invalid, obtaining new ones");
        }

        if self.config.ssl.wildcard {
            info!("Obtaining wildcard Let's Encrypt certificate for domains: {:?}", cert_domains);

            if self.dns_provider.is_none() {
                return Err("Wildcard certificates require DNS provider configuration".into());
            }
        } else {
            info!("Obtaining Let's Encrypt certificate for domain: {}", domain);
        }

        // Get certificate from Let's Encrypt
        let (cert_pem, key_pem) = self.obtain_certificate_for_domains(&cert_domains, email).await?;

        // Save certificates
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        info!("Certificates saved to cache directory");

        // Load into rustls
        self.load_certificates(&cert_path, &key_path)
    }

    /// Obtain certificate from Let's Encrypt for multiple domains
    async fn obtain_certificate_for_domains(&mut self, domains: &[String], email: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        // Choose ACME directory based on staging flag
        let directory_url = if self.config.ssl.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        info!("Using ACME directory: {}", directory_url);

        // Create account
        let (account, _account_credentials) = Account::create(
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

        // Create identifiers for all domains
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        // Create order
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await?;

        info!("ACME order created for domains: {:?}", domains);

        // Get order state and authorizations
        let authorizations = order.authorizations().await?;

        // Process authorizations
        for auth in authorizations {
            // Get domain from identifier
            let auth_domain = match &auth.identifier {
                Identifier::Dns(domain) => domain,
            };

            if self.config.ssl.wildcard && self.dns_provider.is_some() {
                // Use DNS-01 challenge for wildcard
                info!("Processing DNS-01 challenge for {}", auth_domain);
                self.process_dns_challenge(&mut order, &auth).await?;
            } else {
                // Use HTTP-01 challenge for regular certificates
                info!("Processing HTTP-01 challenge for {}", auth_domain);
                self.process_http_challenge(&mut order, &auth).await?;
            }
        }

        // Generate certificate signing request for all domains
        info!("Generating CSR for domains: {:?}", domains);

        // Create certificate parameters with all domains
        let mut params = rcgen::CertificateParams::new(domains.to_vec())?;

        // Set the Common Name to the first domain (usually the wildcard or primary domain)
        params.distinguished_name.push(rcgen::DnType::CommonName, &domains[0]);

        // Generate key pair and CSR
        let key_pair = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;

        info!("CSR generated successfully for domains: {:?}", domains);

        // Finalize order
        info!("Finalizing certificate order...");
        order.finalize(&csr.der()).await?;

        // Wait for certificate
        self.wait_for_certificate_issuance(&mut order, &domains[0]).await?;

        // Download certificate
        let cert_chain_pem = order.certificate().await?.ok_or_else(|| {
            "Certificate not available"
        })?;

        let private_key_pem = key_pair.serialize_pem();

        info!("🎉 Successfully obtained certificate for domains: {:?}", domains);
        Ok((cert_chain_pem, private_key_pem))
    }
    
    /// Process HTTP-01 challenge
    async fn process_http_challenge(
        &self,
        order: &mut instant_acme::Order,
        auth: &instant_acme::Authorization,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Find HTTP-01 challenge
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| "No HTTP-01 challenge found")?;

        let key_authorization = order.key_authorization(challenge);
        let key_auth = key_authorization.as_str().to_string();

        info!("Setting up HTTP-01 challenge");
        info!("Challenge token: {}", challenge.token);

        // Add challenge to store for HTTP server to serve
        self.add_challenge(&challenge.token, &key_auth).await;

        // Validate challenge
        info!("Notifying Let's Encrypt that challenge is ready...");
        order.set_challenge_ready(&challenge.url).await?;

        // Wait for authorization
        let auth_domain = match &auth.identifier {
            Identifier::Dns(domain) => domain,
        };
        self.wait_for_authorization(order, auth_domain).await?;

        // Clean up challenge after successful authorization
        self.remove_challenge(&challenge.token).await;

        Ok(())
    }

    /// Process DNS-01 challenge - IMPROVED VERSION
    async fn process_dns_challenge(
        &mut self,
        order: &mut instant_acme::Order,
        auth: &instant_acme::Authorization,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Extract domain information
        let domain = match &auth.identifier {
            Identifier::Dns(domain) => domain.clone(),
        };

        let record_domain = if domain.starts_with("*.") {
            domain[2..].to_string()
        } else {
            domain.clone()
        };

        let record_name = "_acme-challenge";

        info!("🔐 Setting up DNS-01 challenge for {}", domain);

        // Find DNS-01 challenge
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| "No DNS-01 challenge found")?;

        // Calculate DNS record value
        let dns_value = order.key_authorization(challenge).dns_value();
        info!("📝 Challenge: {}.{} = {}", record_name, record_domain, dns_value);

        // Store record_id for cleanup
        let record_id = {
            let dns_provider = self.dns_provider.as_mut()
                .ok_or("DNS provider not configured for DNS-01 challenge")?;

            info!("🧹 Cleaning up existing TXT records...");
            if let Err(e) = dns_provider.cleanup_txt_records(&record_domain, &record_name).await {
                warn!("⚠️  Cleanup failed (continuing anyway): {}", e);
            }

            info!("✨ Creating challenge TXT record...");
            let record_id = dns_provider.create_txt_record(&record_domain, &record_name, &dns_value).await?;

            info!("⏳ Waiting for DNS propagation...");
            dns_provider.wait_for_propagation(&record_domain, &record_name, &dns_value).await?;

            record_id
        }; 

        info!("📡 Notifying Let's Encrypt that DNS challenge is ready...");
        order.set_challenge_ready(&challenge.url).await?;

        info!("⏳ Waiting for Let's Encrypt authorization...");
        let auth_result = self.wait_for_authorization(order, &domain).await;

        info!("🗑️  Cleaning up challenge DNS record...");
        {
            // Scope the mutable borrow for cleanup
            if let Some(dns_provider) = self.dns_provider.as_mut() {
                if let Err(e) = dns_provider.delete_txt_record(&record_domain, &record_id).await {
                    warn!("⚠️  Failed to clean up challenge record {}: {}", record_id, e);
                    warn!("⚠️  You may need to manually remove the TXT record: {}.{}", record_name, record_domain);
                } else {
                    info!("✅ Challenge record cleaned up successfully");
                }
            }
        } 

        // Return the authorization result
        auth_result
    }
    
    /// Wait for authorization to complete
    async fn wait_for_authorization(
        &self, // Note: &self, not &mut self
        order: &mut instant_acme::Order,
        domain: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 60;
        const RETRY_DELAY: u64 = 5;

        info!("Waiting for authorization for domain: {}", domain);

        loop {
            tokio::time::sleep(Duration::from_secs(RETRY_DELAY)).await;

            let fresh_auths = order.authorizations().await?;

            let current_auth = fresh_auths.iter()
                .find(|auth| {
                    match &auth.identifier {
                        Identifier::Dns(auth_domain) => auth_domain == domain,
                    }
                })
                .ok_or_else(|| format!("No authorization found for {}", domain))?;

            match current_auth.status {
                AuthorizationStatus::Valid => {
                    info!("✅ Authorization completed for {}", domain);
                    break;
                }
                AuthorizationStatus::Invalid => {
                    for challenge in &current_auth.challenges {
                        if let Some(error) = &challenge.error {
                            error!("Challenge error for {}: {:?}", domain, error);
                        }
                    }
                    return Err(format!("❌ Authorization failed for {}", domain).into());
                }
                AuthorizationStatus::Pending => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(format!("❌ Authorization timeout for {} after {} attempts", domain, attempts).into());
                    }
                    info!("⏳ Authorization pending for {} (attempt {}/{})", domain, attempts, MAX_ATTEMPTS);
                }
                status => {
                    info!("⏳ Authorization status: {:?} for {}", status, domain);
                }
            }
        }

        Ok(())
    }
    
    /// Wait for certificate issuance
    async fn wait_for_certificate_issuance(
        &self,
        order: &mut instant_acme::Order,
        domain: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 60;

        loop {
            sleep(Duration::from_secs(5)).await;
            let order_state = order.state();
            info!("Certificate order status: {:?} for {}", order_state.status, domain);

            match order_state.status {
                OrderStatus::Valid => {
                    info!("✅ Certificate issued for {}", domain);
                    break;
                }
                OrderStatus::Invalid => {
                    return Err(format!("❌ Certificate order failed for {}", domain).into());
                }
                _ => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(format!("❌ Certificate generation timeout for {}", domain).into());
                    }
                    info!("⏳ Certificate generation pending for {} (attempt {}/{})", domain, attempts, MAX_ATTEMPTS);
                }
            }
        }

        Ok(())
    }

    /// Load certificates from files
    fn load_certificates(&self, cert_path: &Path, key_path: &Path) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        info!("Loading certificates from files");

        // Read certificate file
        let cert_file = fs::read(cert_path)?;
        let cert_chain = rustls_pemfile::certs(&mut cert_file.as_slice())
            .collect::<Result<Vec<_>, _>>()?;

        // Read private key file
        let key_file = fs::read(key_path)?;
        let private_key = rustls_pemfile::private_key(&mut key_file.as_slice())?
            .ok_or("No private key found")?;

        // Build rustls config
        let config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

    /// Load manual certificates
    fn load_manual_certificates(&self) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.pem", cert_filename));
        let key_path = Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.key", cert_filename));

        if !cert_path.exists() || !key_path.exists() {
            return Err(format!(
                "Manual certificates not found. Please place {}.pem and {}.key in {}",
                self.config.server.domain, self.config.server.domain, self.config.ssl.cert_cache_dir
            ).into());
        }

        self.load_certificates(&cert_path, &key_path)
    }

    /// Generate self-signed certificate (for development)
    pub fn generate_self_signed(&self) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);
        fs::create_dir_all(cache_dir)?;
        let domain = self.config.server.domain.as_str();
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = cache_dir.join(format!("{}.pem", cert_filename));
        let key_path = cache_dir.join(format!("{}.key", cert_filename));

        if !cert_path.exists() || !key_path.exists() {
            warn!("Generating self-signed certificate for {}", domain);
            warn!("This should only be used for development!");

            let subject_alt_names = if self.config.ssl.wildcard {
                vec![domain.to_string(), format!("*.{}", domain)]
            } else {
                vec![domain.to_string()]
            };

            let cert = generate_simple_self_signed(subject_alt_names)?;

            let cert_pem = cert.cert.pem();
            let key_pem = cert.signing_key.serialize_pem();

            fs::write(&cert_path, &cert_pem)?;
            fs::write(&key_path, &key_pem)?;

            // Convert to rustls types
            let cert_der = cert.cert.der().clone();
            let private_key_der = cert.signing_key.serialize_der().try_into()?;

            let cert_chain = vec![cert_der];
            let private_key = private_key_der;

            let config = RustlsConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)?;

            Ok(config)
        } else {
            self.load_certificates(&cert_path, &key_path)
        }
    }

    pub fn get_certificate_info(&self) -> Result<CertificateInfo, Box<dyn std::error::Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.pem", cert_filename));

        if !cert_path.exists() {
            return Ok(CertificateInfo {
                domain: domain.to_string(),
                exists: false,
                expiry_date: None,
                days_until_expiry: None,
                needs_renewal: true,
            });
        }

        let file = File::open(cert_path)?;
        let mut reader = BufReader::new(file);
        match read_one(&mut reader)? {
            Some(Item::X509Certificate(der_vec)) => {
                let (_, cert) = parse_x509_certificate(&der_vec)
                    .map_err(|e| format!("Failed to parse certificate: {}", e))?;
                let not_after = cert.validity().not_after;
                let expiry_time = DateTime::from_timestamp(not_after.timestamp(), 0)
                    .ok_or_else(|| "Invalid certificate expiry time")?;

                let now = Utc::now();
                let days_until_expiry = expiry_time.signed_duration_since(now).num_days();

                Ok(CertificateInfo {
                    domain: domain.to_string(),
                    exists: true,
                    expiry_date: Some(expiry_time),
                    days_until_expiry: Some(days_until_expiry),
                    needs_renewal: days_until_expiry < 30,
                })
            }
            _ => Err("Expected X509Certificate in PEM file".into()),
        }
    }

    pub async fn force_renewal(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Clone ALL values we need upfront to avoid any borrowing conflicts
        let domain = self.config.server.domain.clone(); // CLONE, don't borrow!
        let wildcard = self.config.ssl.wildcard;
        let cert_cache_dir = self.config.ssl.cert_cache_dir.clone();
        let ssl_provider = self.config.ssl.provider.clone();

        info!("🚨 Start certificate renewal for {}", domain);

        let cert_filename = if wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = Path::new(&cert_cache_dir).join(format!("{}.pem", cert_filename));
        let key_path = Path::new(&cert_cache_dir).join(format!("{}.key", cert_filename));

        // Remove existing certificates
        if cert_path.exists() {
            fs::remove_file(&cert_path)?;
        }
        if key_path.exists() {
            fs::remove_file(&key_path)?;
        }

        // Get new certificate (mutable borrow - now safe because domain is cloned)
        let new_config = match ssl_provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await?,
            SslProvider::SelfSigned => self.generate_self_signed()?,
            _ => return Err(format!("Unsupported SSL provider for renewal: {:?}", ssl_provider).into()),
        };

        self.rustls_config = Some(Arc::new(new_config));

        // Use cloned domain - no borrowing conflicts!
        info!("✅ Certificate renewal completed for {}", domain);
        Ok(())
    }
}