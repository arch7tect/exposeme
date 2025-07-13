// src/ssl.rs - Clean and compact version
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

/// Global challenge store for HTTP-01 challenges
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
            let toml_config = if dns_config.config.is_null() {
                None
            } else {
                Some(&dns_config.config)
            };

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

    pub fn get_challenge_store(&self) -> ChallengeStore {
        self.challenge_store.clone()
    }

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

    pub fn get_rustls_config(&self) -> Option<Arc<RustlsConfig>> {
        self.rustls_config.clone()
    }

    async fn setup_letsencrypt(&mut self) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let email = &self.config.ssl.email.clone();
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);

        fs::create_dir_all(cache_dir)?;

        // Determine certificate type and filename
        let (cert_domains, cert_filename) = if self.config.ssl.wildcard {
            let wildcard_domain = format!("*.{}", domain);
            info!("Obtaining wildcard certificate for: {} and {}", wildcard_domain, domain);

            // Request BOTH wildcard domain AND base domain
            // Wildcard certificates do NOT automatically cover the base domain
            let domains = vec![domain.clone(), wildcard_domain];
            let filename = format!("wildcard-{}", domain.replace('.', "-"));
            (domains, filename)
        } else {
            let domains = vec![domain.clone()];
            let filename = domain.replace('.', "-");
            (domains, filename)
        };

        let cert_path = cache_dir.join(format!("{}.pem", cert_filename));
        let key_path = cache_dir.join(format!("{}.key", cert_filename));

        // Check existing certificates
        if cert_path.exists() && key_path.exists() {
            info!("Found existing certificates, checking validity...");
            if let Ok(config) = self.load_certificates(&cert_path, &key_path) {
                info!("Using existing certificates");
                return Ok(config);
            }
            warn!("Existing certificates invalid, obtaining new ones");
        }

        // Validate configuration
        if self.config.ssl.wildcard && self.dns_provider.is_none() {
            return Err("Wildcard certificates require DNS provider configuration".into());
        }

        // Obtain certificate
        let (cert_pem, key_pem) = self.obtain_certificate(&cert_domains, email).await?;

        // Save and load certificates
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, &key_pem)?;
        info!("Certificates saved to cache directory");

        self.load_certificates(&cert_path, &key_path)
    }

    async fn obtain_certificate(&mut self, domains: &[String], email: &str) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let directory_url = if self.config.ssl.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        info!("Using ACME directory: {}", directory_url);

        // Create account and order
        let (account, _) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        ).await?;

        let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account.new_order(&NewOrder { identifiers: &identifiers }).await?;

        info!("ACME order created for domains: {:?}", domains);

        // Process authorizations
        let authorizations = order.authorizations().await?;
        for (i, auth) in authorizations.iter().enumerate() {
            let auth_domain = match &auth.identifier {
                Identifier::Dns(domain) => domain,
            };

            info!("Processing authorization {}/{} for: {}", i + 1, authorizations.len(), auth_domain);

            if auth.status == AuthorizationStatus::Valid {
                info!("Authorization already valid for: {}", auth_domain);
                continue;
            }

            if self.config.ssl.wildcard {
                self.process_dns_challenge(&mut order, auth).await?;
            } else {
                self.process_http_challenge(&mut order, auth).await?;
            }
        }

        // Verify all authorizations are valid
        let final_auths = order.authorizations().await?;
        for auth in &final_auths {
            let domain = match &auth.identifier { Identifier::Dns(d) => d };
            if auth.status != AuthorizationStatus::Valid {
                return Err(format!("Authorization not valid for {}: {:?}", domain, auth.status).into());
            }
        }

        info!("✅ All authorizations valid, finalizing order");

        // Generate CSR and finalize
        let mut params = rcgen::CertificateParams::new(domains.to_vec())?;
        params.distinguished_name.push(rcgen::DnType::CommonName, &domains[0]);
        let key_pair = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;

        // Finalize order (bypass status check - proceed if auths are valid)
        match order.finalize(&csr.der()).await {
            Ok(_) => info!("✅ Order finalized successfully"),
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("not ready") || error_str.contains("pending") {
                    info!("⏳ Order not ready, waiting 30 seconds and retrying...");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    order.finalize(&csr.der()).await?;
                    info!("✅ Order finalized on retry");
                } else {
                    return Err(e.into());
                }
            }
        }

        // Wait for certificate
        self.wait_for_certificate(&mut order, &domains[0]).await?;

        let cert_chain_pem = order.certificate().await?.ok_or("Certificate not available")?;
        let private_key_pem = key_pair.serialize_pem();

        info!("🎉 Successfully obtained certificate for domains: {:?}", domains);
        Ok((cert_chain_pem, private_key_pem))
    }

    async fn process_dns_challenge(&mut self, order: &mut instant_acme::Order, auth: &instant_acme::Authorization) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let domain = match &auth.identifier { Identifier::Dns(domain) => domain.clone() };
        let record_domain = if domain.starts_with("*.") { domain[2..].to_string() } else { domain.clone() };
        let record_name = "_acme-challenge";

        let challenge = auth.challenges.iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or("No DNS-01 challenge found")?;

        let dns_value = order.key_authorization(challenge).dns_value();
        info!("Setting up DNS challenge: {}.{} = {}", record_name, record_domain, dns_value);

        let record_id = {
            let dns_provider = self.dns_provider.as_mut().ok_or("DNS provider not configured")?;

            // Clean up existing records
            if let Err(e) = dns_provider.cleanup_txt_records(&record_domain, record_name).await {
                warn!("DNS cleanup failed: {}", e);
            }

            // Create record and wait for propagation
            let record_id = dns_provider.create_txt_record(&record_domain, record_name, &dns_value).await?;
            if let Err(e) = dns_provider.wait_for_propagation(&record_domain, record_name, &dns_value).await {
                error!("DNS propagation failed: {}", e);
                if let Err(e) = dns_provider.delete_txt_record(&record_domain, &record_id).await {
                    warn!("Failed to cleanup DNS record {}: {}", record_id, e);
                }
                return Err(e);
            }
            record_id
        };

        // Notify Let's Encrypt and wait for authorization
        if let Err(e) = order.set_challenge_ready(&challenge.url).await {
            error!("Setting challenge ready failed: {}", e);
        }
        else if let Err(e) = self.wait_for_authorization(order, &domain).await {
            error!("Waiting for authorization failed: {}", e);
        }

        // Cleanup
        if let Some(dns_provider) = self.dns_provider.as_mut() {
            if let Err(e) = dns_provider.delete_txt_record(&record_domain, &record_id).await {
                warn!("Failed to cleanup DNS record {}: {}", record_id, e);
            }
        }

        Ok(())
    }

    async fn process_http_challenge(&self, order: &mut instant_acme::Order, auth: &instant_acme::Authorization) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let challenge = auth.challenges.iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or("No HTTP-01 challenge found")?;

        let key_auth = order.key_authorization(challenge).as_str().to_string();

        // Add challenge to store
        {
            let mut store = self.challenge_store.write().await;
            store.insert(challenge.token.clone(), key_auth);
        }

        // Notify and wait
        if let Err(e) = order.set_challenge_ready(&challenge.url).await {
            error!("Failed to set challenge ready: {}", e);
        }
        else {
            let domain = match &auth.identifier { Identifier::Dns(domain) => domain };
            if let Err(e) = self.wait_for_authorization(order, domain).await {
                error!("Failed to wait for authorization: {}", e);
            }
        }

        // Cleanup
        {
            let mut store = self.challenge_store.write().await;
            store.remove(&challenge.token);
        }

        Ok(())
    }

    async fn wait_for_authorization(&self, order: &mut instant_acme::Order, domain: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        const MAX_ATTEMPTS: u32 = 60;
        const RETRY_DELAY: u64 = 5;

        for attempt in 1..=MAX_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(RETRY_DELAY)).await;

            let auths = order.authorizations().await?;
            let auth = auths.iter()
                .find(|auth| match &auth.identifier { Identifier::Dns(d) => d == domain })
                .ok_or_else(|| format!("Authorization not found for {}", domain))?;

            match auth.status {
                AuthorizationStatus::Valid => {
                    info!("✅ Authorization completed for {}", domain);
                    return Ok(());
                }
                AuthorizationStatus::Invalid => {
                    for challenge in &auth.challenges {
                        if let Some(error) = &challenge.error {
                            error!("Challenge error for {}: {:?}", domain, error);
                        }
                    }
                    return Err(format!("Authorization failed for {}", domain).into());
                }
                _ => {
                    if attempt % 12 == 0 {
                        info!("⏳ Waiting for authorization: {} (attempt {})", domain, attempt);
                    }
                }
            }
        }

        Err(format!("Authorization timeout for {}", domain).into())
    }

    async fn wait_for_certificate(&self, order: &mut instant_acme::Order, domain: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        const MAX_ATTEMPTS: u32 = 60;
        const RETRY_DELAY: u64 = 10;

        for attempt in 1..=MAX_ATTEMPTS {
            sleep(Duration::from_secs(RETRY_DELAY)).await;

            match order.state().status {
                OrderStatus::Valid => {
                    info!("✅ Certificate issued for {}", domain);
                    return Ok(());
                }
                OrderStatus::Invalid => {
                    return Err(format!("Certificate order failed for {}", domain).into());
                }
                _ => {
                    if attempt % 6 == 0 {
                        info!("⏳ Waiting for certificate: {} (attempt {})", domain, attempt);
                    }
                }
            }
        }

        Err(format!("Certificate timeout for {}", domain).into())
    }

    fn load_certificates(&self, cert_path: &Path, key_path: &Path) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let cert_file = fs::read(cert_path)?;
        let cert_chain = rustls_pemfile::certs(&mut cert_file.as_slice())
            .collect::<Result<Vec<_>, _>>()?;

        let key_file = fs::read(key_path)?;
        let private_key = rustls_pemfile::private_key(&mut key_file.as_slice())?
            .ok_or("No private key found")?;

        let config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

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
                cert_filename, cert_filename, self.config.ssl.cert_cache_dir
            ).into());
        }

        self.load_certificates(&cert_path, &key_path)
    }

    pub fn generate_self_signed(&self) -> Result<RustlsConfig, Box<dyn std::error::Error + Send + Sync>> {
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);
        fs::create_dir_all(cache_dir)?;

        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = cache_dir.join(format!("{}.pem", cert_filename));
        let key_path = cache_dir.join(format!("{}.key", cert_filename));

        if cert_path.exists() && key_path.exists() {
            return self.load_certificates(&cert_path, &key_path);
        }

        warn!("Generating self-signed certificate for {} (development only)", domain);

        let subject_alt_names = if self.config.ssl.wildcard {
            vec![domain.clone(), format!("*.{}", domain)]
        } else {
            vec![domain.clone()]
        };

        let cert = generate_simple_self_signed(subject_alt_names)?;

        fs::write(&cert_path, cert.cert.pem())?;
        fs::write(&key_path, cert.signing_key.serialize_pem())?;

        let cert_chain = vec![cert.cert.der().clone()];
        let private_key = cert.signing_key.serialize_der().try_into()?;

        let config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
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
                domain: domain.clone(),
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
                    .ok_or("Invalid certificate expiry time")?;

                let now = Utc::now();
                let days_until_expiry = expiry_time.signed_duration_since(now).num_days();

                Ok(CertificateInfo {
                    domain: domain.clone(),
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
        let domain = self.config.server.domain.clone();
        let wildcard = self.config.ssl.wildcard;
        let cert_cache_dir = self.config.ssl.cert_cache_dir.clone();
        let ssl_provider = self.config.ssl.provider.clone();

        info!("Starting certificate renewal for {}", domain);

        let cert_filename = if wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = Path::new(&cert_cache_dir).join(format!("{}.pem", cert_filename));
        let key_path = Path::new(&cert_cache_dir).join(format!("{}.key", cert_filename));
        let cert_backup_path = Path::new(&cert_cache_dir).join(format!("{}.pem.backup", cert_filename));
        let key_backup_path = Path::new(&cert_cache_dir).join(format!("{}.key.backup", cert_filename));

        // Create backup copies of existing certificates
        let has_backup = if cert_path.exists() && key_path.exists() {
            match (fs::copy(&cert_path, &cert_backup_path), fs::copy(&key_path, &key_backup_path)) {
                (Ok(_), Ok(_)) => {
                    info!("📦 Created certificate backup for {}", domain);
                    true
                }
                _ => {
                    warn!("Failed to create certificate backup, proceeding without backup");
                    false
                }
            }
        } else {
            false
        };

        // Remove existing certificates
        if cert_path.exists() { fs::remove_file(&cert_path)?; }
        if key_path.exists() { fs::remove_file(&key_path)?; }

        // Try to generate new certificate
        let renewal_result = match ssl_provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await,
            SslProvider::SelfSigned => self.generate_self_signed(),
            _ => Err(format!("Unsupported SSL provider for renewal: {:?}", ssl_provider).into()),
        };

        match renewal_result {
            Ok(new_config) => {
                // Renewal successful
                self.rustls_config = Some(Arc::new(new_config));
                info!("✅ Certificate renewal completed for {}", domain);
                Ok(())
            }
            Err(e) => {
                // Renewal failed - restore from backup if available
                if has_backup {
                    match (fs::copy(&cert_backup_path, &cert_path), fs::copy(&key_backup_path, &key_path)) {
                        (Ok(_), Ok(_)) => {
                            info!("🔄 Restored certificate from backup after renewal failure");

                            if let Ok(restored_config) = self.load_certificates(&cert_path, &key_path) {
                                self.rustls_config = Some(Arc::new(restored_config));
                                info!("✅ Successfully restored working certificates");
                            }
                        }
                        _ => {
                            warn!("Failed to restore certificate backup");
                        }
                    }
                }

                error!("❌ Certificate renewal failed for {}: {}", domain, e);
                Err(format!("Certificate renewal failed: {}", e).into())
            }
        }
    }
}
