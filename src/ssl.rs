use std::collections::HashMap;
use std::error::Error;
use std::io::{BufReader, Cursor};
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order, OrderStatus, RetryPolicy,
};
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig as RustlsConfig;
use rustls_pemfile::{Item, read_one};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
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

#[derive(Debug)]
enum CleanupTask {
    Dns(DnsCleanupInfo),
    Http(String), // token
}

#[derive(Debug)]
struct DnsCleanupInfo {
    domain: String,
    record_id: String,
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
                    info!("DNS provider '{}' initialized", dns_config.provider);
                    Some(provider)
                }
                Err(e) => {
                    error!(
                        "Failed to initialize DNS provider '{}': {}",
                        dns_config.provider, e
                    );
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

    pub async fn initialize(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if !self.config.ssl.enabled {
            info!("SSL disabled, running HTTP only");
            return Ok(());
        }

        info!("Initializing SSL for domain: {}", self.config.server.domain);

        let rustls_config = match self.config.ssl.provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await?,
            SslProvider::Manual => self.load_manual_certificates().await?,
            SslProvider::SelfSigned => self.generate_self_signed().await?,
        };

        self.rustls_config = Some(Arc::new(rustls_config));
        info!("SSL configuration initialized successfully");
        Ok(())
    }

    pub fn get_rustls_config(&self) -> Option<Arc<RustlsConfig>> {
        self.rustls_config.clone()
    }

    async fn setup_letsencrypt(
        &mut self,
    ) -> Result<RustlsConfig, Box<dyn Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let email = &self.config.ssl.email.clone();
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);

        tokio::fs::create_dir_all(cache_dir).await?;

        let (cert_domains, cert_filename) = if self.config.ssl.wildcard {
            let wildcard_domain = format!("*.{}", domain);
            info!(
                "Obtaining wildcard certificate for: {} and {}",
                wildcard_domain, domain
            );
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
            if let Ok(config) = self.load_certificates(&cert_path, &key_path).await {
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
        tokio::fs::write(&cert_path, &cert_pem).await?;
        tokio::fs::write(&key_path, &key_pem).await?;
        info!("Certificates saved to cache directory");

        self.load_certificates(&cert_path, &key_path).await
    }

    async fn obtain_certificate(
        &mut self,
        domains: &[String],
        email: &str,
    ) -> Result<(String, String), Box<dyn Error + Send + Sync>> {
        let directory_url = if self.config.ssl.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        info!("Using ACME directory: {}", directory_url);

        // Create account using correct API
        let new_account = NewAccount {
            contact: &[&format!("mailto:{}", email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let (account, _account_credentials) = Account::builder()?
            .create(&new_account, directory_url.to_owned(), None)
            .await?;

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        // Create order with correct NewOrder API
        let mut order = account
            .new_order(&NewOrder::new(identifiers.as_slice()))
            .await?;

        info!("ACME order created for domains: {:?}", domains);

        let mut cleanup_tasks: Vec<CleanupTask> = Vec::new();

        let mut error = self
            .prepare_acme_order(&mut order, &mut cleanup_tasks)
            .await
            .err();
        if error.is_none() {
            info!("All authorizations processed, poll order ready");

            error = match order.poll_ready(&RetryPolicy::default()).await {
                Ok(status) => {
                    if status != OrderStatus::Ready {
                        Some(format!("Order not ready, status: {:?}", status).into())
                    } else {
                        None
                    }
                }
                Err(e) => Some(e.into()),
            }
        };

        self.cleanup_acme_challenge_records(cleanup_tasks).await;

        if let Some(e) = error {
            error!("Error obtaining certificate: {}", e);
            return Err(e);
        }

        info!("Order is ready. Finalizing.");
        let private_key_pem = order.finalize().await?;
        let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok((cert_chain_pem, private_key_pem))
    }

    async fn prepare_acme_order(
        &mut self,
        order: &mut Order,
        cleanup_tasks: &mut Vec<CleanupTask>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Process authorizations
        let mut authorizations = order.authorizations();
        let mut auth_no = 1;
        while let Some(authz_handle) = authorizations.next().await {
            let mut authz_handle = match authz_handle {
                Ok(authz_handle) => authz_handle,
                Err(e) => return Err(e.into()),
            };

            let domain = match authz_handle.identifier().identifier.clone() {
                Identifier::Dns(domain) => domain,
                _ => return Err("Not DNS identifier".into()),
            };
            match authz_handle.status {
                AuthorizationStatus::Pending => {
                    info!("Processing authorization for: {}", domain);

                    if self.config.ssl.wildcard {
                        match self
                            .prepare_dns_challenge(&mut authz_handle, &domain, auth_no)
                            .await
                        {
                            Ok(info) => cleanup_tasks.push(CleanupTask::Dns(info)),
                            Err(e) => return Err(e),
                        }
                    } else {
                        match self
                            .prepare_http_challenge(&mut authz_handle, &domain)
                            .await
                        {
                            Ok(token) => cleanup_tasks.push(CleanupTask::Http(token)),
                            Err(e) => return Err(e),
                        }
                    }
                }
                AuthorizationStatus::Valid => {
                    info!("Authorization already valid for: {}", domain);
                    continue;
                }
                _ => {
                    return Err(format!("Authorization failed for: {}", domain).into());
                }
            }
            auth_no += 1;
        }
        Ok(())
    }

    async fn cleanup_acme_challenge_records(&mut self, cleanup_tasks: Vec<CleanupTask>) {
        for task in cleanup_tasks {
            match task {
                CleanupTask::Dns(info) => {
                    if let Some(dns) = self.dns_provider.as_mut() {
                        info!(
                            "Cleanup DNS txt record with id {} for {}",
                            info.record_id, info.domain
                        );
                        if let Err(e) = dns.delete_txt_record(&info.domain, &info.record_id).await {
                            warn!("Failed to delete TXT record {}: {}", info.record_id, e);
                        }
                    }
                }
                CleanupTask::Http(token) => {
                    info!("Cleanup HTTPS token {}", token);
                    let mut store = self.challenge_store.write().await;
                    store.remove(&token);
                }
            }
        }
    }

    async fn prepare_dns_challenge<'a>(
        &mut self,
        authz_handle: &'a mut instant_acme::AuthorizationHandle<'a>,
        domain: &str,
        auth_no: i32,
    ) -> Result<DnsCleanupInfo, Box<dyn Error + Send + Sync>> {
        let record_domain = if domain.starts_with("*.") {
            domain[2..].to_string()
        } else {
            domain.to_string()
        };
        let record_name = "_acme-challenge";

        // Get DNS challenge
        let mut challenge = authz_handle
            .challenge(ChallengeType::Dns01)
            .ok_or("No DNS-01 challenge found")?;

        // Get key authorization from the order for this challenge
        let key_authorization = challenge.key_authorization();
        let dns_value = key_authorization.dns_value();
        info!(
            "Setting up DNS challenge: {}.{} = {}",
            record_name, record_domain, dns_value
        );

        let record_id = {
            let dns_provider = self
                .dns_provider
                .as_mut()
                .ok_or("DNS provider not configured")?;

            // Clean up existing records on first auth
            if auth_no == 1 {
                if let Err(e) = dns_provider
                    .cleanup_txt_records(&record_domain, record_name)
                    .await
                {
                    warn!("DNS cleanup failed: {}", e);
                }
            }

            // Create record and wait for propagation
            let record_id = dns_provider
                .create_txt_record(&record_domain, record_name, &dns_value)
                .await?;
            if let Err(e) = dns_provider
                .wait_for_propagation(&record_domain, record_name, &dns_value)
                .await
            {
                error!("DNS propagation failed: {}", e);
                if let Err(e) = dns_provider
                    .delete_txt_record(&record_domain, &record_id)
                    .await
                {
                    warn!("Failed to cleanup DNS record {}: {}", record_id, e);
                }
                return Err(e);
            }
            record_id
        };

        // Set challenge ready
        if let Err(e) = challenge.set_ready().await {
            error!("Setting challenge ready failed: {}", e);
        }

        // Cleanup later - return info for it
        Ok(DnsCleanupInfo {
            domain: domain.to_owned(),
            record_id,
        })
    }

    async fn prepare_http_challenge<'a>(
        &self,
        authz_handle: &'a mut instant_acme::AuthorizationHandle<'a>,
        _domain: &str,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Get HTTP challenge
        let mut challenge = authz_handle
            .challenge(ChallengeType::Http01)
            .ok_or("No HTTP-01 challenge found")?;

        let key_authorization = challenge.key_authorization();

        // Add challenge to store
        {
            let mut store = self.challenge_store.write().await;
            store.insert(
                challenge.token.clone(),
                key_authorization.as_str().to_string(),
            );
        }

        // Set challenge ready
        if let Err(e) = challenge.set_ready().await {
            error!("Failed to set challenge ready: {}", e);
        }

        // Cleanup later - return info for it
        Ok(challenge.token.clone())
    }

    async fn load_certificates(
        &self,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<RustlsConfig, Box<dyn Error + Send + Sync>> {
        let cert_file = tokio::fs::read(cert_path).await?;
        let cert_chain =
            rustls_pemfile::certs(&mut cert_file.as_slice()).collect::<Result<Vec<_>, _>>()?;

        let key_file = tokio::fs::read(key_path).await?;
        let private_key =
            rustls_pemfile::private_key(&mut key_file.as_slice())?.ok_or("No private key found")?;

        let config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

    async fn load_manual_certificates(
        &self,
    ) -> Result<RustlsConfig, Box<dyn Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path =
            Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.pem", cert_filename));
        let key_path =
            Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.key", cert_filename));

        if !cert_path.exists() || !key_path.exists() {
            return Err(format!(
                "Manual certificates not found. Please place {}.pem and {}.key in {}",
                cert_filename, cert_filename, self.config.ssl.cert_cache_dir
            )
            .into());
        }

        self.load_certificates(&cert_path, &key_path).await
    }

    pub async fn generate_self_signed(
        &self,
    ) -> Result<RustlsConfig, Box<dyn Error + Send + Sync>> {
        let cache_dir = Path::new(&self.config.ssl.cert_cache_dir);
        tokio::fs::create_dir_all(cache_dir).await?;

        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path = cache_dir.join(format!("{}.pem", cert_filename));
        let key_path = cache_dir.join(format!("{}.key", cert_filename));

        if cert_path.exists() && key_path.exists() {
            return self.load_certificates(&cert_path, &key_path).await;
        }

        warn!(
            "Generating self-signed certificate for {} (development only)",
            domain
        );

        let subject_alt_names = if self.config.ssl.wildcard {
            vec![domain.clone(), format!("*.{}", domain)]
        } else {
            vec![domain.clone()]
        };

        let cert = generate_simple_self_signed(subject_alt_names)?;

        tokio::fs::write(&cert_path, cert.cert.pem()).await?;
        tokio::fs::write(&key_path, cert.signing_key.serialize_pem()).await?;

        let cert_chain = vec![cert.cert.der().clone()];
        let private_key = cert.signing_key.serialize_der().try_into()?;

        let config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        Ok(config)
    }

    pub async fn get_certificate_info(
        &self,
    ) -> Result<CertificateInfo, Box<dyn Error + Send + Sync>> {
        let domain = &self.config.server.domain;
        let cert_filename = if self.config.ssl.wildcard {
            format!("wildcard-{}", domain.replace('.', "-"))
        } else {
            domain.replace('.', "-")
        };

        let cert_path =
            Path::new(&self.config.ssl.cert_cache_dir).join(format!("{}.pem", cert_filename));

        if !tokio::fs::try_exists(&cert_path).await? {
            return Ok(CertificateInfo {
                domain: domain.clone(),
                exists: false,
                expiry_date: None,
                days_until_expiry: None,
                needs_renewal: true,
            });
        }

        let pem_bytes = tokio::fs::read(&cert_path).await?;
        let mut reader = BufReader::new(Cursor::new(pem_bytes));
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

    pub async fn force_renewal(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
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
        let cert_backup_path =
            Path::new(&cert_cache_dir).join(format!("{}.pem.backup", cert_filename));
        let key_backup_path =
            Path::new(&cert_cache_dir).join(format!("{}.key.backup", cert_filename));

        // Create backup copies
        let has_backup = if cert_path.exists() && key_path.exists() {
            match (
                tokio::fs::copy(&cert_path, &cert_backup_path).await,
                tokio::fs::copy(&key_path, &key_backup_path).await,
            ) {
                (Ok(_), Ok(_)) => {
                    info!("Created certificate backup for {}", domain);
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
        if cert_path.exists() {
            tokio::fs::remove_file(&cert_path).await?;
        }
        if key_path.exists() {
            tokio::fs::remove_file(&key_path).await?;
        }

        // Try to generate new certificate
        let renewal_result = match ssl_provider {
            SslProvider::LetsEncrypt => self.setup_letsencrypt().await,
            SslProvider::SelfSigned => self.generate_self_signed().await,
            _ => Err(format!("Unsupported SSL provider for renewal: {:?}", ssl_provider).into()),
        };

        match renewal_result {
            Ok(new_config) => {
                self.rustls_config = Some(Arc::new(new_config));
                info!("Certificate renewal completed for {}", domain);
                Ok(())
            }
            Err(e) => {
                // Restore from backup if available
                if has_backup {
                    match (
                        tokio::fs::copy(&cert_backup_path, &cert_path).await,
                        tokio::fs::copy(&key_backup_path, &key_path).await,
                    ) {
                        (Ok(_), Ok(_)) => {
                            info!("Restored certificate from backup after renewal failure");
                            if let Ok(restored_config) =
                                self.load_certificates(&cert_path, &key_path).await
                            {
                                self.rustls_config = Some(Arc::new(restored_config));
                                info!("Successfully restored working certificates");
                            }
                        }
                        _ => {
                            warn!("Failed to restore certificate backup");
                        }
                    }
                }

                error!("Certificate renewal failed for {}: {}", domain, e);
                Err(format!("Certificate renewal failed: {}", e).into())
            }
        }
    }
}
