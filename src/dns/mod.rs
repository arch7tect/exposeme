// src/dns/mod.rs - Complete DNS Provider Interface

use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub mod providers;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    // =============================================================================
    // PROVIDER IMPLEMENTS: 4 basic operations
    // =============================================================================

    /// List available domains/zones for this DNS provider
    async fn list_domains(&mut self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;

    /// List existing TXT record IDs for a given domain and record name
    async fn list_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;

    /// Create a TXT record and return record ID
    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Delete a TXT record by ID
    async fn delete_txt_record(
        &mut self,
        domain: &str,
        record_id: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    // =============================================================================
    // FREE: Provider gets these default implementations
    // =============================================================================

    /// Find the best matching domain/zone for the target domain
    async fn find_zone_for_domain(&mut self, domain: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        info!("🔍 Looking up zone for domain: {}", domain);

        let available_domains = self.list_domains().await?;
        info!("📋 Found {} available domains/zones", available_domains.len());

        // Find the longest matching domain (most specific)
        let mut best_match = None;
        let mut best_length = 0;

        for available_domain in &available_domains {
            info!("🔍 Checking domain/zone: {}", available_domain);
            if domain.ends_with(available_domain) && available_domain.len() > best_length {
                best_match = Some(available_domain.clone());
                best_length = available_domain.len();
                info!("✅ Found better match: {}", available_domain);
            }
        }

        match best_match {
            Some(zone) => {
                info!("✅ Using zone: {}", zone);
                Ok(zone)
            }
            None => {
                Err(format!("No DNS zone found for domain: {}", domain).into())
            }
        }
    }

    /// Calculate record name relative to DNS zone
    fn calculate_record_name(&self, domain: &str, zone_name: &str, record_prefix: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let record_name = if domain == zone_name {
            record_prefix.to_string()
        } else {
            let subdomain = domain.strip_suffix(&format!(".{}", zone_name))
                .ok_or_else(|| format!("Invalid domain structure: {} vs {}", domain, zone_name))?;

            if subdomain.is_empty() {
                record_prefix.to_string()
            } else {
                format!("{}.{}", record_prefix, subdomain)
            }
        };

        Ok(record_name)
    }

    /// Clean up existing TXT records using list + delete
    async fn cleanup_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🧹 Cleaning up existing TXT records: {}.{}", name, domain);

        match self.list_txt_records(domain, name).await {
            Ok(existing_records) => {
                if existing_records.is_empty() {
                    info!("✅ No existing TXT records to clean up");
                    return Ok(());
                }

                info!("🗑️  Found {} existing TXT record(s) to clean up", existing_records.len());

                for record_id in existing_records {
                    info!("🗑️  Deleting old TXT record ID: {}", record_id);

                    match self.delete_txt_record(domain, &record_id).await {
                        Ok(_) => {
                            info!("✅ Deleted old TXT record {}", record_id);
                        }
                        Err(e) => {
                            warn!("⚠️  Failed to delete old TXT record {}: {}", record_id, e);
                        }
                    }
                }

                info!("🧹 Cleanup completed");
                Ok(())
            }
            Err(e) => {
                warn!("⚠️  Failed to list existing records for cleanup: {}", e);
                warn!("⚠️  Continuing without cleanup...");
                Ok(())
            }
        }
    }

    /// Wait for DNS propagation
    async fn wait_for_propagation(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("⏳ Waiting for DNS propagation of {}.{}", name, domain);

        sleep(Duration::from_secs(30)).await;

        const MAX_ATTEMPTS: u64 = 25;
        const RETRY_DELAY: u64 = 15;
        for attempt in 1..=MAX_ATTEMPTS {
            info!("DNS propagation check {}/{}", attempt, MAX_ATTEMPTS);

            match self.check_txt_record(domain, name, value).await {
                Ok(true) => {
                    info!("✅ DNS propagation confirmed");
                    return Ok(());
                }
                Ok(false) => {
                    if attempt < MAX_ATTEMPTS {
                        info!("⏳ DNS not yet propagated, waiting {} seconds...", RETRY_DELAY);
                        sleep(Duration::from_secs(RETRY_DELAY)).await;
                        continue;
                    } else {
                        warn!("⚠️  DNS propagation not confirmed after {} minutes, proceeding anyway", MAX_ATTEMPTS*RETRY_DELAY/60);
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!("DNS check error: {}, continuing...", e);
                    sleep(Duration::from_secs(15)).await;
                }
            }
        }

        Ok(())
    }

    /// Check if TXT record exists with expected value
    async fn check_txt_record(
        &self,
        domain: &str,
        name: &str,
        expected_value: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        use hickory_resolver::TokioResolver;

        let resolver = TokioResolver::builder_tokio()?.build();
        let fqdn = format!("{}.{}", name, domain);

        match resolver.txt_lookup(&fqdn).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let record_value = record.to_string().trim_matches('"').to_string();
                    if record_value == expected_value {
                        info!("✅ Found matching TXT record for {}", fqdn);
                        return Ok(true);
                    }
                }
                info!("❌ No matching TXT record found for {}", fqdn);
                Ok(false)
            }
            Err(e) => {
                info!("❌ DNS lookup failed for {}: {}", fqdn, e);
                Ok(false)
            }
        }
    }
}

/// Factory trait for creating DNS providers
pub trait DnsProviderFactory {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Create DNS provider
pub fn create_dns_provider(
    provider_name: &str,
    toml_config: Option<&serde_json::Value>
) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {
    match provider_name {
        "digitalocean" => providers::DigitalOceanProvider::create_with_config(toml_config),
        "azure" => providers::AzureProvider::create_with_config(toml_config),
        "hetzner" => providers::HetznerProvider::create_with_config(toml_config),
        _ => Err(format!(
            "Unsupported DNS provider: '{}'. Supported: digitalocean, azure, hetzner",
            provider_name
        ).into()),
    }
}

/// Helper trait for configuration merging
pub trait ConfigHelper {
    fn get_string_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<String> {
        if let Ok(env_value) = std::env::var(env_key) {
            return Some(env_value);
        }
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_str())
            .map(|s| s.to_string())
    }

    fn get_u64_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<u64> {
        if let Ok(env_value) = std::env::var(env_key) {
            if let Ok(parsed) = env_value.parse::<u64>() {
                return Some(parsed);
            }
        }
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_u64())
    }
}