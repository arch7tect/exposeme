// src/dns/mod.rs - DNS trait with generic default implementations
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub mod providers;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Provider-specific: Create a TXT record and return record ID
    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    /// Provider-specific: Delete a TXT record by ID
    async fn delete_txt_record(
        &mut self,
        domain: &str,
        record_id: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Generic: Wait for DNS propagation (default implementation provided)
    async fn wait_for_propagation(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Waiting for DNS propagation of {}.{}", name, domain);

        // Initial wait for DNS provider to propagate
        info!("Initial wait for DNS propagation...");
        sleep(Duration::from_secs(30)).await;

        // Verify propagation with retries
        const TOTAL_ATTEMPTS: i16 = 25;
        for attempt in 1..=TOTAL_ATTEMPTS {
            info!("DNS propagation check {}/{}", attempt, TOTAL_ATTEMPTS);

            match self.check_txt_record(domain, name, value).await {
                Ok(true) => {
                    info!("✅ DNS propagation confirmed");
                    return Ok(());
                }
                Ok(false) => {
                    if attempt < 20 {
                        info!("⏳ DNS not yet propagated, waiting 15 seconds...");
                        sleep(Duration::from_secs(15)).await;
                        continue;
                    } else {
                        warn!("⚠️  DNS propagation not confirmed after 5 minutes, proceeding anyway");
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

    /// Generic: Check if TXT record exists with expected value (default implementation provided)
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

/// Simplified factory trait - just create or fail
pub trait DnsProviderFactory {
    /// Create provider with environment variables taking priority over TOML config
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>>;
}

/// Create DNS provider - simple and direct
pub fn create_dns_provider(
    provider_name: &str,
    toml_config: Option<&serde_json::Value>
) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {
    match provider_name {
        "digitalocean" => providers::DigitalOceanProvider::create_with_config(toml_config),
        "azure" => providers::AzureProvider::create_with_config(toml_config),
        _ => Err(format!(
            "Unsupported DNS provider: '{}'. Supported: digitalocean, azure",
            provider_name
        ).into()),
    }
}

/// Helper trait for configuration merging
pub trait ConfigHelper {
    /// Get string value with environment override
    fn get_string_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<String> {
        // Environment takes priority
        if let Ok(env_value) = std::env::var(env_key) {
            return Some(env_value);
        }

        // Fall back to TOML config
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_str())
            .map(|s| s.to_string())
    }

    /// Get u64 value with environment override
    fn get_u64_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<u64> {
        // Environment takes priority
        if let Ok(env_value) = std::env::var(env_key) {
            if let Ok(parsed) = env_value.parse::<u64>() {
                return Some(parsed);
            }
        }

        // Fall back to TOML config
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_u64())
    }
}