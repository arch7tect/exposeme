// src/dns/mod.rs - Fixed version
use async_trait::async_trait;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub mod providers;

/// DNS provider trait for managing DNS records
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record for ACME challenge
    async fn create_txt_record(
        &self,
        domain: &str,
        name: &str,
        value: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>; // Returns record ID

    /// Delete a TXT record by ID
    async fn delete_txt_record(
        &self,
        domain: &str,
        record_id: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Wait for DNS propagation
    async fn wait_for_propagation(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Waiting for DNS propagation of {}.{}", name, domain);

        // Default implementation: simple wait
        for attempt in 1..=30 {
            info!("DNS propagation check {}/30", attempt);

            // Try to resolve the TXT record
            match self.check_txt_record(domain, name, value).await {
                Ok(true) => {
                    info!("✅ DNS propagation confirmed");
                    return Ok(());
                }
                Ok(false) => {
                    if attempt < 30 {
                        sleep(Duration::from_secs(10)).await;
                        continue;
                    } else {
                        warn!("DNS propagation not confirmed after 5 minutes, proceeding anyway");
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!("DNS check error: {}, continuing...", e);
                    sleep(Duration::from_secs(10)).await;
                }
            }
        }

        Ok(())
    }

    /// Check if TXT record exists and has correct value
    async fn check_txt_record(
        &self,
        domain: &str,
        name: &str,
        expected_value: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Default implementation using DNS lookup
        use hickory_resolver::TokioResolver;

        let resolver = TokioResolver::builder_tokio()?.build();
        let fqdn = format!("{}.{}", name, domain);

        match resolver.txt_lookup(&fqdn).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let record_value = record.to_string().trim_matches('"').to_string();
                    if record_value == expected_value {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(_) => Ok(false),
        }
    }
}

/// Create DNS provider from configuration
pub fn create_dns_provider(
    provider_type: &str,
    config_value: &serde_json::Value,
) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {
    match provider_type {
        "digitalocean" => {
            let config = serde_json::from_value(config_value.clone())?;
            Ok(Box::new(providers::DigitalOceanProvider::new(config)))
        }
        // Future providers (uncomment when implemented):
        // "cloudflare" => {
        //     let config = serde_json::from_value(config_value.clone())?;
        //     Ok(Box::new(providers::cloudflare::CloudflareProvider::new(config)))
        // }
        // "route53" => {
        //     let config = serde_json::from_value(config_value.clone())?;
        //     Ok(Box::new(providers::route53::Route53Provider::new(config)))
        // }
        _ => Err(format!("Unsupported DNS provider: '{}'. Supported providers: digitalocean", provider_type).into()),
    }
}