// src/dns/providers/digitalocean.rs - Only provider-specific methods
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

use crate::dns::{ConfigHelper, DnsProvider, DnsProviderFactory};

/// DigitalOcean DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalOceanConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

/// DigitalOcean DNS API response structures
#[derive(Debug, Deserialize)]
struct DomainsResponse {
    domains: Vec<Domain>,
}

#[derive(Debug, Deserialize)]
struct Domain {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DnsRecord {
    id: Option<u64>,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    data: String,
    ttl: Option<u32>,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    data: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CreateRecordResponse {
    domain_record: DnsRecord,
}

#[derive(Deserialize)]
struct RecordsResponse {
    domain_records: Vec<DnsRecord>,
}

/// DigitalOcean DNS provider implementation
pub struct DigitalOceanProvider {
    config: DigitalOceanConfig,
    client: reqwest::Client,
}

impl DigitalOceanProvider {
    pub fn new(config: DigitalOceanConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds.unwrap_or(30));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("ExposeME/1.0")
            .build()
            .expect("Failed to create HTTP client");

        info!("✅ DigitalOcean DNS provider initialized");
        Self { config, client }
    }

    /// Get the base domain from DigitalOcean that matches the given domain
    async fn get_base_domain(&self, domain: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        info!("Looking up base domain for: {}", domain);

        let response = self.client
            .get("https://api.digitalocean.com/v2/domains")
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("DigitalOcean API error ({}): {}", status, error_text).into());
        }

        let domains_response: DomainsResponse = response.json().await?;
        info!("Found {} domains in DigitalOcean account", domains_response.domains.len());

        // Find the longest matching domain
        let mut best_match = None;
        let mut best_length = 0;

        for do_domain in domains_response.domains {
            info!("Checking domain: {}", do_domain.name);
            if domain.ends_with(&do_domain.name) && do_domain.name.len() > best_length {
                best_match = Some(do_domain.name.clone());
                best_length = do_domain.name.len();
                info!("Found better match: {}", do_domain.name);
            }
        }

        match best_match {
            Some(domain) => {
                info!("✅ Using base domain: {}", domain);
                Ok(domain)
            }
            None => {
                error!("❌ No DigitalOcean domain found for {}", domain);
                Err(format!("No DigitalOcean domain found for {}", domain).into())
            }
        }
    }

    /// Calculate the record name relative to the base domain
    fn calculate_record_name(&self, domain: &str, base_domain: &str, record_prefix: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let record_name = if domain == base_domain {
            record_prefix.to_string()
        } else {
            let subdomain = domain.strip_suffix(&format!(".{}", base_domain))
                .ok_or_else(|| format!("Invalid domain structure: {} vs {}", domain, base_domain))?;

            if subdomain.is_empty() {
                record_prefix.to_string()
            } else {
                format!("{}.{}", record_prefix, subdomain)
            }
        };

        info!("Calculated record name: {} for domain: {}", record_name, domain);
        Ok(record_name)
    }
    async fn cleanup_existing_txt_records(&mut self, base_domain: &str, record_name: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🧹 Cleaning up existing TXT records: {}.{}", record_name, base_domain);

        // Get all records for the domain
        let url = format!("https://api.digitalocean.com/v2/domains/{}/records", base_domain);
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            warn!("⚠️  Failed to list DNS records for cleanup");
            return Ok(()); // Don't fail the whole process for cleanup issues
        }

        let records_response: RecordsResponse = response.json().await?;

        // Find existing TXT records with matching name
        let matching_records: Vec<&DnsRecord> = records_response.domain_records
            .iter()
            .filter(|record| {
                record.record_type == "TXT" && record.name == record_name
            })
            .collect();

        if matching_records.is_empty() {
            info!("✅ No existing TXT records to clean up");
            return Ok(());
        }

        info!("🗑️  Found {} existing TXT record(s) to clean up", matching_records.len());

        // Delete each matching record
        for record in matching_records {
            if let Some(record_id) = record.id {
                info!("🗑️  Deleting old TXT record ID: {}", record_id);

                let delete_url = format!(
                    "https://api.digitalocean.com/v2/domains/{}/records/{}",
                    base_domain,
                    record_id
                );

                match self.client
                    .delete(&delete_url)
                    .header("Authorization", format!("Bearer {}", self.config.api_token))
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => {
                        info!("✅ Deleted old TXT record {}", record_id);
                    }
                    Ok(_) | Err(_) => {
                        warn!("⚠️  Failed to delete old TXT record {}, continuing...", record_id);
                    }
                }
            }
        }

        info!("🧹 Cleanup completed");
        Ok(())
    }
}

impl ConfigHelper for DigitalOceanProvider {}

impl DnsProviderFactory for DigitalOceanProvider {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {

        let api_token = Self::get_string_with_env(
            toml_config,
            "api_token",
            "EXPOSEME_DIGITALOCEAN_TOKEN"
        ).or_else(|| {
            Self::get_string_with_env(toml_config, "api_token", "EXPOSEME_DNS_API_TOKEN")
        }).ok_or("DigitalOcean API token not found. Set EXPOSEME_DIGITALOCEAN_TOKEN environment variable or configure [ssl.dns_provider.config] api_token in TOML")?;

        let timeout_seconds = Self::get_u64_with_env(
            toml_config,
            "timeout_seconds",
            "EXPOSEME_DIGITALOCEAN_TIMEOUT"
        );

        let config = DigitalOceanConfig {
            api_token,
            timeout_seconds,
        };

        let config_source = if std::env::var("EXPOSEME_DIGITALOCEAN_TOKEN").is_ok()
            || std::env::var("EXPOSEME_DNS_API_TOKEN").is_ok() {
            "environment variables"
        } else {
            "TOML configuration"
        };

        info!("✅ DigitalOcean DNS provider configured from {}", config_source);
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for DigitalOceanProvider {
    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let base_domain = self.get_base_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &base_domain, name)?;

        if let Err(e) = self.cleanup_existing_txt_records(&base_domain, &record_name).await {
            warn!("⚠️  Cleanup failed (continuing anyway): {}", e);
        }

        info!("Creating TXT record: {}.{} = {}", record_name, base_domain, value);

        let create_request = CreateRecordRequest {
            record_type: "TXT".to_string(),
            name: record_name,
            data: value.to_string(),
            ttl: 300,
        };

        let url = format!("https://api.digitalocean.com/v2/domains/{}/records", base_domain);
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .json(&create_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            error!("❌ DigitalOcean API error: {}", error_text);
            return Err(format!("DigitalOcean API error ({}): {}", status, error_text).into());
        }

        let create_response: CreateRecordResponse = response.json().await?;
        let record_id = create_response.domain_record.id
            .ok_or("No record ID returned from DigitalOcean")?;

        info!("✅ Created TXT record with ID: {}", record_id);
        Ok(record_id.to_string())
    }

    async fn delete_txt_record(
        &mut self,
        domain: &str,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let base_domain = self.get_base_domain(domain).await?;
        info!("Deleting TXT record {} from DigitalOcean domain {}", record_id, base_domain);

        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records/{}",
            base_domain,
            record_id
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            warn!("⚠️  Failed to delete DNS record: {}", error_text);
            return Err(format!("Failed to delete record ({}): {}", status, error_text).into());
        }

        info!("✅ Deleted TXT record {}", record_id);
        Ok(())
    }

    // wait_for_propagation and check_txt_record use default implementations from trait
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_record_name() {
        let config = DigitalOceanConfig {
            api_token: "test".to_string(),
            timeout_seconds: None,
        };
        let provider = DigitalOceanProvider::new(config);

        // Test base domain
        let result = provider.calculate_record_name("example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge");

        // Test subdomain
        let result = provider.calculate_record_name("sub.example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge.sub");
    }
}
