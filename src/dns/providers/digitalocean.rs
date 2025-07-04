// src/dns/providers/digitalocean.rs - Fixed version
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};

use crate::dns::DnsProvider;

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

        // Get list of domains from DigitalOcean to find the base domain
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
            // Creating record directly on base domain
            record_prefix.to_string()
        } else {
            // Creating record on subdomain
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
}

#[async_trait]
impl DnsProvider for DigitalOceanProvider {
    async fn create_txt_record(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let base_domain = self.get_base_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &base_domain, name)?;

        info!("Creating TXT record: {}.{} = {}", record_name, base_domain, value);

        let create_request = CreateRecordRequest {
            record_type: "TXT".to_string(),
            name: record_name,
            data: value.to_string(),
            ttl: 300, // 5 minutes TTL for quick propagation
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
        &self,
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

    async fn wait_for_propagation(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Waiting for DNS propagation of {}.{} via DigitalOcean", name, domain);

        // DigitalOcean has relatively fast propagation, but let's wait a bit to be sure
        info!("Initial wait for DigitalOcean propagation...");
        sleep(Duration::from_secs(30)).await;

        // Then use the default implementation for verification
        for attempt in 1..=20 {
            info!("DNS propagation check {}/20", attempt);

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_digitalocean_config_serialization() {
        let config = DigitalOceanConfig {
            api_token: "test-token".to_string(),
            timeout_seconds: Some(30),
        };

        let json_value = serde_json::to_value(&config).unwrap();
        let expected = json!({
            "api_token": "test-token",
            "timeout_seconds": 30
        });

        assert_eq!(json_value, expected);
    }

    #[test]
    fn test_digitalocean_config_deserialization() {
        let json_value = json!({
            "api_token": "test-token",
            "timeout_seconds": 30
        });

        let config: DigitalOceanConfig = serde_json::from_value(json_value).unwrap();
        assert_eq!(config.api_token, "test-token");
        assert_eq!(config.timeout_seconds, Some(30));
    }

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

        // Test nested subdomain
        let result = provider.calculate_record_name("api.sub.example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge.api.sub");
    }
}