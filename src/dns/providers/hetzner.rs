// src/dns/providers/hetzner.rs - Complete final implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{DnsProvider, DnsProviderFactory, ConfigHelper};

/// Hetzner DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HetznerConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

/// Hetzner DNS API response structures
#[derive(Debug, Deserialize)]
struct ZonesResponse {
    zones: Vec<Zone>,
}

#[derive(Debug, Clone, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    zone_id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    value: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CreateRecordResponse {
    record: DnsRecord,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    #[allow(dead_code)]
    zone_id: String,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    #[allow(dead_code)]
    value: String,
    #[allow(dead_code)]
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RecordsResponse {
    records: Vec<DnsRecord>,
}

/// Hetzner DNS provider implementation
pub struct HetznerProvider {
    config: HetznerConfig,
    client: reqwest::Client,
}

impl HetznerProvider {
    pub fn new(config: HetznerConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds.unwrap_or(30));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("ExposeME/1.0")
            .build()
            .expect("Failed to create HTTP client");

        info!("✅ Hetzner DNS provider initialized");
        Self { config, client }
    }

    /// Helper to get zone ID from zone name
    async fn get_zone_id(&self, zone_name: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let response = self.client
            .get("https://dns.hetzner.com/api/v1/zones")
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let zones_response: ZonesResponse = response.json().await?;

        for zone in zones_response.zones {
            if zone.name == zone_name {
                return Ok(zone.id);
            }
        }

        Err(format!("Zone ID not found for {}", zone_name).into())
    }
}

impl ConfigHelper for HetznerProvider {}

impl DnsProviderFactory for HetznerProvider {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {

        let api_token = Self::get_string_with_env(
            toml_config,
            "api_token",
            "EXPOSEME_HETZNER_TOKEN"
        ).ok_or("Hetzner API token not found. Set EXPOSEME_HETZNER_TOKEN environment variable or configure [ssl.dns_provider.config] api_token in TOML")?;

        let timeout_seconds = Self::get_u64_with_env(
            toml_config,
            "timeout_seconds",
            "EXPOSEME_HETZNER_TIMEOUT"
        );

        let config = HetznerConfig {
            api_token,
            timeout_seconds,
        };

        let config_source = if std::env::var("EXPOSEME_HETZNER_TOKEN").is_ok() {
            "environment variables"
        } else {
            "TOML configuration"
        };

        info!("✅ Hetzner DNS provider configured from {}", config_source);
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for HetznerProvider {
    // =============================================================================
    // REQUIRED: Provider implements these 4 basic operations
    // =============================================================================

    async fn list_domains(&mut self) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        info!("📋 Listing available zones from Hetzner DNS");

        let response = self.client
            .get("https://dns.hetzner.com/api/v1/zones")
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("Hetzner API error ({}): {}", status, error_text).into());
        }

        let zones_response: ZonesResponse = response.json().await?;
        let zone_names: Vec<String> = zones_response.zones
            .into_iter()
            .map(|zone| zone.name)
            .collect();

        info!("📋 Found {} zones: {:?}", zone_names.len(), zone_names);
        Ok(zone_names)
    }

    async fn list_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let zone_name = self.find_zone_for_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone_name, name)?;
        let zone_id = self.get_zone_id(&zone_name).await?;

        info!("📋 Listing TXT records: {} in zone {}", record_name, zone_name);

        let url = format!("https://dns.hetzner.com/api/v1/records?zone_id={}", zone_id);
        let response = self.client
            .get(&url)
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("Hetzner API error ({}): {}", status, error_text).into());
        }

        let records_response: RecordsResponse = response.json().await?;
        let matching_record_ids: Vec<String> = records_response.records
            .iter()
            .filter(|record| {
                record.record_type == "TXT" && record.name == record_name
            })
            .map(|record| record.id.clone())
            .collect();

        info!("📋 Found {} existing TXT records", matching_record_ids.len());
        Ok(matching_record_ids)
    }

    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let zone_name = self.find_zone_for_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone_name, name)?;
        let zone_id = self.get_zone_id(&zone_name).await?;

        info!("✨ Creating TXT record: {} in zone {} = {}", record_name, zone_name, value);

        let create_request = CreateRecordRequest {
            zone_id,
            record_type: "TXT".to_string(),
            name: record_name,
            value: value.to_string(),
            ttl: 300,
        };

        let response = self.client
            .post("https://dns.hetzner.com/api/v1/records")
            .header("Auth-API-Token", &self.config.api_token)
            .header("Content-Type", "application/json")
            .json(&create_request)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("Hetzner API error ({}): {}", status, error_text).into());
        }

        let create_response: CreateRecordResponse = response.json().await?;
        let record_id = create_response.record.id;

        info!("✅ Created TXT record with ID: {}", record_id);
        Ok(record_id)
    }

    async fn delete_txt_record(
        &mut self,
        _domain: &str,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🗑️  Deleting TXT record {}", record_id);

        let url = format!("https://dns.hetzner.com/api/v1/records/{}", record_id);

        let response = self.client
            .delete(&url)
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to delete record ({}): {}", status, error_text).into());
        }

        info!("✅ Deleted TXT record {}", record_id);
        Ok(())
    }

    // =============================================================================
    // FREE: Provider gets these default implementations from trait:
    // - find_zone_for_domain()
    // - calculate_record_name()
    // - cleanup_txt_records() 
    // - wait_for_propagation()
    // - check_txt_record()
    // =============================================================================
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_record_name() {
        let config = HetznerConfig {
            api_token: "test".to_string(),
            timeout_seconds: None,
        };
        let provider = HetznerProvider::new(config);

        // Test base domain
        let result = provider.calculate_record_name("example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge");

        // Test subdomain
        let result = provider.calculate_record_name("sub.example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge.sub");
    }
}