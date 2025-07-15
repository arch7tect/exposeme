// src/dns/providers/digitalocean.rs

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{ConfigHelper, DnsProvider, DnsProviderFactory, ZoneInfo};

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
    #[allow(dead_code)]
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
        ).ok_or("DigitalOcean API token not found. Set EXPOSEME_DIGITALOCEAN_TOKEN environment variable or configure [ssl.dns_provider.config] api_token in TOML")?;

        let timeout_seconds = Self::get_u64_with_env(
            toml_config,
            "timeout_seconds",
            "EXPOSEME_DIGITALOCEAN_TIMEOUT"
        );

        let config = DigitalOceanConfig {
            api_token,
            timeout_seconds,
        };

        let config_source = if std::env::var("EXPOSEME_DIGITALOCEAN_TOKEN").is_ok() {
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
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!("📋 Listing available domains from DigitalOcean");

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
        let zone_infos: Vec<ZoneInfo> = domains_response.domains
            .into_iter()
            .map(|domain| ZoneInfo::from_name(domain.name)) // ID = name for DigitalOcean
            .collect();

        info!("📋 Found {} domains", zone_infos.len());
        Ok(zone_infos)
    }

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        info!("📋 Listing TXT records: {} in domain {}", name, zone.name);

        let url = format!("https://api.digitalocean.com/v2/domains/{}/records", zone.name);
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("DigitalOcean API error ({}): {}", status, error_text).into());
        }

        let records_response: RecordsResponse = response.json().await?;
        let matching_record_ids: Vec<String> = records_response.domain_records
            .iter()
            .filter(|record| {
                record.record_type == "TXT" && record.name == name
            })
            .filter_map(|record| record.id.map(|id| id.to_string()))
            .collect();

        info!("📋 Found {} existing TXT records", matching_record_ids.len());
        Ok(matching_record_ids)
    }

    async fn create_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        info!("✨ Creating TXT record: {} in domain {} = {}", name, zone.name, value);

        let create_request = CreateRecordRequest {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            data: value.to_string(),
            ttl: 300,
        };

        let url = format!("https://api.digitalocean.com/v2/domains/{}/records", zone.name);
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
            return Err(format!("DigitalOcean API error ({}): {}", status, error_text).into());
        }

        let create_response: CreateRecordResponse = response.json().await?;
        let record_id = create_response.domain_record.id
            .ok_or("No record ID returned from DigitalOcean")?;

        info!("✅ Created TXT record with ID: {}", record_id);
        Ok(record_id.to_string())
    }

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🗑️  Deleting TXT record {} from domain {}", record_id, zone.name);

        let url = format!(
            "https://api.digitalocean.com/v2/domains/{}/records/{}",
            zone.name,
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
            return Err(format!("Failed to delete record ({}): {}", status, error_text).into());
        }

        info!("✅ Deleted TXT record {}", record_id);
        Ok(())
    }
}
