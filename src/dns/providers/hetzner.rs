use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{DnsProvider, DnsProviderFactory, ConfigHelper, ZoneInfo};

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

        info!("Hetzner DNS provider initialized");
        Self { config, client }
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

        info!("Hetzner DNS provider configured from {}", config_source);
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for HetznerProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!("Listing available zones from Hetzner DNS");

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
        let zone_infos: Vec<ZoneInfo> = zones_response.zones
            .into_iter()
            .map(|zone| ZoneInfo::new(zone.id, zone.name)) // Store both ID and name
            .collect();

        info!("Found {} zones", zone_infos.len());
        Ok(zone_infos)
    }

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        info!("Listing TXT records: {} in zone {}", name, zone.name);

        let url = format!("https://dns.hetzner.com/api/v1/records?zone_id={}", zone.id);
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
                record.record_type == "TXT" && record.name == name
            })
            .map(|record| record.id.clone())
            .collect();

        info!("Found {} existing TXT records", matching_record_ids.len());
        Ok(matching_record_ids)
    }

    async fn create_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        info!("Creating TXT record: {} in zone {} = {}", name, zone.name, value);

        let create_request = CreateRecordRequest {
            zone_id: zone.id.clone(), // No extra lookup needed
            record_type: "TXT".to_string(),
            name: name.to_string(),
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

        info!("Created TXT record with ID: {}", record_id);
        Ok(record_id)
    }

    async fn delete_txt_record_impl(
        &mut self,
        _zone: &ZoneInfo, // Zone not needed for Hetzner delete
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Deleting TXT record {}", record_id);

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

        info!("Deleted TXT record {}", record_id);
        Ok(())
    }


    async fn delete_txt_record(
        &mut self,
        _domain: &str, // Domain not needed for Hetzner delete
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dummy_zone = ZoneInfo::from_name("unused".to_string());
        self.delete_txt_record_impl(&dummy_zone, record_id).await
    }
}
