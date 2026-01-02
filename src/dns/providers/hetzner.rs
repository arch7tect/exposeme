use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{ConfigHelper, DnsProvider, DnsProviderFactory, ZoneInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HetznerConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

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

        info!(event = "dns.provider.init", provider = "hetzner", "DNS provider initialized.");
        Self { config, client }
    }

    async fn ensure_success(
        &self,
        response: reqwest::Response,
        context: &str,
    ) -> Result<reqwest::Response, Box<dyn std::error::Error + Send + Sync>> {
        if response.status().is_success() {
            return Ok(response);
        }

        let error_text = response.text().await?;
        Err(format!("{}: {}", context, error_text).into())
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

        info!(
            event = "dns.provider.configured",
            provider = "hetzner",
            source = config_source,
            "DNS provider configured from source."
        );
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for HetznerProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!(event = "dns.zones.list", provider = "hetzner", "Listing DNS zones from provider.");

        let response = self.client
            .get("https://dns.hetzner.com/api/v1/zones")
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let response = self
            .ensure_success(response, "Hetzner API error")
            .await?;
        let zones_response: ZonesResponse = response.json().await?;
        let zone_infos: Vec<ZoneInfo> = zones_response.zones
            .into_iter()
            .map(|zone| ZoneInfo::new(zone.id, zone.name))
            .collect();

        info!(
            event = "dns.zones.listed",
            provider = "hetzner",
            count = zone_infos.len(),
            "DNS zones listed."
        );
        Ok(zone_infos)
    }

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.txt.list",
            provider = "hetzner",
            name,
            zone = %zone.name,
            "Listing TXT records."
        );

        let url = format!("https://dns.hetzner.com/api/v1/records?zone_id={}", zone.id);
        let response = self.client
            .get(&url)
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        let response = self
            .ensure_success(response, "Hetzner API error")
            .await?;
        let records_response: RecordsResponse = response.json().await?;
        let matching_record_ids: Vec<String> = records_response.records
            .iter()
            .filter(|record| {
                record.record_type == "TXT" && record.name == name
            })
            .map(|record| record.id.clone())
            .collect();

        info!(
            event = "dns.txt.listed",
            provider = "hetzner",
            count = matching_record_ids.len(),
            "TXT records listed."
        );
        Ok(matching_record_ids)
    }

    async fn create_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.txt.create",
            provider = "hetzner",
            name,
            zone = %zone.name,
            "Creating TXT record."
        );

        let create_request = CreateRecordRequest {
            zone_id: zone.id.clone(),
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

        let response = self
            .ensure_success(response, "Hetzner API error")
            .await?;
        let create_response: CreateRecordResponse = response.json().await?;
        let record_id = create_response.record.id;

        info!(
            event = "dns.txt.created",
            provider = "hetzner",
            record_id = %record_id,
            "TXT record created."
        );
        Ok(record_id)
    }

    async fn delete_txt_record_impl(
        &mut self,
        _zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.txt.delete",
            provider = "hetzner",
            record_id,
            "Deleting TXT record."
        );

        let url = format!("https://dns.hetzner.com/api/v1/records/{}", record_id);

        let response = self.client
            .delete(&url)
            .header("Auth-API-Token", &self.config.api_token)
            .send()
            .await?;

        self.ensure_success(response, "Failed to delete record").await?;

        info!(
            event = "dns.txt.deleted",
            provider = "hetzner",
            record_id,
            "TXT record deleted."
        );
        Ok(())
    }


    async fn delete_txt_record(
        &mut self,
        _domain: &str,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dummy_zone = ZoneInfo::from_name("unused".to_string());
        self.delete_txt_record_impl(&dummy_zone, record_id).await
    }
}
