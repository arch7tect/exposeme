use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{ConfigHelper, DnsProvider, DnsProviderFactory, ZoneInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalOceanConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

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

        info!(event = "dns.provider.init", provider = "digitalocean", "DNS provider initialized.");
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

        info!(
            event = "dns.provider.configured",
            provider = "digitalocean",
            source = config_source,
            "DNS provider configured from source."
        );
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for DigitalOceanProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!(event = "dns.zones.list", provider = "digitalocean", "Listing DNS zones from provider.");

        let response = self.client
            .get("https://api.digitalocean.com/v2/domains")
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        let response = self
            .ensure_success(response, "DigitalOcean API error")
            .await?;
        let domains_response: DomainsResponse = response.json().await?;
        let zone_infos: Vec<ZoneInfo> = domains_response.domains
            .into_iter()
            .map(|domain| ZoneInfo::from_name(domain.name))
            .collect();

        info!(
            event = "dns.zones.listed",
            provider = "digitalocean",
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
            provider = "digitalocean",
            name,
            zone = %zone.name,
            "Listing TXT records."
        );

        let url = format!("https://api.digitalocean.com/v2/domains/{}/records", zone.name);
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .send()
            .await?;

        let response = self
            .ensure_success(response, "DigitalOcean API error")
            .await?;
        let records_response: RecordsResponse = response.json().await?;
        let matching_record_ids: Vec<String> = records_response.domain_records
            .iter()
            .filter(|record| {
                record.record_type == "TXT" && record.name == name
            })
            .filter_map(|record| record.id.map(|id| id.to_string()))
            .collect();

        info!(
            event = "dns.txt.listed",
            provider = "digitalocean",
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
            provider = "digitalocean",
            name,
            zone = %zone.name,
            "Creating TXT record."
        );

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

        let response = self
            .ensure_success(response, "DigitalOcean API error")
            .await?;
        let create_response: CreateRecordResponse = response.json().await?;
        let record_id = create_response.domain_record.id
            .ok_or("No record ID returned from DigitalOcean")?;

        info!(
            event = "dns.txt.created",
            provider = "digitalocean",
            record_id = %record_id,
            "TXT record created."
        );
        Ok(record_id.to_string())
    }

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.txt.delete",
            provider = "digitalocean",
            record_id,
            zone = %zone.name,
            "Deleting TXT record."
        );

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

        self.ensure_success(response, "Failed to delete record").await?;

        info!(
            event = "dns.txt.deleted",
            provider = "digitalocean",
            record_id,
            "TXT record deleted."
        );
        Ok(())
    }
}
