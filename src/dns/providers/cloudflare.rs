use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{DnsProvider, DnsProviderFactory, ConfigHelper, ZoneInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    messages: Vec<CloudflareMessage>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareMessage {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
    status: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CloudflareDnsRecord {
    id: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zone_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

pub struct CloudflareProvider {
    config: CloudflareConfig,
    client: reqwest::Client,
}

impl CloudflareProvider {
    pub fn new(config: CloudflareConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds.unwrap_or(30));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("ExposeME/1.0")
            .build()
            .expect("Failed to create HTTP client");

        info!(provider = "cloudflare", "DNS provider initialized.");
        Self { config, client }
    }

    async fn handle_cloudflare_response<T>(
        &self,
        response: reqwest::Response,
    ) -> Result<Option<T>, Box<dyn std::error::Error + Send + Sync>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let text = response.text().await?;

        if !status.is_success() {
            return Err(format!("Cloudflare API error ({}): {}", status, text).into());
        }

        if text.trim().is_empty() {
            return Ok(None);
        }

        let cf_response: CloudflareResponse<T> = serde_json::from_str(&text)
            .map_err(|e| format!("Failed to parse Cloudflare response: {}", e))?;

        if !cf_response.messages.is_empty() {
            let info_messages: Vec<String> = cf_response
                .messages
                .iter()
                .map(|m| format!("Code {}: {}", m.code, m.message))
                .collect();
            info!(
                provider = "cloudflare",
                messages = %info_messages.join(", "),
                "DNS provider returned informational messages."
            );
        }

        if !cf_response.success {
            let error_messages: Vec<String> = cf_response
                .errors
                .iter()
                .map(|e| format!("Code {}: {}", e.code, e.message))
                .collect();
            return Err(format!("Cloudflare API errors: {}", error_messages.join(", ")).into());
        }

        Ok(cf_response.result)
    }
}

impl ConfigHelper for CloudflareProvider {}

impl DnsProviderFactory for CloudflareProvider {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {

        let api_token = Self::get_string_with_env(
            toml_config,
            "api_token",
            "EXPOSEME_CLOUDFLARE_TOKEN"
        ).ok_or("Cloudflare API token not found. Set EXPOSEME_CLOUDFLARE_TOKEN environment variable or configure [ssl.dns_provider.config] api_token in TOML")?;

        let timeout_seconds = Self::get_u64_with_env(
            toml_config,
            "timeout_seconds",
            "EXPOSEME_CLOUDFLARE_TIMEOUT"
        );

        let config = CloudflareConfig {
            api_token,
            timeout_seconds,
        };

        let config_source = if std::env::var("EXPOSEME_CLOUDFLARE_TOKEN").is_ok() {
            "environment variables"
        } else {
            "TOML configuration"
        };

        info!(
            provider = "cloudflare",
            source = config_source,
            "DNS provider configured from source."
        );
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!(provider = "cloudflare", "Listing DNS zones from provider.");

        let response = self.client
            .get("https://api.cloudflare.com/client/v4/zones")
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let zones: Vec<CloudflareZone> = self
            .handle_cloudflare_response(response)
            .await?
            .ok_or("Cloudflare API returned success but no result data")?;

        let zone_infos: Vec<ZoneInfo> = zones
            .into_iter()
            .filter(|zone| zone.status == "active")
            .map(|zone| ZoneInfo::new(zone.id, zone.name))
            .collect();

        info!(
            provider = "cloudflare",
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
            provider = "cloudflare",
            name,
            zone = %zone.name,
            "Listing TXT records."
        );

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records?type=TXT&name={}",
            zone.id,
            name
        );

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let records: Vec<CloudflareDnsRecord> = self
            .handle_cloudflare_response(response)
            .await?
            .ok_or("Cloudflare API returned success but no result data")?;

        let matching_record_ids: Vec<String> = records
            .iter()
            .filter_map(|record| record.id.clone())
            .collect();

        info!(
            provider = "cloudflare",
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
            provider = "cloudflare",
            name,
            zone = %zone.name,
            "Creating TXT record."
        );

        let create_request = CreateRecordRequest {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            content: value.to_string(),
            ttl: 300,
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone.id
        );

        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .json(&create_request)
            .send()
            .await?;

        let record: CloudflareDnsRecord = self
            .handle_cloudflare_response(response)
            .await?
            .ok_or("Cloudflare API returned success but no result data")?;
        let record_id = record.id.ok_or("No record ID returned from Cloudflare")?;

        info!(
            provider = "cloudflare",
            record_id = %record_id,
            "TXT record created."
        );
        Ok(record_id)
    }

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            provider = "cloudflare",
            record_id,
            zone = %zone.name,
            "Deleting TXT record."
        );

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone.id,
            record_id
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        self.handle_cloudflare_response::<serde_json::Value>(response).await?;

        info!(
            provider = "cloudflare",
            record_id,
            "TXT record deleted."
        );
        Ok(())
    }
}
