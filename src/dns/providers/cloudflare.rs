// src/dns/providers/cloudflare.rs

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::info;

use crate::dns::{DnsProvider, DnsProviderFactory, ConfigHelper, ZoneInfo};

/// Cloudflare DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    pub api_token: String,
    pub timeout_seconds: Option<u64>,
}

/// Cloudflare DNS API response structures
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

/// Cloudflare DNS provider implementation
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

        info!("✅ Cloudflare DNS provider initialized");
        Self { config, client }
    }

    async fn handle_cloudflare_response<T>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let status = response.status();
        let response_text = response.text().await?;

        if !status.is_success() {
            return Err(format!("Cloudflare API error ({}): {}", status, response_text).into());
        }

        let cf_response: CloudflareResponse<T> = serde_json::from_str(&response_text)
            .map_err(|e| format!("Failed to parse Cloudflare response: {}", e))?;

        // Log any informational messages from Cloudflare
        if !cf_response.messages.is_empty() {
            let info_messages: Vec<String> = cf_response.messages
                .iter()
                .map(|m| format!("Code {}: {}", m.code, m.message))
                .collect();
            info!("📨 Cloudflare messages: {}", info_messages.join(", "));
        }

        if !cf_response.success {
            let error_messages: Vec<String> = cf_response.errors
                .iter()
                .map(|e| format!("Code {}: {}", e.code, e.message))
                .collect();
            return Err(format!("Cloudflare API errors: {}", error_messages.join(", ")).into());
        }

        cf_response.result.ok_or_else(|| {
            "Cloudflare API returned success but no result data".into()
        })
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

        info!("✅ Cloudflare DNS provider configured from {}", config_source);
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>> {
        info!("📋 Listing available zones from Cloudflare");

        let response = self.client
            .get("https://api.cloudflare.com/client/v4/zones")
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let zones: Vec<CloudflareZone> = self.handle_cloudflare_response(response).await?;

        let zone_infos: Vec<ZoneInfo> = zones
            .into_iter()
            .filter(|zone| zone.status == "active") // Only include active zones
            .map(|zone| ZoneInfo::new(zone.id, zone.name))
            .collect();

        info!("📋 Found {} active zones", zone_infos.len());
        Ok(zone_infos)
    }

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        info!("📋 Listing TXT records: {} in zone {}", name, zone.name);

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

        let records: Vec<CloudflareDnsRecord> = self.handle_cloudflare_response(response).await?;

        let matching_record_ids: Vec<String> = records
            .iter()
            .filter_map(|record| record.id.clone())
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
        info!("✨ Creating TXT record: {} in zone {} = {}", name, zone.name, value);

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

        let record: CloudflareDnsRecord = self.handle_cloudflare_response(response).await?;
        let record_id = record.id.ok_or("No record ID returned from Cloudflare")?;

        info!("✅ Created TXT record with ID: {}", record_id);
        Ok(record_id)
    }

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🗑️  Deleting TXT record {} from zone {}", record_id, zone.name);

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

        // For DELETE operations, Cloudflare returns a different response structure
        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to delete record ({}): {}", status, error_text).into());
        }

        // Try to parse as Cloudflare response, but don't fail if it's just empty
        let response_text = response.text().await?;
        if !response_text.is_empty() {
            let cf_response: CloudflareResponse<serde_json::Value> = serde_json::from_str(&response_text)
                .map_err(|e| format!("Failed to parse Cloudflare delete response: {}", e))?;

            // Log any informational messages from Cloudflare
            if !cf_response.messages.is_empty() {
                let info_messages: Vec<String> = cf_response.messages
                    .iter()
                    .map(|m| format!("Code {}: {}", m.code, m.message))
                    .collect();
                info!("📨 Cloudflare delete messages: {}", info_messages.join(", "));
            }

            if !cf_response.success {
                let error_messages: Vec<String> = cf_response.errors
                    .iter()
                    .map(|e| format!("Code {}: {}", e.code, e.message))
                    .collect();
                return Err(format!("Cloudflare delete errors: {}", error_messages.join(", ")).into());
            }
        }

        info!("✅ Deleted TXT record {}", record_id);
        Ok(())
    }
}
