use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use tracing::info;

use crate::dns::{ConfigHelper, DnsProvider, DnsProviderFactory, ZoneInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub resource_group: String,
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct ZonesListResponse {
    value: Vec<AzureZone>,
}

#[derive(Debug, Deserialize)]
struct AzureZone {
    id: String,
    name: String,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    zone_type: String,
    #[allow(dead_code)]
    location: String,
}

#[derive(Debug, Serialize)]
struct DnsRecordSet {
    properties: DnsRecordProperties,
}

#[derive(Debug, Serialize)]
struct DnsRecordProperties {
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "TXTRecords")]
    txt_records: Vec<TxtRecord>,
}

#[derive(Debug, Serialize)]
struct TxtRecord {
    value: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RecordSetsResponse {
    value: Vec<RecordSetInfo>,
}

#[derive(Debug, Deserialize)]
struct RecordSetInfo {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[allow(dead_code)]
    properties: Option<RecordSetProperties>,
}

#[derive(Debug, Deserialize)]
struct RecordSetProperties {
    #[serde(rename = "TXTRecords")]
    #[allow(dead_code)]
    txt_records: Option<Vec<TxtRecordInfo>>,
}

#[derive(Debug, Deserialize)]
struct TxtRecordInfo {
    #[allow(dead_code)]
    value: Vec<String>,
}

pub struct AzureProvider {
    config: AzureConfig,
    client: reqwest::Client,
    access_token: Option<String>,
    token_expires_at: Option<std::time::Instant>,
}

impl AzureProvider {
    pub fn new(config: AzureConfig) -> Self {
        let timeout = Duration::from_secs(config.timeout_seconds.unwrap_or(30));
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("ExposeME/1.0")
            .build()
            .expect("Failed to create HTTP client");

        info!(event = "dns.provider.init", provider = "azure", "DNS provider initialized.");
        Self {
            config,
            client,
            access_token: None,
            token_expires_at: None,
        }
    }

    async fn get_access_token(&mut self) -> Result<String, Box<dyn Error + Send + Sync>> {
        if let (Some(token), Some(expires_at)) = (&self.access_token, self.token_expires_at) {
            if std::time::Instant::now() < expires_at {
                return Ok(token.clone());
            }
        }

        info!(event = "dns.azure.token.fetch", "Fetching Azure DNS access token.");

        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        );

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
            ("scope", "https://management.azure.com/.default"),
        ];

        let response = self.client
            .post(&token_url)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Azure auth error: {}", error_text).into());
        }

        let token_response: AccessTokenResponse = response.json().await?;

        let expires_at = std::time::Instant::now() + Duration::from_secs(token_response.expires_in - 300);

        self.access_token = Some(token_response.access_token.clone());
        self.token_expires_at = Some(expires_at);

        info!(event = "dns.azure.token.ready", "Azure DNS access token acquired.");
        Ok(token_response.access_token)
    }

    async fn ensure_success(
        &self,
        response: reqwest::Response,
        context: &str,
    ) -> Result<reqwest::Response, Box<dyn Error + Send + Sync>> {
        if response.status().is_success() {
            return Ok(response);
        }

        let error_text = response.text().await?;
        Err(format!("{}: {}", context, error_text).into())
    }
}

impl ConfigHelper for AzureProvider {}

impl DnsProviderFactory for AzureProvider {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn Error + Send + Sync>> {

        let subscription_id = Self::get_string_with_env(
            toml_config, "subscription_id", "EXPOSEME_AZURE_SUBSCRIPTION_ID"
        ).ok_or("Azure subscription_id not found. Set EXPOSEME_AZURE_SUBSCRIPTION_ID environment variable or configure [ssl.dns_provider.config] subscription_id in TOML")?;

        let resource_group = Self::get_string_with_env(
            toml_config, "resource_group", "EXPOSEME_AZURE_RESOURCE_GROUP"
        ).ok_or("Azure resource_group not found. Set EXPOSEME_AZURE_RESOURCE_GROUP environment variable or configure [ssl.dns_provider.config] resource_group in TOML")?;

        let client_id = Self::get_string_with_env(
            toml_config, "client_id", "EXPOSEME_AZURE_CLIENT_ID"
        ).ok_or("Azure client_id not found. Set EXPOSEME_AZURE_CLIENT_ID environment variable or configure [ssl.dns_provider.config] client_id in TOML")?;

        let client_secret = Self::get_string_with_env(
            toml_config, "client_secret", "EXPOSEME_AZURE_CLIENT_SECRET"
        ).ok_or("Azure client_secret not found. Set EXPOSEME_AZURE_CLIENT_SECRET environment variable or configure [ssl.dns_provider.config] client_secret in TOML")?;

        let tenant_id = Self::get_string_with_env(
            toml_config, "tenant_id", "EXPOSEME_AZURE_TENANT_ID"
        ).ok_or("Azure tenant_id not found. Set EXPOSEME_AZURE_TENANT_ID environment variable or configure [ssl.dns_provider.config] tenant_id in TOML")?;

        let timeout_seconds = Self::get_u64_with_env(
            toml_config, "timeout_seconds", "EXPOSEME_AZURE_TIMEOUT"
        );

        let config = AzureConfig {
            subscription_id, resource_group, client_id, client_secret, tenant_id, timeout_seconds,
        };

        let config_source = if std::env::var("EXPOSEME_AZURE_SUBSCRIPTION_ID").is_ok() {
            "environment variables"
        } else {
            "TOML configuration"
        };

        info!(
            event = "dns.provider.configured",
            provider = "azure",
            source = config_source,
            "DNS provider configured from source."
        );
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for AzureProvider {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;

        info!(event = "dns.zones.list", provider = "azure", "Listing DNS zones from provider.");

        let zones_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones?api-version=2018-05-01",
            self.config.subscription_id,
            self.config.resource_group
        );

        let response = self.client
            .get(&zones_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let response = self
            .ensure_success(response, "Azure DNS zones list error")
            .await?;
        let zones_response: ZonesListResponse = response.json().await?;
        let zone_infos: Vec<ZoneInfo> = zones_response.value
            .into_iter()
            .map(|zone| ZoneInfo::new(zone.id, zone.name))
            .collect();

        info!(
            event = "dns.zones.listed",
            provider = "azure",
            count = zone_infos.len(),
            "DNS zones listed."
        );
        Ok(zone_infos)
    }

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;

        info!(
            event = "dns.txt.list",
            provider = "azure",
            name,
            zone = %zone.name,
            "Listing TXT records."
        );

        let list_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/recordsets?api-version=2018-05-01&$filter=recordType eq 'TXT'",
            self.config.subscription_id,
            self.config.resource_group,
            zone.name
        );

        let response = self.client
            .get(&list_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        let response = self
            .ensure_success(response, "Azure DNS records list error")
            .await?;
        let recordsets_response: RecordSetsResponse = response.json().await?;

        let matching_record_ids: Vec<String> = recordsets_response.value
            .iter()
            .filter(|record| {
                record.record_type == "Microsoft.Network/dnszones/TXT" && record.name == name
            })
            .map(|record| record.name.clone())
            .collect();

        info!(
            event = "dns.txt.listed",
            provider = "azure",
            count = matching_record_ids.len(),
            name,
            "TXT records listed."
        );
        Ok(matching_record_ids)
    }

    async fn create_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;

        info!(
            event = "dns.txt.create",
            provider = "azure",
            name,
            zone = %zone.name,
            "Creating TXT record."
        );

        let record_set = DnsRecordSet {
            properties: DnsRecordProperties {
                ttl: 300,
                txt_records: vec![TxtRecord {
                    value: vec![value.to_string()],
                }],
            },
        };

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.config.subscription_id,
            self.config.resource_group,
            zone.name,
            name
        );

        let response = self.client
            .put(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&record_set)
            .send()
            .await?;

        self.ensure_success(response, "Azure DNS record creation error")
            .await?;

        info!(
            event = "dns.txt.created",
            provider = "azure",
            record_id = name,
            "TXT record created."
        );
        Ok(name.to_string())
    }

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;

        info!(
            event = "dns.txt.delete",
            provider = "azure",
            record_id,
            zone = %zone.name,
            "Deleting TXT record."
        );

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.config.subscription_id,
            self.config.resource_group,
            zone.name,
            record_id
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        self.ensure_success(response, "Failed to delete record").await?;

        info!(
            event = "dns.txt.deleted",
            provider = "azure",
            record_id,
            "TXT record deleted."
        );
        Ok(())
    }
}
