// src/dns/providers/azure.rs - Updated with new interface

use std::error::Error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info};

use crate::dns::{DnsProvider, DnsProviderFactory, ConfigHelper};

/// Azure DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    pub subscription_id: String,
    pub resource_group: String,
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub timeout_seconds: Option<u64>,
}

/// Azure DNS API response structures
#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
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

// Response structures for listing records
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

/// Azure DNS provider implementation
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

        info!("✅ Azure DNS provider initialized");
        Self {
            config,
            client,
            access_token: None,
            token_expires_at: None,
        }
    }

    /// Get Azure access token using Service Principal
    async fn get_access_token(&mut self) -> Result<String, Box<dyn Error + Send + Sync>> {
        // Check if current token is still valid
        if let (Some(token), Some(expires_at)) = (&self.access_token, self.token_expires_at) {
            if std::time::Instant::now() < expires_at {
                return Ok(token.clone());
            }
        }

        info!("🔑 Obtaining Azure access token...");

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

        info!("✅ Azure access token obtained");
        Ok(token_response.access_token)
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

        info!("✅ Azure DNS provider configured from {}", config_source);
        Ok(Box::new(Self::new(config)))
    }
}

#[async_trait]
impl DnsProvider for AzureProvider {
    async fn list_domains(&mut self) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;

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

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Azure DNS zones list error: {}", error_text).into());
        }

        let zones_response: serde_json::Value = response.json().await?;
        if let Some(zones) = zones_response["value"].as_array() {
            let mut zone_list = Vec::new();
            for item in zones {
                if let Some(s) = item.as_str() {
                    zone_list.push(s.to_string());
                } else {
                    return Err(format!("Expected string in zones array, got: {:?}", item).into());
                }
            }
            Ok(zone_list)
        }
        else {
            Err("Azure DNS zones list error: Missing or invalid 'value' field in response".into())
        }
    }

    async fn list_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;
        let zone = self.find_zone_for_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone, name)?;

        info!("📋 Listing TXT records: {} in zone {}", record_name, zone);

        // List all TXT recordsets in the zone
        let list_url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/recordsets?api-version=2018-05-01&$filter=recordType eq 'TXT'",
            self.config.subscription_id,
            self.config.resource_group,
            zone
        );

        let response = self.client
            .get(&list_url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Azure DNS records list error: {}", error_text).into());
        }

        let recordsets_response: RecordSetsResponse = response.json().await?;

        // Find existing TXT records with matching name and return their names (Azure uses names as IDs)
        let matching_record_ids: Vec<String> = recordsets_response.value
            .iter()
            .filter(|record| {
                record.record_type == "Microsoft.Network/dnszones/TXT" && record.name == record_name
            })
            .map(|record| record.name.clone())
            .collect();

        info!("📋 Found {} existing TXT records for {}", matching_record_ids.len(), record_name);
        Ok(matching_record_ids)
    }

    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;
        let zone = self.find_zone_for_domain(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone, name)?;

        info!("✨ Creating TXT record: {} in zone {} = {}", record_name, zone, value);

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
            self.config.subscription_id, self.config.resource_group, zone, record_name
        );

        let response = self.client
            .put(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&record_set)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Azure DNS record creation error: {}", error_text).into());
        }

        info!("✅ Created TXT record: {}", record_name);
        // Azure uses record name as ID
        Ok(record_name)
    }

    async fn delete_txt_record(
        &mut self,
        domain: &str,
        record_id: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let token = self.get_access_token().await?;
        let zone = self.find_zone_for_domain(domain).await?;

        info!("🗑️  Deleting TXT record {} from Azure DNS zone {}", record_id, zone);

        let url = format!(
            "https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TXT/{}?api-version=2018-05-01",
            self.config.subscription_id, self.config.resource_group, zone, record_id
        );

        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Failed to delete record: {}", error_text).into());
        }

        info!("✅ Deleted TXT record {}", record_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_record_name() {
        let config = AzureConfig {
            subscription_id: "test".to_string(),
            resource_group: "test".to_string(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            tenant_id: "test".to_string(),
            timeout_seconds: None,
        };
        let provider = AzureProvider::new(config);

        // Test base domain
        let result = provider.calculate_record_name("example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge");

        // Test subdomain
        let result = provider.calculate_record_name("sub.example.com", "example.com", "_acme-challenge").unwrap();
        assert_eq!(result, "_acme-challenge.sub");
    }
}