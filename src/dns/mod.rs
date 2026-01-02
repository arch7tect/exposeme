use async_trait::async_trait;
use hickory_resolver::TokioResolver;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

pub mod providers;

#[derive(Debug, Clone)]
pub(crate) struct ZoneInfo {
    pub id: String,      // For providers that need IDs (Hetzner)
    pub name: String,    // Human-readable zone name
}

impl ZoneInfo {
    pub fn from_name(name: String) -> Self {
        Self {
            id: name.clone(),
            name,
        }
    }

    pub fn new(id: String, name: String) -> Self {
        Self { id, name }
    }
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn list_zones_impl(&mut self) -> Result<Vec<ZoneInfo>, Box<dyn std::error::Error + Send + Sync>>;

    async fn list_txt_records_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;

    async fn create_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        name: &str,
        value: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    async fn delete_txt_record_impl(
        &mut self,
        zone: &ZoneInfo,
        record_id: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    async fn list_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let zone = self.get_zone_info(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone.name, name)?;
        self.list_txt_records_impl(&zone, &record_name).await
    }

    async fn create_txt_record(
        &mut self,
        domain: &str,
        name: &str,
        value: &str
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let zone = self.get_zone_info(domain).await?;
        let record_name = self.calculate_record_name(domain, &zone.name, name)?;
        self.create_txt_record_impl(&zone, &record_name, value).await
    }

    async fn delete_txt_record(
        &mut self,
        domain: &str,
        record_id: &str
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let zone = self.get_zone_info(domain).await?;
        self.delete_txt_record_impl(&zone, record_id).await
    }

    async fn get_zone_info(&mut self, domain: &str) -> Result<ZoneInfo, Box<dyn std::error::Error + Send + Sync>> {
        info!(event = "dns.zone.lookup", domain, "Looking up DNS zone for domain.");

        let available_zones = self.list_zones_impl().await?;
        info!(
            event = "dns.zones.available",
            count = available_zones.len(),
            "Available DNS zones listed."
        );

        let mut best_match = None;
        let mut best_length = 0;

        for zone in &available_zones {
            if domain.ends_with(&zone.name) && zone.name.len() > best_length {
                best_match = Some(zone.clone());
                best_length = zone.name.len();
                info!(
                    event = "dns.zone.match",
                    zone = %zone.name,
                    "Better DNS zone match found."
                );
            }
        }

        match best_match {
            Some(zone) => {
                info!(
                    event = "dns.zone.selected",
                    zone = %zone.name,
                    zone_id = %zone.id,
                    "DNS zone selected for domain."
                );
                Ok(zone)
            }
            None => {
                Err(format!("No DNS zone found for domain: {}", domain).into())
            }
        }
    }

    fn calculate_record_name(&self, domain: &str, zone_name: &str, record_prefix: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let record_name = if domain == zone_name {
            record_prefix.to_string()
        } else {
            let subdomain = domain.strip_suffix(&format!(".{}", zone_name))
                .ok_or_else(|| format!("Invalid domain structure: {} vs {}", domain, zone_name))?;

            if subdomain.is_empty() {
                record_prefix.to_string()
            } else {
                format!("{}.{}", record_prefix, subdomain)
            }
        };

        Ok(record_name)
    }

    async fn cleanup_txt_records(
        &mut self,
        domain: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.txt.cleanup.start",
            name,
            domain,
            "TXT cleanup started."
        );

        match self.list_txt_records(domain, name).await {
            Ok(existing_records) => {
                if existing_records.is_empty() {
                    info!(event = "dns.txt.cleanup.empty", "No TXT records to clean up.");
                    return Ok(());
                }

                info!(
                    event = "dns.txt.cleanup.found",
                    count = existing_records.len(),
                    "Existing TXT records found for cleanup."
                );

                for record_id in existing_records {
                    info!(
                        event = "dns.txt.cleanup.delete",
                        record_id,
                        "Deleting old TXT record."
                    );

                    match self.delete_txt_record(domain, &record_id).await {
                        Ok(_) => {
                            info!(
                                event = "dns.txt.cleanup.deleted",
                                record_id,
                                "Old TXT record deleted."
                            );
                        }
                        Err(e) => {
                            warn!(
                                event = "dns.txt.cleanup.error",
                                record_id,
                                error = %e,
                                "Failed to delete TXT record during cleanup."
                            );
                        }
                    }
                }

                info!(event = "dns.txt.cleanup.done", "TXT cleanup completed.");
                Ok(())
            }
            Err(e) => {
                warn!(
                    event = "dns.txt.cleanup.list_error",
                    error = %e,
                    "Failed to list TXT records for cleanup."
                );
                warn!(event = "dns.txt.cleanup.skip", "Skipping TXT cleanup after list failure.");
                Ok(())
            }
        }
    }

    async fn wait_for_propagation(
        &self,
        domain: &str,
        name: &str,
        value: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            event = "dns.propagation.wait",
            name,
            domain,
            "Waiting for DNS propagation."
        );

        sleep(Duration::from_secs(30)).await;

        const MAX_ATTEMPTS: u64 = 25;
        const RETRY_DELAY: u64 = 15;
        for attempt in 1..=MAX_ATTEMPTS {
            info!(
                event = "dns.propagation.check",
                attempt,
                max_attempts = MAX_ATTEMPTS,
                "Checking DNS propagation."
            );

            match self.check_txt_record(domain, name, value).await {
                Ok(true) => {
                    info!(event = "dns.propagation.confirmed", "DNS propagation confirmed.");
                    return Ok(());
                }
                Ok(false) => {
                    if attempt < MAX_ATTEMPTS {
                        info!(
                            event = "dns.propagation.pending",
                            attempt,
                            retry_delay_secs = RETRY_DELAY,
                            "DNS propagation pending; waiting to retry."
                        );
                        sleep(Duration::from_secs(RETRY_DELAY)).await;
                        continue;
                    } else {
                        warn!(
                            event = "dns.propagation.timeout",
                            minutes = MAX_ATTEMPTS * RETRY_DELAY / 60,
                            "DNS propagation timed out; proceeding anyway."
                        );
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!(
                        event = "dns.propagation.error",
                        error = %e,
                        "DNS propagation check failed."
                    );
                    sleep(Duration::from_secs(RETRY_DELAY)).await;
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
        let resolver = TokioResolver::builder_tokio()?.build();
        let fqdn = format!("{}.{}", name, domain);

        match resolver.txt_lookup(&fqdn).await {
            Ok(txt_records) => {
                for record in txt_records.iter() {
                    let record_value = record.to_string().trim_matches('"').to_string();
                    if record_value == expected_value {
                        info!(
                            event = "dns.txt.match",
                            fqdn = %fqdn,
                            "TXT record match found."
                        );
                        return Ok(true);
                    }
                }
                info!(
                    event = "dns.txt.miss",
                    fqdn = %fqdn,
                    "TXT record match not found."
                );
                Ok(false)
            }
            Err(e) => {
                info!(
                    event = "dns.txt.lookup_error",
                    fqdn = %fqdn,
                    error = %e,
                    "TXT record lookup failed."
                );
                Ok(false)
            }
        }
    }
}

pub trait DnsProviderFactory {
    fn create_with_config(
        toml_config: Option<&serde_json::Value>
    ) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>>;
}

pub fn create_dns_provider(
    provider_name: &str,
    toml_config: Option<&serde_json::Value>
) -> Result<Box<dyn DnsProvider>, Box<dyn std::error::Error + Send + Sync>> {
    match provider_name {
        "digitalocean" => providers::DigitalOceanProvider::create_with_config(toml_config),
        "azure" => providers::AzureProvider::create_with_config(toml_config),
        "hetzner" => providers::HetznerProvider::create_with_config(toml_config),
        "cloudflare" => providers::CloudflareProvider::create_with_config(toml_config),
        _ => Err(format!(
            "Unsupported DNS provider: '{}'. Supported: digitalocean, azure, hetzner, cloudflare",
            provider_name
        ).into()),
    }
}

pub trait ConfigHelper {
    fn get_string_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<String> {
        if let Ok(env_value) = std::env::var(env_key) {
            return Some(env_value);
        }
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_str())
            .map(|s| s.to_string())
    }

    fn get_u64_with_env(
        toml_config: Option<&serde_json::Value>,
        toml_key: &str,
        env_key: &str,
    ) -> Option<u64> {
        if let Ok(env_value) = std::env::var(env_key) {
            if let Ok(parsed) = env_value.parse::<u64>() {
                return Some(parsed);
            }
        }
        toml_config
            .and_then(|config| config.get(toml_key))
            .and_then(|value| value.as_u64())
    }
}
