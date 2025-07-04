// src/dns/providers/mod.rs

pub mod digitalocean;
mod azure;
// Future providers (uncomment when implemented):
// pub mod cloudflare;
// pub mod route53;
// pub mod namecheap;

// Re-export specific types instead of wildcard
pub use digitalocean::DigitalOceanProvider;
pub use azure::AzureProvider;

// Uncomment when implementing additional providers:
// pub use cloudflare::CloudflareProvider;
// pub use route53::Route53Provider;