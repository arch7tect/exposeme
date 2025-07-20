// src/dns/providers/mod.rs

mod digitalocean;
mod azure;
mod hetzner;
mod cloudflare;
// Future providers (uncomment when implemented):
// pub mod route53;
// pub mod namecheap;

// Re-export specific types instead of wildcard
pub use digitalocean::DigitalOceanProvider;
pub use azure::AzureProvider;
pub use hetzner::HetznerProvider;
pub use cloudflare::CloudflareProvider;

// Uncomment when implementing additional providers:
// pub use route53::Route53Provider;