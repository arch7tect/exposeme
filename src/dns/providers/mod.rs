// src/dns/providers/mod.rs

pub mod digitalocean;

// Future providers (uncomment when implemented):
// pub mod cloudflare;
// pub mod route53;
// pub mod namecheap;

// Re-export specific types instead of wildcard
pub use digitalocean::DigitalOceanProvider;

// Uncomment when implementing additional providers:
// pub use cloudflare::CloudflareProvider;
// pub use route53::Route53Provider;