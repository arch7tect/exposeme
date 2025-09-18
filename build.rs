use std::process::Command;
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=ui/src");
    println!("cargo:rerun-if-changed=ui/Cargo.toml");
    println!("cargo:rerun-if-changed=ui/index.html");
    println!("cargo:rerun-if-changed=ui/assets");
    println!("cargo:rerun-if-changed=ui/dist");

    // Check if UI feature is enabled
    let ui_feature_enabled = env::var("CARGO_FEATURE_UI").is_ok();
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    if ui_feature_enabled && profile == "release" {
        // Check if Trunk has built the UI (dist directory exists)
        if !std::path::Path::new("ui/dist/index.html").exists() {
            println!("cargo:warning=Building UI with Trunk...");

            let trunk_output = Command::new("trunk")
                .args(["build", "--release"])
                .current_dir("ui")
                .output();

            match trunk_output {
                Ok(output) if output.status.success() => {
                    println!("cargo:warning=UI build completed successfully with Trunk");
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("cargo:warning=Trunk build failed: {}", stderr);
                    println!("cargo:warning=Please install trunk: cargo install trunk");
                }
                Err(_) => {
                    println!("cargo:warning=Trunk not found, UI will not be embedded");
                    println!("cargo:warning=Please install trunk: cargo install trunk");
                }
            }
        } else {
            println!("cargo:warning=UI dist directory found, using existing build");
        }
    } else if ui_feature_enabled {
        println!("cargo:warning=UI feature enabled but skipping UI build in debug mode");
    } else {
        println!("cargo:warning=UI feature not enabled, skipping UI build");
    }
}