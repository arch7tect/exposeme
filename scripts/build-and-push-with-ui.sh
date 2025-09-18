#!/bin/bash

# scripts/build-and-push-with-ui.sh - Build and publish Docker images with UI enabled

set -e

export BUILD_UI=true

echo "🎨 Building ExposeME Docker images with Web UI Dashboard enabled"
echo ""

# Call the main build script with UI enabled, passing all parameters
./scripts/build-and-push.sh "$@"