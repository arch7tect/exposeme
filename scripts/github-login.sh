#!/bin/bash

# scripts/github-login.sh - GitHub Container Registry authentication helper

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔐 GitHub Container Registry Login Helper${NC}"
echo "════════════════════════════════════════════"
echo ""

# Check if GitHub CLI is installed
if ! command -v gh >/dev/null 2>&1; then
    echo -e "${RED}❌ GitHub CLI not found${NC}"
    echo ""
    echo "Please install GitHub CLI first:"
    echo "  macOS: brew install gh"
    echo "  Linux: https://github.com/cli/cli/blob/trunk/docs/install_linux.md"
    echo "  Windows: https://github.com/cli/cli/releases"
    exit 1
fi

echo -e "${BLUE}📋 Checking GitHub CLI authentication...${NC}"

# Check current auth status
if ! gh auth status >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Not authenticated with GitHub CLI${NC}"
    echo ""
    echo -e "${BLUE}🔧 Setting up GitHub CLI authentication...${NC}"
    gh auth login --hostname github.com --scopes write:packages
else
    # Check if we have the right scopes
    SCOPES=$(gh auth status 2>&1 | grep "Token scopes:" | cut -d':' -f2 | tr -d ' ')

    if [[ "$SCOPES" == *"write:packages"* ]]; then
        echo -e "${GREEN}✅ GitHub CLI already authenticated with packages scope${NC}"
    else
        echo -e "${YELLOW}⚠️  GitHub CLI authenticated but missing 'write:packages' scope${NC}"
        echo "Current scopes: $SCOPES"
        echo ""
        echo -e "${BLUE}🔧 Refreshing authentication with packages scope...${NC}"
        gh auth refresh --hostname github.com --scopes write:packages
    fi
fi

echo ""
echo -e "${BLUE}🐳 Logging into GitHub Container Registry...${NC}"

# Login to Docker registry
if gh auth token | docker login ghcr.io -u $(gh api user --jq '.login') --password-stdin; then
    echo -e "${GREEN}✅ Successfully logged into GitHub Container Registry${NC}"
    echo ""
    echo -e "${BLUE}📦 You can now push to:${NC}"
    echo "   ghcr.io/$(gh api user --jq '.login')/your-image:tag"
    echo ""
    echo -e "${BLUE}🚀 Ready to build and push:${NC}"
    echo "   ./scripts/build-and-push-with-ui.sh 1.4.35"
else
    echo -e "${RED}❌ Failed to login to GitHub Container Registry${NC}"
    echo ""
    echo "Please try again or login manually:"
    echo "   gh auth token | docker login ghcr.io -u \$(gh api user --jq '.login') --password-stdin"
    exit 1
fi