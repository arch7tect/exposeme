#!/bin/bash

# scripts/deploy-server.sh - Deploy ExposeME server via Docker

set -e

DOMAIN=${1}
EMAIL=${2}
STAGING=${3:-"true"}

if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
    echo "❌ Usage: $0 <domain> <email> [staging=true|false]"
    echo "   Example: $0 exposeme.example.com admin@example.com false"
    exit 1
fi

echo "🚀 Deploying ExposeME server"
echo "🌐 Domain: $DOMAIN"
echo "📧 Email: $EMAIL"
echo "🧪 Staging: $STAGING"

# 1. Create directories
echo "📁 Creating directories..."
mkdir -p config data/certs data/logs

# 2. Create .env file
echo "⚙️ Creating .env file..."
cat > .env << EOF
EXPOSEME_DOMAIN=$DOMAIN
EXPOSEME_EMAIL=$EMAIL
EXPOSEME_STAGING=$STAGING
RUST_LOG=info
DOCKER_HUB_USER=arch7tect
EXPOSEME_SERVER_VERSION=latest
EXPOSEME_CLIENT_VERSION=latest
EOF

# 3. Create server.toml if not exists
if [ ! -f "config/server.toml" ]; then
    echo "📝 Creating server configuration..."
    cat > config/server.toml << EOF
[server]
http_bind = "0.0.0.0"
http_port = 80
https_port = 443
ws_bind = "0.0.0.0"
ws_port = 8081
domain = "$DOMAIN"

[ssl]
enabled = true
provider = "letsencrypt"
email = "$EMAIL"
staging = $STAGING
cert_cache_dir = "/etc/exposeme/certs"

[auth]
tokens = [
    "$(openssl rand -hex 16)",
    "telegram-$(openssl rand -hex 12)",
    "github-$(openssl rand -hex 12)",
    "stripe-$(openssl rand -hex 12)"
]

[limits]
max_tunnels = 100
request_timeout_secs = 30
EOF
fi

# 4. Check docker-compose.yml
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ docker-compose.yml file not found!"
    echo "   Make sure you're running the script from project root."
    exit 1
fi

# 5. Stop existing containers
echo "⏹️ Stopping existing containers..."
docker-compose down || true

# 6. Pull latest images
echo "📥 Pulling latest images..."
docker-compose pull

# 7. Start server
echo "🚀 Starting server..."
docker-compose up -d

# 8. Check status
echo "📊 Checking status..."
sleep 5
docker-compose ps
docker-compose logs --tail=20

# 9. Information
echo ""
echo "✅ Server started!"
echo ""
echo "🔍 Useful commands:"
echo "   Logs:           docker-compose logs -f"
echo "   Status:         docker-compose ps"
echo "   Stop:           docker-compose down"
echo "   Restart:        docker-compose restart"
echo ""
echo "🌐 Server URL:     https://$DOMAIN"
echo "🔌 WebSocket:      wss://$DOMAIN:8081"
echo ""
echo "📋 Client tokens (from config/server.toml):"
grep -A 10 "\[auth\]" config/server.toml | grep -E '^\s*"' | sed 's/^/   /'
echo ""
echo "⚠️ Make sure DNS A-record $DOMAIN points to this server!"
echo "   Current IP: $(curl -s ifconfig.me)"