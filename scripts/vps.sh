sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common git
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
sudo apt install docker-ce
git clone https://github.com/arch7tect/exposeme.git
cd exposeme
mkdir -p certs && chmod 777 certs
cp config/server.toml.template config/server.toml
cat > .env <<EOF
EXPOSEME_DOMAIN=exposeme.arch7tect.org
EXPOSEME_EMAIL=arch7tect@gmail.com
EXPOSEME_DNS_PROVIDER=cloudflare
EXPOSEME_CLOUDFLARE_TOKEN=secret-dns-provider-token
EXPOSEME_AUTH_TOKEN=secret-exposeme-token
RUST_LOG=info
EOF