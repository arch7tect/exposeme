#!/bin/bash

# scripts/build-and-push.sh - Build and publish Docker images

set -e

# Configuration
DOCKER_HUB_USER=${DOCKER_HUB_USER:-"arch7tect"}
VERSION=${1:-"1.0"}

echo "🚀 Building and publishing ExposeME Docker images"
echo "👤 Docker Hub user: $DOCKER_HUB_USER"
echo "🏷️ Version: $VERSION"

# Check Docker Hub authorization
if ! docker info | grep -q "Username:"; then
    echo "🔐 Please login to Docker Hub:"
    docker login
fi

# 1. Build images
echo "🔨 Building images..."

# Build base image with both targets
#docker build --target server --platform linux/amd64 --no-cache -t $DOCKER_HUB_USER/exposeme-server:$VERSION .
#docker build --target client --platform linux/amd64 --no-cache -t $DOCKER_HUB_USER/exposeme-client:$VERSION .
docker build --target server --platform linux/amd64 -t $DOCKER_HUB_USER/exposeme-server:$VERSION .
docker build --target client --platform linux/amd64 -t $DOCKER_HUB_USER/exposeme-client:$VERSION .

# Tag as latest
#if [ "$VERSION" != "latest" ]; then
#    docker tag $DOCKER_HUB_USER/exposeme-server:$VERSION $DOCKER_HUB_USER/exposeme-server:latest
#    docker tag $DOCKER_HUB_USER/exposeme-client:$VERSION $DOCKER_HUB_USER/exposeme-client:latest
#fi

# 2. Publish images
echo "📤 Publishing images to Docker Hub..."

docker push $DOCKER_HUB_USER/exposeme-server:$VERSION
docker push $DOCKER_HUB_USER/exposeme-client:$VERSION

#if [ "$VERSION" != "latest" ]; then
#    docker push $DOCKER_HUB_USER/exposeme-server:latest
#    docker push $DOCKER_HUB_USER/exposeme-client:latest
#fi

# 3. Check image sizes
echo "📊 Image sizes:"
docker images | grep -E "(exposeme-server|exposeme-client)" | grep -E "($VERSION|latest)"

echo "✅ Done!"
echo ""
echo "🌐 Published images:"
echo "   Server: docker pull $DOCKER_HUB_USER/exposeme-server:$VERSION"
echo "   Client: docker pull $DOCKER_HUB_USER/exposeme-client:$VERSION"
echo ""
echo "🚀 To start server:"
echo "   docker-compose up -d"
echo ""
echo "🔗 To run client:"
echo "   docker run -it --rm $DOCKER_HUB_USER/exposeme-client:$VERSION"