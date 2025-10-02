#!/bin/bash

# scripts/build-and-push.sh - Build and publish Docker images with UI

set -e

# Configuration
REGISTRY=${REGISTRY:-"ghcr.io"}
DOCKER_USER=${DOCKER_USER:-"arch7tect"}
VERSION=${1:-"1.4"}
NO_CACHE=${2:-"false"}
BUILD_UI=${BUILD_UI:-"false"}

# Check if UI dist exists locally
UI_DIST_EXISTS="false"
if [ "$BUILD_UI" = "true" ] && [ -d "ui/dist" ]; then
    UI_DIST_EXISTS="true"
fi

# Set cache flag
CACHE_FLAG=""
if [ "$NO_CACHE" = "true" ] || [ "$NO_CACHE" = "--no-cache" ]; then
    CACHE_FLAG="--no-cache"
    echo "NO-CACHE MODE: Will rebuild everything from scratch"
fi

echo "Building and publishing ExposeME Docker images"
echo "Registry: $REGISTRY/$DOCKER_USER"
echo "Version: $VERSION"
echo "UI: $( [ "$BUILD_UI" = "true" ] && echo "Enabled (use BUILD_UI=false to disable)" || echo "Disabled (default)" )"
echo "UI Dist: $( [ "$UI_DIST_EXISTS" = "true" ] && echo "Pre-built assets found" || echo "Will build from source" )"
echo "Cache: $( [ -n "$CACHE_FLAG" ] && echo "Disabled (--no-cache)" || echo "Enabled" )"

# Check registry authorization
if ! docker info | grep -q "Username:"; then
    echo "Please login to $REGISTRY:"
    docker login $REGISTRY
fi

# 1. Clean UI build if no-cache mode and UI enabled
if [ -n "$CACHE_FLAG" ] && [ "$BUILD_UI" = "true" ]; then
    echo "Cleaning UI build for fresh rebuild..."
    cd ui && rm -rf dist && trunk build --release && cd ..
fi

# 2. Build images
echo "Building images..."

# Build base image with both targets
docker build $CACHE_FLAG --build-arg BUILD_UI=$BUILD_UI --build-arg UI_DIST_EXISTS=$UI_DIST_EXISTS --target server --platform linux/amd64 -t $REGISTRY/$DOCKER_USER/exposeme-server:$VERSION .
docker build $CACHE_FLAG --build-arg BUILD_UI=$BUILD_UI --build-arg UI_DIST_EXISTS=$UI_DIST_EXISTS --target client --platform linux/amd64 -t $REGISTRY/$DOCKER_USER/exposeme-client:$VERSION .

# Tag as latest
if [ "$VERSION" != "latest" ]; then
    docker tag $REGISTRY/$DOCKER_USER/exposeme-server:$VERSION $REGISTRY/$DOCKER_USER/exposeme-server:latest
    docker tag $REGISTRY/$DOCKER_USER/exposeme-client:$VERSION $REGISTRY/$DOCKER_USER/exposeme-client:latest
fi

# 2. Publish images
echo "Publishing images to $REGISTRY..."

docker push $REGISTRY/$DOCKER_USER/exposeme-server:$VERSION
docker push $REGISTRY/$DOCKER_USER/exposeme-client:$VERSION

if [ "$VERSION" != "latest" ]; then
    docker push $REGISTRY/$DOCKER_USER/exposeme-server:latest
    docker push $REGISTRY/$DOCKER_USER/exposeme-client:latest
fi

# 3. Check image sizes
echo "Image sizes:"
docker images | grep -E "(exposeme-server|exposeme-client)" | grep -E "($VERSION|latest)"

echo "Done!"
echo ""
echo "Published images:"
echo "   Server: docker pull $REGISTRY/$DOCKER_USER/exposeme-server:$VERSION"
echo "   Client: docker pull $REGISTRY/$DOCKER_USER/exposeme-client:$VERSION"
echo ""
if [ "$BUILD_UI" = "true" ]; then
    echo "UI Features:"
    echo "   • Web dashboard included in server image"
    echo "   • Access via https://yourdomain.com/ when no tunnels match"
    echo "   • Real-time metrics and SSL certificate monitoring"
else
    echo "Note: UI not included. To build with UI, use: BUILD_UI=true $0 $VERSION"
fi
echo ""
echo "Usage Examples:"
echo "   Normal build (no UI): $0 1.5.0"
echo "   With UI: BUILD_UI=true $0 1.5.0"
echo "   No cache (UI dev): $0 1.5.0 --no-cache"
echo ""
echo "To start server:"
echo "   docker-compose up -d"
echo ""
echo "To run client:"
echo "   docker run -it --rm $REGISTRY/$DOCKER_USER/exposeme-client:$VERSION"