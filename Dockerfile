# Base builder stage with Trunk cached
FROM rust:1.88-bookworm AS trunk-builder

# Install system dependencies (cached layer)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust tools conditionally based on UI build requirements
ARG UI_DIST_EXISTS=false

# Only install WASM + Trunk if we don't have pre-built UI assets
RUN if [ "$UI_DIST_EXISTS" = "false" ]; then \
        echo "Installing WASM toolchain and Trunk for UI building..."; \
        rustup target add wasm32-unknown-unknown; \
        cargo install trunk --locked; \
    else \
        echo "Skipping WASM/Trunk installation - using pre-built UI assets"; \
    fi

# Main builder stage
FROM trunk-builder AS builder

WORKDIR /app

# Copy dependency files first (for better caching)
COPY Cargo.toml Cargo.lock ./
COPY ui/Cargo.toml ./ui/

# Create dummy source structure to build dependencies (cached layer)
RUN mkdir -p src/bin && echo "fn main() {}" > src/bin/server.rs
RUN mkdir -p src/bin && echo "fn main() {}" > src/bin/client.rs
RUN echo "fn main() {}" > src/main.rs
RUN mkdir -p ui/src && echo "fn main() {}" > ui/src/main.rs && echo "" > ui/src/lib.rs

# Build dependencies only (this layer will be cached until Cargo.toml changes)
RUN cargo build --release --bin exposeme-server --bin exposeme-client

# Only build WASM dependencies if we don't have pre-built UI assets
RUN if [ "$UI_DIST_EXISTS" = "false" ]; then \
        echo "Pre-building WASM dependencies..."; \
        cargo build --release --target wasm32-unknown-unknown -p exposeme-ui; \
    else \
        echo "Skipping WASM dependency build - using pre-built UI"; \
    fi

# Remove dummy source files
RUN rm -rf src ui/src

# Copy actual source code (this layer changes with code changes)
COPY build.rs ./
COPY src/ ./src/
COPY ui/ ./ui/

# Build UI first if needed
RUN if [ "$UI_DIST_EXISTS" = "false" ]; then \
        echo "Building UI with Trunk..."; \
        cd ui && trunk build --release && cd ..; \
    else \
        echo "Using pre-built UI assets"; \
        echo "Files in ui/dist:"; \
        ls -la ui/dist/ || echo "UI dist directory structure:"; \
    fi

# Build the final application (UI is always included now)
RUN cargo build --release --bin exposeme-server --bin exposeme-client

# Runtime stage
FROM debian:bookworm-slim AS server

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create user for security
RUN useradd -r -s /bin/false -m exposeme

# Copy server binary
COPY --from=builder /app/target/release/exposeme-server /usr/local/bin/

# Create directories
RUN mkdir -p /etc/exposeme /var/log/exposeme && \
    chown -R exposeme:exposeme /etc/exposeme /var/log/exposeme

# Expose ports
EXPOSE 80 443 8081

# Switch to exposeme user
USER exposeme

# Start server
ENTRYPOINT ["exposeme-server"]
CMD ["--config", "/etc/exposeme/server.toml"]

# Client stage
FROM debian:bookworm-slim AS client

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -r -s /bin/false -m exposeme

# Copy client binary
COPY --from=builder /app/target/release/exposeme-client /usr/local/bin/

# Create configuration directory
RUN mkdir -p /etc/exposeme && \
    chown -R exposeme:exposeme /etc/exposeme

# Switch to exposeme user
USER exposeme

# Start client
ENTRYPOINT ["exposeme-client"]
CMD ["--config", "/etc/exposeme/client.toml"]