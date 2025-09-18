# Optimized Dockerfile with better layer caching
FROM rust:1.88-bookworm AS builder

# Install system dependencies (cached layer)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust tools once (cached layer)
RUN rustup target add wasm32-unknown-unknown

# Install Trunk conditionally (cached layer if UI build)
ARG BUILD_UI=false
RUN if [ "$BUILD_UI" = "true" ]; then \
        cargo install trunk --locked; \
    fi

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
RUN if [ "$BUILD_UI" = "true" ]; then \
        cargo build --release --target wasm32-unknown-unknown -p exposeme-ui; \
    fi

# Remove dummy source files
RUN rm -rf src ui/src

# Copy actual source code (this layer changes with code changes)
COPY build.rs ./
COPY src/ ./src/
COPY ui/ ./ui/

# Build UI first if needed (cached if UI code unchanged)
RUN if [ "$BUILD_UI" = "true" ]; then \
        if [ ! -d "ui/dist" ]; then \
            echo "No pre-built UI assets found, building with trunk..."; \
            cd ui && trunk build --release && cd ..; \
        else \
            echo "Using pre-built UI assets from host..."; \
            echo "Files in ui/dist:"; \
            ls -la ui/dist/; \
            echo "Preserving pre-built assets, skipping trunk build"; \
        fi \
    fi

# Build the final application (dependencies already built above)
RUN if [ "$BUILD_UI" = "true" ]; then \
        cargo build --release --features ui --bin exposeme-server --bin exposeme-client; \
    else \
        cargo build --release --bin exposeme-server --bin exposeme-client; \
    fi

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