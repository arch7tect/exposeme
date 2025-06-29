# Dockerfile
FROM rust:1.88-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy project files
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY examples/ ./examples/

# Build project in release mode
RUN cargo build --release

# Final server image
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
CMD ["exposeme-server", "--config", "/etc/exposeme/server.toml"]

# Final client image
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
CMD ["exposeme-client", "--config", "/etc/exposeme/client.toml"]