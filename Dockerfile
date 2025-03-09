FROM rust:1.73-slim-bullseye as builder

WORKDIR /usr/src/minisafe
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/minisafe
COPY --from=builder /usr/src/minisafe/target/release/microvm /usr/local/bin/microvm

# Create directory structure
RUN mkdir -p /var/lib/microvm /etc/microvm

# Create basic config 
COPY config/default.toml /etc/microvm/default.toml

# Set up a non-root user
RUN groupadd -r microvm && useradd -r -g microvm microvm \
    && chown -R microvm:microvm /var/lib/microvm

USER microvm
ENTRYPOINT ["microvm"]
CMD ["--help"] 