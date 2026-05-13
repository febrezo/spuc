FROM rust:slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY src ./src
COPY kb ./kb
COPY payloads ./payloads

RUN cargo build --release -p spuc-cli --bin spuc --bin spuc-agent

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
  && rm -rf /var/lib/apt/lists/*

# pySigma stack: sigma-cli + defensive backends used by SPUC converter targets.
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    sigma-cli \
    pysigma-backend-crowdstrike \
    pysigma-backend-elasticsearch \
    pysigma-backend-secops \
    pysigma-backend-splunk

COPY --from=builder /build/target/release/spuc /usr/local/bin/spuc
COPY --from=builder /build/target/release/spuc-agent /usr/local/bin/spuc-agent
COPY payloads /app/payloads
COPY kb /app/kb

ENV SPUC_CONFIG_DIR=/data

VOLUME ["/data"]
EXPOSE 8090

ENTRYPOINT ["spuc"]
