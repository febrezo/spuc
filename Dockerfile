FROM rust:slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
  && rm -rf /var/lib/apt/lists/*

# pySigma stack: sigma-cli + defensive backends used by SPUC converter targets.
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    sigma-cli \
    pysigma-backend-splunk \
    pysigma-backend-elasticsearch \
    pysigma-backend-crowdstrike \
    pysigma-backend-secops

COPY --from=builder /build/target/release/spuc /app/spuc

EXPOSE 8080

ENTRYPOINT ["/app/spuc"]
