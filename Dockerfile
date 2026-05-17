FROM rust:slim-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY src ./src
COPY kb ./kb

RUN cargo build --release -p spuc-cli --bin spuc --bin spuc-agent

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    tini \
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
COPY kb /app/kb

ENV SPUC_CONFIG_DIR=/data
ENV SPUC_WEB_PORT=8090

RUN addgroup --system spuc \
  && adduser --system --ingroup spuc --home /home/spuc --shell /usr/sbin/nologin spuc \
  && mkdir -p /data \
  && chown -R spuc:spuc /app /data

VOLUME ["/data"]
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${SPUC_WEB_PORT}/healthz" || exit 1

USER spuc

ENTRYPOINT ["/usr/bin/tini", "--", "spuc"]
CMD ["web", "--host", "0.0.0.0", "--port", "8090", "--no-open"]
