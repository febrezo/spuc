# CI-only browser smoke/CRUD image. Never uses host Selenium or local browser tools.
FROM rust:slim-bookworm@sha256:86234e857a413004348b471d11a4ebe1aa92d2eae2b6b143cac68fd1ac3c48be AS builder
WORKDIR /project
COPY Cargo.toml Cargo.lock build.rs ./
COPY crates ./crates
COPY src ./src
COPY kb ./kb
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/project/target \
    cargo build --locked -p spuc-cli --bin spuc && cp /project/target/debug/spuc /tmp/spuc-qa

FROM mcr.microsoft.com/playwright:v1.58.2@sha256:6446946a1d9fd62d9ae501312a2d76a43ee688542b21622056a372959b65d63d
WORKDIR /qa
RUN npm install --no-audit --no-fund --no-package-lock playwright-core@1.58.2
COPY --from=builder /tmp/spuc-qa /usr/local/bin/spuc
COPY tests/browser/spuc-e2e.mjs ./spuc-e2e.mjs
RUN node --check spuc-e2e.mjs
USER pwuser
ENV HOME=/tmp SPUC_CONFIG_DIR=/tmp/spuc-browser-ci
CMD ["node", "spuc-e2e.mjs"]
