FROM rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
ENV CARGO_BUILD_JOBS=1
RUN cargo install trunk --version 0.17.5 --locked --jobs 1

COPY Cargo.toml Cargo.lock ./
COPY privaxy/Cargo.toml privaxy/Cargo.toml
COPY src-tauri/Cargo.toml src-tauri/Cargo.toml
COPY web_frontend/Cargo.toml web_frontend/Cargo.toml
COPY web_frontend/package.json web_frontend/package-lock.json web_frontend/
COPY privaxy privaxy
COPY src-tauri src-tauri
COPY web_frontend web_frontend

RUN cd web_frontend && npm ci && trunk build --release --no-default-features --features web-backend
RUN cargo build --locked --release -p privaxy --bin privaxy

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PRIVAXY_BIND_IP=0.0.0.0
ENV PRIVAXY_WEB_BIND=0.0.0.0:8110
ENV PRIVAXY_WEB_DIST=/usr/local/share/privaxy/web
EXPOSE 8100
EXPOSE 8110

COPY --from=builder /app/target/release/privaxy /usr/local/bin/privaxy
COPY --from=builder /app/web_frontend/dist /usr/local/share/privaxy/web

ENTRYPOINT ["privaxy"]
