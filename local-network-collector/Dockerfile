FROM rust:1.99.1-trixie AS builder
WORKDIR /build
COPY local-network-collector/Cargo.toml local-network-collector/Cargo.lock ./local-network-collector/
COPY local-network-collector/src ./local-network-collector/src
COPY snmp-profile-engine ./snmp-profile-engine
WORKDIR /build/local-network-collector
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    cargo build --locked --release

FROM debian:trixie-slim AS runtime
RUN apt-get update \
	&& apt-get upgrade --yes \
	&& apt-get install --no-install-recommends --yes ca-certificates curl iproute2 iputils-ping snmp \
	&& rm -rf /var/lib/apt/lists/*
RUN useradd --system --home-dir /var/lib/sadapp-local-network-collector --create-home sadapp-local-network-collector
COPY --from=builder /build/local-network-collector/target/release/sadapp-local-network-collector /usr/local/bin/sadapp-local-network-collector
USER sadapp-local-network-collector
ENV STATE_DIR=/var/lib/sadapp-local-network-collector
ENTRYPOINT ["/usr/local/bin/sadapp-local-network-collector"]