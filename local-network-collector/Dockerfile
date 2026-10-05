FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
	&& apt-get install --no-install-recommends --yes ca-certificates curl iputils-ping snmp \
	&& rm -rf /var/lib/apt/lists/*
RUN useradd --system --home-dir /var/lib/sadapp-local-network-collector --create-home sadapp-local-network-collector
COPY --from=builder /build/target/release/sadapp-local-network-collector /usr/local/bin/sadapp-local-network-collector
USER sadapp-local-network-collector
ENV STATE_DIR=/var/lib/sadapp-local-network-collector
ENTRYPOINT ["/usr/local/bin/sadapp-local-network-collector"]