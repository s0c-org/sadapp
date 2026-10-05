FROM rust:1.88-bullseye AS builder

RUN apt-get update \
  && apt-get install --no-install-recommends --yes gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf libc6-dev-armhf-cross \
  && rm -rf /var/lib/apt/lists/*

RUN rustup target add armv7-unknown-linux-gnueabihf

ENV CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
    AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar

WORKDIR /build/host-agent
ARG HOST_AGENT_PACKAGE_VERSION
COPY host-agent/Cargo.toml host-agent/Cargo.lock ./
COPY host-agent/.cargo/ .cargo/
COPY host-agent/src/ src/
RUN SADAPP_AGENT_VERSION="${HOST_AGENT_PACKAGE_VERSION}" cargo build --locked --release --target armv7-unknown-linux-gnueabihf

WORKDIR /build/local-network-collector
COPY local-network-collector/Cargo.toml local-network-collector/Cargo.lock ./
COPY local-network-collector/.cargo/ .cargo/
COPY local-network-collector/src/ src/
COPY snmp-profile-engine/ /build/snmp-profile-engine/
RUN cargo build --locked --release --target armv7-unknown-linux-gnueabihf

RUN for binary in \
  /build/host-agent/target/armv7-unknown-linux-gnueabihf/release/sadapp-host-agent \
  /build/local-network-collector/target/armv7-unknown-linux-gnueabihf/release/sadapp-local-network-collector; do \
  if readelf --version-info "$binary" | grep -Eq 'Name: GLIBC_2\.(3[2-9]|[4-9][0-9])'; then \
    echo "${binary} requires a newer glibc than Debian Bullseye provides" >&2; exit 1; \
  fi; \
done

FROM scratch AS artifacts
COPY --from=builder /build/host-agent/target/armv7-unknown-linux-gnueabihf/release/sadapp-host-agent /sadapp-host-agent
COPY --from=builder /build/local-network-collector/target/armv7-unknown-linux-gnueabihf/release/sadapp-local-network-collector /sadapp-local-network-collector