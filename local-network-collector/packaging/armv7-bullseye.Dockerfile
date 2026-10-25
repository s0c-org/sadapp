FROM rust:1.88-bullseye AS builder

RUN apt-get update \
  && apt-get install --no-install-recommends --yes gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf libc6-dev-armhf-cross \
  && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.99.0 --profile minimal \
  && rustup default 1.99.0 \
  && rustup target add armv7-unknown-linux-gnueabihf

ENV CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
    AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar

WORKDIR /build/host-agent
ARG HOST_AGENT_PACKAGE_VERSION
ARG RELEASE_COMPONENTS="host-agent local-network-collector"
COPY host-agent/Cargo.toml host-agent/Cargo.lock ./
COPY host-agent/.cargo/ .cargo/
COPY host-agent/src/ src/
RUN mkdir -p /artifacts && if echo " ${RELEASE_COMPONENTS} " | grep -q ' host-agent '; then \
  SADAPP_AGENT_VERSION="${HOST_AGENT_PACKAGE_VERSION}" cargo build --locked --release --target armv7-unknown-linux-gnueabihf \
  && cp target/armv7-unknown-linux-gnueabihf/release/sadapp-host-agent /artifacts/; fi

WORKDIR /build/local-network-collector
COPY local-network-collector/Cargo.toml local-network-collector/Cargo.lock ./
COPY local-network-collector/.cargo/ .cargo/
COPY local-network-collector/src/ src/
COPY snmp-profile-engine/ /build/snmp-profile-engine/
RUN if echo " ${RELEASE_COMPONENTS} " | grep -q ' local-network-collector '; then \
  cargo build --locked --release --target armv7-unknown-linux-gnueabihf \
  && cp target/armv7-unknown-linux-gnueabihf/release/sadapp-local-network-collector /artifacts/; fi

RUN for binary in /artifacts/*; do \
  if readelf --version-info "$binary" | grep -Eq 'Name: GLIBC_2\.(3[2-9]|[4-9][0-9])'; then \
    echo "${binary} requires a newer glibc than Debian Bullseye provides" >&2; exit 1; \
  fi; \
done

FROM scratch AS artifacts
USER 65532:65532
COPY --from=builder /artifacts/ /