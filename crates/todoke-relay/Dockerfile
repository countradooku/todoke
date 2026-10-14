# syntax=docker/dockerfile:1
# A todoke relay node (PROTOCOL §10). Build from the repository root:
#
#   docker build -f crates/todoke-relay/Dockerfile -t todoke-relay .
#
# Base images are pinned by digest; update a digest with its tag.

# rust:1.99-bookworm, the toolchain rust-toolchain.toml pins.
FROM rust:1.99-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p todoke-relay \
    && mkdir -p /out/state \
    && cp target/release/todoke-relay /out/

# No shell, no package manager, not root (uid 65532).
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /out/todoke-relay /usr/local/bin/todoke-relay
COPY --from=build --chown=65532:65532 /out/state /var/lib/todoke-relay
USER 65532:65532
VOLUME /var/lib/todoke-relay
EXPOSE 4433/udp
ENTRYPOINT ["/usr/local/bin/todoke-relay", "--listen", "[::]:4433", "--state", "/var/lib/todoke-relay"]
