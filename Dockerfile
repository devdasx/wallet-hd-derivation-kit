FROM rust:1.92-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY rust ./rust
COPY test-vectors ./test-vectors
RUN cargo build --locked --release --bin wallethd

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151
LABEL org.opencontainers.image.source="https://github.com/devdasx/wallet-hd-derivation-kit" \
      org.opencontainers.image.version="1.0.1" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/target/release/wallethd /usr/local/bin/wallethd
ENTRYPOINT ["/usr/local/bin/wallethd"]
CMD ["list-chains"]
