# Stage 1: Build the Rust backend
FROM rust:trixie AS builder
WORKDIR /usr/src/app
COPY . .
RUN make box


FROM debian:trixie-slim AS prod
WORKDIR /app

COPY --from=builder /usr/src/app/target/release/telemt /app/telemt
COPY config.toml /app/config.toml

USER root:root

EXPOSE 443 9090 9091

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/telemt", "healthcheck", "/app/config.toml", "--mode", "liveness"]

ENTRYPOINT ["/app/telemt"]
CMD ["config.toml"]
