FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --release --bin tinyserver

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin tinyserver
COPY --from=build /src/target/release/tinyserver /usr/local/bin/tinyserver
COPY deploy/entrypoint.sh /usr/local/bin/tinyserver-entry
RUN chmod 755 /usr/local/bin/tinyserver-entry /usr/local/bin/tinyserver
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/tinyserver-entry"]
