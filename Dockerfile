# The dependencies build in a layer of their own, from a cargo-chef recipe that lists only what
# Cargo.toml and Cargo.lock name. A change to the server's own code then rebuilds the workspace
# crates and not the three hundred crates under them. CI keeps those layers in a registry cache.
FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /src

FROM chef AS planner
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY rust-toolchain.toml ./
COPY --from=planner /src/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json --bin tinyserver
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
