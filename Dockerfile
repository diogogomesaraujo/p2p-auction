FROM rust:latest

WORKDIR /app

COPY src ./src
COPY Cargo.toml .
COPY Cargo.lock .

ARG MODE

RUN cargo build --release
ENTRYPOINT cargo run --bin $MODE --release
