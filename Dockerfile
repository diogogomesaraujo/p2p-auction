FROM rust:latest

RUN apt-get update && apt-get install --no-install-recommends --assume-yes protobuf-compiler

WORKDIR /app

COPY src ./src
COPY proto ./proto
COPY build.rs .
COPY Cargo.toml .
COPY Cargo.lock .
COPY config ./config

ARG MODE
ARG ARGS

RUN cargo build --release
ENTRYPOINT cargo run --bin $MODE --release -- $ARGS
