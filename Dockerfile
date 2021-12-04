FROM rust:slim-buster AS build

RUN apt-get update && \
    apt-get install -y libssl-dev pkg-config

WORKDIR /usr/src/

# Create a fake project and build (and cache)
# the dependencies
RUN USER=root cargo new --bin cache-project
WORKDIR /usr/src/cache-project

COPY Cargo.toml Cargo.lock ./
RUN cargo build --release && rm src/*.rs

COPY migrations migrations
COPY src ./src

RUN rm target/release/papers* && \
    rm target/release/deps/papers* && \
    cargo build --release


# "Production" image
FROM debian:bookworm-slim AS base

WORKDIR /usr/src/app

COPY --from=build /usr/src/cache-project/target/release/papers /usr/local/bin/papers
RUN chmod +x /usr/local/bin/papers

CMD [ "papers" ]
