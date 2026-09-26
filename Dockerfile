FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN useradd --system --no-create-home cdr
COPY --from=build /src/target/release/cdr /usr/local/bin/cdr
USER cdr
ENTRYPOINT ["cdr"]
CMD ["--help"]
