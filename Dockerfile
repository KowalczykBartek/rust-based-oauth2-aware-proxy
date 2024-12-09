FROM rust:1.82 as builder

RUN apt-get update && apt-get install cmake -y

COPY . .
RUN cargo build --release
CMD ["./target/release/auth-enrichment-proxy"]