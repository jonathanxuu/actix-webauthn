# Tells docker to use the latest Rust official image
FROM rust:alpine3.17 as builder
ARG PROFILE=release
WORKDIR /app

# Copy the project files from your machine to the container
COPY ./ ./
# Build your application for release, inside the container

RUN apk add --no-cache -U musl-dev
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

# RUN set -eux && cargo build --${PROFILE} 

# FROM docker.io/library/debian:stable-slim
FROM alpine:3.17

LABEL maintainer="zCloak Network"
LABEL description="zCloak Network provides Zero-Knowledge Proof as a Service for public blockchains."

ARG PROFILE=release
# WORKDIR /usr/local/bin
WORKDIR /app
COPY ./run.sh ./
COPY --from=builder /app/target/$PROFILE/actix ./

RUN apk add --no-cache -U libgcc
RUN apk --no-cache add socat
USER root

# Expose the port for accessing the HTTP server within the container
EXPOSE 3000/tcp
# Run the binary built inside the container
# CMD ["actix"]
RUN chmod +x /app/run.sh
CMD ["/app/run.sh"]

