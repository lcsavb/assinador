# ---- build: binário estático (musl) ----
FROM rust:alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /app
COPY . .
RUN cargo build --release -p assinador-server

# ---- runtime: imagem mínima com CA certs, roda como nonroot ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app/target/release/assinador-server /usr/local/bin/assinador-server
EXPOSE 8080
ENV ASSINADOR_BIND=0.0.0.0:8080
ENTRYPOINT ["/usr/local/bin/assinador-server"]
