# MetaSight Gateway — dev-oriented image (used by ../../docker-compose.yml).
#
# This is NOT the hardened production deploy path — for bare-metal/VM
# production (systemd unit, real TLS certs, hardening checklist), see
# ../../DEPLOYMENT.md. This image favors a fast, correct local
# `docker compose up` over minimal image size or production process
# management, and generates a self-signed dev TLS cert on first start if
# none is mounted in (TLS is mandatory — see docker-entrypoint.sh).

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/metasight-gateway ./cmd/gateway

FROM alpine:3.20
RUN apk add --no-cache openssl
WORKDIR /app
COPY --from=build /out/metasight-gateway .
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

EXPOSE 6543

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["./metasight-gateway"]
