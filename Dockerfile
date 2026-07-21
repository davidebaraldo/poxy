# --- build ---
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# server (linux) + tutti i client (win/mac/linux, amd64/arm64) serviti da /download
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/poxy-server ./cmd/poxy-server
RUN set -e; for t in windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
      os="${t%/*}"; arch="${t#*/}"; ext=""; [ "$os" = "windows" ] && ext=".exe"; \
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -o "/out/poxy-client-$os-$arch$ext" ./cmd/poxy-client; \
    done

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 poxy \
 && mkdir -p /data && chown poxy:poxy /data
COPY --from=build /out/ /usr/local/bin/
USER poxy
WORKDIR /data
VOLUME /data
EXPOSE 8080 9000
ENTRYPOINT ["poxy-server"]
# Il pannello web è in HTTP: tienilo dietro un reverse proxy TLS. Imposta -public
# all'host:porta raggiungibile del tunnel (finisce nei bundle client).
CMD ["-data", "/data", "-web", "0.0.0.0:8080", "-web-insecure", "-tunnel", "0.0.0.0:9000"]
