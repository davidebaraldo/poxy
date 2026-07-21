# --- build ---
FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# server (linux) + client windows/amd64 servito dall'endpoint /download
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/poxy-server ./cmd/poxy-server \
 && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/poxy-client.exe ./cmd/poxy-client

# --- runtime ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 poxy \
 && mkdir -p /data && chown poxy:poxy /data
COPY --from=build /out/poxy-server /usr/local/bin/poxy-server
COPY --from=build /out/poxy-client.exe /usr/local/bin/poxy-client.exe
USER poxy
WORKDIR /data
VOLUME /data
EXPOSE 8080 9000
ENTRYPOINT ["poxy-server"]
# Il pannello web è in HTTP: tienilo dietro un reverse proxy TLS. Imposta -public
# all'host:porta raggiungibile del tunnel (finisce nei bundle client).
CMD ["-data", "/data", "-web", "0.0.0.0:8080", "-web-insecure", "-tunnel", "0.0.0.0:9000"]
