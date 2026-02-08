FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/webhook ./cmd/webhook

FROM alpine:3.20

COPY --from=builder /out/webhook /usr/local/bin/webhook

ENTRYPOINT ["/usr/local/bin/webhook"]
