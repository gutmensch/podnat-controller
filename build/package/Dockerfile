FROM golang:alpine AS builder

RUN apk -U add --no-cache git gcc musl-dev

WORKDIR /build

COPY cmd/ cmd/
COPY internal/ internal/
COPY go.mod go.mod
COPY go.sum go.sum

RUN go test -v ./...

RUN go build -ldflags="-w -s" -o podnat-controller ./cmd/podnat-controller

# runner image
FROM alpine:3.19

RUN apk -U add --no-cache ca-certificates iptables

COPY --from=builder /build/podnat-controller /podnat-controller

ENTRYPOINT ["/podnat-controller"]
