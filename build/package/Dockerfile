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
FROM alpine:3.18

# XXX: cilium 1.15.x uses iptables legacy without bpf masq, so we need to do this too
# (bpf masq only supports ip-masq-agent like setups, but not DNAT and SNAT as we need)
# go-iptables only uses standard commands, so we need to link legacy to new
# https://github.com/coreos/go-iptables/blob/main/iptables/iptables.go#L602
RUN apk -U add --no-cache ca-certificates iptables

COPY --from=builder /build/podnat-controller /podnat-controller

ENTRYPOINT ["/podnat-controller"]
