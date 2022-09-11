FROM golang:alpine AS builder
RUN apk -U add --no-cache git
WORKDIR $GOPATH/src/github.com/gutmensch/podnat-controller/
COPY . .
RUN go get -d -v
RUN GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /go/bin/podnat-controller

FROM alpine:3.16
RUN apk -U add --no-cache ca-certificates iptables
COPY --from=builder /go/bin/podnat-controller /go/bin/podnat-controller
ENTRYPOINT ["/go/bin/podnat-controller"]
