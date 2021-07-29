FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/baseline-proxy

RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.8.4/solc-static-linux > /solc

WORKDIR /go/src/github.com/provideplatform/baseline-proxy
RUN make build

FROM alpine

RUN apk add --no-cache bash curl gcompat libc6-compat

RUN mkdir -p /baseline-proxy
WORKDIR /baseline-proxy

COPY --from=builder /go/src/github.com/provideplatform/baseline-proxy/.bin /baseline-proxy/.bin
COPY --from=builder /go/src/github.com/provideplatform/baseline-proxy/ops /baseline-proxy/ops

COPY --from=builder /solc /usr/bin/solc
RUN chmod +x /usr/bin/solc

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
