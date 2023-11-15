FROM golang:1.17 AS builder

RUN mkdir -p /go/src/github.com/provideplatform
ADD . /go/src/github.com/provideplatform/axiom

RUN curl -L https://github.com/ethereum/solidity/releases/download/v0.8.4/solc-static-linux > /solc

WORKDIR /go/src/github.com/provideplatform/axiom
RUN make build

FROM alpine

RUN apk add --no-cache bash curl gcompat libc6-compat musl

RUN mkdir -p /axiom
WORKDIR /axiom

COPY --from=builder /go/src/github.com/provideplatform/axiom/.bin /axiom/.bin
COPY --from=builder /go/src/github.com/provideplatform/axiom/ops /axiom/ops

COPY --from=builder /solc /usr/bin/solc
RUN chmod +x /usr/bin/solc

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
