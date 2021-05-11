FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/baseline-proxy

RUN mkdir ~/.ssh && cp /go/src/github.com/provideapp/baseline-proxy/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideapp/ident.git /go/src/github.com/provideapp/ident && cd /go/src/github.com/provideapp/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideapp/baseline-proxy/ops/keys

WORKDIR /go/src/github.com/provideapp/baseline-proxy
RUN make build

FROM alpine

RUN apk add --no-cache bash

RUN mkdir -p /baseline-proxy
WORKDIR /baseline-proxy

COPY --from=builder /go/src/github.com/provideapp/baseline-proxy/.bin /baseline-proxy/.bin
COPY --from=builder /go/src/github.com/provideapp/baseline-proxy/ops /baseline-proxy/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
