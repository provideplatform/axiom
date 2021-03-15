FROM golang:1.15 AS builder

RUN mkdir -p /go/src/github.com/provideapp
ADD . /go/src/github.com/provideapp/providibright

RUN mkdir ~/.ssh && cp /go/src/github.com/provideapp/providibright/ops/keys/ident-id_rsa ~/.ssh/id_rsa && chmod 0600 ~/.ssh/id_rsa && ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts
RUN git clone git@github.com:provideapp/ident.git /go/src/github.com/provideapp/ident && cd /go/src/github.com/provideapp/ident
RUN rm -rf ~/.ssh && rm -rf /go/src/github.com/provideapp/providibright/ops/keys

WORKDIR /go/src/github.com/provideapp/providibright
RUN make build

FROM golang:1.15

RUN mkdir -p /providibright
WORKDIR /providibright

COPY --from=builder /go/src/github.com/provideapp/providibright/.bin /providibright/.bin
COPY --from=builder /go/src/github.com/provideapp/providibright/ops /providibright/ops

EXPOSE 8080
ENTRYPOINT ["./ops/run_api.sh"]
