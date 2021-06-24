module github.com/provideplatform/baseline-proxy

go 1.15

require (
	github.com/consensys/gnark v0.3.9-0.20210209002645-110d32683f59
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/ethereum/go-ethereum v1.9.25
	github.com/gin-gonic/gin v1.6.3
	github.com/kthomas/go-logger v0.0.0-20210526080020-a63672d0724c
	github.com/kthomas/go-natsutil v0.0.0-20200602073459-388e1f070b05
	github.com/kthomas/go-pgputil v0.0.0-20200602073402-784e96083943
	github.com/kthomas/go-redisutil v0.0.0-20210621163534-1f741c230b1f
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/nats-io/nats.go v1.10.0
	github.com/nats-io/stan.go v0.8.3
	github.com/onsi/ginkgo v1.15.1 // indirect
	github.com/onsi/gomega v1.11.0 // indirect
	github.com/provideplatform/ident v0.0.0-00010101000000-000000000000
	github.com/provideplatform/provide-go v0.0.0-20210624064849-d7328258f0d8
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
)

replace github.com/provideplatform/ident => ../ident
