module github.com/provideapp/baseline-proxy

go 1.15

require (
	github.com/consensys/gnark v0.3.9-0.20210209002645-110d32683f59
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/kthomas/go-logger v0.0.0-20210411034702-66a0af9aee2c
	github.com/kthomas/go-natsutil v0.0.0-20200602073459-388e1f070b05
	github.com/kthomas/go-redisutil v0.0.0-20200602073431-aa49de17e9ff
	github.com/kthomas/go.uuid v1.2.1-0.20190324131420-28d1fa77e9a4
	github.com/nats-io/nats.go v1.10.0
	github.com/nats-io/stan.go v0.8.3
	github.com/onsi/ginkgo v1.15.1
	github.com/onsi/gomega v1.11.0
	github.com/provideapp/ident v0.0.0-00010101000000-000000000000
	github.com/provideservices/provide-go v0.0.0-20210411230718-e785ebe439fa
)

replace github.com/provideapp/ident => ../ident
