package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kthomas/go-redisutil"

	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideapp/baseline-proxy/middleware"
	"github.com/provideapp/baseline-proxy/proxy"
	"github.com/provideapp/baseline-proxy/stats"
	"github.com/provideapp/baseline-proxy/workgroup"
	identcommon "github.com/provideapp/ident/common"
	"github.com/provideapp/ident/token"

	provide "github.com/provideservices/provide-go/common"
	util "github.com/provideservices/provide-go/common/util"
)

const runloopSleepInterval = 250 * time.Millisecond
const runloopTickInterval = 5000 * time.Millisecond

var (
	cancelF     context.CancelFunc
	closing     uint32
	shutdownCtx context.Context
	sigs        chan os.Signal

	srv *http.Server
)

func init() {
	if common.ConsumeNATSStreamingSubscriptions {
		common.Log.Panicf("dedicated API instance started with CONSUME_NATS_STREAMING_SUBSCRIPTIONS=true")
		return
	}

	util.RequireGin()
	util.RequireJWTVerifiers()
	redisutil.RequireRedis()
	// util.RequireVault()
	identcommon.EnableAPIAccounting()
	configureSOR()
}

func configureSOR() {
	sor := middleware.SORFactory(common.InternalSOR, nil)
	if sor == nil {
		panic("SOR provider not resolved")
	}

	err := sor.HealthCheck()
	if err != nil {
		panic(err.Error())
	}
	common.Log.Debugf("health check completed; SOR API available at %s", common.InternalSOR["url"])

	err = sor.ConfigureProxy(map[string]interface{}{
		"organization_id": common.OrganizationID,
		"ident_endpoint":  fmt.Sprintf("%s://%s", os.Getenv("IDENT_API_SCHEME"), os.Getenv("IDENT_API_HOST")),
		"proxy_endpoint":  common.OrganizationProxyEndpoint,
		"refresh_token":   common.OrganizationRefreshToken,
	})
	if err != nil {
		panic(err.Error())
	}
}

func main() {
	common.Log.Debugf("starting baseline-proxy API...")
	installSignalHandlers()

	runAPI()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			// tick... no-op
		case sig := <-sigs:
			common.Log.Debugf("received signal: %s", sig)
			srv.Shutdown(shutdownCtx)
			shutdown()
		case <-shutdownCtx.Done():
			close(sigs)
		default:
			time.Sleep(runloopSleepInterval)
		}
	}

	common.Log.Debug("exiting baseline-proxy API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for baseline-proxy API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down baseline-proxy API")
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/status", statusHandler)
	proxy.InstallCredentialsAPI(r)

	r.Use(token.AuthMiddleware())
	r.Use(identcommon.AccountingMiddleware())
	r.Use(identcommon.RateLimitingMiddleware())

	proxy.InstallProxyAPI(r)
	stats.InstallStatsAPI(r)
	workgroup.InstallWorkgroupAPI(r)

	srv = &http.Server{
		Addr:    util.ListenAddr,
		Handler: r,
	}

	if util.ServeTLS {
		go srv.ListenAndServeTLS(util.CertificatePath, util.PrivateKeyPath)
	} else {
		go srv.ListenAndServe()
	}

	common.Log.Debugf("listening on %s", util.ListenAddr)
}

func statusHandler(c *gin.Context) {
	provide.Render(nil, 204, c)
}

func shuttingDown() bool {
	return (atomic.LoadUint32(&closing) > 0)
}
