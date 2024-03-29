/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kthomas/go-redisutil"

	"github.com/provideplatform/axiom/axiom"
	"github.com/provideplatform/axiom/common"
	"github.com/provideplatform/axiom/stats"
	identcommon "github.com/provideplatform/ident/common"
	"github.com/provideplatform/ident/token"

	provide "github.com/provideplatform/provide-go/common"
	util "github.com/provideplatform/provide-go/common/util"
)

const jwtVerifierRefreshInterval = 60 * time.Second
const jwtVerifierGracePeriod = 60 * time.Second

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
	identcommon.EnableAPIAccounting()
}

func main() {
	common.Log.Debugf("starting axiom API...")
	installSignalHandlers()

	runAPI()

	startAt := time.Now()
	gracePeriodEndAt := startAt.Add(jwtVerifierGracePeriod)
	verifiersRefreshedAt := time.Now()

	timer := time.NewTicker(runloopTickInterval)
	defer timer.Stop()

	for !shuttingDown() {
		select {
		case <-timer.C:
			now := time.Now()
			if now.Before(gracePeriodEndAt) {
				util.RequireJWTVerifiers()
			} else if now.After(verifiersRefreshedAt.Add(jwtVerifierRefreshInterval)) {
				verifiersRefreshedAt = now
				util.RequireJWTVerifiers()
			}

			// TODO: check NATS subscription statuses
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

	common.Log.Debug("exiting axiom API")
	cancelF()
}

func installSignalHandlers() {
	common.Log.Debug("installing signal handlers for axiom API")
	sigs = make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	shutdownCtx, cancelF = context.WithCancel(context.Background())
}

func shutdown() {
	if atomic.AddUint32(&closing, 1) == 1 {
		common.Log.Debug("shutting down axiom API")
		common.Indexer.Stop()
		cancelF()
	}
}

func runAPI() {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(provide.CORSMiddleware())

	r.GET("/status", statusHandler)
	axiom.InstallCredentialsAPI(r)

	// public config and axiom workgroup APIs...
	axiom.InstallPublicWorkgroupAPI(r)

	r.Use(token.AuthMiddleware())
	r.Use(identcommon.AccountingMiddleware())
	r.Use(identcommon.RateLimitingMiddleware())

	axiom.InstallBPIAPI(r)
	axiom.InstallMappingsAPI(r)
	axiom.InstallSystemsAPI(r)
	axiom.InstallSchemasAPI(r)
	axiom.InstallWorkflowsAPI(r)
	axiom.InstallWorkgroupsAPI(r)
	axiom.InstallWorkstepsAPI(r)
	stats.InstallStatsAPI(r)

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
