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

package common

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/kthomas/go-elasticsearchutil"
	esutil "github.com/kthomas/go-elasticsearchutil"
	logger "github.com/kthomas/go-logger"
	"github.com/olivere/elastic/v7"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common/util"
)

const IndexerDocumentTypeInvertedIndexContext = "inverted_index_context"
const IndexerDocumentTypeWorkflowPrototype = "workflow_prototype"

const IndexerDocumentIndexAxiomContextInverted = "axiom.context.inverted"
const IndexerDocumentIndexAxiomWorkflowPrototypes = "axiom.workflow.prototypes"

var (
	// AxiomPublicWorkgroupID is the configured public workgroup id, if any
	AxiomPublicWorkgroupID *string

	// AxiomPublicWorkgroupRefreshToken is an optional refresh token credential for a public workgroup
	AxiomPublicWorkgroupRefreshToken *string

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool

	// DefaultBPIEndpoint is the BPI endpoint to use if not overridden by a subject account
	DefaultBPIEndpoint *string

	// DefaultIdentEndpoint is the ident endpoint to use if not overridden by a subject account
	DefaultIdentEndpoint *string

	// elasticClient is the elasticsearch client
	ElasticClient *elastic.Client

	// Indexer instance is a handle to the elasticsearch
	Indexer *esutil.Indexer

	// Log is the configured logger
	Log *logger.Logger

	// Vault is the vault instance which is used by the BPI to protect sensitive materials across all tenants
	Vault *vault.Vault

	// VaultEncryptionKey is the encryption key instance which is used by the BPI to protect sensitive materials across all tenants
	VaultEncryptionKey *vault.Key
)

func init() {
	requireLogger()
	requireAxiomPublicWorkgroup()
	requireElastic()
	requireVault()

	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"

	if os.Getenv("DEFAULT_BPI_ENDPOINT") != "" {
		DefaultBPIEndpoint = common.StringOrNil(os.Getenv("DEFAULT_BPI_ENDPOINT"))
	}

	if os.Getenv("DEFAULT_IDENT_ENDPOINT") != "" {
		DefaultIdentEndpoint = common.StringOrNil(os.Getenv("DEFAULT_IDENT_ENDPOINT"))
	}
}

func requireElastic() {
	esutil.RequireElasticsearch()

	var err error
	ElasticClient, err = elasticsearchutil.GetClient()
	if err != nil {
		Log.Panicf("failed to require elasticsearch client; %s", err.Error())
	}

	exists, _ := ElasticClient.IndexExists(IndexerDocumentIndexAxiomContextInverted).Do(context.Background())
	if !exists {
		_, err := ElasticClient.CreateIndex(IndexerDocumentIndexAxiomContextInverted).Do(context.Background())
		if err != nil {
			Log.Panicf("failed to create elasticsearch index %s; %s", IndexerDocumentIndexAxiomContextInverted, err.Error())
		}
	}

	exists, _ = ElasticClient.IndexExists(IndexerDocumentIndexAxiomWorkflowPrototypes).Do(context.Background())
	if !exists {
		_, err := ElasticClient.CreateIndex(IndexerDocumentIndexAxiomWorkflowPrototypes).Do(context.Background())
		if err != nil {
			Log.Panicf("failed to create elasticsearch index %s; %s", IndexerDocumentIndexAxiomWorkflowPrototypes, err.Error())
		}

	}

	Indexer = esutil.NewIndexer()
	go func() {
		err := Indexer.Run()
		if err != nil {
			Log.Panicf("failed to run indexer; %s", err.Error())
		}
	}()
}

func requireLogger() {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "INFO"
	}

	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpt := os.Getenv("SYSLOG_ENDPOINT")
		endpoint = &endpt
	}

	Log = logger.NewLogger("axiom", lvl, endpoint)
}

func requireAxiomPublicWorkgroup() {
	if os.Getenv("AXIOM_PUBLIC_WORKGROUP_REFRESH_TOKEN") == "" {
		Log.Debugf("AXIOM_PUBLIC_WORKGROUP_REFRESH_TOKEN not provided; no public workgroup configured")
		return
	}

	AxiomPublicWorkgroupRefreshToken = common.StringOrNil(os.Getenv("AXIOM_PUBLIC_WORKGROUP_REFRESH_TOKEN"))

	var claims jwt.MapClaims
	var jwtParser jwt.Parser
	_, _, err := jwtParser.ParseUnverified(*AxiomPublicWorkgroupRefreshToken, claims)
	if err != nil {
		common.Log.Panicf("failed to parse JWT; %s", err.Error())
	}

	if axiom, axiomOk := claims["axiom"].(map[string]interface{}); axiomOk {
		if id, identifierOk := axiom["workgroup_id"].(string); identifierOk {
			AxiomPublicWorkgroupID = common.StringOrNil(id)
		}
	} else if prvd, prvdOk := claims["prvd"].(map[string]interface{}); prvdOk {
		if id, identifierOk := prvd["application_id"].(string); identifierOk {
			AxiomPublicWorkgroupID = common.StringOrNil(id)
		}
	}

	if AxiomPublicWorkgroupID != nil {
		common.Log.Panicf("failed to parse public workgroup id from configured VC; %s", err.Error())
	}

	common.Log.Debugf("configured public workgroup: %s", *AxiomPublicWorkgroupID)
}

func requireVault() {
	util.RequireVault()

	vaults, err := vault.ListVaults(util.DefaultVaultAccessJWT, map[string]interface{}{})
	if err != nil {
		Log.Panicf("failed to fetch vaults for given token; %s", err.Error())
	}

	if len(vaults) > 0 {
		Vault = vaults[0] // HACK
		Log.Debugf("resolved vault for BPI: %s", Vault.ID.String())
	} else {
		Vault, err = vault.CreateVault(util.DefaultVaultAccessJWT, map[string]interface{}{
			"name":        fmt.Sprintf("BPI vault %d", time.Now().Unix()),
			"description": "BPI multitenant keystore",
		})
		if err != nil {
			Log.Panicf("failed to create vault for BPI; %s", err.Error())
		}
		Log.Debugf("created vault for BPI: %s", Vault.ID.String())
	}

	keys, err := vault.ListKeys(util.DefaultVaultAccessJWT, Vault.ID.String(), map[string]interface{}{
		"spec": "AES-256-GCM",
	})
	if err != nil {
		Log.Panicf("failed to fetch vault encryption keys for given token; %s", err.Error())
	}

	if len(keys) > 0 {
		VaultEncryptionKey = keys[0] // HACK
		Log.Debugf("resolved vault encryption key for BPI: %s", VaultEncryptionKey.ID.String())
	} else {
		VaultEncryptionKey, err = vault.CreateKey(
			util.DefaultVaultAccessJWT,
			Vault.ID.String(),
			map[string]interface{}{
				"name":        "BPI multitenant encryption key",
				"description": "BPI encryption key across all tenants",
				"spec":        "AES-256-GCM",
				"type":        "symmetric",
				"usage":       "encrypt/decrypt",
			},
		)
		if err != nil {
			Log.Panicf("failed to create vault encryption key for BPI; %s", err.Error())
		}
		Log.Debugf("created vault encryption key for BPI: %s", VaultEncryptionKey.ID.String())
	}
}
