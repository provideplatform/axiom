package common

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	logger "github.com/kthomas/go-logger"
	"github.com/provideapp/ident/common"
	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/api/ident"
	"github.com/provideservices/provide-go/api/nchain"
	"github.com/provideservices/provide-go/api/vault"
	"github.com/provideservices/provide-go/common/util"
)

var (
	// BaselineOrganizationAddress is the baseline organization address
	BaselineOrganizationAddress *string

	// BaselineRegistryContractAddress is a contract address
	BaselineRegistryContractAddress *string

	// BaselineRegistryContract is a compiled contract artifact
	BaselineRegistryContract *nchain.CompiledArtifact

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool

	// DefaultCounterparties are the default counterparties
	DefaultCounterparties []map[string]string

	// Log is the configured logger
	Log *logger.Logger

	// InternalSOR is the internal system of record
	InternalSOR map[string]interface{}

	// NChainBaselineNetworkID baseline network id
	NChainBaselineNetworkID *string

	// OrganizationID is the id of the org
	OrganizationID *string

	// OrganizationRefreshToken is the refresh token for the org
	OrganizationRefreshToken *string

	// Vault is the vault instance
	Vault *vault.Vault
)

func init() {
	requireLogger()

	requireInternalSOR()
	requireOrganization()
	requireVault()

	requireBaseline()

	requireCounterparties()

	ConsumeNATSStreamingSubscriptions = strings.ToLower(os.Getenv("CONSUME_NATS_STREAMING_SUBSCRIPTIONS")) == "true"
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

	Log = logger.NewLogger("ident", lvl, endpoint)
}

func requireBaseline() {
	if os.Getenv("BASELINE_ORGANIZATION_ADDRESS") == "" {
		panic("BASELINE_ORGANIZATION_ADDRESS not provided")
	}
	BaselineOrganizationAddress = common.StringOrNil(os.Getenv("BASELINE_ORGANIZATION_ADDRESS"))

	if os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS") == "" {
		panic("BASELINE_REGISTRY_CONTRACT_ADDRESS not provided")
	}
	BaselineRegistryContractAddress = common.StringOrNil(os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS"))

	if os.Getenv("NCHAIN_BASELINE_NETWORK_ID") == "" {
		panic("NCHAIN_BASELINE_NETWORK_ID not provided")
	}
	NChainBaselineNetworkID = common.StringOrNil(os.Getenv("NCHAIN_BASELINE_NETWORK_ID"))

	capabilitiesClient := &api.Client{
		Host:   "s3.amazonaws.com",
		Scheme: "https",
		Path:   "static.provide.services/capabilities",
	}
	_, capabilities, err := capabilitiesClient.Get("provide-capabilities-manifest.json", map[string]interface{}{})
	if err != nil {
		common.Log.Panicf("failed to fetch capabilities; %s", err.Error())
	}

	if baseline, baselineOk := capabilities.(map[string]interface{})["baseline"].(map[string]interface{}); baselineOk {
		if contracts, contractsOk := baseline["contracts"].([]interface{}); contractsOk {
			for _, contract := range contracts {
				if name, nameOk := contract.(map[string]interface{})["name"].(string); nameOk && strings.ToLower(name) == "orgregistry" {
					raw, _ := json.Marshal(contract)
					err := json.Unmarshal(raw, &BaselineRegistryContract)
					if err != nil {
						panic("failed to parse registry contract from capabilities")
					}
					common.Log.Debug("resolved baseline registry contract artifact")
				}
			}
		}
	}

	if BaselineRegistryContract == nil {
		panic("failed to parse registry contract from capabilities")
	}

	token, err := ident.CreateToken(*OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *OrganizationID,
	})
	if err != nil {
		common.Log.Panicf("failed to vend organization access token; %s", err.Error())
	}

	contract, err := nchain.GetContractDetails(*token.AccessToken, *BaselineRegistryContractAddress, map[string]interface{}{})
	if err != nil || contract == nil {
		cntrct, err := nchain.CreateContract(*token.AccessToken, map[string]interface{}{
			"address":    *BaselineRegistryContractAddress,
			"name":       BaselineRegistryContract.Name,
			"network_id": NChainBaselineNetworkID,
			"params": map[string]interface{}{
				"compiled_artifact": BaselineRegistryContract,
			},
			"type": "organization-registry",
		})
		if err != nil {
			common.Log.Panicf("failed to initialize registry contract; %s", err.Error())
		}
		common.Log.Debugf("resolved baseline organization registry contract: %s", *cntrct.Address)
	} else {
		common.Log.Debugf("resolved baseline organization registry contract: %s", *contract.Address)
	}
}

func requireInternalSOR() {
	if os.Getenv("PROVIDE_SOR_IDENTIFIER") == "" {
		panic("PROVIDE_SOR_IDENTIFIER not provided")
	}

	if os.Getenv("PROVIDE_SOR_URL") == "" {
		panic("PROVIDE_SOR_URL not provided")
	}

	InternalSOR = map[string]interface{}{
		"identifier": os.Getenv("PROVIDE_SOR_IDENTIFIER"),
		"url":        os.Getenv("PROVIDE_SOR_URL"),
	}
}

func requireOrganization() {
	if os.Getenv("PROVIDE_ORGANIZATION_ID") == "" {
		panic("PROVIDE_ORGANIZATION_ID not provided")
	}
	OrganizationID = common.StringOrNil(os.Getenv("PROVIDE_ORGANIZATION_ID"))

	if os.Getenv("PROVIDE_ORGANIZATION_REFRESH_TOKEN") == "" {
		panic("PROVIDE_ORGANIZATION_REFRESH_TOKEN not provided")
	}
	OrganizationRefreshToken = common.StringOrNil(os.Getenv("PROVIDE_ORGANIZATION_REFRESH_TOKEN"))
}

func requireVault() {
	util.RequireVault()

	vaults, err := vault.ListVaults(util.DefaultVaultAccessJWT, map[string]interface{}{})
	if err != nil {
		Log.Panicf("failed to fetch vaults for given token; %s", err.Error())
	}

	if len(vaults) > 0 {
		// HACK
		Vault = vaults[0]
		Log.Debugf("resolved default vault instance for proxy: %s", Vault.ID.String())
	} else {
		Vault, err = vault.CreateVault(util.DefaultVaultAccessJWT, map[string]interface{}{
			"name":        fmt.Sprintf("nchain vault %d", time.Now().Unix()),
			"description": "default organizational keystore",
		})
		if err != nil {
			Log.Panicf("failed to create default vaults for proxy instance; %s", err.Error())
		}
		Log.Debugf("created default vault instance for proxy: %s", Vault.ID.String())
	}
}

func requireCounterparties() {
	DefaultCounterparties = make([]map[string]string, 0)
	DefaultCounterparties = append(DefaultCounterparties, map[string]string{
		"address": "0x3E8E1a128190f9628f918Ef407389e656daB5530",
		"url":     "nats://kt.local:4221",
	})
}
