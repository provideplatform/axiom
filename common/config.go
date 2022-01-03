package common

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	logger "github.com/kthomas/go-logger"
	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common/util"
)

const configGracePeriodTickInterval = 1000 * time.Millisecond
const configGracePeriodSleepInterval = 25 * time.Millisecond
const configGracePeriodTimeout = 60000 * time.Millisecond

var (
	// BaselineOrganizationAddress is the baseline organization address
	BaselineOrganizationAddress *string

	// BaselinePublicWorkgroupID is the configured public workgroup id, if any
	BaselinePublicWorkgroupID *string

	// BaselinePublicWorkgroupRefreshToken is an optional refresh token credential for a public workgroup
	BaselinePublicWorkgroupRefreshToken *string

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

	// OrganizationMessagingEndpoint is the public organziation messaging endpoint
	OrganizationMessagingEndpoint *string

	// OrganizationProxyEndpoint is the configured endpoint for the baseline proxy REST API
	OrganizationProxyEndpoint *string

	// OrganizationRefreshToken is the refresh token for the org
	OrganizationRefreshToken *string

	// Vault is the vault instance
	Vault *vault.Vault
)

func init() {
	requireLogger()

	go requireOrganization()
	requireVault()

	requireInternalSOR()
	requireBaseline()
	requireBaselinePublicWorkgroup()

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

	Log = logger.NewLogger("baseline", lvl, endpoint)
}

func requireBaseline() {
	if os.Getenv("BASELINE_ORGANIZATION_ADDRESS") == "" {
		Log.Warningf("BASELINE_ORGANIZATION_ADDRESS not provided")
	}
	BaselineOrganizationAddress = common.StringOrNil(os.Getenv("BASELINE_ORGANIZATION_ADDRESS"))

	if os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS") == "" {
		Log.Warningf("BASELINE_REGISTRY_CONTRACT_ADDRESS not provided")
	}
	BaselineRegistryContractAddress = common.StringOrNil(os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS"))

	if os.Getenv("NCHAIN_BASELINE_NETWORK_ID") == "" {
		Log.Warningf("NCHAIN_BASELINE_NETWORK_ID not provided")
	}
	NChainBaselineNetworkID = common.StringOrNil(os.Getenv("NCHAIN_BASELINE_NETWORK_ID"))

	ResolveBaselineContract()
}

func requireBaselinePublicWorkgroup() {
	if os.Getenv("BASELINE_PUBLIC_WORKGROUP_REFRESH_TOKEN") == "" {
		Log.Debugf("BASELINE_PUBLIC_WORKGROUP_REFRESH_TOKEN not provided; no public workgroup configured")
		return
	}

	BaselinePublicWorkgroupRefreshToken = common.StringOrNil(os.Getenv("BASELINE_PUBLIC_WORKGROUP_REFRESH_TOKEN"))

	var claims jwt.MapClaims
	var jwtParser jwt.Parser
	_, _, err := jwtParser.ParseUnverified(*BaselinePublicWorkgroupRefreshToken, claims)
	if err != nil {
		common.Log.Panicf("failed to parse JWT; %s", err.Error())
	}

	if baseline, baselineOk := claims["baseline"].(map[string]interface{}); baselineOk {
		if id, identifierOk := baseline["workgroup_id"].(string); identifierOk {
			BaselinePublicWorkgroupID = common.StringOrNil(id)
		}
	} else if prvd, prvdOk := claims["prvd"].(map[string]interface{}); prvdOk {
		if id, identifierOk := prvd["application_id"].(string); identifierOk {
			BaselinePublicWorkgroupID = common.StringOrNil(id)
		}
	}

	if BaselinePublicWorkgroupID != nil {
		common.Log.Panicf("failed to parse public workgroup id from configured VC; %s", err.Error())
	}

	common.Log.Debugf("configured public workgroup: %s", *BaselinePublicWorkgroupID)
}

func requireInternalSOR() {
	if os.Getenv("PROVIDE_SOR_IDENTIFIER") == "" {
		Log.Warningf("PROVIDE_SOR_IDENTIFIER not provided")
	}

	if os.Getenv("PROVIDE_SOR_URL") == "" {
		Log.Warningf("PROVIDE_SOR_URL not provided")
	}

	InternalSOR = map[string]interface{}{
		"identifier": os.Getenv("PROVIDE_SOR_IDENTIFIER"),
	}

	if os.Getenv("PROVIDE_SOR_URL") != "" && os.Getenv("PROVIDE_SOR_URL") != "https://" {
		InternalSOR["url"] = os.Getenv("PROVIDE_SOR_URL")
	}

	if os.Getenv("PROVIDE_SOR_ORGANIZATION_CODE") != "" {
		InternalSOR["organization_code"] = os.Getenv("PROVIDE_SOR_ORGANIZATION_CODE")
	}
}

func requireOrganization() {
	timer := time.NewTicker(configGracePeriodTickInterval)
	defer timer.Stop()

	startedAt := time.Now()
	resolvedOrganization := false

	for !resolvedOrganization {
		select {
		case <-timer.C:
			OrganizationID = StringOrNil(os.Getenv("PROVIDE_ORGANIZATION_ID"))
			OrganizationRefreshToken = StringOrNil(os.Getenv("PROVIDE_ORGANIZATION_REFRESH_TOKEN"))
			OrganizationMessagingEndpoint = StringOrNil(os.Getenv("BASELINE_ORGANIZATION_MESSAGING_ENDPOINT"))
			OrganizationProxyEndpoint = StringOrNil(os.Getenv("BASELINE_ORGANIZATION_PROXY_ENDPOINT"))

			resolvedOrganization = OrganizationID != nil && OrganizationRefreshToken != nil && OrganizationMessagingEndpoint != nil && OrganizationProxyEndpoint != nil
		default:
			if time.Now().After(startedAt.Add(configGracePeriodTimeout)) {
				if os.Getenv("PROVIDE_ORGANIZATION_ID") == "" {
					Log.Warningf("PROVIDE_ORGANIZATION_ID not provided")
				}

				if os.Getenv("PROVIDE_ORGANIZATION_REFRESH_TOKEN") == "" {
					Log.Warningf("PROVIDE_ORGANIZATION_REFRESH_TOKEN not provided")
				}

				if OrganizationMessagingEndpoint == nil {
					Log.Warningf("BASELINE_ORGANIZATION_MESSAGING_ENDPOINT not provided")
				}

				if OrganizationProxyEndpoint == nil {
					Log.Warningf("BASELINE_ORGANIZATION_PROXY_ENDPOINT not provided")
				}

				Log.Panicf("failed to require organization")
			}

			time.Sleep(configGracePeriodSleepInterval)
		}
	}

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
