package common

import (
	"os"
	"strings"

	logger "github.com/kthomas/go-logger"
	"github.com/provideapp/ident/common"
)

var (
	// BaselineRegistryContractAddress is a contract address
	BaselineRegistryContractAddress *string

	// ConsumeNATSStreamingSubscriptions is a flag the indicates if the ident instance is running in API or consumer mode
	ConsumeNATSStreamingSubscriptions bool

	// Log is the configured logger
	Log *logger.Logger

	// InternalSOR is the internal system of record
	InternalSOR map[string]interface{}

	// NChain baseline network id
	NChainBaselineNetworkID *string

	// OrganizationID is the id of the org
	OrganizationID *string

	// OrganizationRefreshToken is the refresh token for the org
	OrganizationRefreshToken *string
)

func init() {
	requireLogger()

	requireBaseline()
	requireInternalSOR()
	requireOrganization()

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
	if os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS") == "" {
		panic("BASELINE_REGISTRY_CONTRACT_ADDRESS not provided")
	}
	BaselineRegistryContractAddress = common.StringOrNil(os.Getenv("BASELINE_REGISTRY_CONTRACT_ADDRESS"))

	if os.Getenv("NCHAIN_BASELINE_NETWORK_ID") == "" {
		panic("NCHAIN_BASELINE_NETWORK_ID not provided")
	}
	NChainBaselineNetworkID = common.StringOrNil(os.Getenv("NCHAIN_BASELINE_NETWORK_ID"))
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
