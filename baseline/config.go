package baseline

import (
	"os"

	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api/baseline"
)

// Config represents the proxy configuration
type Config struct {
	baseline.Config
	Counterparties []*Participant `sql:"-" json:"counterparties,omitempty"`
}

func (c *Config) apply() bool {
	if c.NetworkID != nil {
		common.NChainBaselineNetworkID = common.StringOrNil(c.NetworkID.String())
	}
	if c.OrganizationAddress != nil {
		common.BaselineOrganizationAddress = c.OrganizationAddress
	}
	if c.OrganizationID != nil {
		common.OrganizationID = common.StringOrNil(c.OrganizationID.String())
	}
	if c.OrganizationRefreshToken != nil {
		common.OrganizationRefreshToken = c.OrganizationRefreshToken
	}
	if c.RegistryContractAddress != nil {
		common.BaselineRegistryContractAddress = c.RegistryContractAddress
		common.ResolveBaselineContract()
	}

	if c.Env != nil {
		// FIXME -- require whitelist
		for name, val := range c.Env {
			os.Setenv(name, val)
		}
	}

	c.requireCounterparties()

	return true
}

func (c *Config) requireCounterparties() {
	// FIXME-- mutex
	if c.Counterparties != nil {
		common.DefaultCounterparties = make([]map[string]string, 0)

		for _, participant := range c.Counterparties {
			err := participant.Cache()
			if err != nil {
				common.Log.Warningf("failed to cache counterparties; %s", err.Error())
			}

			common.DefaultCounterparties = append(common.DefaultCounterparties, map[string]string{
				"address":            *participant.Address,
				"messaging_endpoint": *participant.MessagingEndpoint,
			})
			common.Log.Debugf("cached baseline counterparty: %s", *participant.Address)
		}
	}
}
