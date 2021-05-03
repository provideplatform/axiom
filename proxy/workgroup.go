package proxy

import (
	"os"
	"time"

	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideservices/provide-go/api/ident"
)

func init() {
	time.Sleep(time.Second * 3) // HACK! wait for redlock...
	resolveBaselineCounterparties()
}

func resolveBaselineCounterparties() {
	workgroupID := os.Getenv("BASELINE_WORKGROUP_ID")
	if workgroupID == "" {
		common.Log.Panicf("failed to read BASELINE_WORKGROUP_ID from environment; %s", err.Error())
	}

	go func() {
		common.Log.Debugf("attempting to resolve baseline counterparties")

		token, err := ident.CreateToken(*common.OrganizationRefreshToken, map[string]interface{}{
			"grant_type":      "refresh_token",
			"organization_id": *common.OrganizationID,
		})
		if err != nil {
			common.Log.Warningf("failed to vend organization access token; %s", err.Error())
			return
		}

		counterparties := make([]*Participant, 0)

		for _, party := range common.DefaultCounterparties {
			counterparties = append(counterparties, &Participant{
				Address: common.StringOrNil(party["address"]),
				URL:     common.StringOrNil(party["messaging_endpoint"]),
			})
		}

		orgs, err := ident.ListApplicationOrganizations(*token.AccessToken, workgroupID, map[string]interface{}{})
		for _, org := range orgs {
			counterparties = append(counterparties, &Participant{
				Address: common.StringOrNil(org.Metadata["address"].(string)),
				URL:     common.StringOrNil(org.Metadata["messaging_endpoint"].(string)),
			})
		}

		for _, participant := range counterparties {
			err := participant.Cache()
			if err != nil {
				common.Log.Warningf("failed to cache counterparty; %s", err.Error())
			}
			common.Log.Debugf("cached baseline counterparty: %s", *participant.Address)
		}
	}()
}
