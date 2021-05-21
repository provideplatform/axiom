package proxy

import (
	"os"
	"strings"
	"time"

	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideservices/provide-go/api/ident"
)

const requireCounterpartiesSleepInterval = time.Second * 15
const requireCounterpartiesTickerInterval = time.Second * 30 // HACK

func init() {
	time.Sleep(time.Second * 5) // HACK! wait for redlock...

	resolveBaselineCounterparties()

	timer := time.NewTicker(requireCounterpartiesTickerInterval)
	for {
		select {
		case <-timer.C:
			resolveBaselineCounterparties()
		default:
			time.Sleep(requireCounterpartiesSleepInterval)
		}
	}
}

func resolveBaselineCounterparties() {
	workgroupID := os.Getenv("BASELINE_WORKGROUP_ID")
	if workgroupID == "" {
		common.Log.Panicf("failed to read BASELINE_WORKGROUP_ID from environment; %s")
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
				Address:           common.StringOrNil(party["address"]),
				APIEndpoint:       common.StringOrNil(party["api_endpoint"]),
				MessagingEndpoint: common.StringOrNil(party["messaging_endpoint"]),
			})
		}

		orgs, err := ident.ListApplicationOrganizations(*token.AccessToken, workgroupID, map[string]interface{}{})
		for _, org := range orgs {
			addr, addrOk := org.Metadata["address"].(string)
			apiEndpoint, _ := org.Metadata["api_endpoint"].(string)
			messagingEndpoint, _ := org.Metadata["messaging_endpoint"].(string)

			if addrOk {
				counterparties = append(counterparties, &Participant{
					Address:           common.StringOrNil(addr),
					APIEndpoint:       common.StringOrNil(apiEndpoint),
					MessagingEndpoint: common.StringOrNil(messagingEndpoint),
				})
			}
		}

		for _, participant := range counterparties {
			if participant.Address != nil && strings.ToLower(*participant.Address) != strings.ToLower(*common.BaselineOrganizationAddress) {
				err := participant.Cache()
				if err != nil {
					common.Log.Warningf("failed to cache counterparty; %s", err.Error())
					continue
				}
				common.Log.Debugf("cached baseline counterparty: %s", *participant.Address)
			}
		}
	}()
}
