package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/provideplatform/ident/common"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/common/util"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

// PanicIfEmpty panics if the given string is empty
func PanicIfEmpty(val string, msg string) {
	if val == "" {
		panic(msg)
	}
}

// RefreshPublicWorkgroupAccessToken is a convenience function to authorize a new access token
func RefreshPublicWorkgroupAccessToken() (*string, error) {
	token, err := ident.CreateToken(*BaselinePublicWorkgroupRefreshToken, map[string]interface{}{
		"grant_type": "refresh_token",
	})

	if err != nil {
		common.Log.Warningf("failed to authorize access token for given public workgroup refresh token; %s", err.Error())
		return nil, err
	}

	if token.AccessToken == nil {
		err := fmt.Errorf("failed to authorize access token for given public workgroup refresh token: %s", token.ID.String())
		common.Log.Warning(err.Error())
		return nil, err
	}

	return token.AccessToken, nil
}

// FIXME -- return error
func ResolveBaselineContract() {
	if NChainBaselineNetworkID == nil || OrganizationRefreshToken == nil {
		Log.Warning("unable to resolve baseline contract without configured network id and organization refresh token")
		return
	}

	capabilities, err := util.ResolveCapabilitiesManifest()
	if baseline, baselineOk := capabilities["baseline"].(map[string]interface{}); baselineOk {
		if contracts, contractsOk := baseline["contracts"].([]interface{}); contractsOk {
			for _, contract := range contracts {
				if name, nameOk := contract.(map[string]interface{})["name"].(string); nameOk && strings.ToLower(name) == "orgregistry" {
					raw, _ := json.Marshal(contract)
					err := json.Unmarshal(raw, &BaselineRegistryContract)
					if err != nil {
						Log.Warningf("failed to parse registry contract from capabilities; %s", err.Error())
					} else {
						Log.Debug("resolved baseline registry contract artifact")
					}
				}
			}
		}
	}

	if BaselineRegistryContract == nil {
		Log.Warning("failed to parse registry contract from capabilities")
		return
	}

	token, err := ident.CreateToken(*OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *OrganizationID,
	})
	if err != nil {
		Log.Warningf("failed to vend organization access token; %s", err.Error())
		return
	}

	contract, err := nchain.GetContractDetails(*token.AccessToken, *BaselineRegistryContractAddress, map[string]interface{}{})
	if err != nil || contract == nil {
		wallet, err := nchain.CreateWallet(*token.AccessToken, map[string]interface{}{
			"purpose": 44,
		})
		if err != nil {
			Log.Warningf("failed to initialize wallet for organization; %s", err.Error())
		} else {
			Log.Debugf("created HD wallet for organization: %s", wallet.ID)
		}

		cntrct, err := nchain.CreateContract(*token.AccessToken, map[string]interface{}{
			"address":    *BaselineRegistryContractAddress,
			"name":       BaselineRegistryContract.Name,
			"network_id": NChainBaselineNetworkID,
			"params": map[string]interface{}{
				"argv":              []interface{}{},
				"compiled_artifact": BaselineRegistryContract,
				"wallet_id":         wallet.ID,
			},
			"type": "organization-registry",
		})
		if err != nil {
			Log.Warningf("failed to initialize registry contract; %s", err.Error())
		} else {
			Log.Debugf("resolved baseline organization registry contract: %s", *cntrct.Address)
		}
	} else {
		Log.Debugf("resolved baseline organization registry contract: %s", *contract.Address)
	}
}

// StringFromInterface returns the string representation of val, if val
// is in fact a string (or *string)
func StringFromInterface(val interface{}) *string {
	if val == nil {
		return nil
	}
	if str, ok := val.(string); ok {
		return &str
	}
	if strptr, ok := val.(*string); ok {
		return strptr
	}
	if arr, ok := val.([]byte); ok {
		return StringOrNil(string(arr))
	}
	return nil
}

// StringOrNil returns the given string or nil when empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// RandomString generates a random string of the given length
func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}
