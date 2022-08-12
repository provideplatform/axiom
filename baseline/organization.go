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

package baseline

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kthomas/go-redisutil"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/vault"
)

func lookupBaselineOrganization(address string) *Participant {
	var org *Participant

	key := fmt.Sprintf("baseline.organization.%s", address)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline organization: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &org)
	return org
}

func lookupBaselineOrganizationIssuedVC(address string) *string {
	var subjectAccount *SubjectAccount // FIXME-- resolve subject account

	key := fmt.Sprintf("baseline.organization.%s.credential", address)
	secretID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	token, err := vendOrganizationAccessToken(subjectAccount)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	resp, err := vault.FetchSecret(*token, subjectAccount.Metadata.Vault.ID.String(), *secretID, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	return resp.Value
}

func CacheBaselineOrganizationIssuedVC(address, vc string) error {
	var subjectAccount *SubjectAccount // FIXME-- resolve subject account

	token, err := vendOrganizationAccessToken(subjectAccount)
	if err != nil {
		common.Log.Warningf("failed to cache verifiable credential for baseline organization: %s; %s", address, err.Error())
		return err
	}

	secretName := fmt.Sprintf("verifiable credential for %s", address)
	resp, err := vault.CreateSecret(
		*token,
		subjectAccount.Metadata.Vault.ID.String(),
		map[string]interface{}{
			"description": secretName,
			"name":        secretName,
			"type":        "verifiable_credential",
			"value":       hex.EncodeToString([]byte(vc)),
		},
	)
	if err != nil {
		common.Log.Warningf("failed to cache verifiable credential for baseline organization: %s; %s", address, err.Error())
		return err
	}

	key := fmt.Sprintf("baseline.organization.%s.credential", address)
	err = redisutil.Set(key, resp.ID.String(), nil)
	if err != nil {
		common.Log.Warningf("failed to cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return err
	}

	return nil
}

// request a signed VC from the named counterparty
func requestBaselineOrganizationIssuedVC(address string) (*string, error) {
	var subjectAccount *SubjectAccount // FIXME-- resolve subject account

	token, err := vendOrganizationAccessToken(subjectAccount)
	if err != nil {
		common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; %s", address, err.Error())
		return nil, err
	}

	apiURLStr := lookupBaselineOrganizationAPIEndpoint(address)
	if apiURLStr == nil {
		common.Log.Warningf("failed to lookup recipient API endpoint: %s", address)
		return nil, fmt.Errorf("failed to lookup recipient API endpoint: %s", address)
	}

	apiURL, err := url.Parse(*apiURLStr)
	if err != nil {
		common.Log.Warningf("failed to parse recipient API endpoint: %s; %s", address, err.Error())
		return nil, err
	}

	keys, err := vault.ListKeys(*token, subjectAccount.Metadata.Vault.ID.String(), map[string]interface{}{
		"spec": "secp256k1", // FIXME-- make general
	})
	if err != nil {
		common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; failed to resolve signing key; %s", address, err.Error())
		return nil, err
	}

	var key *vault.Key
	if len(keys) == 0 {
		common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; failed to resolve signing key; %s", address, err.Error())
		return nil, fmt.Errorf("failed to request verifiable credential from baseline organization: %s; failed to resolve signing key; %s", address, err.Error())
	}

	for _, k := range keys {
		if k.Address != nil && strings.ToLower(*k.Address) == strings.ToLower(*subjectAccount.Metadata.OrganizationAddress) {
			key = k
			break
		}
	}

	if key == nil {
		common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; failed to resolve signing key", address)
		return nil, fmt.Errorf("failed to request verifiable credential from baseline organization: %s; failed to resolve signing key", address)
	}

	signresp, err := vault.SignMessage(
		*token,
		subjectAccount.Metadata.Vault.ID.String(),
		key.ID.String(),
		crypto.Keccak256Hash([]byte(*subjectAccount.Metadata.OrganizationAddress)).Hex()[2:],
		map[string]interface{}{},
	)
	if err != nil {
		common.Log.Warningf("failed to request verifiable credential for for baseline organization: %s; failed to sign VC issuance request; %s", address, err.Error())
		return nil, fmt.Errorf("failed to request verifiable credential for for baseline organization: %s; failed to sign VC issuance request; %s", address, err.Error())
	}

	client := &api.Client{
		Host:   apiURL.Host,
		Scheme: apiURL.Scheme,
		Path:   "api/v1",
	}

	status, resp, err := client.Post("credentials", map[string]interface{}{
		"address":    *subjectAccount.Metadata.OrganizationAddress,
		"public_key": key.PublicKey,
		"signature":  signresp.Signature,
	})
	if err != nil {
		common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; %s", address, err.Error())
		return nil, fmt.Errorf("failed to request verifiable credential from baseline organization: %s; %s", address, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to request verifiable credential from baseline organization: %s; received status code: %d", address, status)
	}

	var credential *string
	if vc, ok := resp.(map[string]interface{})["credential"].(string); ok {
		err = CacheBaselineOrganizationIssuedVC(address, vc)
		if err != nil {
			common.Log.Warningf("failed to request verifiable credential from baseline organization: %s; failed to cache issued credential; %s", address, err.Error())
			return nil, fmt.Errorf("failed to request verifiable credential from baseline organization: %s; failed to cache issued credential; %s", address, err.Error())
		}
		credential = &vc
	}

	common.Log.Debugf("received requested verifiable credential from counterparty %s", address)
	return credential, nil
}

func lookupBaselineOrganizationAPIEndpoint(recipient string) *string {
	org := lookupBaselineOrganization(recipient)
	if org == nil {
		common.Log.Warningf("failed to retrieve cached API endpoint for baseline organization: %s", recipient)
		return nil
	}

	if org.APIEndpoint == nil {
		// this endpoint does not currently does not live on-chain, and should remain that way
	}

	return org.APIEndpoint
}

func lookupBaselineOrganizationMessagingEndpoint(recipient string) *string {
	var subjectAccount *SubjectAccount // FIXME-- resolve subject account

	org := lookupBaselineOrganization(recipient)
	if org == nil {
		common.Log.Warningf("failed to retrieve cached messaging endpoint for baseline organization: %s", recipient)
		return nil
	}

	if org.MessagingEndpoint == nil {
		token, err := vendOrganizationAccessToken(subjectAccount)
		if err != nil {
			common.Log.Warningf("failed to retrieve messaging endpoint for baseline organization: %s", recipient)
			return nil
		}

		// HACK! this account creation will go away with new nchain...
		account, _ := nchain.CreateAccount(*token, map[string]interface{}{
			"network_id": *subjectAccount.Metadata.NetworkID,
		})

		resp, err := nchain.ExecuteContract(*token, *subjectAccount.Metadata.RegistryContractAddress, map[string]interface{}{
			"account_id": account.ID.String(),
			"method":     "getOrg",
			"params":     []string{recipient},
			"value":      0,
		})

		if err != nil {
			common.Log.Warningf("failed to retrieve messaging endpoint for baseline organization: %s", recipient)
			return nil
		}

		if endpoint, endpointOk := resp.Response.([]interface{})[2].(string); endpointOk {
			endpoint, err := base64.StdEncoding.DecodeString(endpoint)
			if err != nil {
				common.Log.Warningf("failed to retrieve messaging endpoint for baseline organization: %s; failed to base64 decode endpoint", recipient)
				return nil
			}
			org := &Participant{
				Address:           common.StringOrNil(recipient),
				MessagingEndpoint: common.StringOrNil(string(endpoint)),
				Workgroups:        make([]*Workgroup, 0),
				Workflows:         make([]*Workflow, 0),
				Worksteps:         make([]*Workstep, 0),
			}

			err = org.Cache()
			if err != nil {
				common.Log.Warningf("failed to retrieve messaging endpoint for baseline organization: %s; failed to", recipient)
				return nil
			}
		}
	}

	return org.MessagingEndpoint
}

func vendOrganizationAccessToken(subjectAccount *SubjectAccount) (*string, error) {
	token, err := ident.CreateToken(*subjectAccount.Metadata.OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *subjectAccount.Metadata.OrganizationID,
	})

	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return nil, err
	}

	return token.AccessToken, nil
}
