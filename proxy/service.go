package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"

	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	"github.com/ethereum/go-ethereum/crypto"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideapp/baseline-proxy/middleware"
	"github.com/provideservices/provide-go/api"
	provide "github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/api/ident"
	"github.com/provideservices/provide-go/api/nchain"
	"github.com/provideservices/provide-go/api/privacy"
	"github.com/provideservices/provide-go/api/vault"
)

const baselineWorkflowTypeGeneralConsistency = "general_consistency"
const baselineWorkflowTypeProcureToPay = "purchase_order"
const baselineWorkflowTypeServiceNowIncident = "servicenow_incident"

func (r *BaselineRecord) cache() error {
	if r.BaselineID == nil {
		baselineID, _ := uuid.NewV4()
		r.BaselineID = &baselineID
	}

	var baselineIDKey *string
	if r.ID != nil {
		baselineIDKey = common.StringOrNil(fmt.Sprintf("baseline.id.%s", *r.ID))
	}
	baselineRecordKey := fmt.Sprintf("baseline.record.%s", r.BaselineID)

	return redisutil.WithRedlock(baselineRecordKey, func() error {
		if baselineIDKey != nil {
			common.Log.Debugf("mapping internal system of record id to baseline id")
			err := redisutil.Set(*baselineIDKey, r.BaselineID.String(), nil)
			if err != nil {
				common.Log.Warningf("failed to cache baseline record id; %s", err.Error())
				return err
			}
		}

		if r.Workflow != nil {
			err := r.Workflow.Cache()
			if err != nil {
				common.Log.Warningf("failed to cache baseline record id; failed to cache associated workflow; %s", err.Error())
				return err
			}
		}

		raw, _ := json.Marshal(r)
		common.Log.Debugf("mapping baseline id to baseline record: %s", baselineRecordKey)
		err := redisutil.Set(baselineRecordKey, raw, nil)
		if err != nil {
			return err
		}

		if r.Workflow != nil {
			err = r.Workflow.CacheByBaselineID(r.BaselineID.String())
		}

		return err
	})
}

func lookupBaselineRecord(baselineID string) *BaselineRecord {
	var baselineRecord *BaselineRecord

	key := fmt.Sprintf("baseline.record.%s", baselineID)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached baseline record: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &baselineRecord)

	if baselineRecord != nil && baselineRecord.BaselineID != nil && baselineRecord.BaselineID.String() == baselineID && baselineRecord.WorkflowID != nil {
		baselineRecord.Workflow = LookupBaselineWorkflow(baselineRecord.WorkflowID.String())
	}

	return baselineRecord
}

// lookup a baseline record id using the internal system of record id
func lookupBaselineRecordByInternalID(id string) *BaselineRecord {
	key := fmt.Sprintf("baseline.id.%s", id)
	baselineID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline id for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupBaselineRecord(*baselineID)
}

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
	key := fmt.Sprintf("baseline.organization.%s.credential", address)
	secretID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	resp, err := vault.FetchSecret(*token, common.Vault.ID.String(), *secretID, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to retrieve cached verifiable credential for baseline organization: %s; %s", key, err.Error())
		return nil
	}

	return resp.Value
}

func CacheBaselineOrganizationIssuedVC(address, vc string) error {
	token, err := vendOrganizationAccessToken()
	if err != nil {
		common.Log.Warningf("failed to cache verifiable credential for baseline organization: %s; %s", address, err.Error())
		return err
	}

	secretName := fmt.Sprintf("verifiable credential for %s", address)
	resp, err := vault.CreateSecret(*token, common.Vault.ID.String(), vc, secretName, secretName, "verifiable_credential")
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
	token, err := vendOrganizationAccessToken()
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

	keys, err := vault.ListKeys(*token, common.Vault.ID.String(), map[string]interface{}{
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
		if k.Address != nil && strings.ToLower(*k.Address) == strings.ToLower(*common.BaselineOrganizationAddress) {
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
		common.Vault.ID.String(),
		key.ID.String(),
		crypto.Keccak256Hash([]byte(*common.BaselineOrganizationAddress)).Hex()[2:],
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
		"address":    *common.BaselineOrganizationAddress,
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
	org := lookupBaselineOrganization(recipient)
	if org == nil {
		common.Log.Warningf("failed to retrieve cached messaging endpoint for baseline organization: %s", recipient)
		return nil
	}

	if org.MessagingEndpoint == nil {
		token, err := vendOrganizationAccessToken()
		if err != nil {
			common.Log.Warningf("failed to retrieve messaging endpoint for baseline organization: %s", recipient)
			return nil
		}

		// HACK! this account creation will go away with new nchain...
		account, _ := nchain.CreateAccount(*token, map[string]interface{}{
			"network_id": *common.NChainBaselineNetworkID,
		})

		resp, err := nchain.ExecuteContract(*token, *common.BaselineRegistryContractAddress, map[string]interface{}{
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

func (m *ProtocolMessage) baselineInbound() bool {
	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		var workflow *Workflow
		var err error

		workflow = LookupBaselineWorkflow(m.Identifier.String())
		if workflow == nil {
			common.Log.Debugf("initializing baseline workflow: %s", *m.Identifier)

			workflow, err = baselineWorkflowFactory(*m.Type, common.StringOrNil(m.Identifier.String()))
			if err != nil {
				common.Log.Warningf("failed to initialize baseline workflow: %s", *m.Identifier)
				return false
			}
		}

		baselineRecord = &BaselineRecord{
			BaselineID: m.BaselineID,
			Type:       m.Type,
			Workflow:   workflow,
			WorkflowID: m.Identifier,
		}

		err = baselineRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			return false
		}
	}

	err := m.verify(true)
	if err != nil {
		common.Log.Warningf("failed to verify inbound baseline protocol message; invalid state transition; %s", err.Error())
		return false
	}

	sor := middleware.SORFactoryByType(*m.Type, nil)

	if baselineRecord.ID == nil {
		// TODO -- map baseline record id -> internal record id (i.e, this is currently done but lazily on outbound message)
		resp, err := sor.CreateBusinessObject(map[string]interface{}{
			"baseline_id": baselineRecord.BaselineID.String(),
			"payload":     m.Payload.Object,
			"type":        m.Type,
		})
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound baseline; %s", err.Error())
			return false
		}
		common.Log.Debugf("received response from internal system of record; %s", resp)

		const resultField = "result"
		const idField = "sys_id"
		if id, idOk := resp.(map[string]interface{})[idField].(string); idOk {
			baselineRecord.ID = common.StringOrNil(id)
			baselineRecord.cache()
		} else {
			if result, resultOk := resp.(map[string]interface{})[resultField].(map[string]interface{}); resultOk {
				if id, idOk := result[idField].(string); idOk {
					baselineRecord.ID = common.StringOrNil(id)
					baselineRecord.cache()
				}
			}
		}
	} else {
		err := sor.UpdateBusinessObject(*baselineRecord.ID, m.Payload.Object)
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound baseline; %s", err.Error())
			return false
		}
	}

	return true
}

func (m *Message) baselineOutbound() bool {
	if m.ID == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("id is required"),
		})
		return false
	}
	if m.Type == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("type is required"),
		})
		return false
	}
	if m.Payload == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("payload is required"),
		})
		return false
	}

	sor := middleware.SORFactoryByType(*m.Type, nil)

	baselineRecord := lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil && m.BaselineID != nil {
		common.Log.Debugf("attempting to map outbound message to unmapped baseline record with baseline id: %s", m.BaselineID)
		baselineRecord = lookupBaselineRecord(m.BaselineID.String())
	}

	if baselineRecord == nil {
		var workflow *Workflow
		var err error

		if m.BaselineID != nil {
			workflow = LookupBaselineWorkflowByBaselineID(m.BaselineID.String())
			if workflow == nil {
				err = fmt.Errorf("failed to lookup workflow for given baseline id: %s", m.BaselineID.String())
			}
		} else {
			workflow, err = baselineWorkflowFactory(*m.Type, nil)
		}

		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
				"errors":     m.Errors,
				"message_id": m.MessageID,
				"status":     middleware.SORBusinessObjectStatusError,
				"type":       *m.Type,
			})
			return false
		}

		// map internal record id -> baseline record id
		baselineRecord = &BaselineRecord{
			ID:         m.ID,
			Type:       m.Type,
			Workflow:   workflow,
			WorkflowID: workflow.Identifier,
		}

		err = baselineRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
				"errors":     m.Errors,
				"message_id": m.MessageID,
				"status":     middleware.SORBusinessObjectStatusError,
				"type":       *m.Type,
			})
			return false
		}

		circuits := make([]*privacy.Circuit, 0)
		for _, circuit := range workflow.Circuits {
			circuits = append(circuits, &privacy.Circuit{
				Artifacts:     circuit.Artifacts,
				Name:          circuit.Name,
				Description:   circuit.Description,
				Identifier:    circuit.Identifier,
				Provider:      circuit.Provider,
				ProvingScheme: circuit.ProvingScheme,
				Curve:         circuit.Curve,
			})
		}

		for _, recipient := range workflow.Participants {
			msg := &ProtocolMessage{
				BaselineID: baselineRecord.BaselineID,
				Opcode:     common.StringOrNil(ProtocolMessageOpcodeSync),
				Identifier: baselineRecord.WorkflowID,
				Payload: &ProtocolMessagePayload{
					Object: map[string]interface{}{
						"circuits":     circuits,
						"identifier":   workflow.Identifier,
						"participants": workflow.Participants,
						"shield":       workflow.Shield,
					},
					Type: common.StringOrNil("workflow"),
				},
				Recipient: recipient.Address,
				Sender:    nil, // FIXME
				Type:      m.Type,
			}

			err := msg.broadcast(*recipient.Address)
			if err != nil {
				msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", *recipient.Address, err.Error())
				common.Log.Warning(msg)
				m.Errors = append(m.Errors, &provide.Error{
					Message: common.StringOrNil(msg),
				})
			}
		}
	}

	m.BaselineID = baselineRecord.BaselineID

	rawPayload, _ := json.Marshal(m.Payload)

	var i big.Int
	hFunc := mimc.NewMiMC("seed")
	hFunc.Write(rawPayload)
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	m.ProtocolMessage = &ProtocolMessage{
		BaselineID: baselineRecord.BaselineID,
		Opcode:     common.StringOrNil(ProtocolMessageOpcodeBaseline),
		Identifier: baselineRecord.WorkflowID,
		Payload: &ProtocolMessagePayload{
			Object: m.Payload.(map[string]interface{}),
			Type:   m.Type,
			Witness: map[string]interface{}{
				"Document.Hash":     hashString,
				"Document.PreImage": preImageString,
			},
		},
		Shield: baselineRecord.Workflow.Shield,
		Type:   m.Type,
	}

	err := m.prove()
	if err != nil {
		msg := fmt.Sprintf("failed to prove outbound baseline protocol message; invalid state transition; %s", err.Error())
		common.Log.Warning(msg)
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
			"baseline_id": m.BaselineID.String(),
			"errors":      m.Errors,
			"message_id":  m.MessageID,
			"status":      middleware.SORBusinessObjectStatusError,
			"type":        *m.Type,
		})
		return false
	}

	recipients := make([]*Participant, 0)
	if len(m.Recipients) > 0 {
		for _, recipient := range m.Recipients {
			recipients = append(recipients, recipient)
		}
	} else {
		for _, recipient := range baselineRecord.Workflow.Participants {
			recipients = append(recipients, recipient)
		}
	}

	common.Log.Debugf("dispatching outbound protocol message intended for %d recipients", len(recipients))

	for _, recipient := range recipients {
		common.Log.Debugf("dispatching outbound protocol message to %s", *recipient.Address)
		err := m.ProtocolMessage.broadcast(*recipient.Address)
		if err != nil {
			msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", *recipient.Address, err.Error())
			common.Log.Warning(msg)
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(msg),
			})
		}
	}

	err = sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
		"baseline_id": m.BaselineID.String(),
		"message_id":  m.MessageID,
		"status":      middleware.SORBusinessObjectStatusSuccess,
		"type":        *m.Type,
	})
	if err != nil {
		common.Log.Warningf("failed to update business logic status; %s", err.Error())
	}

	return true
}

func (m *Message) prove() error {
	baselineRecord := lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil {
		common.Log.Debugf("failed to resolve baseline record id %s", *m.ID)
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil
	}

	index := baselineRecord.Workflow.WorkstepIndex
	if index >= uint64(len(baselineRecord.Workflow.Circuits)) {
		return fmt.Errorf("failed to resolve workflow circuit at index: %d; index out of range", index)
	}
	circuit := baselineRecord.Workflow.Circuits[index]

	resp, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": m.ProtocolMessage.Payload.Witness,
	})
	if err != nil {
		common.Log.Debugf("failed to prove circuit: %s; %s", circuit.ID, err.Error())
		return err
	}

	m.ProtocolMessage.Payload.Proof = resp.Proof

	return err
}

func (m *ProtocolMessage) broadcast(recipient string) error {
	if strings.ToLower(recipient) == strings.ToLower(*common.BaselineOrganizationAddress) {
		common.Log.Debugf("skipping no-op protocol message broadcast to self: %s", recipient)
		return nil
	}

	payload, err := json.Marshal(&ProtocolMessage{
		BaselineID: m.BaselineID,
		Opcode:     m.Opcode,
		Sender:     m.Shield,
		Recipient:  common.StringOrNil(recipient),
		Shield:     m.Shield,
		Identifier: m.Identifier,
		Signature:  m.Signature,
		Type:       m.Type,
		Payload:    m.Payload,
	})

	if err != nil {
		common.Log.Warningf("failed to broadcast %d-byte protocol message; %s", len(payload), err.Error())
		return err
	}

	common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
	return natsutil.NatsStreamingPublish(natsDispatchProtocolMessageSubject, payload)
}

func (m *ProtocolMessage) verify(store bool) error {
	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		common.Log.Debugf("failed to resolve baseline record id %s", m.BaselineID.String())
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil
	}

	index := baselineRecord.Workflow.WorkstepIndex
	if index >= uint64(len(baselineRecord.Workflow.Circuits)) {
		return fmt.Errorf("failed to resolve workflow circuit at index: %d; index out of range", index)
	}
	circuit := baselineRecord.Workflow.Circuits[index]

	resp, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"store":   store,
		"proof":   m.Payload.Proof,
		"witness": m.Payload.Witness,
	})
	if err != nil {
		common.Log.Warningf("failed to verify circuit: %s; %s", circuit.ID, err.Error())
		return err
	}

	if !resp.Result {
		return fmt.Errorf("failed to verify circuit: %s", circuit.ID)
	}

	return nil
}

func (p *Participant) Cache() error {
	if p.Address == nil {
		return errors.New("failed to cache participant with nil address")
	}

	key := fmt.Sprintf("baseline.organization.%s", *p.Address)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(p)
		return redisutil.Set(key, raw, nil)
	})
}

func vendOrganizationAccessToken() (*string, error) {
	token, err := ident.CreateToken(*common.OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *common.OrganizationID,
	})

	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return nil, err
	}

	return token.AccessToken, nil
}

func circuitParamsFactory(name, identifier string, storeID *string) map[string]interface{} {
	params := map[string]interface{}{
		"curve":          "BN254",
		"identifier":     identifier,
		"name":           name,
		"provider":       "gnark",
		"proving_scheme": "groth16",
	}

	if storeID != nil {
		params["store_id"] = storeID
	}

	return params
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
