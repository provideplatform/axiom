package proxy

import (
	"encoding/json"
	"fmt"
	"math/big"

	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/providibright/common"
	"github.com/provideapp/providibright/middleware"
	provide "github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/api/ident"
	"github.com/provideservices/provide-go/api/privacy"
)

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

		raw, _ := json.Marshal(r)
		common.Log.Debugf("mapping baseline id to baseline record: %s", baselineRecordKey)
		return redisutil.Set(baselineRecordKey, raw, nil)
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
	return baselineRecord
}

// lookup a baseline record id using the internal system of record id
func lookupBaselineRecordByInternalID(id string) *BaselineRecord {
	key := fmt.Sprintf("baseline.id.%s", id)
	baselineID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached baseline id for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupBaselineRecord(*baselineID)
}

func (m *ProtocolMessage) baselineInbound() bool {
	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		workflow, err := baselineWorkflowFactory(*m.Payload.Type)
		if err != nil {
			common.Log.Warning(err.Error())
			return false
		}

		baselineRecord = &BaselineRecord{
			BaselineID: m.BaselineID,
			Workflow:   workflow,
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

	sor := middleware.SORFactory(common.InternalSOR, nil)

	if baselineRecord.ID == nil {
		// TODO -- map baseline record id -> internal record id
		resp, err := sor.CreateBusinessObject(m.Payload.Object)
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound baseline; %s", err.Error())
			return false
		}
		common.Log.Debugf("received response from internal system of record; %s", resp)
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

	sor := middleware.SORFactory(common.InternalSOR, nil)

	baselineRecord := lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil {
		workflow, err := baselineWorkflowFactory(*m.Type)
		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
				"status": middleware.SORBusinessObjectStatusError,
				"errors": m.Errors,
			})
			return false
		}

		// map internal record id -> baseline record id
		baselineRecord = &BaselineRecord{
			ID:       m.ID,
			Workflow: workflow,
		}

		err = baselineRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
				"status": middleware.SORBusinessObjectStatusError,
				"errors": m.Errors,
			})
			return false
		}
	}

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
		Opcode:     common.StringOrNil(protocolMessageOpcodeBaseline),
		Identifier: baselineRecord.Workflow.Identifier,
		Payload: &ProtocolMessagePayload{
			Object: m.Payload.(map[string]interface{}),
			Type:   m.Type,
			Witness: map[string]interface{}{
				"Document.Hash":     hashString,
				"Document.PreImage": preImageString,
			},
		},
		Shield: baselineRecord.Workflow.Shield,
	}

	err := m.prove()
	if err != nil {
		msg := fmt.Sprintf("failed to prove outbound baseline protocol message; invalid state transition; %s", err.Error())
		common.Log.Warning(msg)
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
			"status": middleware.SORBusinessObjectStatusError,
			"errors": m.Errors,
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

	common.Log.Debugf("dispatching outbound protocol message intended for %d recipients", len(m.Recipients))

	for _, recipient := range recipients {
		err := m.ProtocolMessage.broadcast(*recipient.Address)
		if err != nil {
			msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", recipient, err.Error())
			common.Log.Warning(msg)
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(msg),
			})
		}
	}

	err = sor.UpdateBusinessObjectStatus(*m.ID, map[string]interface{}{
		"status": middleware.SORBusinessObjectStatusSuccess,
	})
	if err != nil {
		common.Log.Warningf("failed to update business logic status; %s", err.Error())
	}

	return true
}

func baselineWorkflowFactory(objectType string) (*Workflow, error) {
	identifier, _ := uuid.NewV4()
	workflow := &Workflow{
		Circuits:     make([]*privacy.Circuit, 0),
		Identifier:   common.StringOrNil(identifier.String()),
		Participants: make([]*Participant, 0),
		Shield:       nil,
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil, err
	}

	switch objectType {
	case baselineWorkflowTypeProcureToPay:
		circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("PO", "purchase_order", nil))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("SO", "sales_order", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("SN", "shipment_notification", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("GR", "goods_receipt", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("Invoice", "invoice", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)
		break

	case baselineWorkflowTypeServiceNowIncident:
		circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("PO", "purchase_order", nil))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)
		break
	default:
		return nil, fmt.Errorf("failed to create workflow for type: %s", objectType)
	}

	return workflow, nil
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
		"curve":          "BN256",
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
