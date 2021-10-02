package baseline

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline-proxy/common"
	"github.com/provideplatform/baseline-proxy/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/privacy"
)

const baselineWorkflowTypeGeneralConsistency = "general_consistency"
const baselineWorkflowTypeProcureToPay = "purchase_order"
const baselineWorkflowTypeServiceNowIncident = "servicenow_incident"

func (m *ProtocolMessage) baselineInbound() bool {
	var baselineContext *BaselineContext

	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		var workflow *Workflow
		var err error

		if m.Identifier != nil {
			workflow = LookupBaselineWorkflow(m.Identifier.String())
		}

		if m.BaselineID != nil {
			baselineContext = lookupBaselineContext(m.BaselineID.String())

			if workflow == nil {
				workflow = LookupBaselineWorkflowByBaselineID(m.BaselineID.String())
				if workflow == nil && baselineContext != nil {
					workflow = baselineContext.Workflow
				}
			}
		}

		if workflow == nil {
			common.Log.Debugf("initializing baseline workflow: %s", *m.Identifier)

			workflow, err = baselineWorkflowFactory(*m.Type, common.StringOrNil(m.Identifier.String()))
			if err != nil {
				common.Log.Warningf("failed to initialize baseline workflow: %s", *m.Identifier)
				return false
			}
		}

		if baselineContext == nil {
			common.Log.Debug("initializing new baseline context...")

			baselineContextID, _ := uuid.NewV4()
			baselineContext = &BaselineContext{
				ID:         &baselineContextID,
				BaselineID: m.BaselineID,
				Records:    make([]*BaselineRecord, 0),
			}

			if workflow != nil {
				baselineContext.Workflow = workflow
				baselineContext.WorkflowID = workflow.ID
			}
		}

		baselineRecord = &BaselineRecord{
			BaselineID: m.BaselineID,
			Context:    baselineContext,
			ContextID:  baselineContext.ID,
			Type:       m.Type,
		}

		err = baselineRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			return false
		}

		common.Log.Debugf("inbound baseline protocol message initialized baseline record; baseline id: %s; workflow id: %s; type: %s", m.BaselineID.String(), m.Identifier.String(), *m.Type)
	}

	err := m.verify(true)
	if err != nil {
		common.Log.Warningf("failed to verify inbound baseline protocol message; invalid state transition; %s", err.Error())
		return false
	}

	sor := middleware.SORFactoryByType(*m.Type, nil)

	if baselineRecord.ID == nil {
		// TODO -- map baseline record id -> internal record id (i.e, this is currently done but lazily on outbound message)
		resp, err := sor.CreateObject(map[string]interface{}{
			"baseline_id": baselineRecord.BaselineID.String(),
			"payload":     m.Payload.Object,
			"type":        m.Type,
		})
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound baseline; %s", err.Error())
			return false
		}
		common.Log.Debugf("received response from internal system of record; %s", resp)

		const defaultIDField = "id"

		if id, idOk := resp.(map[string]interface{})[defaultIDField].(string); idOk {
			baselineRecord.ID = common.StringOrNil(id)
			baselineRecord.cache()
		} else {
			common.Log.Warning("failed to create business object during inbound baseline; no id present in response")
			return false
		}
	} else {
		err := sor.UpdateObject(*baselineRecord.ID, m.Payload.Object)
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

	var baselineContext *BaselineContext
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

			baselineContext = lookupBaselineContext(m.BaselineID.String())
			if baselineContext == nil {
				err = fmt.Errorf("failed to lookup baseline context for given baseline id: %s", m.BaselineID.String())
			}
		} else {
			workflow, err = baselineWorkflowFactory(*m.Type, nil)

			if baselineContext == nil {
				common.Log.Debugf("initializing new baseline context with baseline id: %s", m.BaselineID)

				baselineContextID, _ := uuid.NewV4()
				baselineContext = &BaselineContext{
					ID:         &baselineContextID,
					BaselineID: m.BaselineID,
					Records:    make([]*BaselineRecord, 0),
				}

				if workflow != nil {
					baselineContext.Workflow = workflow
					baselineContext.WorkflowID = workflow.ID
				}
			}
		}

		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateObjectStatus(*m.ID, map[string]interface{}{
				"errors":     m.Errors,
				"message_id": m.MessageID,
				"status":     middleware.SORBusinessObjectStatusError,
				"type":       *m.Type,
			})
			return false
		}

		// map internal record id -> baseline record id
		baselineRecord = &BaselineRecord{
			ID:        m.ID,
			Context:   baselineContext,
			ContextID: baselineContext.ID,
			Type:      m.Type,
		}

		err = baselineRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
			sor.UpdateObjectStatus(*m.ID, map[string]interface{}{
				"errors":     m.Errors,
				"message_id": m.MessageID,
				"status":     middleware.SORBusinessObjectStatusError,
				"type":       *m.Type,
			})
			return false
		}

		for _, workstep := range workflow.Worksteps {
			circuit := workstep.Circuit
			workstep.Circuit = &privacy.Circuit{
				Artifacts:     circuit.Artifacts,
				Name:          circuit.Name,
				Description:   circuit.Description,
				Identifier:    circuit.Identifier,
				Provider:      circuit.Provider,
				ProvingScheme: circuit.ProvingScheme,
				Curve:         circuit.Curve,
			}
		}

		for _, recipient := range workflow.Participants {
			msg := &ProtocolMessage{
				BaselineID: baselineRecord.BaselineID,
				Opcode:     common.StringOrNil(ProtocolMessageOpcodeSync),
				Identifier: baselineRecord.Context.WorkflowID,
				Payload: &ProtocolMessagePayload{
					Object: map[string]interface{}{
						"id":           workflow.ID,
						"participants": workflow.Participants,
						"shield":       workflow.Shield,
						"worksteps":    workflow.Worksteps,
					},
					Type: common.StringOrNil(protomsgPayloadTypeWorkflow),
				},
				Recipient: recipient.Address,
				Sender:    nil, // FIXME
				Type:      m.Type,
			}

			if recipient.Address != nil {
				err := msg.broadcast(*recipient.Address)
				if err != nil {
					msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", *recipient.Address, err.Error())
					common.Log.Warning(msg)
					m.Errors = append(m.Errors, &provide.Error{
						Message: common.StringOrNil(msg),
					})
				}
			} else {
				common.Log.Warningf("failed to dispatch protocol message to recipient: %s; no recipient address", *recipient.Address)
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
		Identifier: baselineRecord.Context.WorkflowID,
		Payload: &ProtocolMessagePayload{
			Object: m.Payload.(map[string]interface{}),
			Type:   m.Type,
			Witness: map[string]interface{}{
				"Document.Hash":     hashString,
				"Document.Preimage": preImageString,
			},
		},
		Shield: baselineRecord.Context.Workflow.Shield,
		Type:   m.Type,
	}

	err := m.prove()
	if err != nil {
		msg := fmt.Sprintf("failed to prove outbound baseline protocol message; invalid state transition; %s", err.Error())
		common.Log.Warning(msg)
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		sor.UpdateObjectStatus(*m.ID, map[string]interface{}{
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
		for _, recipient := range baselineRecord.Context.Workflow.Participants {
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

	err = sor.UpdateObjectStatus(*m.ID, map[string]interface{}{
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
	_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)
	return err
}

func (m *Message) prove() error {
	baselineRecord := lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil {
		common.Log.Debugf("no baseline record resolved for internal identifier: %s", *m.ID)
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil
	}

	index := len(baselineRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(baselineRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/circuit at index: %d; index out of range", index)
	}
	circuit := baselineRecord.Context.Workflow.Worksteps[index].Circuit

	resp, err := privacy.Prove(*token, circuit.ID.String(), map[string]interface{}{
		"witness": m.ProtocolMessage.Payload.Witness,
	})
	if err != nil {
		common.Log.Warningf("failed to prove circuit: %s; %s", circuit.ID, err.Error())
		return err
	}

	m.ProtocolMessage.Payload.Proof = resp.Proof

	return err
}

func (m *ProtocolMessage) verify(store bool) error {
	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		common.Log.Debugf("no baseline record cached for baseline record id: %s", m.BaselineID.String())
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil
	}

	index := len(baselineRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(baselineRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/circuit at index: %d; index out of range", index)
	}
	circuit := baselineRecord.Context.Workflow.Worksteps[index].Circuit

	resp, err := privacy.Verify(*token, circuit.ID.String(), map[string]interface{}{
		"store":   store,
		"proof":   m.Payload.Proof,
		"witness": m.Payload.Witness,
	})
	if err != nil {
		common.Log.Warningf("failed to verify: %s; %s", circuit.ID, err.Error())
		return err
	}

	if !resp.Result {
		return fmt.Errorf("failed to verify circuit: %s", circuit.ID)
	}

	return nil
}
