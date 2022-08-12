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
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	mimc "github.com/consensys/gnark/crypto/hash/mimc/bn256"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/privacy"
)

// resolveWorkstepContext is a convenience method to resolve the workstep context
// alongside other relevant items... TODO-- memoize this so it can be reused nicely
func (m *Message) resolveContext() (middleware.SOR, *BaselineContext, *BaselineRecord, *WorkflowInstance, *WorkstepInstance, error) {
	var system middleware.SOR
	var baselineContext *BaselineContext
	var baselineRecord *BaselineRecord
	var workflow *WorkflowInstance
	var workstep *WorkstepInstance
	var err error

	// if m.subjectAccount == nil {
	// 	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	// 	m.subjectAccount, err = resolveSubjectAccount(subjectAccountID)
	// 	if err != nil {
	// 		return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve BPI subject account; %s", err.Error())
	// 	}
	// }

	system, err = m.subjectAccount.resolveSystem(*m.Type)
	if err != nil {
		common.Log.Debugf("failed to resolve system for subject account for mapping type: %s", *m.Type)
		// return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve system for subject account for mapping type: %s", *m.Type)
	}

	baselineRecord = lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil {
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
			baselineContextID, _ := uuid.NewV4()
			m.BaselineID = &baselineContextID

			workflow, err = baselineWorkflowFactory(m.subjectAccount, *m.Type, nil)
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve workflow context; %s", err.Error())
			}
			common.Log.Debugf("resolved workflow context: %s", workflow.ID)

			if baselineContext == nil {
				common.Log.Debugf("initializing new baseline context with baseline id: %s", m.BaselineID)
				baselineContext = &BaselineContext{
					ID:         m.BaselineID,
					BaselineID: m.BaselineID,
					Records:    make([]*BaselineRecord, 0),
				}

				if workflow != nil {
					baselineContext.Workflow = workflow
					baselineContext.WorkflowID = &workflow.ID
				}
			}
		}

		if err != nil {
			common.Log.Warning(err.Error())
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})

			if system != nil {
				system.UpdateObjectStatus(*m.ID, map[string]interface{}{
					"errors":     m.Errors,
					"message_id": m.MessageID,
					"status":     middleware.SORBusinessObjectStatusError,
					"type":       *m.Type,
				})
			}

			return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve context; %s", err.Error())
		}
	} else {
		baselineContext = baselineRecord.Context
		if baselineContext == nil {
			err = fmt.Errorf("failed to lookup baseline context for given baseline id: %s", m.BaselineID.String())
		}

		workflow = baselineRecord.Context.Workflow
	}

	worksteps := FindWorkstepsByWorkflowID(workflow.ID)
	for _, wrkstp := range worksteps {
		if wrkstp.Status != nil && *wrkstp.Status == workstepStatusInit {
			workstep = FindWorkstepInstanceByID(wrkstp.ID)
			break
		}
	}

	return system, baselineContext, baselineRecord, workflow, workstep, err
}

func (m *ProtocolMessage) baselineInbound() bool {
	// FIXME-- this check should never be needed here
	if m.subjectAccount == nil {
		common.Log.Warning("subject account not resolved for inbound protocol message")
		return false
	}

	// FIXME-- use resolveContext() instead...
	var baselineContext *BaselineContext

	baselineRecord := lookupBaselineRecord(m.BaselineID.String())
	if baselineRecord == nil {
		var workflow *WorkflowInstance
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

			workflow, err = baselineWorkflowFactory(m.subjectAccount, *m.Type, common.StringOrNil(m.Identifier.String()))
			if err != nil {
				common.Log.Warningf("failed to initialize baseline workflow: %s", *m.Identifier)
				return false
			}

			workflow.Worksteps = make([]*WorkstepInstance, 0)
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
				baselineContext.WorkflowID = &workflow.ID
			}
		}

		baselineRecord = &BaselineRecord{
			BaselineID: m.BaselineID,
			ContextID:  baselineContext.ID,
			Type:       m.Type,
			Context:    baselineContext,
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

	system, err := m.subjectAccount.resolveSystem(*m.Type)
	if err != nil {
		common.Log.Warningf("failed to resolve system for subject account for mapping type: %s", *m.Type)
		return false
	}

	if baselineRecord.ID == nil {
		// TODO -- map baseline record id -> internal record id (i.e, this is currently done but lazily on outbound message)
		resp, err := system.CreateObject(map[string]interface{}{
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
		err := system.UpdateObject(*baselineRecord.ID, m.Payload.Object)
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

	if m.subjectAccount == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("subject account not resolved"),
		})
		return false
	}

	if m.token == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("access token not resolved"),
		})
		return false
	}

	if m.subjectAccount.Metadata == nil || m.subjectAccount.Metadata.SOR == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("invalid system configuration"),
		})
		return false
	}

	system, _, baselineRecord, workflow, _, err := m.resolveContext()
	if err != nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	err = baselineRecord.cache() // FIXME-- this is currently idempotent, but we should update the cached properties -- we will never cache or persist the payload itself...
	if err != nil {
		common.Log.Warning(err.Error())
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		system.UpdateObjectStatus(*m.ID, map[string]interface{}{
			"errors":     m.Errors,
			"message_id": m.MessageID,
			"status":     middleware.SORBusinessObjectStatusError,
			"type":       *m.Type,
		})
		return false
	}

	// for _, workstep := range workflow.Worksteps {
	// 	prover := workstep.Prover
	// 	workstep.Prover = &privacy.Prover{
	// 		Artifacts:     prover.Artifacts,
	// 		Name:          prover.Name,
	// 		Description:   prover.Description,
	// 		Identifier:    prover.Identifier,
	// 		Provider:      prover.Provider,
	// 		ProvingScheme: prover.ProvingScheme,
	// 		Curve:         prover.Curve,
	// 	}
	// }

	for _, recipient := range workflow.Participants {
		msg := &ProtocolMessage{
			BaselineID: baselineRecord.BaselineID,
			Opcode:     common.StringOrNil(baseline.ProtocolMessageOpcodeSync),
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
				_msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", *recipient.Address, err.Error())
				common.Log.Warning(_msg)
				m.Errors = append(m.Errors, &provide.Error{
					Message: common.StringOrNil(_msg),
				})
			}
		} else {
			common.Log.Warning("failed to dispatch protocol message to recipient; no recipient address")
		}
	}

	m.BaselineID = baselineRecord.BaselineID
	rawPayload, _ := json.Marshal(m.Payload)

	// FIXME-- the following is prover-specific and needs to be extracted into an interface
	var i big.Int
	hFunc := mimc.NewMiMC("seed")
	hFunc.Write(rawPayload)
	preImage := hFunc.Sum(nil)
	preImageString := i.SetBytes(preImage).String()

	hash, _ := mimc.Sum("seed", preImage)
	hashString := i.SetBytes(hash).String()

	var shieldAddress *string
	if baselineRecord.Context.Workflow != nil {
		shieldAddress = baselineRecord.Context.Workflow.Shield
	}

	m.ProtocolMessage = &ProtocolMessage{
		BaselineID: baselineRecord.BaselineID,
		Opcode:     common.StringOrNil(baseline.ProtocolMessageOpcodeBaseline),
		Identifier: baselineRecord.Context.WorkflowID,
		Payload: &ProtocolMessagePayload{
			Object: m.Payload.(map[string]interface{}),
			Type:   m.Type,
			Witness: map[string]interface{}{
				"Document.Hash":     hashString,
				"Document.Preimage": preImageString,
			},
		},
		Shield: shieldAddress,
		Type:   m.Type,
	}

	err = m.prove()
	if err != nil {
		msg := fmt.Sprintf("failed to prove outbound baseline protocol message; invalid state transition; %s", err.Error())
		common.Log.Warning(msg)
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		system.UpdateObjectStatus(*m.ID, map[string]interface{}{
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
		recipients = append(recipients, m.Recipients...)
	} else {
		recipients = append(recipients, baselineRecord.Context.Workflow.Participants...)
	}

	common.Log.Debugf("dispatching outbound protocol message intended for %d recipients", len(recipients))

	for _, recipient := range recipients {
		if recipient.Address != nil {
			common.Log.Debugf("dispatching outbound protocol message to %s", *recipient.Address)
			err := m.ProtocolMessage.broadcast(*recipient.Address)
			if err != nil {
				msg := fmt.Sprintf("failed to dispatch protocol message to recipient: %s; %s", *recipient.Address, err.Error())
				common.Log.Warning(msg)
				m.Errors = append(m.Errors, &provide.Error{
					Message: common.StringOrNil(msg),
				})
			}
		} else {
			common.Log.Warning("failed to dispatch protocol message to recipient; no recipient address")
		}
	}

	err = system.UpdateObjectStatus(*m.ID, map[string]interface{}{
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
	if strings.ToLower(recipient) == strings.ToLower(*m.subjectAccount.Metadata.OrganizationAddress) {
		common.Log.Debugf("skipping no-op protocol message broadcast to self: %s", recipient)
		return nil
	}

	payload, err := json.Marshal(&ProtocolMessage{
		BaselineID: m.BaselineID,
		Opcode:     m.Opcode,
		Sender:     m.Sender,
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

	token, err := vendOrganizationAccessToken(m.subjectAccount)
	if err != nil {
		return nil
	}

	index := len(baselineRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(baselineRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/prover at index: %d; index out of range", index)
	}
	prover := baselineRecord.Context.Workflow.Worksteps[index].Prover

	resp, err := privacy.Prove(*token, prover.ID.String(), map[string]interface{}{
		"witness": m.ProtocolMessage.Payload.Witness,
	})
	if err != nil {
		common.Log.Warningf("failed to prove prover: %s; %s", prover.ID, err.Error())
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

	token, err := vendOrganizationAccessToken(m.subjectAccount)
	if err != nil {
		return nil
	}

	index := len(baselineRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(baselineRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/prover at index: %d; index out of range", index)
	}
	prover := baselineRecord.Context.Workflow.Worksteps[index].Prover

	resp, err := privacy.Verify(*token, prover.ID.String(), map[string]interface{}{
		"store":   store,
		"proof":   m.Payload.Proof,
		"witness": m.Payload.Witness,
	})
	if err != nil {
		common.Log.Warningf("failed to verify: %s; %s", prover.ID, err.Error())
		return err
	}

	if !resp.Result {
		return fmt.Errorf("failed to verify prover: %s", prover.ID)
	}

	return nil
}
