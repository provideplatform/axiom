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

package axiom

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	dbconf "github.com/kthomas/go-db-config"
	esutil "github.com/kthomas/go-elasticsearchutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/olivere/elastic/v7"
	"github.com/provideplatform/axiom/common"
	"github.com/provideplatform/axiom/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/privacy"
)

// InvertedIndexMessagePayload document type for indexing an arbitrary
// `axiom_id` against one or more arbitrary values
type InvertedIndexMessagePayload struct {
	AxiomID *uuid.UUID    `json:"axiom_id"`
	Values  []interface{} `json:"values"`
}

// WorkflowPrototypeMessagePayload document type for indexing the initial
// workstep object type and a list of the ordered workstep object types
// against a given `workflow_id` which references a valid workflow prototype
type WorkflowPrototypeMessagePayload struct {
	InitialWorkstepObjectType string     `json:"initial_workstep_object_type,omitempty"`
	WorkgroupID               *uuid.UUID `json:"workgroup_id"`
	WorkflowID                *uuid.UUID `json:"workflow_id"`
	WorkstepObjectTypes       []string   `json:"workstep_object_types,omitempty"`
}

func (m *ProtocolMessage) index() error {
	common.Log.Debugf("attempting to index protocol message payload with axiom id: %s", m.AxiomID)

	msg := &InvertedIndexMessagePayload{
		AxiomID: m.AxiomID,
		Values:  make([]interface{}, 0),
	}

	// FIXME-- extract the following into a utility function
	for k, v := range m.Payload.Object {
		if strings.Contains(strings.ToLower(k), "id") { // FIXME
			msg.Values = append(msg.Values, v)
		}
	}

	payload, _ := json.Marshal(msg)

	common.Indexer.Q(&esutil.Message{
		Header: &esutil.MessageHeader{
			Index: common.StringOrNil(common.IndexerDocumentIndexAxiomContextInverted),
		},
		Payload: payload,
	})
	return nil
}

func (m *Message) query() (*AxiomContext, error) {
	// FIXME-- extract the following into a utility function
	values := make([]interface{}, 0)
	if payload, payloadOk := m.Payload.(map[string]interface{}); payloadOk {
		for k, v := range payload {
			if strings.Contains(strings.ToLower(k), "id") && v != nil {
				values = append(values, v)
			}
		}
	}
	values = append(values, *m.ID)

	tq := elastic.NewTermsQuery("values", values...) // terms query over the indexed `values` field
	result, err := common.ElasticClient.Search().Index(common.IndexerDocumentIndexAxiomContextInverted).Query(tq).Do(context.TODO())
	if err != nil {
		return nil, err
	}

	var ctx *AxiomContext
	results := make([]*InvertedIndexMessagePayload, 0)

	for _, hit := range result.Hits.Hits {
		var msg *InvertedIndexMessagePayload
		err := json.Unmarshal(hit.Source, &msg)
		if err != nil {
			return nil, err
		}

		results = append(results, msg)
	}

	if len(results) > 0 {
		ctx = lookupAxiomContext(m.AxiomID.String())
		if ctx == nil {
			err = fmt.Errorf("failed to lookup axiom context for given axiom id: %s", m.AxiomID.String())
			return nil, err
		}
	}

	return ctx, nil
}

// resolveWorkstepContext is a convenience method to resolve the workstep context
// alongside other relevant items... TODO-- memoize this so it can be reused nicely
func (m *Message) resolveContext() (middleware.SOR, *AxiomContext, *AxiomRecord, *WorkflowInstance, *WorkstepInstance, error) {
	var system middleware.SOR
	var axiomContext *AxiomContext
	var axiomRecord *AxiomRecord
	var workflow *WorkflowInstance
	var workstep *WorkstepInstance
	var err error

	// if m.subjectAccount == nil {
	// 	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	// 	m.subjectAccount, err = resolveSubjectAccount(subjectAccountID, nil)
	// 	if err != nil {
	// 		return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve BPI subject account; %s", err.Error())
	// 	}
	// }

	system, err = m.subjectAccount.resolveSystem(*m.Type)
	if err != nil {
		common.Log.Debugf("no system resolved for subject account for mapping type: %s", *m.Type)
		err = nil
		// return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve system for subject account for mapping type: %s", *m.Type)
	}

	axiomRecord = lookupAxiomRecordByInternalID(*m.ID)
	if axiomRecord == nil {
		// this is a record we have not seen before...
		// if certain criteria are met, a new workflow instance will be created.
		// note that it is also possible that the `id` provided in the message is
		// associated with an existing workflow instance...

		if m.AxiomID == nil {
			// no axiom id is provided... attempt to resolve the workflow context using the inverted index
			ctx, err := m.query()
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve workflow context; %s", err.Error())
			}

			if ctx == nil {
				// we were unable to resolve a lineage for this document linked to any related workflow instances
				// we will now initialize a new context and workflow instance...
				axiomContextID, _ := uuid.NewV4()
				m.AxiomID = &axiomContextID

				workflow, err = axiomWorkflowFactory(m.subjectAccount, *m.Type, nil)
				if err != nil {
					return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve workflow context; %s", err.Error())
				}
				common.Log.Debugf("resolved workflow context: %s", workflow.ID)

				if axiomContext == nil {
					common.Log.Debugf("initializing new axiom context with axiom id: %s", m.AxiomID)
					axiomContext = &AxiomContext{
						ID:      m.AxiomID,
						AxiomID: m.AxiomID,
						Records: make([]*AxiomRecord, 0),
					}

					if workflow != nil {
						axiomContext.Workflow = workflow
						axiomContext.WorkflowID = &workflow.ID
					}
				}

				if axiomRecord == nil {
					axiomRecord = &AxiomRecord{
						AxiomID:   m.AxiomID,
						Context:   axiomContext,
						ContextID: axiomContext.ID,
						Type:      m.Type,
					}

					err = axiomRecord.cache()
					if err != nil {
						return nil, nil, nil, nil, nil, fmt.Errorf("failed to cache axiom record for newly-initialized context: %s; %s", m.AxiomID.String(), err.Error())
					}
				}
			} else {
				// any sufficiently advanced technology is indistinguishable from magic ;)
				workflow = ctx.Workflow
			}
		} else {
			// this supports custom applications which are "workflow-aware" and
			// pass a `axiom_id` as part of the message; most of our supported
			// system middleware implementations will never send this in order
			// to keep those implementations light clients...
			axiomContext = lookupAxiomContext(m.AxiomID.String())
			if axiomContext == nil {
				err = fmt.Errorf("failed to lookup axiom context for given axiom id: %s", m.AxiomID.String())
			}

			workflow = lookupAxiomWorkflowByAxiomID(m.AxiomID.String())
			if workflow == nil {
				err = fmt.Errorf("failed to lookup workflow for given axiom id: %s", m.AxiomID.String())
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
		// we have seen this record before and looked up the context...
		axiomContext = axiomRecord.Context
		if axiomContext == nil {
			err = fmt.Errorf("failed to lookup axiom context for given axiom id: %s", m.AxiomID.String())
		}

		workflow = axiomRecord.Context.Workflow
	}

	// we need only the workflow to be non-nil at this point!
	// we can now proceed to resolve the workstep context...

	worksteps := FindWorkstepInstancesByWorkflowID(workflow.ID)
	for _, wrkstp := range worksteps {
		if wrkstp.Status != nil && *wrkstp.Status == workstepStatusInit {
			workstep = wrkstp
			break
		}
	}

	if len(workstep.Participants) == 0 {
		common.Log.Debugf("enriching workstep context participants for resolved workstep id: %s", workstep.ID)
		for _, participant := range workstep.listParticipants(dbconf.DatabaseConnection()) {
			workstep.Participants = append(workstep.Participants, &Participant{
				Address: participant.Participant, // HACK
			})
		}
	}

	return system, axiomContext, axiomRecord, workflow, workstep, err
}

func (m *ProtocolMessage) axiomInbound() bool {
	// FIXME-- this check should never be needed here
	if m.subjectAccount == nil {
		common.Log.Warning("subject account not resolved for inbound protocol message")
		return false
	}

	// FIXME-- use resolveContext() instead...
	var axiomContext *AxiomContext

	axiomRecord := lookupAxiomRecord(m.AxiomID.String())
	if axiomRecord == nil {
		var workflow *WorkflowInstance
		var err error

		if m.WorkflowID != nil {
			workflow = LookupAxiomWorkflow(m.WorkflowID.String())
		}

		if m.AxiomID != nil {
			axiomContext = lookupAxiomContext(m.AxiomID.String())

			if workflow == nil {
				workflow = lookupAxiomWorkflowByAxiomID(m.AxiomID.String())
				if workflow == nil && axiomContext != nil {
					workflow = axiomContext.Workflow
				}
			}
		}

		if workflow == nil {
			common.Log.Debugf("initializing axiom workflow: %s", *m.WorkflowID)

			var workflowID *string
			if m.WorkflowID != nil {
				workflowID = common.StringOrNil(m.WorkflowID.String())
			}

			workflow, err = axiomWorkflowFactory(m.subjectAccount, *m.Type, workflowID)
			if err != nil {
				common.Log.Warningf("failed to initialize axiom workflow: %s", *m.WorkflowID)
				return false
			}

			workflow.Worksteps = make([]*WorkstepInstance, 0)
		}

		if axiomContext == nil {
			common.Log.Debug("initializing new axiom context...")

			axiomContextID, _ := uuid.NewV4()
			axiomContext = &AxiomContext{
				ID:      &axiomContextID,
				AxiomID: m.AxiomID,
				Records: make([]*AxiomRecord, 0),
			}

			if workflow != nil {
				axiomContext.Workflow = workflow
				axiomContext.WorkflowID = &workflow.ID
			}
		}

		axiomRecord = &AxiomRecord{
			AxiomID:   m.AxiomID,
			ContextID: axiomContext.ID,
			Type:      m.Type,
			Context:   axiomContext,
		}

		err = axiomRecord.cache()
		if err != nil {
			common.Log.Warning(err.Error())
			return false
		}

		common.Log.Debugf("inbound axiom protocol message initialized axiom record; axiom id: %s; workflow id: %s; type: %s", m.AxiomID.String(), m.WorkflowID.String(), *m.Type)
	}

	err := m.verify(true)
	if err != nil {
		common.Log.Warningf("failed to verify inbound axiom protocol message; invalid state transition; %s", err.Error())
		return false
	}

	system, err := m.subjectAccount.resolveSystem(*m.Type)
	if err != nil {
		common.Log.Warningf("failed to resolve system for subject account for mapping type: %s", *m.Type)
		return false
	}

	if axiomRecord.ID == nil {
		// TODO -- map axiom record id -> internal record id (i.e, this is currently done but lazily on outbound message)
		resp, err := system.CreateObject(map[string]interface{}{
			"axiom_id": axiomRecord.AxiomID.String(),
			"payload":  m.Payload.Object,
			"type":     m.Type,
		})
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound axiom; %s", err.Error())
			return false
		}
		common.Log.Debugf("received response from internal system of record; %s", resp)

		const defaultIDField = "id"

		if id, idOk := resp.(map[string]interface{})[defaultIDField].(string); idOk {
			axiomRecord.ID = common.StringOrNil(id)
			axiomRecord.cache()
		} else {
			common.Log.Warning("failed to create business object during inbound axiom; no id present in response")
			return false
		}
	} else {
		err := system.UpdateObject(*axiomRecord.ID, m.Payload.Object)
		if err != nil {
			common.Log.Warningf("failed to create business object during inbound axiom; %s", err.Error())
			return false
		}
	}

	go m.index()

	return true
}

// prove generates a zk proof using the underlying message
// TODO-- this is deprecated and currently unused; it should likely be removed
func (m *Message) prove() error {
	axiomRecord := lookupAxiomRecordByInternalID(*m.ID)
	if axiomRecord == nil {
		common.Log.Debugf("no axiom record resolved for internal identifier: %s", *m.ID)
	}

	token, err := vendOrganizationAccessToken(m.subjectAccount)
	if err != nil {
		return nil
	}

	index := len(axiomRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(axiomRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/prover at index: %d; index out of range", index)
	}
	prover := axiomRecord.Context.Workflow.Worksteps[index].Prover

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

// verify the underlying protocol message, optionally storing
// the proof for the associated workstep
func (m *ProtocolMessage) verify(store bool) error {
	axiomRecord := lookupAxiomRecord(m.AxiomID.String())
	if axiomRecord == nil {
		common.Log.Debugf("no axiom record cached for axiom record id: %s", m.AxiomID.String())
	}

	token, err := vendOrganizationAccessToken(m.subjectAccount)
	if err != nil {
		return nil
	}

	index := len(axiomRecord.Context.Workflow.Worksteps) - 1
	if index < 0 || index >= len(axiomRecord.Context.Workflow.Worksteps) {
		return fmt.Errorf("failed to resolve workstep/prover at index: %d; index out of range", index)
	}
	prover := axiomRecord.Context.Workflow.Worksteps[index].Prover

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
