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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	dbconf "github.com/kthomas/go-db-config"
	esutil "github.com/kthomas/go-elasticsearchutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/olivere/elastic/v7"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/privacy"
)

// InvertedIndexMessagePayload document type for indexing an arbitrary
// `baseline_id` against one or more arbitrary values
type InvertedIndexMessagePayload struct {
	BaselineID *uuid.UUID    `json:"baseline_id"`
	Values     []interface{} `json:"values"`
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
	common.Log.Debugf("attempting to index protocol message payload with baseline id: %s", m.BaselineID)

	msg := &InvertedIndexMessagePayload{
		BaselineID: m.BaselineID,
		Values:     make([]interface{}, 0),
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
			Index: common.StringOrNil(common.IndexerDocumentIndexBaselineContextInverted),
		},
		Payload: payload,
	})
	return nil
}

func (m *Message) query() (*BaselineContext, error) {
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
	result, err := common.ElasticClient.Search().Index(common.IndexerDocumentIndexBaselineContextInverted).Query(tq).Do(context.TODO())
	if err != nil {
		return nil, err
	}

	var ctx *BaselineContext
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
		ctx = lookupBaselineContext(m.BaselineID.String())
		if ctx == nil {
			err = fmt.Errorf("failed to lookup baseline context for given baseline id: %s", m.BaselineID.String())
			return nil, err
		}
	}

	return ctx, nil
}

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
		common.Log.Debugf("no system resolved for subject account for mapping type: %s", *m.Type)
		err = nil
		// return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve system for subject account for mapping type: %s", *m.Type)
	}

	baselineRecord = lookupBaselineRecordByInternalID(*m.ID)
	if baselineRecord == nil {
		// this is a record we have not seen before...
		// if certain criteria are met, a new workflow instance will be created.
		// note that it is also possible that the `id` provided in the message is
		// associated with an existing workflow instance...

		if m.BaselineID == nil {
			// no baseline id is provided... attempt to resolve the workflow context using the inverted index
			ctx, err := m.query()
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("failed to resolve workflow context; %s", err.Error())
			}

			if ctx == nil {
				// we were unable to resolve a lineage for this document linked to any related workflow instances
				// we will now initialize a new context and workflow instance...
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

				if baselineRecord == nil {
					baselineRecord = &BaselineRecord{
						BaselineID: m.BaselineID,
						Context:    baselineContext,
						ContextID:  baselineContext.ID,
						Type:       m.Type,
					}

					err = baselineRecord.cache()
					if err != nil {
						return nil, nil, nil, nil, nil, fmt.Errorf("failed to cache baseline record for newly-initialized context: %s; %s", m.BaselineID.String(), err.Error())
					}
				}
			} else {
				// any sufficiently advanced technology is indistinguishable from magic ;)
				workflow = ctx.Workflow
			}
		} else {
			// this supports custom applications which are "workflow-aware" and
			// pass a `baseline_id` as part of the message; most of our supported
			// system middleware implementations will never send this in order
			// to keep those implementations light clients...
			baselineContext = lookupBaselineContext(m.BaselineID.String())
			if baselineContext == nil {
				err = fmt.Errorf("failed to lookup baseline context for given baseline id: %s", m.BaselineID.String())
			}

			workflow = lookupBaselineWorkflowByBaselineID(m.BaselineID.String())
			if workflow == nil {
				err = fmt.Errorf("failed to lookup workflow for given baseline id: %s", m.BaselineID.String())
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
		baselineContext = baselineRecord.Context
		if baselineContext == nil {
			err = fmt.Errorf("failed to lookup baseline context for given baseline id: %s", m.BaselineID.String())
		}

		workflow = baselineRecord.Context.Workflow
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

		if m.WorkflowID != nil {
			workflow = LookupBaselineWorkflow(m.WorkflowID.String())
		}

		if m.BaselineID != nil {
			baselineContext = lookupBaselineContext(m.BaselineID.String())

			if workflow == nil {
				workflow = lookupBaselineWorkflowByBaselineID(m.BaselineID.String())
				if workflow == nil && baselineContext != nil {
					workflow = baselineContext.Workflow
				}
			}
		}

		if workflow == nil {
			common.Log.Debugf("initializing baseline workflow: %s", *m.WorkflowID)

			var workflowID *string
			if m.WorkflowID != nil {
				workflowID = common.StringOrNil(m.WorkflowID.String())
			}

			workflow, err = baselineWorkflowFactory(m.subjectAccount, *m.Type, workflowID)
			if err != nil {
				common.Log.Warningf("failed to initialize baseline workflow: %s", *m.WorkflowID)
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

		common.Log.Debugf("inbound baseline protocol message initialized baseline record; baseline id: %s; workflow id: %s; type: %s", m.BaselineID.String(), m.WorkflowID.String(), *m.Type)
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

	go m.index()

	return true
}

// prove generates a zk proof using the underlying message
// TODO-- this is deprecated and currently unused; it should likely be removed
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

// verify the underlying protocol message, optionally storing
// the proof for the associated workstep
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
