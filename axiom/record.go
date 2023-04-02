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
	"encoding/json"
	"fmt"

	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/axiom/common"
)

// AxiomRecord represents a link between an object in the internal system of record
// and the external AxiomContext
type AxiomRecord struct {
	ID        *string       `sql:"-" json:"id,omitempty"`
	AxiomID   *uuid.UUID    `sql:"-" json:"axiom_id,omitempty"`
	Context   *AxiomContext `sql:"-" json:"-"`
	ContextID *uuid.UUID    `sql:"-" json:"context_id"`
	Type      *string       `sql:"-" json:"type"`
}

func (r *AxiomRecord) cache() error {
	if r.AxiomID == nil {
		axiomID, _ := uuid.NewV4()
		r.AxiomID = &axiomID

		if r.Context != nil {
			r.Context.AxiomID = &axiomID
		}

		common.Log.Debugf("generated new axiom id for association with axiom record and associated context: %s", r.AxiomID.String())
	}

	common.Log.Debugf("attempting to cache axiom record and associated context with axiom id: %s", r.AxiomID.String())

	var axiomIDKey *string
	if r.ID != nil {
		axiomIDKey = common.StringOrNil(fmt.Sprintf("axiom.record.id.%s", *r.ID))
	}
	axiomRecordKey := fmt.Sprintf("axiom.record.%s", r.AxiomID)
	axiomRecordMutexKey := fmt.Sprintf("axiom.record.mutex.%s", r.AxiomID)

	return redisutil.WithRedlock(axiomRecordMutexKey, func() error {
		if axiomIDKey != nil {
			err := redisutil.Set(*axiomIDKey, r.AxiomID.String(), nil)
			if err != nil {
				common.Log.Warningf("failed to cache axiom record; %s", err.Error())
				return err
			}
			common.Log.Debugf("mapped internal system of record id to axiom id: %s; key: %s", r.AxiomID.String(), *axiomIDKey)
		}

		raw, _ := json.Marshal(r)
		err := redisutil.Set(axiomRecordKey, raw, nil)
		if err != nil {
			common.Log.Warningf("failed to cache axiom record; failed to cache associated workflow; %s", err.Error())
			return err
		}
		common.Log.Debugf("mapped axiom record to axiom id: %s; key: %s", r.AxiomID.String(), axiomRecordKey)

		if r.Context != nil {
			if !r.Context.contains(r) {
				r.Context.Records = append(r.Context.Records, r)
			}

			err := r.Context.cache()
			if err != nil {
				common.Log.Warningf("failed to cache axiom record; failed to cache associated context; %s", err.Error())
				return err
			}
		}

		return err
	})
}

func (r *AxiomRecord) resolveExecutableWorkstepContext() (*WorkstepInstance, error) {
	if r.Context == nil && r.Context.Workflow == nil {
		return nil, fmt.Errorf("failed to resolve workflow context for axiom record: %s", *r.ID)
	}

	for _, workstep := range r.Context.Workflow.Worksteps {
		if workstep.Status != nil && *workstep.Status == workstepStatusInit {
			return workstep, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve executable workstep context from resolved workflow context for axiom record: %s", *r.ID)
}

func lookupAxiomRecord(axiomID string) *AxiomRecord {
	var axiomRecord *AxiomRecord

	key := fmt.Sprintf("axiom.record.%s", axiomID)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached axiom record: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &axiomRecord)

	if axiomRecord != nil && axiomRecord.AxiomID != nil && axiomRecord.AxiomID.String() == axiomID && axiomRecord.ContextID != nil {
		axiomRecord.Context = lookupAxiomContext(axiomRecord.AxiomID.String())
		if axiomRecord.Context != nil && axiomRecord.Context.WorkflowID != nil {
			axiomRecord.Context.Workflow = LookupAxiomWorkflow(axiomRecord.Context.WorkflowID.String())
			common.Log.Debugf("enriched workflow on axiom record context instance; workflow id: %s", axiomRecord.Context.WorkflowID.String())
		}
	}

	return axiomRecord
}

// lookup a axiom record using the internal system of record id
func lookupAxiomRecordByInternalID(id string) *AxiomRecord {
	key := fmt.Sprintf("axiom.record.id.%s", id)
	axiomID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached axiom id for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupAxiomRecord(*axiomID)
}
