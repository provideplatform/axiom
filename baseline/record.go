/*
 *
 *  * Copyright 2017-2022 Provide Technologies Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 *
 *
 */

package baseline

import (
	"encoding/json"
	"fmt"

	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api/baseline"
)

// BaselineRecord represents a link between an object in the internal system of record
// and the external BaselineContext
type BaselineRecord struct {
	baseline.BaselineRecord
	Context *BaselineContext `sql:"-" json:"-"`
}

func (r *BaselineRecord) cache() error {
	if r.BaselineID == nil {
		baselineID, _ := uuid.NewV4()
		r.BaselineID = &baselineID

		if r.Context != nil {
			r.Context.BaselineID = &baselineID
		}
	}

	var baselineIDKey *string
	if r.ID != nil {
		baselineIDKey = common.StringOrNil(fmt.Sprintf("baseline.record.id.%s", *r.ID))
	}
	baselineRecordKey := fmt.Sprintf("baseline.record.%s", r.BaselineID)
	baselineRecordMutexKey := fmt.Sprintf("baseline.record.mutex.%s", r.BaselineID)

	return redisutil.WithRedlock(baselineRecordMutexKey, func() error {
		if baselineIDKey != nil {
			err := redisutil.Set(*baselineIDKey, r.BaselineID.String(), nil)
			if err != nil {
				common.Log.Warningf("failed to cache baseline record; %s", err.Error())
				return err
			}
			common.Log.Debugf("mapped internal system of record id to baseline id: %s; key: %s", r.BaselineID.String(), *baselineIDKey)
		}

		raw, _ := json.Marshal(r)
		err := redisutil.Set(baselineRecordKey, raw, nil)
		if err != nil {
			common.Log.Warningf("failed to cache baseline record; failed to cache associated workflow; %s", err.Error())
			return err
		}
		common.Log.Debugf("mapped baseline record to baseline id: %s; key: %s", r.BaselineID.String(), baselineRecordKey)

		if r.Context != nil {
			if !r.Context.contains(r) {
				r.Context.Records = append(r.Context.Records, r)
			}

			err := r.Context.cache()
			if err != nil {
				common.Log.Warningf("failed to cache baseline record; failed to cache associated context; %s", err.Error())
				return err
			}
		}

		return err
	})
}

func (r *BaselineRecord) resolveExecutableWorkstepContext() (*baseline.WorkstepInstance, error) {
	if r.Context == nil && r.Context.Workflow == nil {
		return nil, fmt.Errorf("failed to resolve workflow context for baseline record: %s", *r.ID)
	}

	for _, workstep := range r.Context.Workflow.Worksteps {
		if workstep.Status != nil && *workstep.Status == workstepStatusInit {
			return workstep, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve executable workstep context from resolved workflow context for baseline record: %s", *r.ID)
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

	if baselineRecord != nil && baselineRecord.BaselineID != nil && baselineRecord.BaselineID.String() == baselineID && baselineRecord.ContextID != nil {
		baselineRecord.Context = lookupBaselineContext(baselineRecord.BaselineID.String())
		if baselineRecord.Context != nil && baselineRecord.Context.WorkflowID != nil {
			baselineRecord.Context.Workflow = LookupBaselineWorkflow(baselineRecord.Context.WorkflowID.String())
			common.Log.Debugf("enriched workflow on baseline record context instance; workflow id: %s", baselineRecord.Context.WorkflowID.String())
		}
	}

	return baselineRecord
}

// lookup a baseline record using the internal system of record id
func lookupBaselineRecordByInternalID(id string) *BaselineRecord {
	key := fmt.Sprintf("baseline.record.id.%s", id)
	baselineID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline id for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupBaselineRecord(*baselineID)
}
