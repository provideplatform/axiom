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

// BaselineContext represents a collection of BaselineRecord instances in the context of a workflow
type BaselineContext struct {
	baseline.BaselineContext
	Records  []*BaselineRecord `sql:"-" json:"records,omitempty"`
	Workflow *WorkflowInstance `sql:"-" json:"-"`
}

func (c *BaselineContext) cache() error {
	if c.BaselineID == nil {
		baselineID, _ := uuid.NewV4()
		c.BaselineID = &baselineID
	}

	var baselineIDKey *string
	if c.ID != nil {
		baselineIDKey = common.StringOrNil(fmt.Sprintf("baseline.context.id.%s", *c.ID))
	}
	baselineContextKey := fmt.Sprintf("baseline.context.%s", c.BaselineID)
	baselineContextMutexKey := fmt.Sprintf("baseline.context.mutex.%s", c.BaselineID)

	return redisutil.WithRedlock(baselineContextMutexKey, func() error {
		if baselineIDKey != nil {
			err := redisutil.Set(*baselineIDKey, c.BaselineID.String(), nil)
			if err != nil {
				common.Log.Warningf("failed to cache baseline context; %s", err.Error())
				return err
			}
			common.Log.Debugf("mapped internal context id to baseline id: %s; key: %s", c.BaselineID.String(), *baselineIDKey)
		}

		raw, _ := json.Marshal(c)
		err := redisutil.Set(baselineContextKey, raw, nil)
		if err != nil {
			common.Log.Warningf("failed to cache baseline context; failed to cache associated workflow; %s", err.Error())
			return err
		}
		common.Log.Debugf("mapped baseline context to baseline id: %s; key: %s", c.BaselineID.String(), baselineContextKey)

		if c.Workflow != nil {
			err := c.Workflow.Cache()
			if err != nil {
				common.Log.Warningf("failed to cache baseline context; failed to cache associated workflow; %s", err.Error())
				return err
			}
			common.Log.Debugf("cached baseline workflow: %s", c.Workflow.ID.String())

			err = c.Workflow.CacheByBaselineID(c.BaselineID.String())
			if err != nil {
				common.Log.Warningf("failed to cache baseline context; failed to index associated workflow by baseline id; %s", err.Error())
				return err
			}
			common.Log.Debugf("indexed baseline workflow by baseline id: %s", c.BaselineID.String())
		}

		return err
	})
}

func (c *BaselineContext) contains(record *BaselineRecord) bool {
	for _, rec := range c.Records {
		if rec.ID != nil && record.ID != nil && *rec.ID == *record.ID {
			return true
		}
	}
	return false
}

func lookupBaselineContext(baselineID string) *BaselineContext {
	var baselineContext *BaselineContext

	key := fmt.Sprintf("baseline.context.%s", baselineID)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached baseline context: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &baselineContext)

	if baselineContext != nil && baselineContext.BaselineID != nil && baselineContext.BaselineID.String() == baselineID && baselineContext.WorkflowID != nil {
		baselineContext.Workflow = LookupBaselineWorkflow(baselineContext.WorkflowID.String())
		common.Log.Debugf("enriched workflow on baseline context instance; workflow id: %s", baselineContext.WorkflowID.String())
	}

	return baselineContext
}

// lookup a baseline context id using the internal system of record id
func lookupBaselineContextByInternalID(id string) *BaselineContext {
	key := fmt.Sprintf("baseline.context.id.%s", id)
	baselineID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline context for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupBaselineContext(*baselineID)
}
