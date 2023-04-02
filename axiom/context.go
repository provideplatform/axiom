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

// AxiomContext represents a collection of AxiomRecord instances in the context of a workflow
type AxiomContext struct {
	ID         *uuid.UUID        `sql:"-" json:"id,omitempty"`
	AxiomID    *uuid.UUID        `sql:"-" json:"axiom_id,omitempty"`
	Records    []*AxiomRecord    `sql:"-" json:"records,omitempty"`
	Workflow   *WorkflowInstance `sql:"-" json:"-"`
	WorkflowID *uuid.UUID        `sql:"-" json:"workflow_id"`
}

func (c *AxiomContext) cache() error {
	if c.AxiomID == nil {
		axiomID, _ := uuid.NewV4()
		c.AxiomID = &axiomID
	}

	var axiomIDKey *string
	if c.ID != nil {
		axiomIDKey = common.StringOrNil(fmt.Sprintf("axiom.context.id.%s", *c.ID))
	}
	axiomContextKey := fmt.Sprintf("axiom.context.%s", c.AxiomID)
	axiomContextMutexKey := fmt.Sprintf("axiom.context.mutex.%s", c.AxiomID)

	return redisutil.WithRedlock(axiomContextMutexKey, func() error {
		if axiomIDKey != nil {
			err := redisutil.Set(*axiomIDKey, c.AxiomID.String(), nil)
			if err != nil {
				common.Log.Warningf("failed to cache axiom context; %s", err.Error())
				return err
			}
			common.Log.Debugf("mapped internal context id to axiom id: %s; key: %s", c.AxiomID.String(), *axiomIDKey)
		}

		raw, _ := json.Marshal(c)
		err := redisutil.Set(axiomContextKey, raw, nil)
		if err != nil {
			common.Log.Warningf("failed to cache axiom context; failed to cache associated workflow; %s", err.Error())
			return err
		}
		common.Log.Debugf("mapped axiom context to axiom id: %s; key: %s", c.AxiomID.String(), axiomContextKey)

		if c.Workflow != nil {
			err := c.Workflow.Cache()
			if err != nil {
				common.Log.Warningf("failed to cache axiom context; failed to cache associated workflow; %s", err.Error())
				return err
			}
			common.Log.Debugf("cached axiom workflow: %s", c.Workflow.ID.String())

			err = c.Workflow.CacheByAxiomID(c.AxiomID.String())
			if err != nil {
				common.Log.Warningf("failed to cache axiom context; failed to index associated workflow by axiom id; %s", err.Error())
				return err
			}
			common.Log.Debugf("indexed axiom workflow by axiom id: %s", c.AxiomID.String())
		}

		return err
	})
}

func (c *AxiomContext) contains(record *AxiomRecord) bool {
	for _, rec := range c.Records {
		if rec.ID != nil && record.ID != nil && *rec.ID == *record.ID {
			return true
		}
	}
	return false
}

func lookupAxiomContext(axiomID string) *AxiomContext {
	var axiomContext *AxiomContext

	key := fmt.Sprintf("axiom.context.%s", axiomID)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("failed to retrieve cached axiom context: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &axiomContext)

	if axiomContext != nil && axiomContext.AxiomID != nil && axiomContext.AxiomID.String() == axiomID && axiomContext.WorkflowID != nil {
		axiomContext.Workflow = LookupAxiomWorkflow(axiomContext.WorkflowID.String())
		common.Log.Debugf("enriched workflow on axiom context instance; workflow id: %s", axiomContext.WorkflowID.String())
	}

	return axiomContext
}

// lookup a axiom context id using the internal system of record id
func lookupAxiomContextByInternalID(id string) *AxiomContext {
	key := fmt.Sprintf("axiom.context.id.%s", id)
	axiomID, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached axiom context for internal id: %s; %s", key, err.Error())
		return nil
	}

	return lookupAxiomContext(*axiomID)
}
