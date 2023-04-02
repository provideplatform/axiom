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
	"errors"
	"fmt"
	"time"

	"github.com/kthomas/go-redisutil"
)

// Participant is a party to a axiom workgroup or workflow context
type Participant struct {
	Metadata          map[string]interface{} `sql:"-" json:"metadata,omitempty"`
	BPIEndpoint       *string                `sql:"-" json:"bpi_endpoint,omitempty"`
	MessagingEndpoint *string                `sql:"-" json:"messaging_endpoint,omitempty"`
	WebsocketEndpoint *string                `sql:"-" json:"websocket_endpoint,omitempty"`

	Address    *string      `gorm:"column:participant" json:"address"`
	Workgroups []*Workgroup `sql:"-" json:"workgroups,omitempty"`
	Workflows  []*Workflow  `sql:"-" json:"workflows,omitempty"`
	Worksteps  []*Workstep  `sql:"-" json:"worksteps,omitempty"`
}

// WorkgroupParticipant is a party to a axiom workgroup
type WorkgroupParticipant struct {
	Participant *string     `json:"address"`
	Proof       *string     `json:"proof"`
	Witness     interface{} `json:"witness"`
	WitnessedAt *time.Time  `json:"witnessed_at"`
}

// WorkflowParticipant is a party to a axiom workflow
type WorkflowParticipant struct {
	Participant *string     `json:"address"`
	Proof       *string     `json:"proof"`
	Witness     interface{} `json:"witness"`
	WitnessedAt *time.Time  `json:"witnessed_at"`
}

// WorkstepParticipant is a party to a axiom workstep
type WorkstepParticipant struct {
	Participant *string     `json:"address"`
	Proof       *string     `json:"proof"`
	Witness     interface{} `json:"witness"`
	WitnessedAt *time.Time  `json:"witnessed_at"`
}

func (p *Participant) Cache() error {
	if p.Address == nil {
		return errors.New("failed to cache participant with nil address")
	}

	key := fmt.Sprintf("axiom.organization.%s", *p.Address)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(p)
		return redisutil.Set(key, raw, nil)
	})
}
