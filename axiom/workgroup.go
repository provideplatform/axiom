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
	"time"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/axiom/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/ident"
)

const requireCounterpartiesSleepInterval = time.Second * 15
const requireCounterpartiesTickerInterval = time.Second * 30 // HACK

// Workgroup is a axiom workgroup prototype
type Workgroup struct {
	provide.Model
	Participants       []*Participant `sql:"-" json:"participants,omitempty"`
	Shield             *string        `json:"shield,omitempty"`
	Workflows          []*Workflow    `sql:"-" json:"workflows,omitempty"`
	PrivacyPolicy      interface{}    `json:"privacy_policy"`      // outlines data visibility rules for each participant
	SecurityPolicy     interface{}    `json:"security_policy"`     // consists of authentication and authorization rules for the workgroup participants
	TokenizationPolicy interface{}    `json:"tokenization_policy"` // consists of policies governing tokenization of workflow outputs

	Name           *string     `json:"name"`
	Description    *string     `json:"description"`
	Config         interface{} `sql:"-" json:"config"`
	NetworkID      *uuid.UUID  `sql:"-" json:"network_id"`
	OrganizationID *uuid.UUID  `json:"-"`
}

// FindWorkgroupByID retrieves a workgroup for the given id
func FindWorkgroupByID(id uuid.UUID) *Workgroup {
	db := dbconf.DatabaseConnection()
	workgroup := &Workgroup{}
	db.Where("id = ?", id.String()).Find(&workgroup)
	if workgroup == nil || workgroup.ID == uuid.Nil {
		return nil
	}
	return workgroup
}

func init() {
	redisutil.RequireRedis()
}

func LookupAxiomWorkgroup(identifier string) *Workgroup {
	var workgroup *Workgroup

	key := fmt.Sprintf("axiom.workgroup.%s", identifier)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("no axiom workgroup cached for key: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &workgroup)
	return workgroup
}

func (w *Workgroup) Create() bool {
	if !w.Validate() {
		return false
	}

	newRecord := w.ID == uuid.Nil || FindWorkgroupByID(w.ID) == nil
	success := false

	if newRecord {
		db := dbconf.DatabaseConnection()
		result := db.Create(&w)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}

		success = rowsAffected > 0
	}

	return success
}

func (w *Workgroup) Update(other *Workgroup) bool {
	if !other.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if other.Name != nil {
		w.Name = other.Name
	}

	if other.Description != nil {
		w.Description = other.Description
	}

	// privacy_policy ?
	// security_policy ?
	// tokenization_policy ?

	// broadcast changes ?

	result := tx.Save(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	success := rowsAffected >= 1 && len(errors) == 0
	if success {
		tx.Commit()
	}

	return success
}

func (w *Workgroup) participantsCount(tx *gorm.DB) int {
	rows, err := tx.Raw("SELECT count(*) FROM workgroups_participants WHERE workgroup_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to read workgroup participants count; %s", err.Error())
		return 0
	}

	var len int
	for rows.Next() {
		err = rows.Scan(&len)
		if err != nil {
			common.Log.Warningf("failed to read workgroup participants count; %s", err.Error())
			return 0
		}
	}

	return len
}

func (w *Workgroup) listParticipants(tx *gorm.DB) []*WorkgroupParticipant {
	participants := make([]*WorkgroupParticipant, 0)
	rows, err := tx.Raw("SELECT * FROM workgroups_participants WHERE workgroup_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to list workgroup participants; %s", err.Error())
		return participants
	}

	for rows.Next() {
		p := &WorkgroupParticipant{}
		err = tx.ScanRows(rows, &p)
		if err != nil {
			common.Log.Warningf("failed to list workgroup participants; %s", err.Error())
			return participants
		}
		participants = append(participants, p)
	}

	return participants
}

func (w *Workgroup) addParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("adding participant %s to workgroup: %s", participant, w.ID)
	result := tx.Exec("INSERT INTO workgroups_participants (workgroup_id, participant) VALUES (?, ?)", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added participant %s from workgroup: %s", participant, w.ID)
	} else {
		common.Log.Tracef("participant %s not added to workgroup: %s", participant, w.ID)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}

	return len(w.Errors) == 0
}

func (w *Workgroup) removeParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("removing participant %s to workgroup: %s", participant, w.ID)
	result := tx.Exec("DELETE FROM workgroups_participants WHERE workgroup_id=? AND participant=?", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed participant %s from workgroup: %s", participant, w.ID)
	} else {
		common.Log.Tracef("participant %s not removed from workgroup: %s", participant, w.ID)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}

	return len(w.Errors) == 0
}

func (w *Workgroup) Validate() bool {
	return true
}

func (w *Workgroup) Enrich(token string) bool {
	app, err := ident.GetApplicationDetails(token, w.ID.String(), map[string]interface{}{})
	if err != nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	w.Config = app.Config
	w.NetworkID = &app.NetworkID

	return len(w.Errors) == 0
}
