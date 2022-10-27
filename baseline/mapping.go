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

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
)

// Mapping is a baseline mapping prototype
type Mapping struct {
	provide.Model
	Models      []*MappingModel `sql:"-" json:"models"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	Type        *string         `json:"type"`

	OrganizationID *uuid.UUID `json:"organization_id"`
	Ref            *string    `json:"ref,omitempty"`
	RefMappingID   *uuid.UUID `json:"ref_mapping_id"`
	Version        *string    `json:"version"`
	WorkgroupID    *uuid.UUID `json:"workgroup_id"`
}

// MappingModel is a baseline mapping model prototype
type MappingModel struct {
	provide.Model
	Description *string `json:"description"`
	PrimaryKey  *string `json:"primary_key"`
	Standard    *string `json:"standard"`
	Type        *string `json:"type"`

	MappingID  uuid.UUID       `json:"mapping_id"`
	RefModelID *uuid.UUID      `json:"ref_model_id"`
	Fields     []*MappingField `sql:"-" json:"fields"`
}

// MappingField is a baseline mapping field prototype
type MappingField struct {
	provide.Model
	DefaultValue interface{} `json:"default_value,omitempty"`
	IsPrimaryKey bool        `json:"is_primary_key"`
	Name         string      `json:"name"`
	Description  *string     `json:"description"`
	Type         string      `json:"type"`

	MappingModelID uuid.UUID  `gorm:"column:mappingmodel_id" json:"mapping_model_id"`
	RefFieldID     *uuid.UUID `json:"ref_field_id"`
}

func mappingRefFactory(organizationID uuid.UUID, mappingType string) string {
	return common.SHA256(fmt.Sprintf("%s.%s", organizationID.String(), mappingType))
}

// FindMappingByID finds a mapping for the given id
func FindMappingByID(id uuid.UUID) *Mapping {
	db := dbconf.DatabaseConnection()
	mapping := &Mapping{}
	db.Where("id = ?", id.String()).Find(&mapping)
	if mapping == nil || mapping.ID == uuid.Nil {
		return nil
	}
	mapping.Models = FindMappingModelsByMappingID(mapping.ID)
	for _, model := range mapping.Models {
		model.Fields = FindMappingFieldsByMappingModelID(model.ID)
	}
	return mapping
}

// ListMappingsByRefQuery returns a query to list of mappings which match the given ref and optional version
func ListMappingsByRefQuery(ref string, version *string) *gorm.DB {
	db := dbconf.DatabaseConnection()
	query := db.Where("ref = ?", ref)
	if version != nil {
		query = query.Where("version = ?", *version)
	}
	return query
}

// FindMappingModelsByMappingID finds the mapping models for the given mapping id
func FindMappingModelsByMappingID(mappingID uuid.UUID) []*MappingModel {
	db := dbconf.DatabaseConnection()
	models := make([]*MappingModel, 0)
	db.Where("mapping_id = ?", mappingID.String()).Find(&models)
	if models == nil {
		return nil
	}
	return models
}

// FindMappingFieldsByMappingModelID finds the mapping fields for the given mapping model id
func FindMappingFieldsByMappingModelID(mappingModelID uuid.UUID) []*MappingField {
	db := dbconf.DatabaseConnection()
	fields := make([]*MappingField, 0)
	db.Where("mappingmodel_id = ?", mappingModelID.String()).Find(&fields)
	if fields == nil {
		return nil
	}
	return fields
}

// FindMappingModelByID finds the mapping model for the given id
func FindMappingModelByID(id uuid.UUID) *MappingModel {
	db := dbconf.DatabaseConnection()
	model := &MappingModel{}
	db.Where("id = ?", id.String()).Find(&model)
	return model
}

func (m *Mapping) enrich() {
	m.Models = FindMappingModelsByMappingID(m.ID)
	for _, model := range m.Models {
		model.Fields = FindMappingFieldsByMappingModelID(model.ID)
	}
}

func (m *Mapping) enrichRef() bool {
	if m.OrganizationID == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("cannot enrich ref with nil mapping organization id"),
		})
	}
	if m.Type == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("cannot enrich ref with nil mapping type"),
		})
	}

	if len(m.Errors) > 0 {
		return false
	}

	m.Ref = common.StringOrNil(mappingRefFactory(*m.OrganizationID, *m.Type))
	return true
}

func (m *Mapping) Create() bool {
	if !m.Validate() {
		return false
	}

	if !m.enrichRef() {
		return false
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	success := false
	if tx.NewRecord(m) {
		result := tx.Create(&m)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				m.Errors = append(m.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !tx.NewRecord(m) {
			success = rowsAffected > 0
			if success {
				for _, model := range m.Models {
					model.MappingID = m.ID
					if !model.Create(tx) {
						common.Log.Warning("failed to create mapping model; transaction will be rolled back")
						m.Errors = append(m.Errors, model.Errors...)
						return false
					}
				}

				tx.Commit()
				m.sync()
			}
		}
	}

	return success
}

func (m *Mapping) Delete() bool {
	db := dbconf.DatabaseConnection()
	result := db.Delete(m)
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	return len(m.Errors) == 0
}

// Update the underlying mapping instance with values from the given mapping;
// this method uses a db transaction to wipe the old models and fields to
// perform a wholesale update of the entire mapping...
func (m *Mapping) Update(mapping *Mapping) bool {
	if !mapping.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if mapping.Name != "" {
		m.Name = mapping.Name
	}
	if mapping.Description != nil {
		m.Description = mapping.Description
	}
	if mapping.Type != nil {
		m.Type = mapping.Type
	}
	if mapping.Ref != nil {
		m.Ref = mapping.Ref
	}
	if mapping.RefMappingID != nil {
		m.RefMappingID = mapping.RefMappingID
	}
	if m.Version == nil && mapping.Version != nil { // FIXME-- implement finalization of mappings and lock version
		m.Version = mapping.Version
	}

	if !m.enrichRef() {
		return false
	}

	for _, model := range m.Models {
		tx.Delete(&model) // this should also wipe the constrained fields...
	}

	for _, model := range mapping.Models {
		model.MappingID = m.ID
		if !model.Create(tx) {
			m.Errors = append(m.Errors, model.Errors...)
			return false
		}
	}
	m.Models = FindMappingModelsByMappingID(m.ID)

	result := tx.Save(&m)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			m.Errors = append(m.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	success := rowsAffected > 0
	if success {
		tx.Commit()
		m.sync()
	}

	return success
}

func (m *Mapping) Validate() bool {
	if m.Ref != nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("mapping ref must not be provided"),
		})
	}
	return len(m.Errors) == 0
}

func (m *MappingModel) TableName() string {
	return "mappingmodels"
}

func (m *MappingModel) Create(tx *gorm.DB) bool {
	if !m.Validate() {
		return false
	}

	common.Log.Tracef("attempting to create mapping model for mapping: %s", m.MappingID)

	success := false
	if tx.NewRecord(m) {
		result := tx.Create(&m)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				m.Errors = append(m.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !tx.NewRecord(m) {
			success = rowsAffected > 0
			if success {
				for _, field := range m.Fields {
					field.MappingModelID = m.ID
					if !field.Create(tx) {
						common.Log.Warningf("failed to create mapping model field; transaction will be rolled back")
						m.Errors = append(m.Errors, field.Errors...)
						return false
					}
				}
			}
		}
	}

	return success
}

func (m *MappingModel) Validate() bool {
	return true
}

func (f *MappingField) Create(tx *gorm.DB) bool {
	if !f.Validate() {
		return false
	}

	common.Log.Tracef("attempting to create mapping model field for model: %s", f.MappingModelID)

	success := false
	if tx.NewRecord(f) {
		result := tx.Create(&f)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				f.Errors = append(f.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !tx.NewRecord(f) {
			success = rowsAffected > 0
		}
	}

	return success
}

// resolveSubjectAccount resolves the BPI subject account for the underlying mapping
func (m *Mapping) resolveSubjectAccount() (*SubjectAccount, error) {
	if m.OrganizationID == nil || m.WorkgroupID == nil {
		return nil, fmt.Errorf("failed to resolve subject account for mapping without an organization and workgroup id; mapping: %s", m.ID)
	}

	subjectAccountID := subjectAccountIDFactory(m.OrganizationID.String(), m.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		return nil, err
	}

	return subjectAccount, nil
}

// sync distributes the underlying mapping to downstream workgroup participants
func (m *Mapping) sync() error {
	subjectAccount, err := m.resolveSubjectAccount()
	if err != nil {
		return err
	}

	raw, _ := json.Marshal(m)
	obj := map[string]interface{}{}
	err = json.Unmarshal(raw, &obj)
	if err != nil {
		return err
	}

	accessToken, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		return err
	}

	org, err := ident.GetOrganizationDetails(*accessToken.AccessToken, *subjectAccount.Metadata.OrganizationID, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to sync mapping; failed to resolve organization address; %s", err.Error())
		return err
	}

	var address *string
	if addr, ok := org.Metadata["address"].(string); ok {
		address = &addr
	}

	if address == nil {
		return fmt.Errorf("failed to sync mapping: %s; failed to resolve sending organization address", m.ID)
	}

	workgroup := FindWorkgroupByID(*m.WorkgroupID)
	if workgroup == nil {
		return fmt.Errorf("failed to sync mapping: %s; failed to resolve workgroup: %s", m.ID, m.WorkgroupID.String())
	}

	for _, participant := range workgroup.listParticipants(dbconf.DatabaseConnection()) {
		msg := &ProtocolMessage{
			Opcode: common.StringOrNil(baseline.ProtocolMessageOpcodeSync),
			Payload: &ProtocolMessagePayload{
				Object: obj,
				Type:   common.StringOrNil(protomsgPayloadTypeMapping),
			},
			Recipient:        participant.Participant,
			Sender:           address,
			SubjectAccountID: subjectAccount.ID,
			WorkgroupID:      m.WorkgroupID,
		}
		payload, _ := json.Marshal(msg)

		common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
		_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)
		if err != nil {
			common.Log.Warningf("failed to dispatch protocol message; %s", err.Error())
			// FIXME?? should we rollback a transaction here?
			return err
		}
	}

	return nil
}

func (f *MappingField) Validate() bool {
	return true
}

func (f *MappingField) TableName() string {
	return "mappingfields"
}
