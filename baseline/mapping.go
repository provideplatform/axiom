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
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
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

// MappingsByOrganizationID returns a query to a list of mappings which are associated with the given organization id
func FindMappingsByOrganizationID(organizationID uuid.UUID) *gorm.DB {
	db := dbconf.DatabaseConnection()
	query := db.Where("mo.organization_id = ?", organizationID.String())
	return query.Joins("JOIN mappings_organizations as mo ON mo.mapping_id = mappings.id")
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

func (m *Mapping) enrich() {
	m.Models = FindMappingModelsByMappingID(m.ID)
	for _, model := range m.Models {
		model.Fields = FindMappingFieldsByMappingModelID(model.ID)
	}
}

func (m *Mapping) Create(token string) bool {
	if !m.Validate() {
		return false
	}

	m.Ref = common.StringOrNil(mappingRefFactory(*m.OrganizationID, *m.Type))

	wg_orgs, err := ident.ListApplicationOrganizations(token, m.WorkgroupID.String(), map[string]interface{}{})
	if err != nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
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

		for _, wg_org := range wg_orgs {
			result = db.Exec("INSERT INTO mappings_organizations (mapping_id, organization_id, permissions) VALUES (?, ?, ?)", m.ID, *wg_org.ID, 0)
			rowsAffected = result.RowsAffected
			errors = result.GetErrors()
			if len(errors) > 0 {
				for _, err := range errors {
					m.Errors = append(m.Errors, &provide.Error{
						Message: common.StringOrNil(err.Error()),
					})
				}
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
	if !m.Validate() {
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

	// FIXME-- if you updated the type of a mapping that was created from a schema then go and try to use that schema again, it will create a new mapping and the initial connection of schema and mapping is broken
	m.Ref = common.StringOrNil(mappingRefFactory(*m.OrganizationID, *m.Type))

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
	}

	return success
}

func (m *Mapping) Validate() bool {
	if m.OrganizationID == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("organization_id is required"),
		})
	}

	if m.WorkgroupID == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("workgroup_id is required"),
		})
	}

	if m.Type == nil {
		m.Errors = append(m.Errors, &provide.Error{
			Message: common.StringOrNil("type is required"),
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
	// if tx.NewRecord(m) {
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
	// }

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
	// if tx.NewRecord(f) {
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
	// }

	return success
}

func (f *MappingField) Validate() bool {
	return true
}

func (f *MappingField) TableName() string {
	return "mappingfields"
}
