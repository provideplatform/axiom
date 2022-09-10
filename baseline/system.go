package baseline

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/vault"
)

// System is a persistent representation and instance of a functional
// `middleware.System` implementation that uses a vault secret to
// securely store the configuration
type System struct {
	provide.Model

	Name           *string    `sql:"not null" json:"name"`
	Description    *string    `json:"description"`
	Type           *string    `sql:"not null" json:"type"`
	OrganizationID *uuid.UUID `sql:"not null" json:"organization_id"`
	WorkgroupID    *uuid.UUID `sql:"not null" json:"workgroup_id"`

	Auth        *middleware.SystemAuth       `sql:"-" json:"auth,omitempty"`
	EndpointURL *string                      `sql:"-" json:"endpoint_url"`
	Middleware  *middleware.SystemMiddleware `sql:"-" json:"middleware,omitempty"`

	VaultID  *uuid.UUID `sql:"not null" json:"-"`
	SecretID *uuid.UUID `sql:"not null" json:"-"`

	// delegate *SubjectAccount `sql:"-" json:"-"`
	metadata *middleware.SystemMetadata `sql:"-" json:"-"`
}

// ListSystemsQuery returns the query for retrieving a list of systems for the given subject account context
func ListSystemsQuery(organizationID, workgroupID uuid.UUID) *gorm.DB {
	db := dbconf.DatabaseConnection()
	return db.Where("organization_id = ? AND workgroup_id = ?", organizationID.String(), workgroupID.String())
}

// FindSystemByID retrieves a system for the given id
func FindSystemByID(id uuid.UUID) *System {
	db := dbconf.DatabaseConnection()
	system := &System{}
	db.Where("id = ?", id.String()).Find(&system)
	if system == nil || system.ID == uuid.Nil {
		return nil
	}
	system.enrich()
	return system
}

// SystemFromEphemeralSystemMetadata returns a system for the given middleware system metadata
func SystemFromEphemeralSystemMetadata(metadata *middleware.SystemMetadata) (*System, error) {
	system := &System{
		Auth:        metadata.Auth,
		EndpointURL: metadata.EndpointURL,
		Middleware:  metadata.Middleware,
		Name:        metadata.Name,
		Type:        metadata.Type,
		metadata:    metadata,
	}

	return system, nil
}

// enrich the underlying system
func (s *System) enrich() error {
	if s.OrganizationID == nil || s.WorkgroupID == nil {
		return fmt.Errorf("failed to enrich system: %s; invalid subject account context", s.ID)
	}

	subjectAccountID := subjectAccountIDFactory(s.OrganizationID.String(), s.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		return fmt.Errorf("failed to enrich system: %s; invalid subject account context; %s", s.ID, err.Error())
	}

	if s.VaultID != nil && s.SecretID != nil {
		token, err := subjectAccount.authorizeAccessToken()
		if err != nil {
			return err
		}

		secret, err := vault.FetchSecret(
			*token.AccessToken,
			s.VaultID.String(),
			s.SecretID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}

		raw, err := hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode BPI subject account metadata from hex; %s", err.Error())
			return err
		}

		err = json.Unmarshal(raw, &s.metadata)
		if err != nil {
			return err
		}

		s.Auth = s.metadata.Auth
		s.EndpointURL = s.metadata.EndpointURL
		s.Middleware = s.metadata.Middleware
	}

	return nil
}

func (s *System) deleteSecret() bool {
	subjectAccountID := subjectAccountIDFactory(s.OrganizationID.String(), s.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich system: %s; invalid subject account context; %s", s.ID, err.Error())),
		})
		return false
	}

	token, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	err = vault.DeleteSecret(
		*token.AccessToken,
		s.VaultID.String(),
		s.SecretID.String(),
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to delete system metadata for system: %s; BPI subject account %s from vault %s; %s", s.ID, subjectAccountID, s.VaultID.String(), err.Error())),
		})
		return false
	}

	s.SecretID = nil
	return true
}

func (s *System) persistSecret() bool {
	subjectAccountID := subjectAccountIDFactory(s.OrganizationID.String(), s.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich system: %s; invalid subject account context; %s", s.ID, err.Error())),
		})
		return false
	}

	token, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	s.metadata = &middleware.SystemMetadata{
		Auth:        s.Auth,
		EndpointURL: s.EndpointURL,
		Middleware:  s.Middleware,
	}

	raw, err := json.Marshal(s.metadata)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	secret, err := vault.CreateSecret(
		*token.AccessToken,
		s.VaultID.String(),
		map[string]interface{}{
			"description": fmt.Sprintf("BPI subject account system %s", s.ID),
			"name":        fmt.Sprintf("%s system: %s (%s)", *s.Type, *s.Name, s.ID),
			"type":        vaultSecretTypeSystem,
			"value":       hex.EncodeToString(raw),
		},
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store system metadata for system: %s; BPI subject account %s in vault %s; %s", s.ID, subjectAccountID, s.VaultID.String(), err.Error())),
		})
		return false
	}

	s.SecretID = &secret.ID
	if s.SecretID == nil || *s.SecretID == uuid.Nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("secret_id is required"),
		})
	}

	return s.SecretID != nil && *s.SecretID != uuid.Nil
}

// middlewareFactory initializes the middleware system implementation
func (s *System) middlewareFactory() middleware.SOR {
	if s.metadata == nil && s.SecretID != nil {
		s.enrich()
	}

	return middleware.SystemFactory(&middleware.SystemMetadata{
		Auth:        s.Auth,
		EndpointURL: s.EndpointURL,
		Middleware:  s.Middleware,
		Name:        s.Name,
		Type:        s.Type,
	})
}

// Validate a system
func (s *System) Validate() bool {
	if s.Name == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("name is required"),
		})
	}

	if s.Type == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("type is required"),
		})
	}

	if s.WorkgroupID == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("workgroup_id is required"),
		})
	}

	if s.OrganizationID == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("organization_id is required"),
		})
	}

	if s.VaultID == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("vault_id is required"),
		})
	}

	return len(s.Errors) == 0
}

// Create a system
func (s *System) Create() bool {
	if !s.Validate() {
		return false
	}

	if !s.persistSecret() {
		return false
	}

	success := false
	db := dbconf.DatabaseConnection()
	if db.NewRecord(&s) {
		result := db.Create(&s)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				s.Errors = append(s.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}

		success = rowsAffected > 0
	}

	return success
}

// Update the system
func (s *System) Update() bool {
	if !s.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	result := db.Save(&s)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	return rowsAffected == 1 && len(errors) == 0
}

// Delete the underlying system
func (s *System) Delete() bool {
	db := dbconf.DatabaseConnection()
	result := db.Delete(&s)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	success := rowsAffected > 0
	if success {
		if !s.deleteSecret() {
			common.Log.Warningf("failed to delete system secret from vault; system: %s", s.ID)
		}
	}

	return success
}
