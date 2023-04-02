package axiom

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/axiom/common"
	"github.com/provideplatform/axiom/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/vault"
)

const systemTypeD365 = "d365"
const systemTypeSAP = "sap"
const systemTypeServiceNow = "servicenow"

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
	Path        *string                      `sql:"-" json:"path,omitempty"`

	VaultID  *uuid.UUID `sql:"not null" json:"-"`
	SecretID *uuid.UUID `sql:"not null" json:"-"`

	IdentEndpoint *string `sql:"-" json:"ident_endpoint,omitempty"`
	BPIEndpoint   *string `sql:"-" json:"bpi_endpoint,omitempty"`

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
		Path:        metadata.Path,
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
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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
		s.Path = s.metadata.Path
	}

	return nil
}

func (s *System) deleteSecret() bool {
	subjectAccountID := subjectAccountIDFactory(s.OrganizationID.String(), s.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

func (s *System) resolveSubjectAccount() (*SubjectAccount, error) {
	subjectAccountID := subjectAccountIDFactory(s.OrganizationID.String(), s.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve subject account for system: %s; %s", s.ID, err.Error())
	}

	return subjectAccount, nil
}

func (s *System) persistSecret() bool {
	if s.SecretID != nil {
		if !s.deleteSecret() {
			return false
		}

		s.SecretID = nil
	}

	subjectAccount, err := s.resolveSubjectAccount()
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich system; %s", err.Error())),
		})
		return false
	}

	token, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to enrich system; %s", err.Error())),
		})
		return false
	}

	// HACK!!!
	if s.metadata == nil {
		s.metadata = &middleware.SystemMetadata{}
	}

	s.metadata = &middleware.SystemMetadata{
		Auth:        s.Auth,
		EndpointURL: s.EndpointURL,
		Middleware:  s.Middleware,
		Name:        s.Name,
		Path:        s.Path,
		Type:        s.Type,
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
			Message: common.StringOrNil(fmt.Sprintf("failed to store system metadata for system: %s; BPI subject account %s in vault %s; %s", s.ID, *subjectAccount.ID, s.VaultID.String(), err.Error())),
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
		Path:        s.Path,
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
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if tx.NewRecord(&s) {
		result := tx.Create(&s)
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

	if success {
		common.Log.Debugf("successfully created system %s", s.ID)

		sor := s.middlewareFactory()
		if sor != nil {
			common.Log.Debugf("successfully resolved middleware instance for created system %s; attempting to invoke middleware tenant creation", s.ID)

			subjectAccount, err := s.resolveSubjectAccount()
			if err != nil {
				s.Errors = append(s.Errors, &provide.Error{
					Message: common.StringOrNil(fmt.Sprintf("failed to invoke middleware tenant creation for created system %s: %s", s.ID, err.Error())),
				})
				return false
			}

			err = sor.ConfigureTenant(map[string]interface{}{
				"organization_id":    s.OrganizationID.String(),
				"subject_account_id": subjectAccount.ID,
				"workgroup_id":       s.WorkgroupID.String(),
				"bpi_endpoint":       s.BPIEndpoint, // FIXME
				"ident_endpoint":     s.IdentEndpoint,
				"refresh_token":      subjectAccount.refreshTokenRaw,
			})

			if err != nil {
				s.Errors = append(s.Errors, &provide.Error{
					Message: common.StringOrNil(fmt.Sprintf("failed to invoke middleware tenant creation for created system %s: %s", s.ID, err.Error())),
				})
				return false
			}
		}

		success = len(s.Errors) == 0
	}

	if success {
		tx.Commit()
	}

	return success
}

// Update the system
func (s *System) Update() bool {
	if !s.Validate() {
		return false
	}

	if !s.persistSecret() {
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
