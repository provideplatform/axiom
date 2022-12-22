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
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/olivere/elastic/v7"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common/util"
	"golang.org/x/crypto/ssh"
)

const prvdSubjectAccountType = "PRVD"
const vaultSecretTypeBPISubjectAccount = "bpi_subject_account"
const vaultSecretTypeSystem = "system"

const requireSyncResponseTimeout = time.Second * 10

var (
	// SubjectAccounts are the cached BPI subject accounts on the configured instance; in-memory cache available only to instances serving the API
	SubjectAccounts []*SubjectAccount

	// SubjectAccountsByID lazy loaded, in-memory cache for subject account id -> BPI subject account; in-memory cache available only to instances serving the API
	SubjectAccountsByID map[string][]*SubjectAccount
)

// InviteClaims represent JWT invitation claims
type InviteClaims struct {
	jwt.MapClaims

	Baseline *BaselineClaims `json:"baseline"`
	Kid      *string         `json:"kid,omitempty"` // key fingerprint
	Audience *string         `json:"aud,omitempty"`
	ID       *string         `json:"jti,omitempty"`
	Issuer   *string         `json:"iss,omitempty"`
	// IssuedAt  *string         `json:"iat,omitempty"`
	// ExpiresAt *string         `json:"exp,omitempty"`
	// NotBefore *string         `json:"nbf,omitempty"`
	Subject *string `json:"sub,omitempty"`
}

// BaselineClaims represent JWT invitation claims
type BaselineClaims struct {
	BPIEndpoint                *string `json:"bpi_endpoint,omitempty"`
	RegistryContractAddress    *string `json:"registry_contract_address,omitempty"`
	WorkgroupID                *string `json:"workgroup_id,omitempty"`
	InvitorBPIEndpoint         *string `json:"invitor_bpi_endpoint,omitempty"`
	InvitorOrganizationAddress *string `json:"invitor_organization_address,omitempty"`
	InvitorSubjectAccountID    *string `json:"invitor_subject_account_id,omitempty"`
}

// SendProtocolMessageAPIResponse is returned upon successfully sending a protocol message
type SendProtocolMessageAPIResponse struct {
	BaselineID       *uuid.UUID `json:"baseline_id"`
	Proof            *string    `json:"proof"`
	Recipients       []*string  `json:"recipients"`
	Root             *uuid.UUID `json:"root,omitempty"`
	SubjectAccountID *string    `json:"subject_account_id"`
	Type             *string    `json:"type"`
	WorkgroupID      *uuid.UUID `json:"workgroup_id"`
}

// SubjectAccount is a baseline BPI Subject Account per the specification
type SubjectAccount struct {
	provide.ModelWithDID
	SubjectID *string    `json:"subject_id"`
	Type      *string    `json:"type,omitempty"`
	VaultID   *uuid.UUID `json:"vault_id"`

	Credentials         *json.RawMessage `sql:"-" json:"credentials,omitempty"`
	CredentialsSecretID *uuid.UUID       `json:"credentials_secret_id,omitempty"`

	Metadata         *SubjectAccountMetadata `sql:"-" json:"metadata,omitempty"`
	MetadataSecretID *uuid.UUID              `json:"metadata_secret_id,omitempty"`

	RecoveryPolicy         *json.RawMessage `sql:"-" json:"recovery_policy,omitempty"`
	RecoveryPolicySecretID *uuid.UUID       `json:"recovery_policy_secret_id,omitempty"`

	Role         *json.RawMessage `sql:"-" json:"role,omitempty"`
	RoleSecretID *uuid.UUID       `json:"role_secret_id,omitempty"`

	SecurityPolicies         *json.RawMessage `sql:"-" json:"security_policies,omitempty"`
	SecurityPoliciesSecretID *uuid.UUID       `json:"security_policies_secret_id,omitempty"`

	RefreshToken    *string `json:"-"` // encrypted, hex-encoded refresh token for the BPI subject account
	refreshTokenRaw *string `sql:"-" json:"-"`
}

// SubjectAccountMetadata is `SubjectAccount` metadata specific to this BPI instance
type SubjectAccountMetadata struct {
	// Counterparties are the default counterparties
	Counterparties []*Participant `sql:"-" json:"counterparties,omitempty"`

	// NetworkID is the baseline network id
	NetworkID *string `json:"network_id,omitempty"`

	// OrganizationAddress is the baseline organization address
	OrganizationAddress *string `json:"organization_address,omitempty"`

	// OrganizationDomain is the baseline organization domain
	OrganizationDomain *string `json:"organization_domain,omitempty"`

	// OrganizationID is the id of the org
	OrganizationID *string `json:"organization_id,omitempty"`

	// OrganizationBPIEndpoint is the configured endpoint for the BPI REST API
	OrganizationBPIEndpoint *string `json:"organization_bpi_endpoint,omitempty"`

	// OrganizationMessagingEndpoint is the public organziation messaging endpoint
	OrganizationMessagingEndpoint *string `json:"organization_messaging_endpoint,omitempty"`

	// OrganizationRefreshToken is the refresh token for the org
	OrganizationRefreshToken *string `json:"organization_refresh_token,omitempty"`

	// OrganizationWebsocketEndpoint is the configured endpoint for the baseline websocket
	OrganizationWebsocketEndpoint *string `json:"organization_websocket_endpoint,omitempty"`

	// RegistryContractAddress is a contract address
	RegistryContractAddress *string `json:"registry_contract_address,omitempty"`

	// RegistryContract is a compiled contract artifact
	RegistryContract *nchain.CompiledArtifact `sql:"-" json:"-"`

	// SOR contains one or more systems of record configurations
	SOR map[string]interface{} `json:"sor,omitempty"`

	// WorkgroupID is the id of the workgroup
	WorkgroupID *string `json:"workgroup_id,omitempty"`

	// Vault is the vault instance
	Vault *vault.Vault `sql:"-" json:"-"`
}

func (s *SubjectAccount) TableName() string {
	return "subjectaccounts"
}

func (s *SubjectAccount) validate() bool {
	if s.Metadata == nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("metadata is required"),
		})
	} else {
		if s.Metadata.OrganizationID == nil || uuid.FromStringOrNil(*s.Metadata.OrganizationID) == uuid.Nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("organization_id is required"),
			})
		}

		if s.Metadata.OrganizationAddress == nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("organization_address is required"),
			})
		}

		if s.Metadata.OrganizationRefreshToken == nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("organization_refresh_token is required"),
			})
		}

		if s.Metadata.WorkgroupID == nil || uuid.FromStringOrNil(*s.Metadata.WorkgroupID) == uuid.Nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("workgroup_id is required"),
			})
		}

		if s.Metadata.NetworkID == nil || uuid.FromStringOrNil(*s.Metadata.NetworkID) == uuid.Nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("network_id is required"),
			})
		}

		if s.Metadata.RegistryContractAddress == nil {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil("registry_contract_address is required"),
			})
		}
	}

	return len(s.Errors) == 0
}

func (s *SubjectAccount) listSystems() ([]*System, error) {
	if s.SubjectID == nil || s.Metadata == nil || s.Metadata.WorkgroupID == nil {
		return nil, fmt.Errorf("failed to list systems for subject account: %s", *s.ID)
	}

	organizationID, err := uuid.FromString(*s.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed parse organization id for subject account: %s", *s.ID)
	}

	workgroupID, err := uuid.FromString(*s.Metadata.WorkgroupID)
	if err != nil {
		return nil, fmt.Errorf("failed parse workgroup id for subject account: %s", *s.ID)
	}

	systems := make([]*System, 0)
	ListSystemsQuery(organizationID, workgroupID).Find(&systems)

	return systems, nil
}

func (s *SubjectAccount) resolveSystem(mappingType string) (middleware.SOR, error) {
	systems, err := s.listSystems()
	if err != nil {
		return nil, err
	}

	for _, sys := range systems {
		err := sys.enrich()
		if err != nil {
			return nil, err
		}

		if sys.Type != nil {
			switch *sys.Type {
			case systemTypeSAP, systemTypeServiceNow:
				middleware := sys.middlewareFactory()
				if middleware != nil {
					schema, err := middleware.GetSchema(mappingType, map[string]interface{}{})
					if err != nil {
						return nil, fmt.Errorf("failed to retrieve schema type %s for system: %s", mappingType, *sys.Type)
					}

					if schema != nil {
						return middleware, nil
					}
				}
			default:
				// no-op
			}

		}
	}

	return nil, fmt.Errorf("no system resolved for type: %s", mappingType)
}

func (s *SubjectAccount) persistCredentials() bool {
	raw, err := json.Marshal(s.Credentials)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	token, err := s.authorizeAccessToken()
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
			"description": fmt.Sprintf("BPI subject account credentials %s", *s.ID),
			"name":        fmt.Sprintf("BPI subject account credentials %s", *s.ID),
			"type":        vaultSecretTypeBPISubjectAccount,
			"value":       hex.EncodeToString(raw),
		},
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store BPI subject account credentials for subject account %s in vault %s; %s", *s.ID, s.VaultID.String(), err.Error())),
		})
		return false
	}

	s.CredentialsSecretID = &secret.ID
	return s.CredentialsSecretID != nil && *s.CredentialsSecretID != uuid.Nil
}

func (s *SubjectAccount) persistMetadata() bool {
	raw, err := json.Marshal(s.Metadata)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	token, err := s.authorizeAccessToken()
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
			"description": fmt.Sprintf("BPI subject account metadata %s", *s.ID),
			"name":        fmt.Sprintf("BPI subject account metadata %s", *s.ID),
			"type":        vaultSecretTypeBPISubjectAccount,
			"value":       hex.EncodeToString(raw),
		},
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to store BPI subject account metadata for subject account %s in vault %s; %s", *s.ID, s.VaultID.String(), err.Error())),
		})
		return false
	}

	s.MetadataSecretID = &secret.ID
	return s.MetadataSecretID != nil && *s.MetadataSecretID != uuid.Nil
}

func (s *SubjectAccount) resolveCredentials() bool {
	jwks, err := s.resolveJWKs()
	if err != nil {
		return false
	}

	// FIXME-- expand this interface
	credentials := map[string]interface{}{
		"jwks": jwks,
	}

	credsJSON, _ := json.Marshal(credentials)
	_credsJSON := json.RawMessage(credsJSON)
	s.Credentials = &_credsJSON

	return s.Credentials != nil
}

// resolveJWKs resolves the configured JWKs for the subject account
func (s *SubjectAccount) resolveJWKs() (map[string]*ident.JSONWebKey, error) {
	token, err := s.authorizeAccessToken()
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return nil, err
	}

	keys, err := vault.ListKeys(
		*token.AccessToken,
		s.VaultID.String(),
		map[string]interface{}{
			"spec": "RSA-4096",
		},
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to list RSA keys for BPI subject account %s in vault %s; %s", *s.ID, s.VaultID.String(), err.Error())),
		})
		return nil, err
	}

	jwks := map[string]*ident.JSONWebKey{}

	for _, key := range keys {
		publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(*key.PublicKey))
		if err != nil {
			common.Log.Warningf("failed to parse JWT public key; %s", err.Error())
			continue
		}

		sshPublicKey, err := ssh.NewPublicKey(publicKey)
		if err != nil {
			common.Log.Warningf("failed to resolve JWT public key fingerprint; %s", err.Error())
			continue
		}

		fingerprint := common.StringOrNil(ssh.FingerprintLegacyMD5(sshPublicKey))
		jwks[*fingerprint] = &ident.JSONWebKey{
			E:           fmt.Sprintf("%X", publicKey.E),
			Fingerprint: *fingerprint,
			Kid:         *fingerprint,
			N:           publicKey.N.String(),
			PublicKey:   *key.PublicKey,
		}

		common.Log.Debugf("resolved JWK for BPI subject account %s: %s", *s.ID, *key.PublicKey)
	}

	return jwks, nil
}

func (s *SubjectAccount) createNatsWorkgroupSyncSubscriptions(wg *sync.WaitGroup) {
	subject := strings.Replace(natsWorkgroupSyncSubject, "*", *s.Metadata.WorkgroupID, -1)
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsWorkgroupSyncAckWait,
			subject,
			subject,
			subject,
			consumeWorkgroupSyncRequestMsg,
			natsWorkgroupSyncAckWait,
			natsWorkgroupSyncMaxInFlight,
			natsWorkgroupSyncMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsSubjectAccountRegistrationSubject, err.Error())
		}
	}
}

func (s *SubjectAccount) create(tx *gorm.DB) bool {
	if !s.validate() {
		return false
	}

	if !s.encryptRefreshToken() {
		msg := fmt.Sprintf("failed to encrypt refresh token BPI subject account: %s; ", *s.ID)
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	err := s.requireWorkgroup()
	if err != nil {
		msg := fmt.Sprintf("failed to require workgroup for BPI subject account; %s", err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	err = s.requireVault()
	if err != nil {
		msg := fmt.Sprintf("failed to require vault for BPI subject account; %s", err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	err = s.resolveBaselineContract()
	if err != nil {
		msg := fmt.Sprintf("failed to resolve registry contract for BPI subject account; %s", err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	err = s.resolveWorkgroupParticipants()
	if err != nil {
		msg := fmt.Sprintf("failed to resolve counterparties for BPI subject account; %s", err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	if !s.resolveCredentials() {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil("failed to resolve credentials for BPI subject account"),
		})
		return false
	}

	if !s.persistCredentials() {
		return false
	}

	if !s.persistMetadata() {
		return false
	}

	result := tx.Create(&s)
	errors := result.GetErrors()
	success := len(errors) == 0
	if !success {
		for _, err := range errors {
			s.Errors = append(s.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}

		return false
	}

	err = s.requireSystems()
	if err != nil {
		common.Log.Warningf("failed to require system for BPI subject account: %s", *s.ID)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"subject_account_id": *s.ID,
	})
	common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
	_, err = natsutil.NatsJetstreamPublish(natsSubjectAccountRegistrationSubject, payload)
	if err != nil {
		msg := fmt.Sprintf("failed to broadcast %d-byte protocol message; %s", len(payload), err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	return success
}

func (s *SubjectAccount) setDefaultItems() error {
	if s.Type == nil {
		s.Type = common.StringOrNil(prvdSubjectAccountType)
	}

	if s.refreshTokenRaw == nil && s.Metadata != nil && s.Metadata.OrganizationRefreshToken != nil {
		s.refreshTokenRaw = s.Metadata.OrganizationRefreshToken
	}

	if os.Getenv("BASELINE_ORGANIZATION_PROXY_ENDPOINT") != "" {
		s.Metadata.OrganizationBPIEndpoint = common.StringOrNil(os.Getenv("BASELINE_ORGANIZATION_PROXY_ENDPOINT"))
	}

	if os.Getenv("BASELINE_ORGANIZATION_MESSAGING_ENDPOINT") != "" {
		s.Metadata.OrganizationMessagingEndpoint = common.StringOrNil(os.Getenv("BASELINE_ORGANIZATION_MESSAGING_ENDPOINT"))
	}

	return nil
}

func (s *SubjectAccount) enrich() error {
	if s.refreshTokenRaw == nil {
		err := s.enrichRefreshToken()
		if err != nil {
			common.Log.Warningf("failed to enrich BPI subject account; failed to resolve refresh token; %s", err.Error())
			return err
		}
	}

	err := s.enrichCredentials()
	if err != nil {
		common.Log.Warningf("failed to enrich BPI subject account credentials; %s", err.Error())
		return err
	}

	err = s.enrichMetadata()
	if err != nil {
		common.Log.Warningf("failed to enrich BPI subject account metadata; %s", err.Error())
		return err
	}

	return nil
}

func (s *SubjectAccount) enrichCredentials() error {
	if s.Credentials == nil && s.CredentialsSecretID != nil {
		token, err := s.authorizeAccessToken()
		if err != nil {
			return err
		}

		secret, err := vault.FetchSecret(
			*token.AccessToken,
			s.VaultID.String(),
			s.CredentialsSecretID.String(),
			map[string]interface{}{},
		)
		if err != nil {
			return err
		}

		raw, err := hex.DecodeString(*secret.Value)
		if err != nil {
			common.Log.Warningf("failed to decode BPI subject account credentials from hex; %s", err.Error())
			return err
		}

		err = json.Unmarshal(raw, &s.Credentials)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SubjectAccount) enrichMetadata() error {
	if s.Metadata == nil && s.MetadataSecretID != nil {
		token, err := s.authorizeAccessToken()
		if err != nil {
			return err
		}

		secret, err := vault.FetchSecret(
			*token.AccessToken,
			s.VaultID.String(),
			s.MetadataSecretID.String(),
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

		err = json.Unmarshal(raw, &s.Metadata)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SubjectAccount) enrichRefreshToken() error {
	if s.RefreshToken == nil {
		return fmt.Errorf("failed to enrich refresh token for BPI subject account: %s", *s.ID)
	}

	resp, err := vault.Decrypt(
		util.DefaultVaultAccessJWT,
		common.Vault.ID.String(),
		common.VaultEncryptionKey.ID.String(),
		map[string]interface{}{
			"data": *s.RefreshToken,
		},
	)
	if err != nil {
		common.Log.Warningf("failed to enrich refresh token for BPI subject account: %s; %s", *s.ID, err.Error())
		return err
	}

	s.refreshTokenRaw = &resp.Data
	return nil
}

func (s *SubjectAccount) encryptRefreshToken() bool {
	if s.refreshTokenRaw == nil {
		msg := fmt.Sprintf("failed to encrypt refresh token for BPI subject account: %s", *s.ID)
		common.Log.Warningf(msg)
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
		})
		return false
	}

	resp, err := vault.Encrypt(
		util.DefaultVaultAccessJWT,
		common.Vault.ID.String(),
		common.VaultEncryptionKey.ID.String(),
		*s.refreshTokenRaw,
	)
	if err != nil {
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(err.Error()),
		})
		return false
	}

	s.RefreshToken = &resp.Data
	return s.RefreshToken != nil
}

// findWorkflowPrototypeCandidatesByObjectType attempts to resolve the appropriate workflow prototype candidates
// which are appropriate for initialization (i.e., of a new workflow instance and the associated workstep instances)
// based on the subject account context and a given object type; this is intended to support arbitrary as well as
// standard domain models/mappings
func (s *SubjectAccount) findWorkflowPrototypeCandidatesByObjectType(objectType string) ([]*Workflow, error) {
	if s.Metadata == nil || s.Metadata.WorkgroupID == nil {
		return nil, fmt.Errorf("failed to query workflow prototype candidates by object type %s; subject account: %s", objectType, *s.ID)
	}

	query := fmt.Sprintf(`
  {
	"bool": {
	  "must": {
		"term": { "initial_workstep_object_type.keyword": "%s" }
	  },
	  "filter": [
		{ "term": { "workgroup_id.keyword": "%s" }}
	  ]
	}
  }
  `, objectType, *s.Metadata.WorkgroupID)

	sq := elastic.NewRawStringQuery(query)
	result, err := common.ElasticClient.Search().Index(common.IndexerDocumentIndexBaselineWorkflowPrototypes).Query(sq).Do(context.TODO())
	if err != nil {
		return nil, err
	}

	results := make([]*WorkflowPrototypeMessagePayload, 0)
	for _, hit := range result.Hits.Hits {
		var msg *WorkflowPrototypeMessagePayload
		err := json.Unmarshal(hit.Source, &msg)
		if err != nil {
			return nil, err
		}

		common.Log.Debugf("marshaled workflow prototype search result with initial workstep object type %s; workgroup id: %s", msg.InitialWorkstepObjectType, msg.WorkgroupID.String())
		results = append(results, msg)
	}

	candidates := make([]*Workflow, 0)
	for _, proto := range results {
		if proto.WorkflowID == nil {
			common.Log.Warningf("malformed workflow prototype exists in %s index", common.IndexerDocumentIndexBaselineWorkflowPrototypes)
			continue
		}

		candidates = append(candidates, FindWorkflowByID(*proto.WorkflowID))

	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("failed to resolve workflow prototype candidates for type: %s; subject account id: %s", objectType, *s.ID)
	}

	return candidates, nil
}

func (s *SubjectAccount) parseJWKs() (map[string]*ident.JSONWebKey, error) {
	if s.Credentials == nil {
		msg := "failed to resolve credentials for BPI subject account"
		if s.ID != nil {
			msg = fmt.Sprintf("%s %s", msg, *s.ID)
		}
		return nil, errors.New(msg)
	}

	var creds map[string]interface{}
	err := json.Unmarshal(*s.Credentials, &creds)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials for BPI subject account %s; %s", *s.ID, err.Error())
	}

	jwksMap, jwksOk := creds["jwks"].(map[string]interface{})
	if !jwksOk {
		return nil, fmt.Errorf("failed to unmarshal JWKs from resolved credentials for BPI subject account %s", *s.ID)
	}

	var jwks map[string]*ident.JSONWebKey
	jwksRaw, _ := json.Marshal(jwksMap) // HACK!!
	err = json.Unmarshal(jwksRaw, &jwks)
	if err != nil {
		common.Log.Warningf("failed to unmarshal credentials for BPI subject account %s; %s", *s.ID, err.Error())
		return nil, err
	}

	return jwks, nil
}

func init() {
	if len(SubjectAccounts) != 0 {
		common.Log.Panicf("failed to initialize baseline api; %d unexpected BPI subject accounts resolved during init", len(SubjectAccounts))
	}

	SubjectAccountsByID = map[string][]*SubjectAccount{}
	// initSubjectAccounts()
}

// FindSubjectAccountByID finds the BPI subject accounts for the given subject id
func FindSubjectAccountByID(id string) *SubjectAccount {
	db := dbconf.DatabaseConnection()
	subjectAccount := &SubjectAccount{}
	db.Where("id = ?", id).Find(&subjectAccount)
	if subjectAccount == nil || subjectAccount.ID == nil || subjectAccount.SubjectID == nil {
		return nil
	}
	return subjectAccount
}

// ListSubjectAccountsBySubjectID finds the BPI subject accounts for the given subject id
func ListSubjectAccountsBySubjectID(subjectID string) []*SubjectAccount {
	subjectAccounts := make([]*SubjectAccount, 0)
	db := dbconf.DatabaseConnection()
	db.Where("subject_id = ?", subjectID).Find(&subjectAccounts)
	return subjectAccounts
}

func initSubjectAccounts() {
	db := dbconf.DatabaseConnection()

	subjectAccounts := make([]*SubjectAccount, 0)
	db.Find(&subjectAccounts)

	for _, subjectAccount := range subjectAccounts {
		// HACK -- these two items also happen as part of enrich()
		subjectAccount.enrichCredentials()
		subjectAccount.enrichMetadata()

		err := subjectAccount.enrich()
		if err != nil {
			common.Log.Warningf("failed to start daemon for subject account: %s; failed to enrich; %s", *subjectAccount.ID, err.Error())
		}

		err = subjectAccount.startDaemon(subjectAccount.refreshTokenRaw)
		if err != nil {
			common.Log.Warningf("failed to start daemon for subject account: %s", *subjectAccount.ID)
		}
	}
}

// configureSystem
func (s *SubjectAccount) configureSystem(system *middleware.SystemMetadata) error {
	if system.EndpointURL == nil {
		return errors.New("no endpoint url resolved for configured system")
	}

	sor := middleware.SystemFactory(system)
	if sor == nil {
		common.Log.Warning("middleware system configuration not resolved")
		return errors.New("middleware system configuration not resolved")
	}

	err := sor.HealthCheck()
	if err != nil {
		common.Log.Warningf("failed to configure system; health check failed; %s", err.Error())
		return err
	}
	common.Log.Debugf("system health check completed; system is reachable at endpoint: %s", *system.EndpointURL)

	bpiEndpoint := s.Metadata.OrganizationBPIEndpoint
	if bpiEndpoint == nil {
		accessToken, err := s.authorizeAccessToken()
		if err != nil {
			common.Log.Warningf("failed to configure system; failed to fetch organization details; %s", err.Error())
			return err
		}

		org, err := ident.GetOrganizationDetails(*accessToken.AccessToken, *s.Metadata.OrganizationID, map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to configure system; failed to resolve organization BPI endpoint; %s", err.Error())
			return err
		}

		if endpt, ok := org.Metadata["bpi_endpoint"].(string); ok {
			bpiEndpoint = &endpt
		}

		if bpiEndpoint == nil && common.DefaultBPIEndpoint != nil {
			bpiEndpoint = common.DefaultBPIEndpoint
		}
	}

	sorConfiguration := map[string]interface{}{
		"bpi_endpoint":       bpiEndpoint,
		"ident_endpoint":     common.DefaultIdentEndpoint,
		"organization_id":    s.Metadata.OrganizationID,
		"refresh_token":      s.Metadata.OrganizationRefreshToken,
		"subject_account_id": *s.ID,
	}

	err = sor.ConfigureTenant(sorConfiguration)
	if err != nil {
		common.Log.Warningf("failed to configure system; %s", err.Error())
		return err
	}

	sorConfigurationJSON, _ := json.MarshalIndent(sorConfiguration, "", "  ")
	common.Log.Debugf("system tenant configured for BPI subject account: %s;\n%s", *s.ID, sorConfigurationJSON)

	return nil
}

// resolveSubjectAccount resolves the BPI subject account for a given subject account id
func resolveSubjectAccount(subjectAccountID string, vc *string) (*SubjectAccount, error) {
	if saccts, ok := SubjectAccountsByID[subjectAccountID]; ok {
		return saccts[0], nil
	}

	var err error

	// TODO-- refactor
	subjectAccount := FindSubjectAccountByID(subjectAccountID)
	if subjectAccount != nil {
		err = subjectAccount.enrich()
		if err != nil {
			return nil, fmt.Errorf("failed to enrich BPI subject account: %s; %s", subjectAccountID, err.Error())
		}

		return subjectAccount, nil
	}

	if vc != nil {
		// attempt to parse workgroup id and invitor bpi endpoint from verifiable credential
		claims := &InviteClaims{} // TODO-- refactor
		var jwtParser jwt.Parser
		_, _, err := jwtParser.ParseUnverified(*vc, claims)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve DID-based BPI subject account: %s; failed to parse workgroup ID from verifiable credential; %s", subjectAccountID, err)
		}

		var workgroupID *string
		if claims.Baseline != nil {
			workgroupID = claims.Baseline.WorkgroupID
		}

		if workgroupID == nil {
			return nil, fmt.Errorf("failed to resolve DID-based BPI subject account: %s; failed to parse workgroup ID from verifiable credential; %s", subjectAccountID, err)
		}

		uuid, _ := uuid.NewV4()
		name := fmt.Sprintf("baseline-workgroup-%s-sync-%s", *workgroupID, uuid.String())
		conn, err := natsutil.GetNatsConnection(name, *claims.Audience, time.Second*10, vc)
		if err != nil {
			return nil, fmt.Errorf("failed to establish NATS connection to invitor messaging endpoint: %s; %s", *claims.Audience, err.Error())
		}
		defer conn.Close()

		replyTo := fmt.Sprintf("baseline.workgroup.%s.reply.%s", *workgroupID, uuid.String())
		sub, err := conn.SubscribeSync(replyTo)
		if err != nil {
			return nil, fmt.Errorf("failed to subscribe to reply subject for invitor messaging endpoint: %s; %s", *claims.Audience, err.Error())
		}
		defer sub.Unsubscribe()
		conn.Flush()

		raw, _ := json.Marshal(claims.Baseline)
		err = conn.PublishRequest(fmt.Sprintf("baseline.workgroup.%s.sync", *workgroupID), replyTo, raw)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve DID-based BPI subject account: %s; request failed; %s", subjectAccountID, err.Error())
		}

		startTime := time.Now()
		for {
			resp, err := sub.NextMsg(2500 * time.Millisecond)
			if err != nil {
				common.Log.Warningf("failed to read reply on subject %s for invitor messaging endpoint: %s; %s", replyTo, *claims.Audience, err.Error())
				if startTime.Add(requireSyncResponseTimeout).Before(time.Now()) {
					common.Log.Warningf("failed to read reply on subject %s for invitor messaging endpoint: %s; timed out waiting for response", replyTo, *claims.Audience)
					break
				}
			}

			if resp != nil && err == nil {
				err = json.Unmarshal(resp.Data, &subjectAccount)
				if err != nil {
					common.Log.Warningf("failed to resolve DID-based BPI subject account: %s; failed to parse response; %s", subjectAccountID, err)
				}

				if subjectAccount != nil {
					common.Log.Debugf("resolved DID-based BPI subject account: %s", subjectAccountID)
					return subjectAccount, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to resolve BPI subject account: %s", subjectAccountID)
}

func (s *SubjectAccount) requireWorkgroup() error {
	common.Log.Debug("attempting to require workgroup")

	workgroupID, err := uuid.FromString(*s.Metadata.WorkgroupID)
	if err != nil {
		common.Log.Warningf("failed to parse workgroup id; %s", err.Error())
		return err
	}

	workgroup := FindWorkgroupByID(workgroupID)
	if workgroup == nil {
		common.Log.Debugf("persisting workgroup: %s", workgroupID)
		workgroup = &Workgroup{}
		workgroup.ID = workgroupID

		subjectID, err := uuid.FromString(*s.SubjectID)
		if err != nil {
			common.Log.Warningf("failed to persist workgroup; invalid subject id; %s", err.Error())
			return err
		}

		workgroup.OrganizationID = &subjectID

		token, err := s.authorizeAccessToken()
		if err != nil {
			common.Log.Warningf("failed to vend organization access token; %s", err.Error())
			return err
		}

		application, err := ident.GetApplicationDetails(*token.AccessToken, workgroupID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to fetch workgroup details from ident; %s", err.Error())
			return err
		}

		workgroup.Name = application.Name
		workgroup.Description = application.Description
		if !workgroup.Create() {
			common.Log.Warningf("failed to persist workgroup")
		}
	}

	return nil
}

func (s *SubjectAccount) resolveWorkgroupParticipants() error {
	common.Log.Debug("attempting to resolve baseline counterparties for BPI subject account")

	workgroupID, err := uuid.FromString(*s.Metadata.WorkgroupID)
	if err != nil {
		common.Log.Warningf("failed to resolve workgroup id for BPI subject account; %s", err.Error())
		return err
	}

	workgroup := FindWorkgroupByID(workgroupID)
	if workgroup == nil {
		msg := fmt.Sprintf("failed to resolve workgroup for BPI subject account; workgroup: %s", workgroupID)
		common.Log.Warning(msg)
		return errors.New(msg)
	}

	db := dbconf.DatabaseConnection()

	go func() {
		common.Log.Trace("attempting to resolve baseline counterparties")

		token, err := s.authorizeAccessToken()
		if err != nil {
			common.Log.Warningf("failed to vend organization access token; %s", err.Error())
			return
		}

		counterparties := make([]*Participant, 0)

		for _, party := range s.Metadata.Counterparties { // FIXME
			p := &Participant{
				Address:           party.Address,
				BPIEndpoint:       party.BPIEndpoint,
				MessagingEndpoint: party.MessagingEndpoint,
				WebsocketEndpoint: party.WebsocketEndpoint,
				Workgroups:        make([]*Workgroup, 0),
				Workflows:         make([]*Workflow, 0),
				Worksteps:         make([]*Workstep, 0),
			}

			counterparties = append(counterparties, p)
		}

		orgs, err := ident.ListApplicationOrganizations(*token.AccessToken, workgroupID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to list organizations for workgroup: %s; %s", workgroupID, err.Error())
			return
		}

		for _, org := range orgs {
			addr, addrOk := org.Metadata["address"].(string)
			apiEndpoint, _ := org.Metadata["bpi_endpoint"].(string)
			messagingEndpoint, _ := org.Metadata["messaging_endpoint"].(string)

			if addrOk {
				p := &Participant{}
				p.Address = common.StringOrNil(addr)
				p.BPIEndpoint = common.StringOrNil(apiEndpoint)
				p.MessagingEndpoint = common.StringOrNil(messagingEndpoint)

				counterparties = append(counterparties, p)
			}
		}

		for _, participant := range counterparties {
			if participant.Address != nil {
				exists := lookupBaselineOrganization(*participant.Address) != nil

				workgroup.addParticipant(*participant.Address, db)
				err := participant.Cache()
				if err != nil {
					common.Log.Warningf("failed to cache counterparty; %s", err.Error())
					continue
				}
				if !exists {
					common.Log.Debugf("cached baseline counterparty: %s", *participant.Address)
				}
			}
		}
	}()

	return nil
}

// resolveBaselineContract resolves the configured baseline registry contract for the BPI subject account
func (s *SubjectAccount) resolveBaselineContract() error {
	if s.Metadata.NetworkID == nil || s.Metadata.OrganizationRefreshToken == nil {
		return errors.New("unable to resolve baseline contract without configured network id and organization refresh token")
	}

	capabilities, err := util.ResolveCapabilitiesManifest()
	if err != nil {
		return fmt.Errorf("failed to resolve capabilities manifest; %s", err.Error())
	}

	if baseline, baselineOk := capabilities["baseline"].(map[string]interface{}); baselineOk {
		if contracts, contractsOk := baseline["contracts"].([]interface{}); contractsOk {
			for _, contract := range contracts {
				if name, nameOk := contract.(map[string]interface{})["name"].(string); nameOk && strings.ToLower(name) == "orgregistry" {
					raw, _ := json.Marshal(contract)
					err := json.Unmarshal(raw, &s.Metadata.RegistryContract)
					if err != nil {
						return fmt.Errorf("failed to parse registry contract from capabilities; %s", err.Error())
					} else {
						common.Log.Debug("resolved baseline registry contract artifact")
					}
				}
			}
		}
	}

	if s.Metadata.RegistryContract == nil {
		return errors.New("failed to parse registry contract from capabilities")
	}

	if s.Metadata.OrganizationID == nil {
		return errors.New("organization id not set to resolve baseline contract")
	}

	token, err := ident.CreateToken(*s.Metadata.OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *s.Metadata.OrganizationID,
	})
	if err != nil {
		return fmt.Errorf("failed to vend organization access token; %s", err.Error())
	}

	contract, err := nchain.GetContractDetails(*token.AccessToken, *s.Metadata.RegistryContractAddress, map[string]interface{}{})
	if err != nil || contract == nil {
		wallet, err := nchain.CreateWallet(*token.AccessToken, map[string]interface{}{
			"purpose": 44,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize wallet for organization; %s", err.Error())
		} else {
			common.Log.Debugf("created HD wallet for organization: %s", wallet.ID)
		}

		cntrct, err := nchain.CreateContract(*token.AccessToken, map[string]interface{}{
			"address":    *s.Metadata.RegistryContractAddress,
			"name":       s.Metadata.RegistryContract.Name,
			"network_id": s.Metadata.NetworkID,
			"params": map[string]interface{}{
				"argv":              []interface{}{},
				"compiled_artifact": s.Metadata.RegistryContract,
				"wallet_id":         wallet.ID,
			},
			"type": "organization-registry",
		})
		if err != nil {
			return fmt.Errorf("failed to initialize registry contract; %s", err.Error())
		} else {
			common.Log.Debugf("resolved baseline organization registry contract: %s", *cntrct.Address)
		}
	} else {
		common.Log.Debugf("resolved baseline organization registry contract: %s", *contract.Address)
	}

	return nil
}

// requireSystems ensures each system is configured
func (s *SubjectAccount) requireSystems() error {
	common.Log.Debugf("attempting to require systems for BPI subject account: %s", *s.ID)

	systems, err := s.listSystems()
	if err != nil {
		return err
	}

	for _, system := range systems {
		if system.Type == nil || system.Name == nil {
			common.Log.Warningf("misconfigured system configured for BPI subject account: %s", *s.ID)
			continue
		}

		err := s.enrich()
		if err != nil {
			common.Log.Warningf("failed to to configure %s system for BPI subject account: %s; system: %s; enrichment failed; %s", *system.Type, *s.ID, system.ID, err.Error())
			continue
		}

		common.Log.Debugf("attempting to configure %s system for BPI subject account: %s", *system.Type, *s.ID)
		err = s.configureSystem(system.metadata)
		if err != nil {
			common.Log.Warningf("failed to configure %s system: %s; %s", *system.Type, *system.Name, err.Error())
			continue
		}

		common.Log.Debugf("configured %s system for BPI subject account: %s", *system.Type, *s.ID)
	}

	return nil
}

func (s *SubjectAccount) authorizeAccessToken() (*ident.Token, error) {
	if s.refreshTokenRaw == nil {
		return nil, fmt.Errorf("failed to vend access token for BPI subject account: %s; no refresh token", *s.ID)
	}

	if s.SubjectID == nil {
		return nil, fmt.Errorf("failed to vend access token for BPI subject account: %s; nil subject id", *s.ID)
	}

	token, err := ident.CreateToken(*s.refreshTokenRaw, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *s.SubjectID,
	})
	if err != nil {
		common.Log.Warningf("failed to vend access token for BPI subject account; %s", err.Error())
		return nil, err
	}

	return token, nil
}

func (s *SubjectAccount) requireVault() error {
	token, err := s.authorizeAccessToken()
	if err != nil {
		common.Log.Warningf("failed to vend access token for BPI subject account; %s", err.Error())
		return err
	}

	vaults, err := vault.ListVaults(*token.AccessToken, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to fetch vaults for given token; %s", err.Error())
		return err
	}

	if len(vaults) > 0 {
		// HACK
		s.Metadata.Vault = vaults[0]
		common.Log.Debugf("resolved default vault instance for BPI: %s", s.Metadata.Vault.ID.String())
	} else {
		s.Metadata.Vault, err = vault.CreateVault(*token.AccessToken, map[string]interface{}{
			"name":        fmt.Sprintf("nchain vault %d", time.Now().Unix()),
			"description": "default organizational keystore",
		})
		if err != nil {
			common.Log.Panicf("failed to create default vaults for BPI; %s", err.Error())
			return err
		}
		common.Log.Debugf("created default vault instance for BPI: %s", s.Metadata.Vault.ID.String())
	}

	if s.VaultID == nil && s.Metadata.Vault != nil {
		s.VaultID = &s.Metadata.Vault.ID
	}

	return nil
}

// startDaemon starts the daemon for underlying the BPI subject account instance
func (s *SubjectAccount) startDaemon(refreshToken *string) error {
	_refreshToken := s.Metadata.OrganizationRefreshToken
	if _refreshToken == nil {
		_refreshToken = refreshToken
	}
	if _refreshToken == nil {
		return fmt.Errorf("refresh token required to start BPI subject account daemon: %s", *s.ID)
	}

	err := s.enrich()
	if err != nil {
		msg := fmt.Sprintf("failed to enrich BPI subject account; %s", err.Error())
		common.Log.Warningf(msg)
		return errors.New(msg)
	}

	s.requireSystems()

	go func() {
		timer := time.NewTicker(requireCounterpartiesTickerInterval)
		for {
			select {
			case <-timer.C:
				s.resolveWorkgroupParticipants()
			default:
				time.Sleep(requireCounterpartiesSleepInterval)
			}
		}
	}()

	return nil
}

// // subjectAccountExists returns true if a subject account exists for the given organization and workgroup id
// func subjectAccountExists(organizationID, workgroupID uuid.UUID) bool {
// 	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workgroupID.String())

// 	if saccts, ok := SubjectAccountsByID[subjectAccountID]; ok {
// 		return len(saccts) > 0
// 	}

// 	sacct := FindSubjectAccountByID(subjectAccountID)
// 	subjectAccounts := make([]*SubjectAccount, 0)
// 	subjectAccounts = append(subjectAccounts, sacct) // HACK

// 	SubjectAccounts = append(SubjectAccounts, subjectAccounts...)
// 	SubjectAccountsByID[subjectAccountID] = subjectAccounts

// 	// FIXME!! if this fails for any reason here, we are swallowing the error and no daemon will start...
// 	// Nothing bad will happen here until we are at scale, then all sorts of bad things could happen...
// 	// Make this more fault tolerant by handling I/O errors...
// 	err := sacct.startDaemon()
// 	return err == nil
// }

// subjectAccountIDFactory returns H(organization_id, workgroup_id)
func subjectAccountIDFactory(organizationID, workgroupID string) string {
	return common.SHA256(fmt.Sprintf("%s.%s", organizationID, workgroupID))
}

func resolveEphemeralSystems(accessToken, vaultID string, systemSecretIDs []string) ([]*middleware.SystemMetadata, error) {
	systems := make([]*middleware.SystemMetadata, 0)

	for _, secretID := range systemSecretIDs {
		common.Log.Debugf("resolved system secret id... %s", secretID)
		secret, err := vault.FetchSecret(
			accessToken,
			vaultID,
			secretID,
			map[string]interface{}{},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch system secret: %s; %s", secretID, err.Error())
		}

		var system *middleware.SystemMetadata
		err = json.Unmarshal([]byte(*secret.Value), &system)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal system secret value: %s", err.Error())
		}

		systems = append(systems, system)
	}

	return systems, nil
}
