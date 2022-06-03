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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/vault"
	"github.com/provideplatform/provide-go/common/util"
	"golang.org/x/crypto/ssh"
)

const prvdSubjectAccountType = "PRVD"
const vaultSecretTypeBPISubjectAccount = "bpi_subject_account"

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
}

// BaselineClaims represent JWT claims encoded within the invite token
// FIXME!! this should be referenced from lib package
type BaselineClaims struct {
	InvitorOrganizationAddress *string `json:"invitor_organization_address"`
	RegistryContractAddress    *string `json:"registry_contract_address"`
	WorkgroupID                *string `json:"workgroup_id"`
}

// SubjectAccount is a baseline BPI Subject Account per the specification
type SubjectAccount struct {
	baseline.SubjectAccount

	RefreshToken    *string `json:"-"` // encrypted, hex-encoded refresh token for the BPI subject account
	refreshTokenRaw *string `sql:"-" json:"-"`
}

func (s *SubjectAccount) TableName() string {
	return "subjectaccounts"
}

func (s *SubjectAccount) validate() bool {
	if s.Type == nil {
		s.Type = common.StringOrNil(prvdSubjectAccountType)
	}

	if s.refreshTokenRaw == nil && s.Metadata != nil && s.Metadata.OrganizationRefreshToken != nil {
		s.refreshTokenRaw = s.Metadata.OrganizationRefreshToken

	}

	return true
}

func (s *SubjectAccount) listSystems() ([]*middleware.System, error) {
	token, err := s.authorizeAccessToken()
	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return nil, err
	}

	org, err := ident.GetOrganizationDetails(*token.AccessToken, *s.Metadata.OrganizationID, map[string]interface{}{})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve organization: %s; %s", *s.Metadata.OrganizationID, err.Error())
	}

	systems := make([]*middleware.System, 0)

	if workgroupsMap, workgroupsMapOk := org.Metadata["workgroups"].(map[string]interface{}); workgroupsMapOk {
		if workgroup, workgroupOk := workgroupsMap[*s.Metadata.WorkgroupID].(map[string]interface{}); workgroupOk {
			common.Log.Debugf("resolved workgroup... %s", workgroup)
			if systemSecretIDs, systemSecretIDsOk := workgroup["system_secret_ids"].([]interface{}); systemSecretIDsOk {
				for _, secretID := range systemSecretIDs {
					common.Log.Debugf("resolved system secret id... %s", secretID)
					secret, err := vault.FetchSecret(
						*token.AccessToken,
						workgroup["vault_id"].(string),
						secretID.(string),
						map[string]interface{}{},
					)
					if err != nil {
						return nil, fmt.Errorf("failed to fetch system secret: %s; %s", secretID, err.Error())
					}

					var system *middleware.System
					err = json.Unmarshal([]byte(*secret.Value), &system)
					if err != nil {
						return nil, fmt.Errorf("failed to unmarshal system secret value: %s", err.Error())
					}

					systems = append(systems, system)
				}
			}
		}
	}

	return systems, nil
}

func (s *SubjectAccount) resolveSystem(mappingType string) (middleware.SOR, error) {
	systems, err := s.listSystems()
	if err != nil {
		return nil, err
	}

	for _, sys := range systems {
		if sys.Name != nil && *sys.Name == "sap" {
			// HACK!!! TODO-- reesolve all systems and return []*middleware.SOR
			return middleware.SystemFactory(sys), nil
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
		hex.EncodeToString(raw),
		fmt.Sprintf("BPI subject account credentials %s", *s.ID),
		fmt.Sprintf("BPI subject account credentials %s", *s.ID),
		vaultSecretTypeBPISubjectAccount,
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
		hex.EncodeToString(raw),
		fmt.Sprintf("BPI subject account metadata %s", *s.ID),
		fmt.Sprintf("BPI subject account metadata %s", *s.ID),
		vaultSecretTypeBPISubjectAccount,
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
		msg := fmt.Sprintf("failed to resolve credentials for BPI subject account; %s", err.Error())
		s.Errors = append(s.Errors, &provide.Error{
			Message: common.StringOrNil(msg),
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

func (s *SubjectAccount) parseJWKs() (map[string]*ident.JSONWebKey, error) {
	if s.Credentials == nil {
		return nil, fmt.Errorf("failed to resolve credentials for BPI subject account %s", *s.ID)
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

	// bootstrapEnvironmentSubjectAccount()
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

func (s *SubjectAccount) configureSystem() error {
	sor := middleware.SORFactory(s.Metadata.SOR, nil)
	if sor == nil {
		common.Log.Warning("middleware system configuration not resolved")
		return errors.New("middleware  system configuration not resolved")
	}

	err := sor.HealthCheck()
	if err != nil {
		common.Log.Warningf("failed to configure system; health check failed; %s", err.Error())
		return err
	}

	common.Log.Debugf("health check completed; SOR API available")
	if sorURL, sorURLOk := s.Metadata.SOR["url"].(string); sorURLOk {
		common.Log.Debugf("SOR API endpoint: %s", sorURL)
	}

	sorConfiguration := map[string]interface{}{
		"bpi_endpoint":    s.Metadata.OrganizationProxyEndpoint,
		"ident_endpoint":  fmt.Sprintf("%s://%s", os.Getenv("IDENT_API_SCHEME"), os.Getenv("IDENT_API_HOST")),
		"organization_id": s.Metadata.OrganizationID,
		"refresh_token":   s.Metadata.OrganizationRefreshToken,
	}

	err = sor.ConfigureTenant(sorConfiguration)
	if err != nil {
		common.Log.Warningf("failed to configure system; %s", err.Error())
		return err
	}

	sorConfigurationJSON, _ := json.MarshalIndent(sorConfiguration, "", "  ")
	common.Log.Debugf("SOR configured:\n%s", sorConfigurationJSON)

	return nil
}

// resolveSubjectAccount resolves the BPI subject account for a given subject account id
func resolveSubjectAccount(subjectAccountID string) (*SubjectAccount, error) {
	if saccts, ok := SubjectAccountsByID[subjectAccountID]; ok {
		return saccts[0], nil
	}

	subjectAccount := FindSubjectAccountByID(subjectAccountID)
	if subjectAccount != nil {
		subjectAccount.enrich()
		return subjectAccount, nil
	}

	return nil, fmt.Errorf("failed to resolve BPI subject account for subject account id: %s", subjectAccountID)
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
				baseline.Participant{
					Address:           party.Address,
					APIEndpoint:       party.APIEndpoint,
					MessagingEndpoint: party.MessagingEndpoint,
					WebsocketEndpoint: party.WebsocketEndpoint,
				},
				party.Address,
				make([]*Workgroup, 0),
				make([]*Workflow, 0),
				make([]*Workstep, 0),
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
			apiEndpoint, _ := org.Metadata["api_endpoint"].(string)
			messagingEndpoint, _ := org.Metadata["messaging_endpoint"].(string)

			if addrOk {
				p := &Participant{}
				p.Address = common.StringOrNil(addr)
				p.APIEndpoint = common.StringOrNil(apiEndpoint)
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

func (s *SubjectAccount) requireSOR() {
	common.Log.Warningf("FIXME-- require all SORs")
	// FIXME!!!

	if os.Getenv("PROVIDE_SOR_IDENTIFIER") == "" {
		common.Log.Warningf("PROVIDE_SOR_IDENTIFIER not provided")
	}

	if os.Getenv("PROVIDE_SOR_URL") == "" {
		common.Log.Warningf("PROVIDE_SOR_URL not provided")
	}

	s.Metadata.SOR = map[string]interface{}{
		"identifier": os.Getenv("PROVIDE_SOR_IDENTIFIER"),
	}

	if os.Getenv("PROVIDE_SOR_URL") != "" && os.Getenv("PROVIDE_SOR_URL") != "https://" {
		s.Metadata.SOR["url"] = os.Getenv("PROVIDE_SOR_URL")
	}

	if os.Getenv("PROVIDE_SOR_ORGANIZATION_CODE") != "" {
		s.Metadata.SOR["organization_code"] = os.Getenv("PROVIDE_SOR_ORGANIZATION_CODE")
	}
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
