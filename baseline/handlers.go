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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-pgputil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/baseline/middleware"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
	provide "github.com/provideplatform/provide-go/common"
	"github.com/provideplatform/provide-go/common/util"
)

// InstallBPIAPI installs public API for interacting with the baseline protocol abstraction
// layer, i.e., with `Subject`, `SubjectContext` and `BPIAccount`
func InstallBPIAPI(r *gin.Engine) {
	r.GET("/api/v1/bpi_accounts", listBPIAccountsHandler)
	r.GET("/api/v1/bpi_accounts/:id", bpiAccountDetailsHandler)
	r.POST("/api/v1/bpi_accounts", createBPIAccountHandler)

	r.POST("/api/v1/protocol_messages", sendProtocolMessageHandler)

	r.GET("/api/v1/subjects", listSubjectsHandler)
	r.GET("/api/v1/subjects/:id", subjectDetailsHandler)
	r.POST("/api/v1/subjects", createSubjectHandler)
	r.PUT("/api/v1/subjects/:id", updateSubjectHandler)

	r.GET("/api/v1/subjects/:id/accounts", listSubjectAccountsHandler)
	r.GET("/api/v1/subjects/:id/accounts/:accountId", subjectAccountDetailsHandler)
	r.POST("/api/v1/subjects/:id/accounts", createSubjectAccountHandler)
	r.PUT("/api/v1/subjects/:id/accounts/:accountId", updateSubjectAccountsHandler)
}

const defaultResultsPerPage = 25

// InstallCredentialsAPI installs public API for interacting with verifiable credentials
func InstallCredentialsAPI(r *gin.Engine) {
	r.POST("/api/v1/credentials", issueVerifiableCredentialHandler)
}

// InstallMappingsAPI installs mapping management APIs
func InstallMappingsAPI(r *gin.Engine) {
	r.GET("/api/v1/mappings", listMappingsHandler)
	r.POST("/api/v1/mappings", createMappingHandler)
	r.PUT("/api/v1/mappings/:id", updateMappingHandler)
	r.DELETE("/api/v1/mappings/:id", deleteMappingHandler)
}

// InstallPublicWorkgroupAPI installs an API servicing a configured public workgroup
func InstallPublicWorkgroupAPI(r *gin.Engine) {
	r.POST("/api/v1/pub/invite", createPublicWorkgroupInviteHandler)
}

// InstallSystemsAPI installs system management APIs
func InstallSystemsAPI(r *gin.Engine) {
	r.POST("/api/v1/systems/reachability", systemReachabilityHandler)
}

// InstallSchemasAPI installs middleware schemas API
func InstallSchemasAPI(r *gin.Engine) {
	r.GET("/api/v1/workgroups/:id/schemas", listSchemasHandler)
	r.GET("/api/v1/workgroups/:id/schemas/:schemaId", schemaDetailsHandler)
}

// InstallWorkgroupsAPI installs workgroup management APIs
func InstallWorkgroupsAPI(r *gin.Engine) {
	r.GET("/api/v1/workgroups", listWorkgroupsHandler)
	r.GET("/api/v1/workgroups/:id", workgroupDetailsHandler)
	r.GET("/api/v1/workgroups/:id/analytics", workgroupAnalyticsHandler)
	r.POST("/api/v1/workgroups", createWorkgroupHandler)
	r.PUT("/api/v1/workgroups/:id", updateWorkgroupHandler)
}

// InstallWorkflowsAPI installs workflow management APIs
func InstallWorkflowsAPI(r *gin.Engine) {
	r.GET("/api/v1/workflows", listWorkflowsHandler)
	r.GET("/api/v1/workflows/:id", workflowDetailsHandler)
	r.POST("/api/v1/workflows", createWorkflowHandler)
	r.PUT("/api/v1/workflows/:id", updateWorkflowHandler)
	r.POST("/api/v1/workflows/:id/deploy", deployWorkflowHandler)
	r.GET("/api/v1/workflows/:id/versions", listWorkflowVersionsHandler)
	r.POST("/api/v1/workflows/:id/versions", versionWorkflowHandler)
	r.DELETE("/api/v1/workflows/:id", deleteWorkflowHandler)
}

// InstallWorkstepsAPI installs workstep management APIs
func InstallWorkstepsAPI(r *gin.Engine) {
	r.GET("/api/v1/worksteps", listWorkstepsHandler)
	r.GET("/api/v1/workflows/:id/worksteps", listWorkstepsHandler)
	r.GET("/api/v1/workflows/:id/worksteps/:workstepId", workstepDetailsHandler)
	r.POST("/api/v1/workflows/:id/worksteps", createWorkstepHandler)
	r.PUT("/api/v1/workflows/:id/worksteps/:workstepId", updateWorkstepHandler)
	r.DELETE("/api/v1/workflows/:id/worksteps/:workstepId", deleteWorkstepHandler)
	r.POST("/api/v1/workflows/:id/worksteps/:workstepId/execute", executeWorkstepHandler)
	r.GET("/api/v1/workflows/:id/worksteps/:workstepId/participants", listWorkstepParticipantsHandler)
	r.POST("/api/v1/workflows/:id/worksteps/:workstepId/participants", createWorkstepParticipantHandler)
	r.DELETE("/api/v1/workflows/:id/worksteps/:workstepId/participants/:participantId", deleteWorkstepParticipantHandler)
}

func sendProtocolMessageHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	message := &Message{}
	err = json.Unmarshal(buf, message)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if message.ID != nil {
		record := lookupBaselineRecordByInternalID(*message.ID)
		if record == nil {
			provide.RenderError("baseline record not found", 404, c)
			return
		}

		workstep, err := record.resolveExecutableWorkstepContext()
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		workflow := FindWorkflowByID(*workstep.WorkflowID)
		if workflow == nil {
			provide.RenderError("workflow not resolved", 500, c)
			return
		}

		subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
		message.subjectAccount, err = resolveSubjectAccount(subjectAccountID)
		if err != nil {
			provide.RenderError("failed to resolve BPI subject account", 403, c)
			return
		}

		authorizedSender := false
		for _, participant := range workstep.Participants {
			if participant.Address != nil && *participant.Address == *message.subjectAccount.Metadata.OrganizationAddress {
				authorizedSender = true
				break
			}
		}

		if !authorizedSender {
			provide.RenderError("forbidden", 403, c)
			return
		}
	}

	// HACK!!
	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	message.token = common.StringOrNil(token.Raw)

	if message.baselineOutbound() {
		message.ProtocolMessage.Payload.Object = nil
		provide.Render(message.ProtocolMessage, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = message.Errors
		provide.Render(obj, 422, c)
	}
}

func createWorkgroupHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		msg := fmt.Sprintf("failed to unmarshal workgroup params; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	isAcceptInvite := params["token"] != nil && params["subject_account_params"] != nil
	isCreateWorkgroup := params["token"] == nil && params["subject_account_params"] == nil

	if isCreateWorkgroup {
		token, _ := util.ParseBearerAuthorizationHeader(c, nil)
		resp, err := ident.CreateApplication(token.Raw, params)
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		var workgroup *Workgroup

		err = json.Unmarshal(buf, &workgroup)
		if err != nil {
			msg := fmt.Sprintf("failed to unmarshal workgroup params; %s", err.Error())
			provide.RenderError(msg, 422, c)
			return
		}

		workgroup.ID = resp.ID
		workgroup.OrganizationID = organizationID

		if !workgroup.Create() {
			obj := map[string]interface{}{}
			obj["errors"] = workgroup.Errors
			provide.Render(obj, 422, c)
			return
		}

		workgroup.Config = resp.Config
		workgroup.NetworkID = &resp.NetworkID

		provide.Render(workgroup, 201, c)
		return
	}

	if isAcceptInvite {
		acceptWorkgroupInvite(c, *organizationID, params)
		return
	}

	provide.RenderError("failed to create workgroup; must provide subject_account_params and token or create workgroup params", 422, c)
}

func updateWorkgroupHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		msg := fmt.Sprintf("failed to handle update workgroup params; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workgroup := FindWorkgroupByID(workgroupID)
	if workgroup == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	err = ident.UpdateApplication(token.Raw, workgroupID.String(), params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	var _workgroup *Workgroup
	err = json.Unmarshal(buf, &_workgroup)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if workgroup.Update(_workgroup) {
		provide.Render(nil, 204, c)
	} else if len(workgroup.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workgroup.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func acceptWorkgroupInvite(c *gin.Context, organizationID uuid.UUID, params map[string]interface{}) {
	bearerToken := params["token"].(string)

	claims := &InviteClaims{}
	var jwtParser jwt.Parser
	_, _, err := jwtParser.ParseUnverified(bearerToken, claims)

	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; failed to parse jwt; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Baseline == nil {
		msg := "failed to accept workgroup invitation; no baseline claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Baseline.WorkgroupID == nil {
		msg := "failed to accept workgroup invitation; no baseline workgroup identifier claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Baseline.InvitorOrganizationAddress == nil {
		msg := "failed to accept workgroup invitation; no baseline invitor organization address claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Baseline.InvitorSubjectAccountID == nil {
		msg := "failed to accept workgroup invitation; no baseline invitor subject account id claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	identifierUUID, err := uuid.FromString(*claims.Baseline.WorkgroupID)
	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; invalid identifier; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	invitorSubjectAccount, err := resolveSubjectAccount(*claims.Baseline.InvitorSubjectAccountID)
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	// subjectAccountID := subjectAccountIDFactory(organizationID.String(), identifierUUID.String())
	// subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	// if err != nil {
	// 	common.Log.Debugf("no BPI subject account resolved during attempted workgroup invite acceptance for subject account %s", subjectAccountID)
	// 	// provide.RenderError(err.Error(), 403, c)
	// 	// return
	// }

	// parse the token again, this time verifying the signature origin as the named subject account
	_, err = jwt.Parse(bearerToken, func(_jwtToken *jwt.Token) (interface{}, error) {
		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		jwks, err := invitorSubjectAccount.resolveJWKs() //parseJWKs()
		if err != nil {
			return nil, err
		}

		jwk := jwks[*kid]
		if jwk == nil {
			msg := "failed to resolve a valid JWT verification key"
			if kid != nil {
				msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
			} else {
				msg = fmt.Sprintf("%s; no default verification key configured", msg)
			}
			return nil, fmt.Errorf(msg)
		}

		publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(jwk.PublicKey))
		if err != nil {
			common.Log.Warningf("failed to parse JWT public key for BPI subject account %s; %s", *invitorSubjectAccount.ID, err.Error())
			return nil, fmt.Errorf("failed to parse JWT public key; %s", err.Error())
		}

		common.Log.Debugf("resolved JWK for BPI subject account %s: %s", *invitorSubjectAccount.ID, *kid)
		return publicKey, nil
	})

	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; failed to parse jwt; %s", err.Error())
		provide.RenderError(msg, 403, c)
		return
	}

	// FIXME!!
	// var registryContractAddress *string
	// if addr, registryContractAddressOk := baselineClaim["registry_contract_address"].(string); registryContractAddressOk {
	// 	registryContractAddress = common.StringOrNil(addr)
	// } else {
	// 	msg := fmt.Sprintf("no registry contract address provided by invitor: %s", *invitorAddress)
	// 	common.Log.Warningf(msg)
	// 	provide.RenderError(msg, 422, c)
	// 	return
	// }

	// if registryContractAddress == nil || *registryContractAddress != *subjectAccount.Metadata.RegistryContractAddress {
	// 	msg := fmt.Sprintf("given registry contract address (%s) did not match configured address (%s)", *invitorAddress, *subjectAccount.Metadata.RegistryContractAddress)
	// 	common.Log.Warningf(msg)
	// 	provide.RenderError(msg, 422, c)
	// 	return
	// }

	var vc *string
	if bearerToken, bearerTokenOk := params["authorized_bearer_token"].(string); bearerTokenOk {
		vc = common.StringOrNil(bearerToken)
	}

	invitor := &Participant{
		Address:    claims.Baseline.InvitorOrganizationAddress,
		Workgroups: make([]*Workgroup, 0),
		Workflows:  make([]*Workflow, 0),
		Worksteps:  make([]*Workstep, 0),
	}
	invitor.Cache()

	participants := make([]*Participant, 0)
	participants = append(participants, invitor) // FIXME!! this should be used to dispatch join opcode to the L3

	if vc != nil {
		err = CacheBaselineOrganizationIssuedVC(*claims.Baseline.InvitorOrganizationAddress, *vc)
		if err != nil {
			msg := fmt.Sprintf("failed to cache organization-issued vc; %s", err.Error())
			common.Log.Warningf(msg)
			provide.RenderError(msg, 422, c)
			return
		}
	}

	// FIXME -- audit use of `authorized_bearer_token` and `jwt`
	// var authorizedVC *string // TODO: vend NATS bearer token
	// common.Log.Warningf("TODO-- vent counterparty VC...")

	subjectAccountParams := params["subject_account_params"]
	raw, err := json.Marshal(subjectAccountParams)

	var subjectAccount *SubjectAccount
	err = json.Unmarshal(raw, &subjectAccount)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if isValid, errors := validateSubjectAccountParams(subjectAccount); !isValid {
		obj := map[string]interface{}{}
		obj["errors"] = errors
		provide.Render(obj, 422, c)
		return
	}

	subjectAccountID := subjectAccountIDFactory(*subjectAccount.Metadata.OrganizationID, *subjectAccount.Metadata.WorkgroupID)
	if FindSubjectAccountByID(subjectAccountID) != nil {
		provide.RenderError("BPI subject account exists", 409, c)
		return
	}

	subjectAccount.ID = &subjectAccountID
	subjectAccount.SubjectID = common.StringOrNil(organizationID.String())

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if subjectAccount.create(tx) {
		SubjectAccounts = append(SubjectAccounts, subjectAccount)
		SubjectAccountsByID[subjectAccountID] = append(SubjectAccountsByID[subjectAccountID], subjectAccount)

		err = subjectAccount.startDaemon(subjectAccount.Metadata.OrganizationRefreshToken)
		if err != nil {
			provide.RenderError(fmt.Sprintf("BPI subject account initialization failed; %s", err.Error()), 500, c)
			return
		}

		// give other workgroup participants access to new organization domain models wip -- currently solved by creating mappings after invitation has been accepted

		// token, _ := util.ParseBearerAuthorizationHeader(c, nil)
		// wg_orgs, err := ident.ListApplicationOrganizations(token.Raw, *claims.Baseline.WorkgroupID, map[string]interface{}{})
		// if err != nil {
		// 	subjectAccount.Errors = append(subjectAccount.Errors, &api.Error{
		// 		Message: common.StringOrNil(err.Error()),
		// 	})

		// 	obj := map[string]interface{}{}
		// 	obj["errors"] = subjectAccount.Errors
		// 	provide.Render(obj, 422, c)
		// 	return
		// }

		// give new organization access to all workgroup domain models
		var mappings []*Mapping
		tx.Where("workgroup_id = ?", *claims.Baseline.WorkgroupID).Find(&mappings)

		for _, m := range mappings {
			result := db.Exec("INSERT INTO organizations_mappings (organization_id, mapping_id, permissions) VALUES (?, ?, ?)", *subjectAccount.Metadata.OrganizationID, m.ID, 0) // TODO-- default permission level ??
			rowsAffected := result.RowsAffected
			errors := result.GetErrors()
			if len(errors) > 0 {
				for _, err := range errors {
					subjectAccount.Errors = append(subjectAccount.Errors, &api.Error{
						Message: common.StringOrNil(err.Error()),
					})
				}
			}

			if rowsAffected == 0 {
				obj := map[string]interface{}{}
				obj["errors"] = subjectAccount.Errors
				provide.Render(obj, 422, c)
				return
			}
		}

		tx.Commit()

		common.Log.Debugf("BPI subject account intiailized: %s", *subjectAccount.ID)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
		provide.Render(obj, 422, c)
		return
	}

	obj := map[string]interface{}{
		// 	"authorized_bearer_token": authorizedVC,
	}

	if subjectAccount != nil && subjectAccount.Metadata != nil && subjectAccount.Metadata.OrganizationAddress != nil {
		// FIXME... allow "subject_account" param to be provided
		obj["address"] = *subjectAccount.Metadata.OrganizationAddress
	}

	msg := &ProtocolMessage{
		Opcode:     common.StringOrNil(baseline.ProtocolMessageOpcodeJoin),
		Identifier: &identifierUUID,
		Payload: &ProtocolMessagePayload{
			Object: obj,
		},
	}
	payload, _ := json.Marshal(msg)

	common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
	_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)
	if err != nil {
		common.Log.Warningf("failed to dispatch protocol message; %s", err.Error())
		// FIXME?? should we rollback a transaction here?
	}

	if err == nil {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}

func listWorkgroupsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var rpp int64
	var err error

	rpp, err = strconv.ParseInt(c.Query("rpp"), 10, 64)
	if err != nil {
		rpp = defaultResultsPerPage
	}

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	resp, err := ident.ListApplications(token.Raw, map[string]interface{}{
		"rpp":  250, // HACK
		"type": "baseline",
	})

	if err == nil {
		workgroups := make([]*Workgroup, 0)

		for _, app := range resp {
			workgroup := FindWorkgroupByID(app.ID)
			if workgroup != nil {
				if !workgroup.Enrich(token.Raw) {
					obj := map[string]interface{}{}
					obj["errors"] = workgroup.Errors
					provide.Render(obj, 422, c)
					return
				}

				workgroups = append(workgroups, workgroup)
			}

			if len(workgroups) == int(rpp) {
				break
			}
		}

		provide.Render(workgroups, 200, c)
	} else {
		provide.RenderError(fmt.Sprintf("failed to list workgroups; %s", err.Error()), 500, c)
	}
}

func workgroupDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroup := LookupBaselineWorkgroup(c.Param("id"))

	if workgroup == nil {
		workgroupID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		workgroup = FindWorkgroupByID(workgroupID)
	}

	if workgroup == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	_, err := ident.GetApplicationDetails(token.Raw, workgroup.ID.String(), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 404, c) // FIXME-- pass thru ident status
		return
	}

	// FIXME-- the following enrich call should be handed the above application ptr
	if !workgroup.Enrich(token.Raw) {
		obj := map[string]interface{}{}
		obj["errors"] = workgroup.Errors
		provide.Render(obj, 422, c)
		return
	}

	provide.Render(workgroup, 200, c)
}

func workgroupAnalyticsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroup := LookupBaselineWorkgroup(c.Param("id"))

	if workgroup == nil {
		workgroupID, err := uuid.FromString(c.Param("id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}

		workgroup = FindWorkgroupByID(workgroupID)
	}

	if workgroup == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	_, err := ident.GetApplicationDetails(token.Raw, workgroup.ID.String(), map[string]interface{}{})
	if err != nil {
		provide.RenderError(err.Error(), 404, c) // FIXME-- pass thru ident status
		return
	}

	// FIXME-- the following enrich call should be handed the above application ptr
	if !workgroup.Enrich(token.Raw) {
		obj := map[string]interface{}{}
		obj["errors"] = workgroup.Errors
		provide.Render(obj, 422, c)
		return
	}

	analytics, err := workgroup.queryAnalytics()
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	provide.Render(analytics, 200, c)
}

func createPublicWorkgroupInviteHandler(c *gin.Context) {
	if common.BaselinePublicWorkgroupID == nil {
		provide.RenderError("no public workgroup configured", 501, c)
		return
	}

	token, err := common.RefreshPublicWorkgroupAccessToken()
	if err != nil {
		msg := fmt.Sprintf("failed to authorize public workgroup access token; %s", err.Error())
		common.Log.Warningf(msg)

		provide.RenderError(msg, 500, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	params := &baseline.PublicWorkgroupInvitationRequest{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	ident.CreateInvitation(*token, map[string]interface{}{
		"email":      params.Email,
		"first_name": params.FirstName,
		"last_name":  params.LastName,
		"params": map[string]interface{}{
			"organization_name": params.OrganizationName,
		},
	})
}

func systemReachabilityHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var system middleware.System
	err = json.Unmarshal(buf, &system)
	if err != nil {
		msg := fmt.Sprintf("failed to check system reachability status; %s", err.Error())
		provide.RenderError(msg, 422, c)
		return
	}

	if system.Type == nil {
		msg := "failed to check system reachability status; system type required"
		provide.RenderError(msg, 422, c)
		return
	}

	switch *system.Type {
	case "sap":
		sor := middleware.SAPFactory(&system)
		if err := sor.HealthCheck(); err != nil {
			msg := fmt.Sprintf("system healthcheck failed; %s", err.Error())
			provide.RenderError(msg, 422, c)
			return
		}

		provide.Render(nil, 204, c)
	default:
		msg := fmt.Sprintf("system healthcheck failed; %s sor not implemented", *system.Type)
		provide.RenderError(msg, 422, c)
	}
}

func listMappingsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var mappings []*Mapping

	query := FindMappingsByOrganizationID(*organizationID)

	if c.Query("workgroup_id") != "" {
		workgroupID, err := uuid.FromString(c.Query("workgroup_id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		query = query.Where("workgroup_id = ?", workgroupID)
	}

	if c.Query("ref") != "" {
		query = query.Where("ref = ?", c.Query("ref"))
	}

	if c.Query("version") != "" {
		query = query.Where("version = ?", c.Query("version"))
	}

	query = query.Order("type DESC")
	provide.Paginate(c, query, &Mapping{}).Find(&mappings)

	for _, mapping := range mappings {
		mapping.enrich()
	}

	provide.Render(mappings, 200, c)
}

func createMappingHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var mapping *Mapping
	err = json.Unmarshal(buf, &mapping)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if mapping.Ref != nil {
		provide.RenderError("cannot specify ref", 400, c)
		return
	}

	mapping.OrganizationID = organizationID

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)

	if mapping.Create(token.Raw) {
		provide.Render(mapping, 201, c)
	} else if len(mapping.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = mapping.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func updateMappingHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	mappingIDStr := c.Param("id")
	mappingID, err := uuid.FromString(mappingIDStr)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	mapping := FindMappingByID(mappingID)
	if mapping == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	// if *mapping.OrganizationID != *organizationID {
	// 	provide.RenderError("forbidden", 403, c)
	// 	return
	// }

	_mapping := &Mapping{}
	err = json.Unmarshal(buf, _mapping)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if _mapping.ID != uuid.Nil && mapping.ID != _mapping.ID {
		provide.RenderError("cannot modify mapping id", 400, c)
		return
	}

	if _mapping.Ref != nil {
		provide.RenderError("cannot specify ref", 400, c)
		return
	}

	if mapping.Update(_mapping) {
		provide.Render(nil, 204, c)
	} else if len(mapping.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = mapping.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteMappingHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	mappingIDStr := c.Param("id")
	mappingID, err := uuid.FromString(mappingIDStr)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	mapping := FindMappingByID(mappingID)
	if mapping == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	if *mapping.OrganizationID != *organizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if mapping.Delete() {
		provide.Render(nil, 204, c)
	} else if len(mapping.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = mapping.Errors
		provide.Render(obj, 422, c)
	}
}

func listSchemasHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var systems []*middleware.System
	var err error

	useEphemeralSystem := c.Query("system_secret_ids") != ""

	if !useEphemeralSystem {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), c.Param("id"))
		subjectAccount, err := resolveSubjectAccount(subjectAccountID)
		if err != nil {
			provide.RenderError(err.Error(), 403, c)
			return
		}

		systems, err = subjectAccount.listSystems()
		if err != nil {
			provide.RenderError("failed to list systems for subject account", 403, c)
			return
		}
	} else {
		if c.Query("vault_id") == "" {
			provide.RenderError("vault_id required for querying ephemerally-referenced system secrets", 422, c)
			return
		}

		token, _ := util.ParseBearerAuthorizationHeader(c, nil)
		systemSecretIDs := strings.Split(c.Query("system_secret_ids"), ",")
		systems, err = resolveSystems(token.Raw, c.Query("vault_id"), systemSecretIDs)
		if err != nil {
			provide.RenderError("failed to list systems for ephemerally-referenced system secrets", 403, c)
			return
		}
	}

	resp := make([]interface{}, 0) // FIXME?? use []*Mapping

	// FIXME-- dispatch goroutine-per-system with channel to sync the returned schemas for aggregation...
	for _, system := range systems {
		sor := middleware.SystemFactory(system)
		if sor == nil {
			common.Log.Warningf("subject account has unsupported or misconfigured system: %s; skipping...", *system.Name)
			continue
		}

		schemas, err := sor.ListSchemas(map[string]interface{}{
			"q": c.Query("q"),
		})
		if err != nil {
			provide.RenderError(err.Error(), 500, c)
			return
		}

		if arr, arrOk := schemas.([]interface{}); arrOk {
			if len(c.Query("q")) > 0 {
				// HACK!! proof of concept filter only... proper impl forthcoming
				for _, result := range arr {
					if schema, schemaOk := result.(map[string]interface{}); schemaOk {
						if schemaType, schemaTypeOk := schema["type"].(string); schemaTypeOk {
							if strings.Contains(strings.ToLower(schemaType), strings.ToLower(c.Query("q"))) {
								resp = append(resp, schema)
							}
						}
					}
				}
			} else {
				resp = append(resp, arr...)
			}
		}
	}

	// TODO-- aggregate local mappings and dedupe/enrich with SOR results
	// to return blended API response

	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	provide.Render(resp, 200, c)
}

func schemaDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var systems []*middleware.System
	var err error

	useEphemeralSystem := c.Query("system_secret_ids") != ""

	if !useEphemeralSystem {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), c.Param("id"))
		subjectAccount, err := resolveSubjectAccount(subjectAccountID)
		if err != nil {
			provide.RenderError(err.Error(), 403, c)
			return
		}

		systems, err = subjectAccount.listSystems()
		if err != nil {
			provide.RenderError("failed to list systems for subject account", 403, c)
			return
		}
	} else {
		if c.Query("vault_id") == "" {
			provide.RenderError("vault_id required for querying ephemerally-referenced system secrets", 422, c)
			return
		}

		token, _ := util.ParseBearerAuthorizationHeader(c, nil)
		systemSecretIDs := strings.Split(c.Query("system_secret_ids"), ",")
		systems, err = resolveSystems(token.Raw, c.Query("vault_id"), systemSecretIDs)
		if err != nil {
			provide.RenderError("failed to list systems for ephemerally-referenced system secrets", 403, c)
			return
		}
	}

	var resp interface{}

	// FIXME-- filter systems to resolve the original system from which the requested schema is being requested...
	for _, system := range systems {
		sor := middleware.SystemFactory(system)
		if sor == nil {
			common.Log.Warningf("subject account has unsupported or misconfigured system: %s; skipping...", *system.Name)
			continue
		}

		// schemaID, err := url.QueryUnescape(c.Param("schemaId"))
		// if err != nil {
		// 	provide.RenderError("invalid schema id", 400, c)
		// 	return
		// }

		resp, err = sor.GetSchema(c.Param("schemaId"), map[string]interface{}{})
		if err != nil {
			provide.RenderError(err.Error(), 422, c) // FIXME-- pass the status code thru...
			return
		}

		provide.Render(resp, 200, c)
		return
	}

	provide.RenderError("not found", 404, c)
}

func createWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var workflow *Workflow
	err = json.Unmarshal(buf, &workflow)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow.OrganizationID = organizationID

	if workflow.Create(nil) {
		provide.Render(workflow, 201, c)
	} else if len(workflow.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workflow.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deployWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	_workflow := &Workflow{}
	_workflow.Status = common.StringOrNil(workflowStatusDeployed) // HACK!!!
	_workflow.Version = workflow.Version

	if workflow.Update(_workflow) {
		provide.Render(workflow, 202, c)
	} else if len(workflow.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workflow.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func versionWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	var params map[string]interface{}
	err = json.Unmarshal(buf, &params)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	var name *string
	if nme, ok := params["name"].(string); ok {
		name = common.StringOrNil(nme)
	}

	var description *string
	if desc, ok := params["description"].(string); ok {
		description = common.StringOrNil(desc)
	}

	var version *string
	if vrsn, ok := params["version"].(string); ok {
		version = common.StringOrNil(vrsn)
	} else {
		provide.RenderError("version is required", 422, c)
		return
	}

	raw, err := json.Marshal(workflow)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	var _workflow *Workflow
	err = json.Unmarshal(raw, &_workflow)
	if err != nil {
		provide.RenderError(err.Error(), 500, c)
		return
	}

	_workflow.ID = uuid.Nil
	_workflow.Status = common.StringOrNil(workflowStatusDraft)
	_workflow.Version = version

	if name != nil {
		_workflow.Name = name
	}

	if description != nil {
		_workflow.Description = description
	}

	_workflow.OrganizationID = organizationID

	if _workflow.createVersion(workflow, *version) {
		provide.Render(_workflow, 201, c)
	} else if len(_workflow.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = _workflow.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func listWorkflowVersionsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	db := dbconf.DatabaseConnection()
	versions := workflow.listVersions(db)
	// var versions []*WorkflowVersion
	// query := workflow.listVersionsQuery()
	// provide.Paginate(c, query, &WorkflowVersion{}).Find(&versions)
	provide.Render(versions, 200, c)
}

func updateWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	var _workflow *Workflow
	err = json.Unmarshal(buf, &_workflow)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if workflow.Update(_workflow) {
		provide.Render(nil, 204, c)
	} else if len(workflow.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workflow.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	if workflow.Delete() {
		provide.Render(nil, 204, c)
	} else if len(workflow.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workflow.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func listWorkflowsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var workflows []*Workflow

	filterInstances := strings.ToLower(c.Query("filter_instances")) == "true"
	filterPrototypes := strings.ToLower(c.Query("filter_prototypes")) == "true"

	db := dbconf.DatabaseConnection()
	query := db.Where("organization_id = ?", organizationID).Order("created_at DESC")

	if c.Query("workgroup_id") != "" {
		query = query.Where("workgroup_id = ?", c.Query("workgroup_id"))
	}
	if c.Query("workflow_id") != "" {
		query = query.Where("workflow_id = ?", c.Query("workflow_id"))
	}
	if filterInstances {
		query = query.Where("workflow_id IS NULL")
	}
	if filterPrototypes {
		query = query.Where("workflow_id IS NOT NULL")
	}

	provide.Paginate(c, query, &Workflow{}).Find(&workflows)
	provide.Render(workflows, 200, c)
}

func workflowDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)

	if workflow != nil {
		workflow.enrich()
		provide.Render(workflow, 200, c)
	} else {
		provide.RenderError("workflow not found", 404, c)
	}
}

func createWorkstepHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var workstep *Workstep
	err = json.Unmarshal(buf, &workstep)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	// workstep.OrganizationID = organizationID
	workstep.WorkflowID = &workflowID

	workflow := FindWorkflowByID(workflowID)
	if workflow != nil && !workflow.isPrototype() {
		provide.RenderError("cannot add workstep to workflow instance", 400, c)
		return
	}

	if workflow != nil && workflow.Status != nil && *workflow.Status != workflowStatusDraft {
		provide.RenderError("cannot add worksteps to non-draft workflow prototype", 400, c)
		return
	}

	if workstep.Create(nil) {
		provide.Render(workstep, 201, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func updateWorkstepHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var _workstep *Workstep
	err = json.Unmarshal(buf, &_workstep)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	var __workstep map[string]interface{}
	err = json.Unmarshal(buf, &__workstep)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}
	if _, ok := __workstep["cardinality"].(float64); ok {
		_workstep.userInputCardinality = true
	}

	if workstep.Status != nil && _workstep.Status != nil && *workstep.Status != *_workstep.Status {
		provide.RenderError("cannot modify workstep status", 400, c)
		return
	}

	if workstep.Update(_workstep) {
		provide.Render(nil, 204, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteWorkstepHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if workstep.Delete() {
		provide.Render(nil, 204, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func executeWorkstepHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workflow := FindWorkflowByID(workflowID)
	if workflow == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if workstep.Status != nil && *workstep.Status != workstepStatusInit && *workstep.Status != workstepStatusRunning {
		provide.RenderError("cannot execute workstep", 400, c)
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		provide.RenderError(err.Error(), 403, c)
		return
	}

	var payload *ProtocolMessagePayload
	err = json.Unmarshal(buf, &payload)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c, nil)
	proof, err := workstep.execute(subjectAccount, token.Raw, payload)
	if err != nil {
		provide.RenderError(fmt.Sprintf("cannot execute workstep; %s", err.Error()), 422, c)
		return
	}

	if proof != nil {
		provide.Render(proof, 201, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func listWorkstepsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var worksteps []*Workstep

	filterInstances := strings.ToLower(c.Query("filter_instances")) == "true"
	filterPrototypes := strings.ToLower(c.Query("filter_prototypes")) == "true"

	db := dbconf.DatabaseConnection()
	var query *gorm.DB

	if c.Param("id") != "" {
		query = db.Where("worksteps.workflow_id = ?", c.Param("id"))
	}
	if filterInstances {
		query = db.Where("worksteps.workstep_id IS NULL")
	}
	if filterPrototypes {
		query = db.Where("worksteps.workstep_id IS NOT NULL")
	}

	if query == nil {
		query = db.Order("worksteps.cardinality ASC")
	} else {
		query = query.Order("worksteps.cardinality ASC")
	}

	provide.Paginate(c, query, &Workstep{}).Find(&worksteps)
	provide.Render(worksteps, 200, c)
}

func workstepDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)

	if workstep != nil {
		token, _ := util.ParseBearerAuthorizationHeader(c, nil)
		workstep.enrich(token.Raw)
		provide.Render(workstep, 200, c)
	} else {
		provide.RenderError("workstep not found", 404, c)
	}
}

func issueVerifiableCredentialHandler(c *gin.Context) {
	issueVCRequest := &baseline.IssueVerifiableCredentialRequest{}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &issueVCRequest)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal workgroup invitation acceptance request; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if issueVCRequest.Address == nil {
		provide.RenderError("address is required", 422, c)
		return
	}

	// FIXME-- make general with PublicKey
	if issueVCRequest.PublicKey == nil {
		provide.RenderError("public_key is required", 422, c)
		return
	}

	if issueVCRequest.Signature == nil {
		provide.RenderError("signature is required", 422, c)
		return
	}

	msg := crypto.Keccak256Hash([]byte(*issueVCRequest.Address))
	sig, _ := hex.DecodeString(*issueVCRequest.Signature)
	pubkey, err := crypto.Ecrecover(msg.Bytes(), []byte(sig))
	if err != nil {
		msg := fmt.Sprintf("failed to recover public key from signature: %s; %s", *issueVCRequest.Signature, err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	// pubkeyBytes := crypto.Keccak256Hash(pubkey).Bytes()
	// recoveredAddress := fmt.Sprintf("0x%s", pubkeyBytes[12:32])
	// common.Log.Debugf("recovered public key: 0x%s; recovered address: %s", hex.EncodeToString(pubkeyBytes), recoveredAddress)

	signerPubkey, err := hex.DecodeString((*issueVCRequest.PublicKey)[2:])
	if err != nil {
		msg := fmt.Sprintf("failed to recover public key from signature: %s; %s", *issueVCRequest.Signature, err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if !bytes.Equal(pubkey, signerPubkey) {
		// common.Log.Warningf("recovered address %s did not match expected signer %s", string(recoveredAddress), *issueVCRequest.Address)
		common.Log.Warningf("recovered public key %s did not match expected signer %s", string(pubkey), *issueVCRequest.PublicKey)
		provide.RenderError("recovered address did not match signer", 422, c)
		return
	}

	credential, err := IssueVC(*issueVCRequest.Address, map[string]interface{}{})

	if err == nil {
		provide.Render(&baseline.IssueVerifiableCredentialResponse{
			VC: credential,
		}, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}

func listWorkstepParticipantsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	db := dbconf.DatabaseConnection()
	participants := workstep.listParticipants(db)
	// var participants []*WorkstepParticipant
	// query := workstep.listParticipantsQuery()
	// provide.Paginate(c, query, &WorkstepParticipant{}).Find(&participants)
	provide.Render(participants, 200, c)
}

func createWorkstepParticipantHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var participant *WorkstepParticipant

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &participant)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal participant; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if workstep.Status == nil || *workstep.Status != workstepStatusDraft {
		provide.RenderError("cannot execute workstep", 400, c)
		return
	}

	if participant.Participant == nil {
		provide.RenderError("address required", 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	if workstep.addParticipant(*participant.Participant, db) {
		provide.Render(nil, 204, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteWorkstepParticipantHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	address := c.Param("participantId")

	workflowID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstepID, err := uuid.FromString(c.Param("workstepId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if workstep.WorkflowID == nil || workstep.WorkflowID.String() != workflowID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if workstep.Status == nil || *workstep.Status != workstepStatusDraft {
		provide.RenderError("cannot execute workstep", 400, c)
		return
	}

	db := dbconf.DatabaseConnection()
	if workstep.removeParticipant(address, db) {
		provide.Render(nil, 204, c)
	} else if len(workstep.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = workstep.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func listBPIAccountsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func bpiAccountDetailsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createBPIAccountHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func listSubjectsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func subjectDetailsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createSubjectHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func updateSubjectHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func listSubjectAccountsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var subjectAccounts []*SubjectAccount

	db := dbconf.DatabaseConnection()
	query := db.Where("subject_id = ?", organizationID).Order("created_at DESC")

	provide.Paginate(c, query, &SubjectAccount{}).Find(&subjectAccounts)
	provide.Render(subjectAccounts, 200, c)
}

func subjectAccountDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	subjectAccountID := c.Param("accountId")
	if subjectAccountID == "" {
		provide.RenderError("invalid subject account id", 400, c)
		return
	}

	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		provide.RenderError(err.Error(), 403, c)
		return
	}

	if subjectAccount == nil || subjectAccount.ID == nil {
		provide.RenderError("BPI subject account not found", 404, c)
		return
	}

	provide.Render(subjectAccount, 200, c)
}

func createSubjectAccountHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	id, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError("malformed subject id", 422, c)
		return
	}

	if id.String() != organizationID.String() {
		provide.RenderError("subject id mismatch", 403, c)
		return
	}

	var subjectAccount *SubjectAccount
	err = json.Unmarshal(buf, &subjectAccount)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if subjectAccount.ID != nil {
		provide.RenderError("id is derived and should not be provided", 422, c)
		return
	}

	if subjectAccount.SubjectID != nil && *subjectAccount.SubjectID != organizationID.String() {
		provide.RenderError("subject_id mismatch", 403, c)
		return
	}

	if isValid, errors := validateSubjectAccountParams(subjectAccount); !isValid {
		obj := map[string]interface{}{}
		obj["errors"] = errors
		provide.Render(obj, 422, c)
		return
	}

	subjectAccountID := subjectAccountIDFactory(*subjectAccount.Metadata.OrganizationID, *subjectAccount.Metadata.WorkgroupID)
	if FindSubjectAccountByID(subjectAccountID) != nil {
		provide.RenderError("BPI subject account exists", 409, c)
		return
	}

	subjectAccount.ID = &subjectAccountID
	subjectAccount.SubjectID = common.StringOrNil(organizationID.String())

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if subjectAccount.create(tx) {
		SubjectAccounts = append(SubjectAccounts, subjectAccount)
		SubjectAccountsByID[subjectAccountID] = append(SubjectAccountsByID[subjectAccountID], subjectAccount)

		err = subjectAccount.startDaemon(subjectAccount.Metadata.OrganizationRefreshToken)
		if err != nil {
			provide.RenderError(fmt.Sprintf("BPI subject account initialization failed; %s", err.Error()), 500, c)
			return
		}

		tx.Commit()

		common.Log.Debugf("BPI subject account intiailized: %s", *subjectAccount.ID)
		provide.Render(subjectAccount, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
		provide.Render(obj, 422, c)
	}
}

func validateSubjectAccountParams(params *SubjectAccount) (bool, []*api.Error) {
	errors := make([]*api.Error, 0)

	if params.Metadata == nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("metadata is required"),
		})
		return false, errors
	}

	if params.Metadata.OrganizationID == nil || uuid.FromStringOrNil(*params.Metadata.OrganizationID) == uuid.Nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("organization_id is required"),
		})
	}

	if params.Metadata.OrganizationAddress == nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("organization_address is required"),
		})
	}

	if params.Metadata.OrganizationRefreshToken == nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("organization_refresh_token is required"),
		})
	}

	if params.Metadata.WorkgroupID == nil || uuid.FromStringOrNil(*params.Metadata.WorkgroupID) == uuid.Nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("workgroup_id is required"),
		})
	}

	if params.Metadata.NetworkID == nil || uuid.FromStringOrNil(*params.Metadata.NetworkID) == uuid.Nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("network_id is required"),
		})
	}

	if params.Metadata.RegistryContractAddress == nil {
		errors = append(errors, &api.Error{
			Message: common.StringOrNil("registry_contract_address is required"),
		})
	}

	if len(errors) > 0 {
		return false, errors
	}

	return true, nil
}

func updateSubjectAccountsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}
