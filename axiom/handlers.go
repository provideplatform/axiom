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
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/axiom/common"
	"github.com/provideplatform/axiom/middleware"
	"github.com/provideplatform/provide-go/api/axiom"
	"github.com/provideplatform/provide-go/api/ident"
	provide "github.com/provideplatform/provide-go/common"
	"github.com/provideplatform/provide-go/common/util"
)

// InstallBPIAPI installs public API for interacting with the axiom protocol abstraction
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

	r.GET("/api/v1/workgroups/:id/systems", listSystemsHandler)
	r.GET("/api/v1/workgroups/:id/systems/:systemId", systemDetailsHandler)
	r.POST("/api/v1/workgroups/:id/systems", createSystemHandler)
	r.PUT("/api/v1/workgroups/:id/systems/:systemId", updateSystemHandler)
	r.DELETE("/api/v1/workgroups/:id/systems/:systemId", deleteSystemHandler)
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
	r.POST("/api/v1/workflows/:id/worksteps/:workstepId/verify", verifyWorkstepHandler)

	r.GET("/api/v1/workflows/:id/worksteps/:workstepId/constraints", listWorkstepConstraintsHandler)
	r.POST("/api/v1/workflows/:id/worksteps/:workstepId/constraints", createWorkstepConstraintHandler)
	r.PUT("/api/v1/workflows/:id/worksteps/:workstepId/constraints/:constraintId", updateWorkstepConstraintHandler)
	r.DELETE("/api/v1/workflows/:id/worksteps/:workstepId/constraints/:constraintId", deleteWorkstepConstraintHandler)

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
	err = json.Unmarshal(buf, &message)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if message.ID == nil {
		provide.RenderError("id is required", 422, c)
		return
	}

	if message.Payload == nil {
		provide.RenderError("payload is required", 422, c)
		return
	}

	if message.Type == nil {
		provide.RenderError("type is required", 422, c)
		return
	}

	var subjectAccountID *string

	if message.WorkgroupID != nil {
		subjectAccountID = common.StringOrNil(subjectAccountIDFactory(organizationID.String(), message.WorkgroupID.String()))
	} else {
		// attempt to resolve a subject account for the authorized organization...
		subjectAccounts := ListSubjectAccountsBySubjectID(organizationID.String())
		if len(subjectAccounts) == 1 {
			subjectAccountID = subjectAccounts[0].ID
		} else if len(subjectAccounts) > 1 {
			provide.RenderError("subject account context is ambiguous; workgroup_id is required", 422, c)
			return
		}
	}

	if subjectAccountID == nil {
		provide.RenderError("no subject account resolved", 422, c)
		return
	}

	message.subjectAccount, err = resolveSubjectAccount(*subjectAccountID, nil)
	if err != nil {
		provide.RenderError("failed to resolve BPI subject account", 403, c)
		return
	}

	_, _, _, _, workstep, err := message.resolveContext()
	if err != nil {
		provide.RenderError(err.Error(), 403, c)
		return
	}

	if workstep == nil {
		provide.RenderError("failed to resolve workstep context", 404, c)
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
		provide.RenderError(fmt.Sprintf("subject account is not an authorized sender; subject account id: %s", *subjectAccountID), 403, c)
		return
	}

	message.ProtocolMessage = &ProtocolMessage{
		Payload: &ProtocolMessagePayload{},
	}

	if mappedPayload, mappedPayloadOk := message.Payload.(map[string]interface{}); mappedPayloadOk {
		message.ProtocolMessage.Payload.Object = mappedPayload // HACK!!!
	}

	if message.ProtocolMessage.Payload.Object == nil {
		provide.RenderError("cannot execute workstep without mappable protocol message payload", 422, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
	proof, err := workstep.execute(message.subjectAccount, token.Raw, message.ProtocolMessage.Payload)
	if err != nil {
		provide.RenderError(fmt.Sprintf("cannot execute workstep; %s", err.Error()), 422, c)
		return
	}

	if proof != nil {
		if len(proof.Errors) == 0 {
			recipients := make([]*string, 0)
			for _, recipient := range message.Recipients {
				if *recipient.Address != *message.subjectAccount.Metadata.OrganizationAddress {
					recipients = append(recipients, common.StringOrNil(*recipient.Address))
				}

				// FIXME!! move this logic to its own method...
				msg := &ProtocolMessage{
					Opcode: common.StringOrNil(axiom.ProtocolMessageOpcodeSync),
					Payload: &ProtocolMessagePayload{
						Object: message.ProtocolMessage.Payload.Object,
						Proof:  proof.Proof,
						Type:   common.StringOrNil(protomsgPayloadTypeMapping),
					},
					Recipient:        common.StringOrNil(*recipient.Address),
					Sender:           message.subjectAccount.Metadata.OrganizationAddress,
					SubjectAccountID: message.subjectAccount.ID,
					WorkgroupID:      message.WorkgroupID,
				}
				payload, _ := json.Marshal(msg)

				common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
				_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)
				if err != nil {
					common.Log.Warningf("failed to dispatch protocol message; %s", err.Error())
				}
				// end FIXME... all the above logic should be refactored to live somewhere else...
			}

			provide.Render(&SendProtocolMessageAPIResponse{
				AxiomID:          message.AxiomID,
				Proof:            proof.Proof,
				Recipients:       recipients,
				Root:             nil,
				SubjectAccountID: subjectAccountID,
				Type:             message.Type,
				WorkgroupID:      message.WorkgroupID,
			}, 202, c)
		} else {
			obj := map[string]interface{}{}
			obj["errors"] = proof.Errors
			provide.Render(obj, 422, c)
		}
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

	isAcceptInvite := params["verifiable_credential"] != nil && params["subject_account_params"] != nil
	isCreateWorkgroup := params["verifiable_credential"] == nil && params["subject_account_params"] == nil

	if isCreateWorkgroup {
		token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
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

	provide.RenderError("failed to create workgroup; must provide subject_account_params and verifiable_credential or create workgroup params", 422, c)
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

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
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
	vcToken := params["verifiable_credential"].(string) // FIXME-- pass as verifiable_credential in params?

	// FIXME-- the use of InviteClaims here could become a bit misleading in the future... consider renaming it...
	claims := &InviteClaims{}
	var jwtParser jwt.Parser
	_, _, err := jwtParser.ParseUnverified(vcToken, claims)

	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; failed to parse jwt; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Axiom == nil {
		msg := "failed to accept workgroup invitation; no axiom claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Axiom.WorkgroupID == nil {
		msg := "failed to accept workgroup invitation; no workgroup identifier claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Axiom.InvitorBPIEndpoint == nil {
		msg := "failed to accept workgroup invitation; no invitor organization BPI endpoint claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Axiom.InvitorOrganizationAddress == nil {
		msg := "failed to accept workgroup invitation; no invitor organization address claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if claims.Axiom.InvitorSubjectAccountID == nil {
		msg := "failed to accept workgroup invitation; no invitor subject account id claim resolved in VC"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	workgroupID, err := uuid.FromString(*claims.Axiom.WorkgroupID)
	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; invalid workgroup identifier; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	// invitorSubjectAccount, err := resolveSubjectAccount(*claims.Axiom.InvitorSubjectAccountID, &vcToken)
	// if err != nil {
	// 	provide.RenderError(err.Error(), 404, c)
	// 	return
	// }

	// subjectAccountID := subjectAccountIDFactory(organizationID.String(), identifierUUID.String())
	// subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
	// if err != nil {
	// 	common.Log.Debugf("no BPI subject account resolved during attempted workgroup invite acceptance for subject account %s", subjectAccountID)
	// 	// provide.RenderError(err.Error(), 403, c)
	// 	// return
	// }

	// parse the token again, this time verifying the signature origin as the named subject account
	// _, err = jwt.Parse(vcToken, func(_jwtToken *jwt.Token) (interface{}, error) {
	// 	var kid *string
	// 	if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
	// 		kid = &kidhdr
	// 	}

	// FIXME-- we probably need to add a .well-known path to the BPI to allow fetching of these creds
	// 	jwks, err := invitorSubjectAccount.parseJWKs()
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	jwk := jwks[*kid]
	// 	if jwk == nil {
	// 		msg := "failed to resolve a valid JWT verification key"
	// 		if kid != nil {
	// 			msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
	// 		} else {
	// 			msg = fmt.Sprintf("%s; no default verification key configured", msg)
	// 		}
	// 		return nil, fmt.Errorf(msg)
	// 	}

	// 	publicKey, err := pgputil.DecodeRSAPublicKeyFromPEM([]byte(jwk.PublicKey))
	// 	if err != nil {
	// 		common.Log.Warningf("failed to parse JWT public key for BPI subject account %s; %s", *invitorSubjectAccount.ID, err.Error())
	// 		return nil, fmt.Errorf("failed to parse JWT public key; %s", err.Error())
	// 	}

	// 	common.Log.Debugf("resolved JWK for BPI subject account %s: %s", *invitorSubjectAccount.ID, *kid)
	// 	return publicKey, nil
	// })

	// if err != nil {
	// 	msg := fmt.Sprintf("failed to accept workgroup invitation; failed to parse jwt; %s", err.Error())
	// 	provide.RenderError(msg, 403, c)
	// 	return
	// }

	// FIXME!!
	// var registryContractAddress *string
	// if addr, registryContractAddressOk := axiomClaim["registry_contract_address"].(string); registryContractAddressOk {
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

	invitor := &Participant{
		Address:    claims.Axiom.InvitorOrganizationAddress,
		Workgroups: make([]*Workgroup, 0),
		Workflows:  make([]*Workflow, 0),
		Worksteps:  make([]*Workstep, 0),
	}
	invitor.Cache()

	subjectAccountParams := params["subject_account_params"]
	raw, _ := json.Marshal(subjectAccountParams)

	var subjectAccount *SubjectAccount
	err = json.Unmarshal(raw, &subjectAccount)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if !subjectAccount.validate() {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
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

	if err := subjectAccount.setDefaultItems(); err != nil {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
		provide.Render(obj, 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if subjectAccount.create(tx) {
		SubjectAccounts = append(SubjectAccounts, subjectAccount)
		SubjectAccountsByID[subjectAccountID] = append(SubjectAccountsByID[subjectAccountID], subjectAccount)

		var waitGroup sync.WaitGroup // HACK!!!
		subjectAccount.createNatsWorkgroupSyncSubscriptions(&waitGroup)

		err = subjectAccount.startDaemon(subjectAccount.Metadata.OrganizationRefreshToken)
		if err != nil {
			provide.RenderError(fmt.Sprintf("BPI subject account initialization failed; %s", err.Error()), 500, c)
			return
		}

		tx.Commit()
		common.Log.Debugf("BPI subject account intiailized: %s", *subjectAccount.ID)

		// cache the provided verifiable credential issued by the inviting counterparty
		var vc *string
		if verifiableCredential, verifiableCredentialOk := params["verifiable_credential"].(string); verifiableCredentialOk {
			vc = common.StringOrNil(verifiableCredential)
		}
		if vc != nil {
			err = subjectAccount.CacheAxiomOrganizationIssuedVC(*claims.Axiom.InvitorOrganizationAddress, *vc)
			if err != nil {
				msg := fmt.Sprintf("failed to cache organization-issued vc; %s", err.Error())
				common.Log.Warningf(msg)
				provide.RenderError(msg, 422, c)
				return
			}
		}
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
		provide.Render(obj, 422, c)
		return
	}

	authorizedVC, err := subjectAccount.IssueVC(*invitor.Address, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to issue verifiable credential for counterparty: %s; %s", *invitor.Address, err.Error())
		// FIXME?? probably need to rollback the subject accoutn tx and render the err...
	}

	obj := map[string]interface{}{
		"verifiable_credential": authorizedVC,
	}

	if subjectAccount != nil && subjectAccount.Metadata != nil && subjectAccount.Metadata.OrganizationAddress != nil {
		obj["address"] = *subjectAccount.Metadata.OrganizationAddress
	}

	if subjectAccount != nil && subjectAccount.Metadata != nil && subjectAccount.Metadata.OrganizationDomain != nil {
		obj["domain"] = *subjectAccount.Metadata.OrganizationDomain
	}

	msg := &ProtocolMessage{
		Opcode: common.StringOrNil(axiom.ProtocolMessageOpcodeJoin),
		Payload: &ProtocolMessagePayload{
			Object: obj,
		},
		Recipient:        invitor.Address,
		Sender:           subjectAccount.Metadata.OrganizationAddress,
		SubjectAccountID: subjectAccount.ID,
		WorkgroupID:      &workgroupID,
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
		obj["errors"] = []interface{}{}
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

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
	resp, err := ident.ListApplications(token.Raw, map[string]interface{}{
		"rpp":  250, // HACK
		"type": "axiom",
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

	workgroup := LookupAxiomWorkgroup(c.Param("id"))

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

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
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

	workgroup := LookupAxiomWorkgroup(c.Param("id"))

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

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
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
	if common.AxiomPublicWorkgroupID == nil {
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

	params := &axiom.PublicWorkgroupInvitationRequest{}
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

func listSystemsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var systems []*System

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	query := ListSystemsQuery(*organizationID, workgroupID)

	if c.Query("secret_ids") != "" {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), workgroupID.String())
		subjectAccount, _ := resolveSubjectAccount(subjectAccountID, nil)

		query = query.Where("vault_id = ? AND secret_id IN ?", subjectAccount.VaultID.String(), strings.Split(c.Query("secret_ids"), ","))
	}

	if c.Query("type") != "" {
		query = query.Where("type = ?", c.Query("type"))
	}

	query = query.Order("type DESC")
	provide.Paginate(c, query, &System{}).Find(&systems)

	for _, system := range systems {
		system.enrich()
	}

	provide.Render(systems, 200, c)
}

func systemDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	systemID, err := uuid.FromString(c.Param("systemId"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	system := FindSystemByID(systemID)
	if system == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	if system.WorkgroupID == nil || !strings.EqualFold(workgroupID.String(), system.WorkgroupID.String()) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if system != nil {
		system.enrich()
		provide.Render(system, 200, c)
	} else {
		provide.RenderError("system not found", 404, c)
	}
}

func createSystemHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var system *System
	err = json.Unmarshal(buf, &system)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	system.WorkgroupID = &workgroupID
	system.OrganizationID = organizationID

	if system.VaultID == nil {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), workgroupID.String())
		subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
		if err != nil {
			provide.RenderError(fmt.Sprintf("failed to resolve subject account when attempting to create system; %s", err.Error()), 500, c)
			return
		}

		system.VaultID = subjectAccount.VaultID
	}

	if system.Create() {
		provide.Render(system, 201, c)
	} else if len(system.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = system.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func updateSystemHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 404, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	var _system *System
	err = json.Unmarshal(buf, &_system)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	systemIDStr := c.Param("systemId")
	systemID, err := uuid.FromString(systemIDStr)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if _system.ID != uuid.Nil && !strings.EqualFold(_system.ID.String(), systemID.String()) {
		provide.RenderError("system id cannot be changed", 422, c)
		return
	}

	system := FindSystemByID(systemID)
	if system == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	if system.WorkgroupID == nil || !strings.EqualFold(workgroupID.String(), system.WorkgroupID.String()) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if !strings.EqualFold(system.ID.String(), systemID.String()) {
		provide.RenderError("", 422, c)
		return
	}

	if system.Update() {
		provide.Render(nil, 204, c)
	} else if len(system.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = system.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteSystemHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	workgroupID, err := uuid.FromString(c.Param("id"))
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	systemIDStr := c.Param("systemId")
	systemID, err := uuid.FromString(systemIDStr)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	system := FindSystemByID(systemID)
	if system == nil {
		provide.RenderError("not found", 404, c)
		return
	}

	if system.WorkgroupID == nil || !strings.EqualFold(workgroupID.String(), system.WorkgroupID.String()) {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if system.Delete() {
		provide.Render(nil, 204, c)
	} else if len(system.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = system.Errors
		provide.Render(obj, 422, c)
	}
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

	var system middleware.SystemMetadata
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

	sor := middleware.SystemFactory(&system)
	if sor == nil {
		provide.RenderError("unsupported system specified", 422, c)
		return
	}

	if err := sor.HealthCheck(); err != nil {
		msg := fmt.Sprintf("system healthcheck failed; %s", err.Error())
		provide.RenderError(msg, 422, c)
		return
	}

	provide.Render(nil, 204, c)
}

func listMappingsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var mappings []*Mapping

	db := dbconf.DatabaseConnection()
	var query *gorm.DB
	if c.Query("workgroup_id") != "" {
		workgroupID, err := uuid.FromString(c.Query("workgroup_id"))
		if err != nil {
			provide.RenderError(err.Error(), 422, c)
			return
		}
		query = db.Where("organization_id = ? AND workgroup_id = ?", organizationID, workgroupID)
	} else {
		query = db.Where("organization_id = ?", organizationID)
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

	mapping.OrganizationID = organizationID

	if mapping.Create() {
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

	systems := make([]*System, 0)
	var err error

	useEphemeralSystem := c.Query("system_secret_ids") != ""

	if !useEphemeralSystem {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), c.Param("id"))
		subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

		token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
		systemSecretIDs := strings.Split(c.Query("system_secret_ids"), ",")
		ephemeralSystems, err := resolveEphemeralSystems(token.Raw, c.Query("vault_id"), systemSecretIDs)
		if err != nil {
			provide.RenderError("failed to list systems for ephemerally-referenced system secrets", 403, c)
			return
		}

		for _, ephemeralSystem := range ephemeralSystems {
			sys, err := SystemFromEphemeralSystemMetadata(ephemeralSystem)
			if err != nil {
				provide.RenderError("failed to initialize ephemeral system using ephemerally-referenced system secret", 403, c)
				return
			}

			systems = append(systems, sys)
		}
	}

	resp := make([]interface{}, 0) // FIXME?? use []*Mapping

	// FIXME-- dispatch goroutine-per-system with channel to sync the returned schemas for aggregation...
	for _, system := range systems {
		sor := system.middlewareFactory()
		if sor == nil {
			systemName := "(nil)"
			if system.Name != nil {
				systemName = *system.Name
			}

			systemType := "(nil)"
			if system.Type != nil {
				systemType = *system.Type
			}

			common.Log.Warningf("subject account has unsupported or misconfigured system: %s; type: %s; skipping...", systemName, systemType)
			continue
		}

		schemaParams := map[string]interface{}{}
		if len(c.Query("q")) > 0 {
			schemaParams["q"] = c.Query("q")
		}

		schemas, err := sor.ListSchemas(schemaParams)
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

	systems := make([]*System, 0)
	var err error

	useEphemeralSystem := c.Query("system_secret_ids") != ""

	if !useEphemeralSystem {
		subjectAccountID := subjectAccountIDFactory(organizationID.String(), c.Param("id"))
		subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

		token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
		systemSecretIDs := strings.Split(c.Query("system_secret_ids"), ",")
		ephemeralSystems, err := resolveEphemeralSystems(token.Raw, c.Query("vault_id"), systemSecretIDs)
		if err != nil {
			provide.RenderError("failed to list systems for ephemerally-referenced system secrets", 403, c)
			return
		}

		for _, ephemeralSystem := range ephemeralSystems {
			sys, err := SystemFromEphemeralSystemMetadata(ephemeralSystem)
			if err != nil {
				provide.RenderError("failed to initialize ephemeral system using ephemerally-referenced system secret", 403, c)
				return
			}

			systems = append(systems, sys)
		}
	}

	var resp interface{}

	// FIXME-- filter systems to resolve the original system from which the requested schema is being requested...
	for _, system := range systems {
		sor := system.middlewareFactory()
		if sor == nil {
			systemName := "(nil)"
			if system.Name != nil {
				systemName = *system.Name
			}

			systemType := "(nil)"
			if system.Type != nil {
				systemType = *system.Type
			}

			common.Log.Warningf("subject account has unsupported or misconfigured system: %s; type: %s; skipping...", systemName, systemType)
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

		if resp != nil {
			provide.Render(resp, 200, c)
			return
		}
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

	if workstep.Status != nil && *workstep.Status != workstepStatusInit && *workstep.Status != workstepStatusExecuting {
		provide.RenderError("cannot execute workstep", 400, c)
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
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

func verifyWorkstepHandler(c *gin.Context) {
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

	if workstep.Status != nil && *workstep.Status != workstepStatusCompleted {
		provide.RenderError("cannot verify workstep", 400, c)
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

	if payload.Proof == nil {
		provide.RenderError("proof required for verification", 422, c)
		return
	}

	if payload.Witness == nil {
		provide.RenderError("witness required for verification", 422, c)
		return
	}

	token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
	resp, err := workstep.verify(subjectAccount, token.Raw, payload)
	if err != nil {
		provide.RenderError(fmt.Sprintf("cannot verify workstep; %s", err.Error()), 422, c)
		return
	}

	if resp != nil {
		provide.Render(resp, 200, c)
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
		token, _ := util.ParseBearerAuthorizationHeader(c.GetHeader("authorization"), nil)
		workstep.enrich(token.Raw)
		provide.Render(workstep, 200, c)
	} else {
		provide.RenderError("workstep not found", 404, c)
	}
}

func issueVerifiableCredentialHandler(c *gin.Context) {
	issueVCRequest := &axiom.IssueVerifiableCredentialRequest{}

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

	if issueVCRequest.WorkgroupID == nil {
		provide.RenderError("workgroup_id is required", 422, c)
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

	subjectAccounts := ListSubjectAccountsByWorkgroupID(issueVCRequest.WorkgroupID.String())
	if len(subjectAccounts) == 0 {
		msg := fmt.Sprintf("failed to resolve issuing subject account for workgroup: %s", issueVCRequest.WorkgroupID.String())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}
	if len(subjectAccounts) > 1 {
		msg := fmt.Sprintf("failed to resolve issuing subject account for workgroup: %s; subject account resolution is ambiguous in a multi-tenant BPI context", issueVCRequest.WorkgroupID.String())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	subjectAccountID := *subjectAccounts[0].ID
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil) // FIXME-- this is a bit redundant but handles enrichment...
	if err != nil {
		msg := fmt.Sprintf("failed to resolve issuing subject account: %s; %s", subjectAccountID, err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	credential, err := subjectAccount.IssueVC(*issueVCRequest.Address, map[string]interface{}{})

	if err == nil {
		provide.Render(&axiom.IssueVerifiableCredentialResponse{
			VC: credential,
		}, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}

func listWorkstepConstraintsHandler(c *gin.Context) {
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
	constraints := workstep.listConstraints(db)
	// var constraints []*WorkstepConstraint
	// query := workstep.listConstraintsQuery()
	// provide.Paginate(c, query, &WorkstepConstraint{}).Find(&constraints)
	provide.Render(constraints, 200, c)
}

func createWorkstepConstraintHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var constraint *Constraint

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &constraint)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal constraint; %s", err.Error())
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
		provide.RenderError("cannot add workstep constraint", 400, c)
		return
	}

	if constraint.WorkstepID == nil || constraint.WorkstepID.String() != workstep.ID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if constraint.Create(nil) {
		provide.Render(constraint, 201, c)
	} else if len(constraint.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = constraint.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func updateWorkstepConstraintHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	}

	var _constraint *Constraint

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &_constraint)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal constraint; %s", err.Error())
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

	constraintID, err := uuid.FromString(c.Param("constraintId"))
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
		provide.RenderError("cannot update workstep constraint", 400, c)
		return
	}

	constraint := FindConstraintByID(constraintID)
	if constraint == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if constraint.WorkstepID == nil || constraint.WorkstepID.String() != workstep.ID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if (constraint.WorkstepID == nil || _constraint.WorkstepID == nil) || constraint.WorkstepID.String() != _constraint.WorkstepID.String() {
		provide.RenderError("constraint workstep id mismatch", 403, c)
		return
	}

	if constraint.Update(_constraint) {
		provide.Render(nil, 204, c)
	} else if len(constraint.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = constraint.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
	}
}

func deleteWorkstepConstraintHandler(c *gin.Context) {
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

	constraintID, err := uuid.FromString(c.Param("constraintId"))
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
		provide.RenderError("cannot remove workstep constraint", 400, c)
		return
	}

	constraint := FindConstraintByID(constraintID)
	if constraint == nil {
		provide.RenderError("not found", 404, c)
		return
	} else if constraint.WorkstepID == nil || constraint.WorkstepID.String() != workstep.ID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if constraint.Delete() {
		provide.Render(nil, 204, c)
	} else if len(constraint.Errors) > 0 {
		obj := map[string]interface{}{}
		obj["errors"] = constraint.Errors
		provide.Render(obj, 422, c)
	} else {
		provide.RenderError("internal persistence error", 500, c)
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
		provide.RenderError("cannot add workstep participant", 400, c)
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
		provide.RenderError("cannot remove workstep participant", 400, c)
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

	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

	if !subjectAccount.validate() {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
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

	if err := subjectAccount.setDefaultItems(); err != nil {
		obj := map[string]interface{}{}
		obj["errors"] = subjectAccount.Errors
		provide.Render(obj, 422, c)
		return
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if subjectAccount.create(tx) {
		SubjectAccounts = append(SubjectAccounts, subjectAccount)
		SubjectAccountsByID[subjectAccountID] = append(SubjectAccountsByID[subjectAccountID], subjectAccount)

		var waitGroup sync.WaitGroup // HACK!!!
		subjectAccount.createNatsWorkgroupSyncSubscriptions(&waitGroup)

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

func updateSubjectAccountsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}
