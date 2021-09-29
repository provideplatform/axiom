package baseline

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline-proxy/common"
	provide "github.com/provideplatform/provide-go/common"
	"github.com/provideplatform/provide-go/common/util"
)

// InstallBPIAPI installs public API for interacting with the baseline protocol abstraction
// layer, i.e., with `Subject`, `SubjectContext` and `BPIAccount`
func InstallBPIAPI(r *gin.Engine) {
	r.GET("/api/v1/bpi_accounts", listBPIAccountsHandler)
	r.GET("/api/v1/bpi_accounts/:id", bpiAccountDetailsHandler)
	r.POST("/api/v1/bpi_accounts", createBPIAccountHandler)

	r.POST("/api/v1/protocol_messages", createProtocolMessageHandler)

	r.GET("/api/v1/subjects", listSubjectsHandler)
	r.GET("/api/v1/subjects/:id", subjectDetailsHandler)
	r.POST("/api/v1/subjects", createSubjectHandler)
	r.PUT("/api/v1/subjects/:id", updateSubjectHandler)

	r.GET("/api/v1/subjects/:id/accounts", listSubjectAccountsHandler)
	r.GET("/api/v1/subjects/:id/accounts/:accountId", subjectAccountDetailsHandler)
	r.POST("/api/v1/subjects/:id/accounts", createSubjectAccountsHandler)
	r.PUT("/api/v1/subjects/:id/accounts/:accountId", updateSubjectAccountsHandler)
}

// InstallCredentialsAPI installs public API for interacting with verifiable credentials
func InstallCredentialsAPI(r *gin.Engine) {
	r.POST("/api/v1/credentials", issueVerifiableCredentialHandler)
}

// InstallObjectsAPI installs system of record proxy objects API
func InstallObjectsAPI(r *gin.Engine) {
	r.POST("/api/v1/objects", createObjectHandler)
	r.PUT("/api/v1/objects/:id", updateObjectHandler)

	r.PUT("/api/v1/config", configurationHandler)

	// remain backward compatible for now...
	r.POST("/api/v1/business_objects", createObjectHandler)
	r.PUT("/api/v1/business_objects/:id", updateObjectHandler)
}

// InstallWorkflowsAPI installs workflow management APIs
func InstallWorkflowsAPI(r *gin.Engine) {
	r.GET("/api/v1/workflows", listWorkflowsHandler)
	r.GET("/api/v1/workflows/:id", workflowDetailsHandler)
	r.POST("/api/v1/workflows", createWorkflowHandler)
}

// InstallWorkgroupsAPI installs workgroup management APIs
func InstallWorkgroupsAPI(r *gin.Engine) {
	r.GET("/api/v1/workgroups", listWorkgroupsHandler)
	r.GET("/api/v1/workgroups/:id", workgroupDetailsHandler)
	r.POST("/api/v1/workgroups", createWorkgroupHandler)
}

// InstallWorkstepsAPI installs workstep management APIs
func InstallWorkstepsAPI(r *gin.Engine) {
	// r.GET("/api/v1/worksteps", listWorkstepsHandler)
	// r.GET("/api/v1/worksteps/:id", workstepDetailsHandler)
	// r.POST("/api/v1/worksteps", createWorkstepHandler)

	r.GET("/api/v1/workflows/:id/worksteps", listWorkstepsHandler)
	r.GET("/api/v1/workflows/:id/worksteps/:workstepId", workstepDetailsHandler)
	r.POST("/api/v1/workflows/:id/worksteps", createWorkstepHandler)
}

func configurationHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	cfg := &Config{}
	err = json.Unmarshal(buf, cfg)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if cfg.OrganizationID != nil && cfg.OrganizationID.String() != organizationID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if cfg.apply() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = cfg.Errors
		provide.Render(obj, 422, c)
	}
}

func createObjectHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
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

	if message.baselineOutbound() {
		message.ProtocolMessage.Payload.Object = nil
		provide.Render(message.ProtocolMessage, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = message.Errors
		provide.Render(obj, 422, c)
	}
}

func updateObjectHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	record := lookupBaselineRecordByInternalID(c.Param("id"))
	if record == nil {
		provide.RenderError("baseline record not found", 404, c)
		return
	}

	message := &Message{}
	err = json.Unmarshal(buf, message)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if message.baselineOutbound() {
		message.ProtocolMessage.Payload.Object = nil
		provide.Render(message.ProtocolMessage, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = message.Errors
		provide.Render(obj, 422, c)
	}
}

func createProtocolMessageHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createWorkgroupHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var params map[string]interface{}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &params)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal workgroup invitation acceptance request; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if params["token"] == nil {
		provide.RenderError("workgroup invitation token is required", 400, c)
		return
	}

	bearerToken := c.Param("token")

	token, err := jwt.Parse(bearerToken, func(_jwtToken *jwt.Token) (interface{}, error) {
		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		publicKey, _, _, _ := util.ResolveJWTKeypair(kid)
		if publicKey == nil {
			msg := "failed to resolve a valid JWT verification key"
			if kid != nil {
				msg = fmt.Sprintf("%s; invalid kid specified in header: %s", msg, *kid)
			} else {
				msg = fmt.Sprintf("%s; no default verification key configured", msg)
			}
			return nil, fmt.Errorf(msg)
		}

		return publicKey, nil
	})

	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; failed to parse jwt; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	// prvd := claims["prvd"].(map[string]interface{})
	// data := prvd["data"].(map[string]interface{})
	baseline := claims["baseline"].(map[string]interface{})

	var identifier *string
	if id, identifierOk := baseline["workgroup_id"].(string); identifierOk {
		identifier = common.StringOrNil(id)
	}

	identifierUUID, err := uuid.FromString(*identifier)
	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; invalid identifier; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	var invitorAddress *string
	if addr, invitorAddressOk := baseline["invitor_organization_address"].(string); invitorAddressOk {
		invitorAddress = common.StringOrNil(addr)
	} else {
		msg := "no invitor address provided in vc"
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	var registryContractAddress *string
	if addr, registryContractAddressOk := baseline["registry_contract_address"].(string); registryContractAddressOk {
		registryContractAddress = common.StringOrNil(addr)
	} else {
		msg := fmt.Sprintf("no registry contract address provided by invitor: %s", *invitorAddress)
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if registryContractAddress == nil || *registryContractAddress != *common.BaselineRegistryContractAddress {
		msg := fmt.Sprintf("given registry contract address (%s) did not match configured address (%s)", *invitorAddress, *common.BaselineRegistryContractAddress)
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	var vc *string
	if bearerToken, bearerTokenOk := params["authorized_bearer_token"].(string); bearerTokenOk {
		vc = common.StringOrNil(bearerToken)
	}

	invitor := &Participant{
		Address: invitorAddress,
	}
	invitor.Cache()

	participants := make([]*Participant, 0)
	participants = append(participants, invitor)

	err = CacheBaselineOrganizationIssuedVC(*invitorAddress, *vc)
	if err != nil {
		msg := fmt.Sprintf("failed to cache organization-issued vc; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	// workgroup := &proxy.Workgroup{
	// 	Identifier:   &identifierUUID,
	// 	Participants: participants,
	// }

	// err = workgroup.Cache()
	// if err != nil {
	// 	msg := fmt.Sprintf("failed to accept workgroup invitation; failed to cache workflow; %s", err.Error())
	// 	common.Log.Warningf(msg)
	// 	provide.RenderError(msg, 422, c)
	// 	return
	// }

	// FIXME-- ensure org registry and shield is available via nchain...

	// 	'organization-registry': {
	// 	  address: invite.prvd.data.params.organization_registry_contract_address,
	// 	  name: 'OrgRegistry',
	// 	  network_id: this.baselineConfig?.networkId,
	// 	  params: {
	// 		compiled_artifact: contracts['organization-registry'].params?.compiled_artifact
	// 	  },
	// 	  type: 'organization-registry',
	// 	},
	// 	'shield': {
	// 	  address: invite.prvd.data.params.shield_contract_address,
	// 	  name: 'Shield',
	// 	  network_id: this.baselineConfig?.networkId,
	// 	  params: {
	// 		compiled_artifact: contracts['shield'].params?.compiled_artifact
	// 	  },
	// 	  type: 'shield',
	// 	},

	//   await this.registerOrganization(this.baselineConfig.orgName, this.natsConfig.natsServers[0]);
	// async registerOrganization(name: string, messagingEndpoint: string): Promise<any> {
	// 	this.org = await this.baseline?.createOrganization({
	// 	  name: name,
	// 	  metadata: {
	// 		messaging_endpoint: messagingEndpoint,
	// 	  },
	// 	});

	// 	if (this.org) {
	// 	  const vault = await this.requireVault();
	// 	  this.babyJubJub = await this.createVaultKey(vault.id!, 'babyJubJub');
	// 	  await this.createVaultKey(vault.id!, 'secp256k1');
	// 	  this.hdwallet = await this.createVaultKey(vault.id!, 'BIP39');
	// 	  await this.registerWorkgroupOrganization();
	// 	}

	// 	return this.org;
	//   }

	var authorizedVC *string // TODO: vend NATS bearer token

	msg := &ProtocolMessage{
		Opcode:     common.StringOrNil(ProtocolMessageOpcodeJoin),
		Identifier: &identifierUUID,
		Payload: &ProtocolMessagePayload{
			Object: map[string]interface{}{
				"address":                 *common.BaselineOrganizationAddress,
				"authorized_bearer_token": authorizedVC,
			},
		},
	}
	payload, _ := json.Marshal(msg)

	common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
	_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)

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
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var workgroup []*Workgroup
	provide.Render(workgroup, 200, c)
}

func workgroupDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	workgroup := LookupBaselineWorkgroup(c.Param("id"))

	if workgroup != nil {
		provide.Render(workgroup, 200, c)
	} else {
		provide.RenderError("workgroup not found", 404, c)
	}
}

func createWorkflowHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	err := fmt.Errorf("not implemented")

	if err == nil {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}

func listWorkflowsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var workflows []*Workflow
	provide.Render(workflows, 200, c)
}

func workflowDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	workflow := LookupBaselineWorkflow(c.Param("id"))

	if workflow != nil {
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
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	err := fmt.Errorf("not implemented")

	if err == nil {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}

func listWorkstepsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var worksteps []*Workstep
	provide.Render(worksteps, 200, c)
}

func workstepDetailsHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	workstep := LookupBaselineWorkstep(c.Param("id"))

	if workstep != nil {
		provide.Render(workstep, 200, c)
	} else {
		provide.RenderError("workstep not found", 404, c)
	}
}

func issueVerifiableCredentialHandler(c *gin.Context) {
	issueVCRequest := &IssueVerifiableCredentialRequest{}

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
		provide.Render(&IssueVerifiableCredentialResponse{
			VC: credential,
		}, 201, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
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
	provide.RenderError("not implemented", 501, c)
}

func subjectAccountDetailsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func createSubjectAccountsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}

func updateSubjectAccountsHandler(c *gin.Context) {
	provide.RenderError("not implemented", 501, c)
}
