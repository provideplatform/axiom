package workgroup

import (
	"encoding/json"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/providibright/common"
	"github.com/provideapp/providibright/proxy"
	provide "github.com/provideservices/provide-go/common"
	"github.com/provideservices/provide-go/common/util"
)

const natsDispatchProtocolMessageSubject = "providibright.protocolmessage.outbound"

// InstallProxyAPI installs system of record proxy API
func InstallProxyAPI(r *gin.Engine) {
	r.POST("/api/v1/invitations", acceptWorkgroupInvitationHandler)
}

func acceptWorkgroupInvitationHandler(c *gin.Context) {
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

	token, err := jwt.Parse(c.Param("token"), func(_jwtToken *jwt.Token) (interface{}, error) {
		var kid *string
		if kidhdr, ok := _jwtToken.Header["kid"].(string); ok {
			kid = &kidhdr
		}

		publicKey, _, _ := util.ResolveJWTKeypair(kid)
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
	prvd := claims["prvd"].(map[string]interface{})
	data := prvd["data"].(map[string]interface{})
	params := data["params"].(map[string]interface{})

	var identifier *string
	if id, identifierOk := params["workflow_identifier"].(string); identifierOk {
		identifier = common.StringOrNil(id)
	}

	identifierUUID, err := uuid.FromString(*identifier)
	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; invalid workflow identifier; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	var shield *string
	if shld, shieldOk := params["shield_contract_address"].(string); shieldOk {
		shield = common.StringOrNil(shld)
	}

	var invitorAddress *string
	if addr, invitorAddressOk := params["invitor_organization_address"].(string); invitorAddressOk {
		invitorAddress = common.StringOrNil(addr)
	}

	var vc *string
	if bearerToken, bearerTokenOk := params["authorized_bearer_token"].(string); bearerTokenOk {
		vc = common.StringOrNil(bearerToken)
	}

	invitor := &proxy.Participant{
		Address: invitorAddress,
	}
	invitor.Cache()

	participants := make([]*proxy.Participant, 0)
	participants = append(participants, invitor)

	err = proxy.CacheBaselineOrganizationIssuedVC(*invitorAddress, *vc)
	if err != nil {
		msg := fmt.Sprintf("failed to cache organization-issued vc; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	workflow := &proxy.Workflow{
		Identifier:   &identifierUUID,
		Shield:       shield,
		Participants: participants,
	}

	err = workflow.Cache()
	if err != nil {
		msg := fmt.Sprintf("failed to accept workgroup invitation; failed to cache workflow; %s", err.Error())
		common.Log.Warningf(msg)
		provide.RenderError(msg, 422, c)
		return
	}

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

	msg := &proxy.ProtocolMessage{
		Opcode:     common.StringOrNil(proxy.ProtocolMessageOpcodeJoin),
		Identifier: &identifierUUID,
		Payload: &proxy.ProtocolMessagePayload{
			Object: map[string]interface{}{
				"address":                 *common.BaselineOrganizationAddress,
				"authorized_bearer_token": authorizedVC,
			},
		},
	}
	payload, _ := json.Marshal(msg)

	common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
	err = natsutil.NatsStreamingPublish(natsDispatchProtocolMessageSubject, payload)

	if err == nil {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}
