package baseline

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/api/vault"
)

const defaultNatsStream = "baseline"

const protomsgPayloadTypeCircuit = "prover"
const protomsgPayloadTypeWorkflow = "workflow"

const natsDispatchInvitationSubject = "baseline.invitation.outbound"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30
const natsDispatchInvitationMaxDeliveries = 10

const natsBaselineWorkflowDeployMessageSubject = "baseline.workflow.deploy"
const natsBaselineWorkflowDeployMessageMaxInFlight = 2048
const baselineWorkflowDeployMessageAckWait = time.Second * 30
const natsBaselineWorkflowDeployMessageMaxDeliveries = 10

const natsBaselineWorkstepDeployMessageSubject = "baseline.workstep.deploy"
const natsBaselineWorkstepDeployMessageMaxInFlight = 2048
const baselineWorkstepDeployMessageAckWait = time.Second * 30
const natsBaselineWorkstepDeployMessageMaxDeliveries = 10

const natsBaselineWorkstepFinalizeDeployMessageSubject = "baseline.workstep.deploy.finalize"
const natsBaselineWorkstepFinalizeDeployMessageMaxInFlight = 2048
const baselineWorkstepFinalizeDeployMessageAckWait = time.Second * 30
const natsBaselineWorkstepFinalizeDeployMessageMaxDeliveries = 10

const natsDispatchProtocolMessageSubject = "baseline.protocolmessage.outbound"
const natsDispatchProtocolMessageMaxInFlight = 2048
const dispatchProtocolMessageAckWait = time.Second * 30
const natsDispatchProtocolMessageMaxDeliveries = 10

const natsBaselineProxyInboundSubject = "baseline.inbound"
const natsBaselineProxyInboundMaxInFlight = 2048
const baselineProxyInboundAckWait = time.Second * 30
const natsBaselineProxyInboundMaxDeliveries = 10

const natsSubjectAccountRegistrationSubject = "baseline.subject-account.registration"
const natsSubjectAccountRegistrationMaxInFlight = 256
const natsSubjectAccountRegistrationAckWait = time.Minute * 1
const natsSubjectAccountRegistrationMaxDeliveries = 10

const natsBaselineSubject = "baseline"
const baselineProxyAckWait = time.Second * 30

// const organizationRegistrationTimeout = int64(natsOrganizationRegistrationAckWait * 10)
const organizationRegistrationMethod = "registerOrg"
const organizationUpdateRegistrationMethod = "updateOrg"

// const organizationSetInterfaceImplementerMethod = "setInterfaceImplementer"
// const contractTypeRegistry = "registry"
const contractTypeOrgRegistry = "organization-registry"
const contractTypeERC1820Registry = "erc1820-registry"

// Message is a proxy-internal wrapper for protocol message handling
type Message struct {
	baseline.Message
	ProtocolMessage *ProtocolMessage `sql:"-" json:"protocol_message,omitempty"`
}

// ProtocolMessage is a baseline protocol message
// see https://github.com/ethereum-oasis/baseline/blob/master/core/types/src/protocol.ts
type ProtocolMessage struct {
	baseline.ProtocolMessage
}

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("baseline package consumer configured to skip NATS streaming subscription setup")
		return
	}

	var waitGroup sync.WaitGroup

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	createNatsBaselineProxySubscriptions(&waitGroup)
	createNatsBaselineWorkflowDeploySubscriptions(&waitGroup)
	createNatsBaselineWorkstepDeploySubscriptions(&waitGroup)
	createNatsBaselineWorkstepFinalizeDeploySubscriptions(&waitGroup)
	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
	createNatsSubjectAccountRegistrationSubscriptions(&waitGroup)
}

func createNatsBaselineProxySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			baselineProxyInboundAckWait,
			natsBaselineProxyInboundSubject,
			natsBaselineProxyInboundSubject,
			natsBaselineProxyInboundSubject,
			consumeBaselineProxyInboundSubscriptionsMsg,
			baselineProxyAckWait,
			natsBaselineProxyInboundMaxInFlight,
			natsBaselineProxyInboundMaxDeliveries,
			nil,
		)
	}

	conn, _ := natsutil.GetSharedNatsConnection(nil)
	conn.Subscribe(natsBaselineSubject, func(msg *nats.Msg) {
		common.Log.Debugf("consuming %d-byte NATS inbound protocol message on subject: %s", len(msg.Data), msg.Subject)
		_, err := natsutil.NatsJetstreamPublish(natsBaselineProxyInboundSubject, msg.Data)
		if err != nil {
			common.Log.Warningf("failed to publish inbound protocol message to local jetstream consumers; %s", err.Error())
			msg.Nak()
			return
		}

		msg.Ack()
	})
}

func createNatsBaselineWorkflowDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			baselineWorkflowDeployMessageAckWait,
			natsBaselineWorkflowDeployMessageSubject,
			natsBaselineWorkflowDeployMessageSubject,
			natsBaselineWorkflowDeployMessageSubject,
			consumeBaselineWorkflowFinalizeDeploySubscriptionsMsg,
			baselineWorkflowDeployMessageAckWait,
			natsBaselineWorkflowDeployMessageMaxInFlight,
			natsBaselineWorkflowDeployMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsBaselineWorkstepDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			baselineWorkstepDeployMessageAckWait,
			natsBaselineWorkstepDeployMessageSubject,
			natsBaselineWorkstepDeployMessageSubject,
			natsBaselineWorkstepDeployMessageSubject,
			consumeBaselineWorkstepDeploySubscriptionsMsg,
			baselineWorkstepDeployMessageAckWait,
			natsBaselineWorkstepDeployMessageMaxInFlight,
			natsBaselineWorkstepDeployMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsBaselineWorkstepFinalizeDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			baselineWorkstepFinalizeDeployMessageAckWait,
			natsBaselineWorkstepFinalizeDeployMessageSubject,
			natsBaselineWorkstepFinalizeDeployMessageSubject,
			natsBaselineWorkstepFinalizeDeployMessageSubject,
			consumeBaselineWorkstepFinalizeDeploySubscriptionsMsg,
			baselineWorkstepFinalizeDeployMessageAckWait,
			natsBaselineWorkstepFinalizeDeployMessageMaxInFlight,
			natsBaselineWorkstepFinalizeDeployMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsDispatchInvitationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			dispatchInvitationAckWait,
			natsDispatchInvitationSubject,
			natsDispatchInvitationSubject,
			natsDispatchInvitationSubject,
			consumeDispatchInvitationSubscriptionsMsg,
			dispatchInvitationAckWait,
			natsDispatchInvitationMaxInFlight,
			natsDispatchInvitationMaxDeliveries,
			nil,
		)
	}
}

func createNatsDispatchProtocolMessageSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			dispatchProtocolMessageAckWait,
			natsDispatchProtocolMessageSubject,
			natsDispatchProtocolMessageSubject,
			natsDispatchProtocolMessageSubject,
			consumeDispatchProtocolMessageSubscriptionsMsg,
			dispatchProtocolMessageAckWait,
			natsDispatchProtocolMessageMaxInFlight,
			natsDispatchProtocolMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsSubjectAccountRegistrationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		_, err := natsutil.RequireNatsJetstreamSubscription(wg,
			natsSubjectAccountRegistrationAckWait,
			natsSubjectAccountRegistrationSubject,
			natsSubjectAccountRegistrationSubject,
			natsSubjectAccountRegistrationSubject,
			consumeSubjectAccountRegistrationMsg,
			natsSubjectAccountRegistrationAckWait,
			natsSubjectAccountRegistrationMaxInFlight,
			natsSubjectAccountRegistrationMaxDeliveries,
			nil,
		)

		if err != nil {
			common.Log.Panicf("failed to subscribe to NATS stream via subject: %s; %s", natsSubjectAccountRegistrationSubject, err.Error())
		}
	}
}

func consumeBaselineProxyInboundSubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS inbound protocol message on internal subject: %s", len(msg.Data), msg.Subject)

	protomsg := &ProtocolMessage{}
	err := json.Unmarshal(msg.Data, &protomsg)
	if err != nil {
		common.Log.Warningf("failed to umarshal inbound protocol message; %s", err.Error())
		msg.Nak()
		return
	}

	if protomsg.Opcode == nil {
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		msg.Term()
		return
	}

	switch *protomsg.Opcode {
	case baseline.ProtocolMessageOpcodeBaseline:
		success := protomsg.baselineInbound()
		if !success {
			common.Log.Warning("failed to baseline inbound protocol message")
			return
		}

	case baseline.ProtocolMessageOpcodeJoin:
		common.Log.Warningf("JOIN opcode not yet implemented")
		// const payload = JSON.parse(msg.payload.toString());
		// const messagingEndpoint = await this.resolveMessagingEndpoint(payload.address);
		// if (!messagingEndpoint || !payload.address || !payload.authorized_bearer_token) {
		//   return Promise.reject('failed to handle baseline JOIN protocol message');
		// }
		// this.workgroupCounterparties.push(payload.address);
		// this.natsBearerTokens[messagingEndpoint] = payload.authorized_bearer_token;

		// const prover = JSON.parse(JSON.stringify(this.baselineCircuit));
		// prover.proving_scheme = prover.provingScheme;
		// prover.verifier_contract = prover.verifierContract;
		// delete prover.verifierContract;
		// delete prover.createdAt;
		// delete prover.vaultId;
		// delete prover.provingScheme;
		// delete prover.provingKeyId;
		// delete prover.verifyingKeyId;
		// delete prover.status;

		// // sync prover artifacts
		// this.sendProtocolMessage(payload.address, Opcode.Sync, {
		//   type: 'prover',
		//   payload: prover,
		// });

	case baseline.ProtocolMessageOpcodeSync:
		token, err := vendOrganizationAccessToken()
		if err != nil {
			common.Log.Warningf("failed to handle inbound sync protocol message; %s", err.Error())
			return
		}

		// FIXME -- use switch and attempt nack if invalid sync type...
		if protomsg.Payload.Type != nil && *protomsg.Payload.Type == protomsgPayloadTypeCircuit {
			prover, err := privacy.CreateProver(*token, protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to create prover; %s", err.Error())
				return
			}
			common.Log.Debugf("sync protocol message created prover: %s", prover.ID)
		} else if protomsg.Payload.Type != nil && *protomsg.Payload.Type == protomsgPayloadTypeWorkflow {
			workflow := &WorkflowInstance{}
			raw, err := json.Marshal(protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to marshal payload object; %s", err.Error())
				return
			}
			json.Unmarshal(raw, &workflow)

			for _, workstep := range workflow.Worksteps {
				params := map[string]interface{}{}
				rawprover, _ := json.Marshal(workstep.Prover)
				json.Unmarshal(rawprover, &params)

				workstep.Prover, err = privacy.CreateProver(*token, params)
				if err != nil {
					common.Log.Warningf("failed to handle inbound sync protocol message; failed to create prover; %s", err.Error())
					return
				}
				workstep.ProverID = &workstep.Prover.ID
				common.Log.Debugf("sync protocol message created prover: %s", workstep.Prover.ID)
			}

			err = workflow.Cache()
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to cache workflow; %s", err.Error())
				msg.Nak()
				return
			}

			if protomsg.BaselineID != nil {
				err = workflow.CacheByBaselineID(protomsg.BaselineID.String())
				if err != nil {
					common.Log.Warningf("failed to handle inbound sync protocol message; failed to cache workflow identifier by baseline id; %s", err.Error())
					msg.Nak()
					return
				}
			}

			common.Log.Debugf("cached %d-workstep workflow: %s", len(workflow.Worksteps), workflow.ID)
		}

	default:
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		msg.Term()
		return
	}

	msg.Ack()
}

func consumeBaselineWorkflowFinalizeDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS baseline workflow deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal baseline workflow deploy message; %s", err.Error())
		msg.Nak()
		return
	}

	workflowID, err := uuid.FromString(params["workflow_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse baseline workflow id; %s", err.Error())
		msg.Nak()
		return
	}

	success := true

	workflow := FindWorkflowByID(workflowID)
	worksteps := FindWorkstepsByWorkflowID(workflow.ID)
	for _, workstep := range worksteps {
		if workstep.Status != nil && *workstep.Status != workstepStatusDeployed {
			common.Log.Debugf("waiting on workstep with id %s for pending deployment of workflow: %s", workstep.ID, workflow.ID)
			success = false
		}
	}

	if success {
		db := dbconf.DatabaseConnection()

		deployedAt := time.Now()
		workflow.DeployedAt = &deployedAt
		workflow.Status = common.StringOrNil(workstepStatusDeployed)

		db.Save(&workflow)
		msg.Ack()
	} else {
		common.Log.Warningf("deployment not finalized for workflow: %s", workflow.ID)
	}
}

func consumeBaselineWorkstepDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS baseline workstep deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal baseline workstep deploy message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, err := uuid.FromString(params["organization_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse organization id; %s", err.Error())
		msg.Nak()
		return
	}

	workstepID, err := uuid.FromString(params["workstep_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse baseline workstep id; %s", err.Error())
		msg.Nak()
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		common.Log.Warningf("failed to resolve baseline workstep: %s", workstepID)
		msg.Nak()
		return
	}

	workflow := FindWorkflowByID(*workstep.WorkflowID)
	if workflow == nil {
		common.Log.Errorf("failed to resolve baseline workflow: %s", workstep.WorkflowID)
		msg.Nak()
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		common.Log.Errorf("failed to resolve BPI subject account for workflow: %s; %s", workstep.WorkflowID, err.Error())
		msg.Nak()
		return
	}

	if subjectAccount.Metadata == nil || subjectAccount.Metadata.OrganizationID == nil {
		common.Log.Errorf("failed to resolve BPI subject account; organization id required")
		msg.Nak()
		return
	}

	if *subjectAccount.Metadata.OrganizationID != organizationID.String() {
		common.Log.Error("failed to resolve BPI subject account; organization id mismatch")
		msg.Nak()
		return
	}

	token, err := ident.CreateToken(*subjectAccount.Metadata.OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *subjectAccount.Metadata.OrganizationID,
	})
	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return
	}

	if workstep.deploy(*token.AccessToken, organizationID) {
		common.Log.Debugf("workstep pending deployment: %s", workstep.ID)
		msg.Ack()
	} else {
		common.Log.Warningf("deployment not finalized for workstep: %s", workstep.ID)
	}
}

func consumeBaselineWorkstepFinalizeDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS baseline workstep finalize deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal baseline workstep finalize deploy message; %s", err.Error())
		msg.Nak()
		return
	}

	organizationID, err := uuid.FromString(params["organization_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse organization id; %s", err.Error())
		msg.Nak()
		return
	}

	workstepID, err := uuid.FromString(params["workstep_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse baseline workstep id; %s", err.Error())
		msg.Nak()
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		common.Log.Warningf("failed to resolve baseline workstep: %s", workstepID)
		msg.Nak()
		return
	}

	workflow := FindWorkflowByID(*workstep.WorkflowID)
	if workflow == nil {
		common.Log.Warningf("failed to resolve baseline workflow: %s", workstep.WorkflowID)
		msg.Nak()
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		common.Log.Errorf("failed to resolve BPI subject account for workflow: %s; %s", workstep.WorkflowID, err.Error())
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationID == nil {
		common.Log.Error("failed to resolve BPI subject account; organization id required")
		msg.Nak()
		return
	}

	token, err := ident.CreateToken(*subjectAccount.Metadata.OrganizationRefreshToken, map[string]interface{}{
		"grant_type":      "refresh_token",
		"organization_id": *subjectAccount.Metadata.OrganizationID,
	})
	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return
	}

	if workstep.finalizeDeploy(*token.AccessToken) {
		common.Log.Debugf("deployed workstep: %s", workstep.ID)
		msg.Ack()
	} else {
		common.Log.Warningf("deployment not finalized for workstep: %s", workstep.ID)
	}
}

func consumeDispatchInvitationSubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS dispatch invitation message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal dispatch invitation message; %s", err.Error())
		msg.Nak()
		return
	}

	// TODO!

	msg.Ack()
}

func consumeDispatchProtocolMessageSubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS dispatch protocol message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal baseline workstep finalize deploy message; %s", err.Error())
		msg.Nak()
		return
	}

	protomsg := &ProtocolMessage{}
	err = json.Unmarshal(msg.Data, &protomsg)
	if err != nil {
		common.Log.Warningf("failed to umarshal dispatch protocol message; %s", err.Error())
		msg.Nak()
		return
	}

	if protomsg.Recipient == nil {
		common.Log.Warningf("no participant specified in protocol message; %s", err.Error())
		msg.Term()
		return
	}

	if protomsg.Identifier == nil {
		common.Log.Warningf("no workflow identifier specified in protocol message; %s", err.Error())
		msg.Term()
		return
	}

	organizationID, err := uuid.FromString(params["organization_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse organization id; %s", err.Error())
		msg.Nak()
		return
	}

	workflow := FindWorkflowByID(*protomsg.Identifier)
	if workflow == nil {
		common.Log.Warningf("failed to resolve baseline workflow: %s", protomsg.Identifier)
		msg.Nak()
		return
	}

	url := lookupBaselineOrganizationMessagingEndpoint(*protomsg.Recipient)
	if url == nil {
		common.Log.Warningf("failed to lookup recipient messaging endpoint: %s", *protomsg.Recipient)
		msg.Nak()
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID)
	if err != nil {
		common.Log.Errorf("failed to resolve BPI subject account for workflow: %s; %s", *protomsg.Identifier, err.Error())
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationID == nil {
		common.Log.Error("failed to resolve BPI subject account; organization id required")
		msg.Nak()
		return
	}

	jwt := lookupBaselineOrganizationIssuedVC(*protomsg.Recipient)
	if jwt == nil {
		// request a VC from the counterparty
		jwt, err = requestBaselineOrganizationIssuedVC(*protomsg.Recipient)
		if err != nil {
			subjectAccount.resolveWorkgroupParticipants() // HACK-- this should not re-resolve all counterparties...

			common.Log.Warningf("failed to request verifiable credential from recipient counterparty: %s; %s", *protomsg.Recipient, err.Error())
			msg.Nak()
			return
		}
	}

	if jwt == nil {
		common.Log.Warningf("failed to dispatch protocol message to recipient: %s; no bearer token resolved", *protomsg.Recipient)
		msg.Nak()
		return
	}

	uuid, _ := uuid.NewV4()
	name := fmt.Sprintf("%s-%s", *subjectAccount.Metadata.OrganizationAddress, uuid.String())
	conn, err := natsutil.GetNatsConnection(name, *url, time.Second*10, jwt)
	if err != nil {
		common.Log.Warningf("failed to establish NATS connection to recipient: %s; %s", *protomsg.Recipient, err.Error())
		msg.Nak()
		return
	}

	defer conn.Close()

	err = conn.Publish(natsBaselineSubject, msg.Data)
	if err != nil {
		// clear cached endpoint so it will be re-fetched...
		// counterparty := lookupBaselineOrganization(*protomsg.Recipient)
		// counterparty.MessagingEndpoint = nil
		// counterparty.Cache()

		subjectAccount.resolveWorkgroupParticipants() // HACK-- this should not re-resolve all counterparties...

		common.Log.Warningf("failed to publish protocol message to recipient: %s; %s", *protomsg.Recipient, err.Error())
		msg.Nak()
		return
	}

	common.Log.Debugf("broadcast %d-byte protocol message to recipient: %s", len(msg.Data), *protomsg.Recipient)
	msg.Ack()
}

func consumeSubjectAccountRegistrationMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered in BPI subject account registration message handler; %s", r)
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS BPI subject account registration message on subject: %s", len(msg.Data), msg.Subject)

	params := map[string]interface{}{}
	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to unmarshal BPI subject account registration message; %s", err.Error())
		msg.Nak()
		return
	}

	subjectAccountID, subjectAccountIDOk := params["subject_account_id"].(string)
	if !subjectAccountIDOk {
		common.Log.Warning("failed to parse BPI subject_account_id during BPI subject account registration message handler")
		msg.Nak()
		return
	}

	// FIXME-- resolve whether or not this subject account has been registered...
	updateRegistry := false
	if update, updateOk := params["update_registry"].(bool); updateOk {
		updateRegistry = update
	}

	db := dbconf.DatabaseConnection()

	subjectAccount := FindSubjectAccountByID(subjectAccountID)
	if subjectAccount == nil || subjectAccount.ID == nil {
		common.Log.Warningf("failed to resolve BPI subject account during BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	organization := &ident.Organization{}
	db.Where("id = ?", *subjectAccount.SubjectID).Find(&organization)

	if organization == nil || organization.ID == nil {
		common.Log.Warningf("failed to resolve organization during BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	workgroup := &Workgroup{}
	db.Where("id = ?", *subjectAccount.Metadata.WorkgroupID).Find(&workgroup)

	if workgroup == nil || workgroup.ID == uuid.Nil {
		common.Log.Warningf("failed to resolve organization during BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	var orgDomain *string
	var orgZeroKnowledgePublicKey *string

	orgToken, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		common.Log.Warningf("failed to authorize access token for BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	vaults, err := vault.ListVaults(*orgToken.Token, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to fetch vaults during implicit key exchange message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	var keys []*vault.Key

	// HACK!!! the following should not be needed...
	if len(vaults) > 0 {
		orgVault := vaults[0]

		// babyJubJub
		keys, err = vault.ListKeys(*orgToken.Token, orgVault.ID.String(), map[string]interface{}{
			"spec": "babyJubJub",
		})
		if err != nil {
			common.Log.Warningf("failed to fetch babyJubJub keys from vault during implicit key exchange message handler; BPI subject account id: %s", subjectAccountID)
			msg.Nak()
			return
		}
		if len(keys) > 0 {
			key := keys[0]
			if key.PublicKey != nil {
				orgZeroKnowledgePublicKey = common.StringOrNil(*key.PublicKey)
			}
		}
	}

	// metadata := organization.ParseMetadata()
	updateOrgMetadata := false

	// if _, addrOk := metadata["address"].(string); !addrOk {
	// 	metadata["address"] = orgAddress
	// 	updateOrgMetadata = true
	// }

	// FIXME!! add domain to subjectAccount.Metadata
	// if domain, domainOk := metadata["domain"].(string); domainOk {
	// 	orgDomain = common.StringOrNil(domain)
	// }

	if subjectAccount.Metadata.OrganizationAddress == nil {
		common.Log.Warningf("failed to resolve organization public address for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	// FIXME!!
	// if subjectAccount.Metadata.Domain == nil {
	// 	common.Log.Warningf("failed to resolve organization domain for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
	// 	msg.Nak()
	// 	return
	// }

	if subjectAccount.Metadata.OrganizationMessagingEndpoint == nil {
		common.Log.Warningf("failed to resolve organization messaging endpoint for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	if orgZeroKnowledgePublicKey == nil {
		common.Log.Warningf("failed to resolve organization zero-knowledge public key for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	contracts, err := nchain.ListContracts(*orgToken.AccessToken, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to resolve organization registry contract to which the organization registration tx should be sent; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	var erc1820RegistryContractID *string
	var orgRegistryContractID *string

	var erc1820RegistryContractAddress *string
	var orgRegistryContractAddress *string

	var orgWalletID *string

	// org api token & hd wallet

	orgWalletResp, err := nchain.CreateWallet(*orgToken.Token, map[string]interface{}{
		"purpose": 44,
	})
	if err != nil {
		common.Log.Warningf("failed to create organization HD wallet for organization registration tx should be sent; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	orgWalletID = common.StringOrNil(orgWalletResp.ID.String())
	common.Log.Debugf("created HD wallet %s for organization %s", *orgWalletID, organization.ID)

	for _, c := range contracts {
		resp, err := nchain.GetContractDetails(*orgToken.AccessToken, c.ID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to resolve organization registry contract to which the organization registration tx should be sent; BPI subject account id: %s", subjectAccountID)
			msg.Nak()
			return
		}

		if resp.Type != nil {
			switch *resp.Type {
			case contractTypeERC1820Registry:
				erc1820RegistryContractID = common.StringOrNil(resp.ID.String())
				erc1820RegistryContractAddress = resp.Address
			case contractTypeOrgRegistry:
				orgRegistryContractID = common.StringOrNil(resp.ID.String())
				orgRegistryContractAddress = resp.Address
			}
		}
	}

	if erc1820RegistryContractID == nil || erc1820RegistryContractAddress == nil {
		common.Log.Warningf("failed to resolve ERC1820 registry contract; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	if orgRegistryContractID == nil || orgRegistryContractAddress == nil {
		common.Log.Warningf("failed to resolve organization registry contract; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	if orgWalletID == nil {
		common.Log.Warningf("failed to resolve organization HD wallet for signing organization impl transaction transaction; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	// registerOrg/updateOrg

	method := organizationRegistrationMethod
	if updateRegistry {
		method = organizationUpdateRegistrationMethod
	}

	common.Log.Debugf("attempting to register organization %s, with on-chain registry contract: %s", organization.ID, *orgRegistryContractAddress)
	_, err = nchain.ExecuteContract(*orgToken.AccessToken, *orgRegistryContractID, map[string]interface{}{
		"wallet_id": orgWalletID,
		"method":    method,
		"params": []interface{}{
			*subjectAccount.Metadata.OrganizationAddress,
			*organization.Name,
			*orgDomain,
			*subjectAccount.Metadata.OrganizationMessagingEndpoint,
			*orgZeroKnowledgePublicKey,
			"{}",
		},
		"value": 0,
	})
	if err != nil {
		common.Log.Warningf("organization registry transaction broadcast failed on behalf of organization: %s; org registry contract id: %s; %s", organization.ID, *orgRegistryContractID, err.Error())
		return
	}

	if updateOrgMetadata {
		common.Log.Debugf("ident organization record not updated for BPI subject account: ")
	}

	common.Log.Debugf("broadcast organization registry and interface impl transactions on behalf of organization: %s", organization.ID)
	msg.Ack()
}
