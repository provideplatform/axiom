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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/axiom/common"
	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/axiom"
	"github.com/provideplatform/provide-go/api/ident"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/api/vault"
)

const defaultNatsStream = "axiom"

const protomsgPayloadTypeMapping = "mapping"
const protomsgPayloadTypeProof = "proof"
const protomsgPayloadTypeProver = "prover"
const protomsgPayloadTypeWorkflow = "workflow"

const natsDispatchInvitationSubject = "axiom.invitation.outbound"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30
const natsDispatchInvitationMaxDeliveries = 10

const natsAxiomWorkflowDeployMessageSubject = "axiom.workflow.deploy"
const natsAxiomWorkflowDeployMessageMaxInFlight = 2048
const axiomWorkflowDeployMessageAckWait = time.Second * 5
const natsAxiomWorkflowDeployMessageMaxDeliveries = 500

const natsAxiomWorkstepDeployMessageSubject = "axiom.workstep.deploy"
const natsAxiomWorkstepDeployMessageMaxInFlight = 2048
const axiomWorkstepDeployMessageAckWait = time.Second * 30
const natsAxiomWorkstepDeployMessageMaxDeliveries = 10

const natsAxiomWorkstepFinalizeDeployMessageSubject = "axiom.workstep.deploy.finalize"
const natsAxiomWorkstepFinalizeDeployMessageMaxInFlight = 2048
const axiomWorkstepFinalizeDeployMessageAckWait = time.Second * 5
const natsAxiomWorkstepFinalizeDeployMessageMaxDeliveries = 1000

const natsDispatchProtocolMessageSubject = "axiom.protocolmessage.outbound"
const natsDispatchProtocolMessageMaxInFlight = 2048
const dispatchProtocolMessageAckWait = time.Second * 30
const natsDispatchProtocolMessageMaxDeliveries = 10

const natsAxiomProxyInboundSubject = "axiom.inbound"
const natsAxiomProxyInboundMaxInFlight = 2048
const axiomProxyInboundAckWait = time.Second * 30
const natsAxiomProxyInboundMaxDeliveries = 10

const natsSubjectAccountRegistrationSubject = "axiom.subject-account.registration"
const natsSubjectAccountRegistrationMaxInFlight = 256
const natsSubjectAccountRegistrationAckWait = time.Minute * 1
const natsSubjectAccountRegistrationMaxDeliveries = 10

const natsWorkgroupSyncSubject = "axiom.workgroup.*.sync"
const natsWorkgroupSyncMaxInFlight = 256
const natsWorkgroupSyncAckWait = time.Minute * 1
const natsWorkgroupSyncMaxDeliveries = 10

const natsAxiomSubject = "axiom"
const axiomProxyAckWait = time.Second * 30

// const organizationRegistrationTimeout = int64(natsOrganizationRegistrationAckWait * 10)
const organizationRegistrationMethod = "registerOrg"
const organizationUpdateRegistrationMethod = "updateOrg"

// const organizationSetInterfaceImplementerMethod = "setInterfaceImplementer"
// const contractTypeRegistry = "registry"
const contractTypeOrgRegistry = "organization-registry"

// Message is a proxy-internal wrapper for protocol message handling
type Message struct {
	ID              *string          `sql:"-" json:"id,omitempty"`
	AxiomID         *uuid.UUID       `sql:"-" json:"axiom_id,omitempty"` // optional; when included, can be used to map outbound message just-in-time
	Errors          []*api.Error     `sql:"-" json:"errors,omitempty"`
	MessageID       *string          `sql:"-" json:"message_id,omitempty"`
	Payload         interface{}      `sql:"-" json:"payload,omitempty"`
	ProtocolMessage *ProtocolMessage `sql:"-" json:"protocol_message,omitempty"`
	Recipients      []*Participant   `sql:"-" json:"recipients"`
	Status          *string          `sql:"-" json:"status,omitempty"`
	Type            *string          `sql:"-" json:"type,omitempty"`
	WorkgroupID     *uuid.UUID       `sql:"-" json:"workgroup_id,omitempty"`

	// HACK -- convenience ptr ... for access during axiomOutbound()
	subjectAccount *SubjectAccount `sql:"-" json:"-"`
	//token          *string         `sql:"-" json:"-"`
}

// ProtocolMessage is a axiom protocol message
// see https://github.com/ethereum-oasis/axiom/blob/master/core/types/src/protocol.ts
type ProtocolMessage struct {
	AxiomID   *uuid.UUID              `sql:"-" json:"axiom_id,omitempty"`
	Opcode    *string                 `sql:"-" json:"opcode,omitempty"`
	Sender    *string                 `sql:"-" json:"sender,omitempty"`
	Recipient *string                 `sql:"-" json:"recipient,omitempty"`
	Shield    *string                 `sql:"-" json:"shield,omitempty"`
	Signature *string                 `sql:"-" json:"signature,omitempty"`
	Type      *string                 `sql:"-" json:"type,omitempty"`
	Payload   *ProtocolMessagePayload `sql:"-" json:"payload,omitempty"`

	SubjectAccountID *string `sql:"-" json:"subject_account_id,omitempty"`

	WorkgroupID *uuid.UUID `sql:"-" json:"workgroup_id,omitempty"`
	WorkflowID  *uuid.UUID `sql:"-" json:"workflow_id,omitempty"`
	WorkstepID  *uuid.UUID `sql:"-" json:"workstep_id,omitempty"`

	// HACK -- convenience ptr ... for access during axiomInbound()
	subjectAccount *SubjectAccount `sql:"-" json:"-"`
}

// ProtocolMessagePayload is a axiom protocol message payload
type ProtocolMessagePayload struct {
	Object  map[string]interface{} `sql:"-" json:"object,omitempty"`
	Proof   *string                `sql:"-" json:"proof,omitempty"`
	Type    *string                `sql:"-" json:"type,omitempty"`
	Witness interface{}            `sql:"-" json:"witness,omitempty"`
}

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("axiom package consumer configured to skip NATS streaming subscription setup")
		return
	}

	var waitGroup sync.WaitGroup

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	createNatsAxiomProxySubscriptions(&waitGroup)
	createNatsAxiomWorkflowDeploySubscriptions(&waitGroup)
	createNatsAxiomWorkstepDeploySubscriptions(&waitGroup)
	createNatsAxiomWorkstepFinalizeDeploySubscriptions(&waitGroup)
	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
	createNatsSubjectAccountRegistrationSubscriptions(&waitGroup)
}

func createNatsAxiomProxySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			axiomProxyInboundAckWait,
			natsAxiomProxyInboundSubject,
			natsAxiomProxyInboundSubject,
			natsAxiomProxyInboundSubject,
			consumeAxiomProxyInboundSubscriptionsMsg,
			axiomProxyAckWait,
			natsAxiomProxyInboundMaxInFlight,
			natsAxiomProxyInboundMaxDeliveries,
			nil,
		)
	}

	conn, _ := natsutil.GetSharedNatsConnection(nil)
	conn.Subscribe(natsAxiomSubject, func(msg *nats.Msg) {
		common.Log.Debugf("consuming %d-byte NATS inbound protocol message on subject: %s", len(msg.Data), msg.Subject)
		_, err := natsutil.NatsJetstreamPublish(natsAxiomProxyInboundSubject, msg.Data)
		if err != nil {
			common.Log.Warningf("failed to publish inbound protocol message to local jetstream consumers; %s", err.Error())
			msg.Nak()
			return
		}

		msg.Ack()
	})
}

func createNatsAxiomWorkflowDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			axiomWorkflowDeployMessageAckWait,
			natsAxiomWorkflowDeployMessageSubject,
			natsAxiomWorkflowDeployMessageSubject,
			natsAxiomWorkflowDeployMessageSubject,
			consumeAxiomWorkflowFinalizeDeploySubscriptionsMsg,
			axiomWorkflowDeployMessageAckWait,
			natsAxiomWorkflowDeployMessageMaxInFlight,
			natsAxiomWorkflowDeployMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsAxiomWorkstepDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			axiomWorkstepDeployMessageAckWait,
			natsAxiomWorkstepDeployMessageSubject,
			natsAxiomWorkstepDeployMessageSubject,
			natsAxiomWorkstepDeployMessageSubject,
			consumeAxiomWorkstepDeploySubscriptionsMsg,
			axiomWorkstepDeployMessageAckWait,
			natsAxiomWorkstepDeployMessageMaxInFlight,
			natsAxiomWorkstepDeployMessageMaxDeliveries,
			nil,
		)
	}
}

func createNatsAxiomWorkstepFinalizeDeploySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			axiomWorkstepFinalizeDeployMessageAckWait,
			natsAxiomWorkstepFinalizeDeployMessageSubject,
			natsAxiomWorkstepFinalizeDeployMessageSubject,
			natsAxiomWorkstepFinalizeDeployMessageSubject,
			consumeAxiomWorkstepFinalizeDeploySubscriptionsMsg,
			axiomWorkstepFinalizeDeployMessageAckWait,
			natsAxiomWorkstepFinalizeDeployMessageMaxInFlight,
			natsAxiomWorkstepFinalizeDeployMessageMaxDeliveries,
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

func consumeAxiomProxyInboundSubscriptionsMsg(msg *nats.Msg) {
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

	if protomsg.Recipient == nil {
		common.Log.Warningf("inbound protocol message must include recipient address; %s", err.Error())
		msg.Term()
		return
	}

	var recipientOrganizationID uuid.UUID
	var workflow *Workflow
	var subjectAccountID *string

	org := lookupAxiomOrganization(*protomsg.Recipient)
	if org != nil || org.Metadata == nil {
		common.Log.Warning("failed to resolve recipient organization for inbound protocol message")
		msg.Nak()
		return
	}

	if protomsg.WorkflowID != nil {
		workflow = FindWorkflowByID(*protomsg.WorkflowID)
		if workflow == nil {
			common.Log.Warningf("failed to resolve workflow referenced by inbound protocol message; workflow id: %s", protomsg.WorkflowID.String())
			msg.Nak()
			return
		}
	}

	if orgID, ok := org.Metadata["organization_id"].(string); ok {
		if workflow != nil {
			subjectAccountID = common.StringOrNil(subjectAccountIDFactory(orgID, workflow.WorkgroupID.String()))
			protomsg.subjectAccount, err = resolveSubjectAccount(*subjectAccountID, nil)
			if err != nil {
				common.Log.Warningf("failed to resolve subject account %s during processing of inbound protocol message to recipient: %s", *subjectAccountID, *protomsg.Recipient)
				return
			}

			if protomsg.subjectAccount != nil && protomsg.subjectAccount.Metadata != nil && protomsg.subjectAccount.Metadata.OrganizationID != nil {
				recipientOrganizationID, err = uuid.FromString(*protomsg.subjectAccount.Metadata.OrganizationID)
				if err != nil {
					common.Log.Warningf("failed to parse recipient organization id %s during processing of inbound protocol message to recipient: %s", *protomsg.subjectAccount.Metadata.OrganizationID, *protomsg.Recipient)
					return
				}
			}
		}
	}

	switch *protomsg.Opcode {
	case axiom.ProtocolMessageOpcodeAxiom:
		if protomsg.WorkgroupID == nil {
			common.Log.Warningf("inbound protocol message specified invalid workgroup identifier; %s", err.Error())
			msg.Term()
			return
		}

		if protomsg.WorkflowID == nil {
			common.Log.Warningf("inbound protocol message specified invalid workflow identifier; %s", err.Error())
			msg.Term()
			return
		}

		if protomsg.Recipient == nil {
			common.Log.Warningf("inbound protocol message specified invalid recipient; %s", err.Error())
			msg.Term()
			return
		}

		if protomsg.Sender == nil {
			common.Log.Warningf("inbound protocol message specified invalid sender; %s", err.Error())
			msg.Term()
			return
		}

		if protomsg.subjectAccount == nil {
			common.Log.Warningf("inbound protocol message failed to resolve subject account for recipient: %s; workflow id: %s", *protomsg.Recipient, *protomsg.WorkflowID)
			msg.Term() // FIXME-- should this just return and allow for redelivery in case of temporary latency issues?
			return
		}

		success := protomsg.axiomInbound()
		if !success {
			common.Log.Warning("failed to axiom inbound protocol message")
			return
		}

	case axiom.ProtocolMessageOpcodeJoin:
		common.Log.Warningf("JOIN opcode not yet implemented")
		// const payload = JSON.parse(msg.payload.toString());
		// const messagingEndpoint = await this.resolveMessagingEndpoint(payload.address);
		// if (!messagingEndpoint || !payload.address || !payload.verifiable_credential) {
		//   return Promise.reject('failed to handle axiom JOIN protocol message');
		// }
		// this.workgroupCounterparties.push(payload.address);
		// this.natsBearerTokens[messagingEndpoint] = payload.verifiable_credential;

		// const prover = JSON.parse(JSON.stringify(this.axiomCircuit));
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

	case axiom.ProtocolMessageOpcodeSync:
		token, err := vendOrganizationAccessToken(protomsg.subjectAccount)
		if err != nil {
			common.Log.Warningf("failed to handle inbound sync protocol message; %s", err.Error())
			return
		}

		if protomsg.Payload.Type == nil {
			common.Log.Warning("failed to handle inbound sync protocol message; payload must contain a type")
			msg.Term()
			return
		}

		raw, err := json.Marshal(protomsg.Payload.Object)
		if err != nil {
			common.Log.Warningf("failed to handle object within payload of received sync protocol message; %s", err.Error())
			return
		}

		switch *protomsg.Payload.Type {
		case protomsgPayloadTypeMapping:

			var _mapping *Mapping
			err = json.Unmarshal(raw, &_mapping)
			if err != nil {
				common.Log.Warningf("failed to unmarshal mapping from payload of received sync protocol message; %s", err.Error())
				return
			}

			common.Log.Debugf("received sync payload containing upstream mapping; attempting to upsert mapping: %s", _mapping.ID)
			mapping := FindMappingByID(_mapping.ID)
			if mapping == nil {
				if !_mapping.Create() {
					common.Log.Warningf("failed to insert mapping received in sync protocol message; %s", err.Error())
					msg.Nak()
				}
			} else {
				mapping.OrganizationID = &recipientOrganizationID
				mapping.Update(_mapping)
			}

		case protomsgPayloadTypeProof:
			common.Log.Debugf("received sync payload type: %s", protomsgPayloadTypeProof)
		case protomsgPayloadTypeProver:
			prover, err := privacy.CreateProver(*token, protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to create prover; %s", err.Error())
				return
			}
			common.Log.Debugf("sync protocol message created prover: %s", prover.ID)
		case protomsgPayloadTypeWorkflow:
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

			if protomsg.AxiomID != nil {
				err = workflow.CacheByAxiomID(protomsg.AxiomID.String())
				if err != nil {
					common.Log.Warningf("failed to handle inbound sync protocol message; failed to cache workflow identifier by axiom id; %s", err.Error())
					msg.Nak()
					return
				}
			}

			common.Log.Debugf("cached %d-workstep workflow: %s", len(workflow.Worksteps), workflow.ID)
		default:
			common.Log.Warningf("inbound protocol message specified invalid type; %s", err.Error())
			msg.Term()
			return
		}
	default:
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		msg.Term()
		return
	}

	msg.Ack()
}

func consumeAxiomWorkflowFinalizeDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS axiom workflow deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal axiom workflow deploy message; %s", err.Error())
		msg.Nak()
		return
	}

	workflowID, err := uuid.FromString(params["workflow_id"].(string))
	if err != nil {
		common.Log.Warningf("failed to parse axiom workflow id; %s", err.Error())
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
		err := workflow.index()
		if err != nil {
			common.Log.Warningf("failed to index workflow prototype; %s", err.Error())
			return
		}

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

func consumeAxiomWorkstepDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS axiom workstep deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal axiom workstep deploy message; %s", err.Error())
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
		common.Log.Warningf("failed to parse axiom workstep id; %s", err.Error())
		msg.Nak()
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		common.Log.Warningf("failed to resolve axiom workstep: %s", workstepID)
		msg.Nak()
		return
	}

	workflow := FindWorkflowByID(*workstep.WorkflowID)
	if workflow == nil {
		common.Log.Errorf("failed to resolve axiom workflow: %s", workstep.WorkflowID)
		msg.Nak()
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
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

func consumeAxiomWorkstepFinalizeDeploySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS axiom workstep finalize deploy message on subject: %s", len(msg.Data), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal axiom workstep finalize deploy message; %s", err.Error())
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
		common.Log.Warningf("failed to parse axiom workstep id; %s", err.Error())
		msg.Nak()
		return
	}

	workstep := FindWorkstepByID(workstepID)
	if workstep == nil {
		common.Log.Warningf("failed to resolve axiom workstep: %s", workstepID)
		msg.Nak()
		return
	}

	workflow := FindWorkflowByID(*workstep.WorkflowID)
	if workflow == nil {
		common.Log.Warningf("failed to resolve axiom workflow: %s", workstep.WorkflowID)
		msg.Nak()
		return
	}

	subjectAccountID := subjectAccountIDFactory(organizationID.String(), workflow.WorkgroupID.String())
	subjectAccount, err := resolveSubjectAccount(subjectAccountID, nil)
	if err != nil {
		common.Log.Errorf("failed to resolve BPI subject account for workflow: %s; %s", workstep.WorkflowID, err.Error())
		msg.Nak()
		return
	}

	if subjectAccount.Metadata == nil {
		common.Log.Error("failed to resolve BPI subject account metadata")
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
		common.Log.Warningf("failed to umarshal axiom workstep finalize deploy message; %s", err.Error())
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
		common.Log.Warning("no recipient specified in protocol message")
		msg.Term()
		return
	}

	if protomsg.Sender == nil {
		common.Log.Warning("no sender specified in protocol message")
		msg.Term()
		return
	}

	if protomsg.SubjectAccountID == nil {
		common.Log.Warning("no subject account id specified in protocol message")
		msg.Term()
		return
	}

	var workgroup *Workgroup
	var workflow *Workflow

	if protomsg.WorkgroupID != nil {
		workgroup = FindWorkgroupByID(*protomsg.WorkgroupID)
		if workgroup == nil {
			common.Log.Warningf("failed to resolve axiom workgroup: %s", protomsg.WorkgroupID)
			msg.Nak()
			return
		}
	}

	if protomsg.WorkflowID != nil {
		workflow = FindWorkflowByID(*protomsg.WorkflowID)
		if workflow == nil {
			common.Log.Warningf("failed to resolve axiom workflow: %s", protomsg.WorkflowID)
			msg.Nak()
			return
		}
	}

	// var workgroupID *string
	// if protomsg.WorkgroupID != nil {
	// 	workgroupID = common.StringOrNil(protomsg.WorkgroupID.String())
	// } else if workflow != nil {
	// 	workgroupID = common.StringOrNil(workflow.WorkgroupID.String())
	// }

	// if workgroupID == nil {
	// 	common.Log.Warningf("failed to resolve workgroup for %d-byte protocol message", len(msg.Data))
	// 	msg.Term()
	// 	return
	// }

	// subjectAccountID := subjectAccountIDFactory(organizationID.String(), *workgroupID)
	subjectAccount, err := resolveSubjectAccount(*protomsg.SubjectAccountID, nil) // FIXME... audit this to verify it is sufficiently secure...
	if err != nil {
		common.Log.Errorf("failed to resolve BPI subject account for workflow: %s; %s", *protomsg.WorkflowID, err.Error())
		msg.Nak()
		return
	}

	if subjectAccount.Metadata == nil {
		common.Log.Error("failed to resolve BPI subject account metadata")
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationID == nil {
		common.Log.Error("failed to resolve BPI subject account; organization id required")
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationAddress != nil && strings.EqualFold(strings.ToLower(*subjectAccount.Metadata.OrganizationAddress), strings.ToLower(*protomsg.Recipient)) {
		common.Log.Debugf("skipping protocol message broadcast recipient matching the originating subject account with address: %s", *protomsg.Recipient)
		msg.Ack()
		return
	}

	url := subjectAccount.lookupAxiomOrganizationMessagingEndpoint(*protomsg.Recipient)
	if url == nil {
		common.Log.Warningf("failed to lookup recipient messaging endpoint: %s", *protomsg.Recipient)
		return
	}

	jwt := subjectAccount.lookupAxiomOrganizationIssuedVC(*protomsg.Recipient)
	if jwt == nil {
		// request a VC from the counterparty
		jwt, err = subjectAccount.requestAxiomOrganizationIssuedVC(*protomsg.Recipient)
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

	err = conn.Publish(natsAxiomSubject, msg.Data)
	if err != nil {
		// clear cached endpoint so it will be re-fetched...
		// counterparty := lookupAxiomOrganization(*protomsg.Recipient)
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
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		common.Log.Warningf("recovered in BPI subject account registration message handler; %s", r)
	// 		msg.Nak()
	// 	}
	// }()

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

	err = subjectAccount.enrich()
	if err != nil {
		common.Log.Warningf("failed to enrich BPI subject account during BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
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

	orgToken, err := subjectAccount.authorizeAccessToken()
	if err != nil {
		common.Log.Warningf("failed to authorize access token for BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	organization, err := ident.GetOrganizationDetails(*orgToken.AccessToken, *subjectAccount.SubjectID, map[string]interface{}{})
	if err != nil {
		common.Log.Warningf("failed to fetch organization details during BPI subject account registration message handler; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	var orgZeroKnowledgePublicKey *string

	vaults, err := vault.ListVaults(*orgToken.AccessToken, map[string]interface{}{})
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
		keys, err = vault.ListKeys(*orgToken.AccessToken, orgVault.ID.String(), map[string]interface{}{
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

	if subjectAccount.Metadata.OrganizationAddress == nil {
		common.Log.Warningf("failed to resolve organization public address for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationDomain == nil {
		common.Log.Warningf("failed to resolve organization domain for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	if subjectAccount.Metadata.OrganizationBPIEndpoint == nil {
		common.Log.Warningf("failed to resolve organization API endpoint for storage in the public org registry; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

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

	// var erc1820RegistryContractID *string
	var orgRegistryContractID *string

	// var erc1820RegistryContractAddress *string
	var orgRegistryContractAddress *string

	var orgWalletID *string

	// org api token & hd wallet

	orgWalletResp, err := nchain.CreateWallet(*orgToken.AccessToken, map[string]interface{}{
		"purpose": 44,
	})
	if err != nil {
		common.Log.Warningf("failed to create organization HD wallet for organization registration tx should be sent; BPI subject account id: %s", subjectAccountID)
		msg.Nak()
		return
	}

	orgWalletID = common.StringOrNil(orgWalletResp.ID.String())
	common.Log.Debugf("created HD wallet %s for organization %s", *orgWalletID, *subjectAccount.SubjectID)

	for _, c := range contracts {
		resp, err := nchain.GetContractDetails(*orgToken.AccessToken, c.ID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to resolve organization registry contract to which the organization registration tx should be sent; BPI subject account id: %s", subjectAccountID)
			msg.Nak()
			return
		}

		if resp.Type != nil {
			switch *resp.Type {
			case contractTypeOrgRegistry:
				orgRegistryContractID = common.StringOrNil(resp.ID.String())
				orgRegistryContractAddress = resp.Address
			}
		}
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

	common.Log.Debugf("attempting to register organization %s, with on-chain registry contract: %s", *subjectAccount.SubjectID, *orgRegistryContractAddress)
	_, err = nchain.ExecuteContract(*orgToken.AccessToken, *orgRegistryContractID, map[string]interface{}{
		"wallet_id": orgWalletID,
		"method":    method,
		"params": []interface{}{
			*subjectAccount.Metadata.OrganizationAddress,
			*organization.Name,
			*subjectAccount.Metadata.OrganizationDomain,
			*subjectAccount.Metadata.OrganizationMessagingEndpoint,
			*orgZeroKnowledgePublicKey,
			"{}",
		},
		"value": 0,
	})
	if err != nil {
		common.Log.Warningf("organization registry transaction broadcast failed on behalf of organization: %s; org registry contract id: %s; %s", *subjectAccount.SubjectID, *orgRegistryContractID, err.Error())
		return
	}

	if updateOrgMetadata {
		common.Log.Debugf("ident organization record not updated for BPI subject account: ")
	}

	common.Log.Debugf("broadcast organization registry and interface impl transactions on behalf of organization: %s", *subjectAccount.SubjectID)
	msg.Ack()
}

func consumeWorkgroupSyncRequestMsg(msg *nats.Msg) {
	defer func() {
		if r := recover(); r != nil {
			common.Log.Warningf("recovered in axiom workgroup sync request message on subject; %s", r)
			msg.Nak()
		}
	}()

	common.Log.Debugf("consuming %d-byte NATS axiom workgroup sync request message on subject: %s", len(msg.Data), msg.Subject)

	var claims *AxiomClaims
	err := json.Unmarshal(msg.Data, &claims)
	if err != nil {
		common.Log.Warningf("failed to umarshal payload from workgroup sync request message; %s", err.Error())
		msg.Nak()
		return
	}

	if claims.InvitorSubjectAccountID == nil {
		common.Log.Warning("failed to accept workgroup invitation; no axiom invitor subject account id resolved from claims")
		msg.Term()
		return
	}

	subjectAccount, err := resolveSubjectAccount(*claims.InvitorSubjectAccountID, nil)
	if err != nil {
		common.Log.Warningf("failed to resolve subject account for workgroup sync request message; %s", err.Error())
		msg.Nak()
		return
	}

	payload, _ := json.Marshal(subjectAccount)
	err = msg.Respond(payload)
	if err != nil {
		common.Log.Warningf("failed to write payload in response to axiom workgroup sync request message on subject: %s", err.Error())
		msg.Nak()
		return
	}

	msg.Ack()
}
