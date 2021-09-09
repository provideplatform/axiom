package baseline

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/nats.go"
	"github.com/provideplatform/baseline-proxy/common"
	"github.com/provideplatform/provide-go/api/privacy"
)

const defaultNatsStream = "baseline-proxy"

const protomsgPayloadTypeCircuit = "circuit"
const protomsgPayloadTypeWorkflow = "workflow"

const natsDispatchInvitationSubject = "baseline-proxy.invitation.outbound"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30
const natsDispatchInvitationMaxDeliveries = 10

const natsDispatchProtocolMessageSubject = "baseline-proxy.protocolmessage.outbound"
const natsDispatchProtocolMessageMaxInFlight = 2048
const dispatchProtocolMessageAckWait = time.Second * 30
const natsDispatchProtocolMessageMaxDeliveries = 10

const natsBaselineProxyInboundSubject = "baseline-proxy.inbound"
const natsBaselineProxyInboundMaxInFlight = 2048
const baselineProxyInboundAckWait = time.Second * 30
const natsBaselineProxyInboundMaxDeliveries = 10

const natsBaselineProxySubject = "baseline.proxy"
const baselineProxyAckWait = time.Second * 30

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("proxy package consumer configured to skip NATS streaming subscription setup")
		return
	}

	var waitGroup sync.WaitGroup

	natsutil.EstablishSharedNatsConnection(nil)
	natsutil.NatsCreateStream(defaultNatsStream, []string{
		fmt.Sprintf("%s.>", defaultNatsStream),
	})

	createNatsBaselineProxySubscriptions(&waitGroup)
	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
}

func createNatsBaselineProxySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			baselineProxyInboundAckWait,
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
	conn.Subscribe(natsBaselineProxySubject, func(msg *nats.Msg) {
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

func createNatsDispatchInvitationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsJetstreamSubscription(wg,
			dispatchInvitationAckWait,
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
			consumeDispatchProtocolMessageSubscriptionsMsg,
			dispatchProtocolMessageAckWait,
			natsDispatchProtocolMessageMaxInFlight,
			natsDispatchProtocolMessageMaxDeliveries,
			nil,
		)
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
	case ProtocolMessageOpcodeBaseline:
		success := protomsg.baselineInbound()
		if !success {
			common.Log.Warning("failed to baseline inbound protocol message")
			return
		}

	case ProtocolMessageOpcodeJoin:
		common.Log.Warningf("JOIN opcode not yet implemented")
		// const payload = JSON.parse(msg.payload.toString());
		// const messagingEndpoint = await this.resolveMessagingEndpoint(payload.address);
		// if (!messagingEndpoint || !payload.address || !payload.authorized_bearer_token) {
		//   return Promise.reject('failed to handle baseline JOIN protocol message');
		// }
		// this.workgroupCounterparties.push(payload.address);
		// this.natsBearerTokens[messagingEndpoint] = payload.authorized_bearer_token;

		// const circuit = JSON.parse(JSON.stringify(this.baselineCircuit));
		// circuit.proving_scheme = circuit.provingScheme;
		// circuit.verifier_contract = circuit.verifierContract;
		// delete circuit.verifierContract;
		// delete circuit.createdAt;
		// delete circuit.vaultId;
		// delete circuit.provingScheme;
		// delete circuit.provingKeyId;
		// delete circuit.verifyingKeyId;
		// delete circuit.status;

		// // sync circuit artifacts
		// this.sendProtocolMessage(payload.address, Opcode.Sync, {
		//   type: 'circuit',
		//   payload: circuit,
		// });

	case ProtocolMessageOpcodeSync:
		token, err := vendOrganizationAccessToken()
		if err != nil {
			common.Log.Warningf("failed to handle inbound sync protocol message; %s", err.Error())
			return
		}

		// FIXME -- use switch and attempt nack if invalid sync type...
		if protomsg.Payload.Type != nil && *protomsg.Payload.Type == protomsgPayloadTypeCircuit {
			circuit, err := privacy.CreateCircuit(*token, protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to create circuit; %s", err.Error())
				return
			}
			common.Log.Debugf("sync protocol message created circuit: %s", circuit.ID)
		} else if protomsg.Payload.Type != nil && *protomsg.Payload.Type == protomsgPayloadTypeWorkflow {
			workflow := &Workflow{}
			raw, err := json.Marshal(protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to marshal payload object; %s", err.Error())
				return
			}
			json.Unmarshal(raw, &workflow)

			for _, workstep := range workflow.Worksteps {
				params := map[string]interface{}{}
				rawcircuit, _ := json.Marshal(workstep.Circuit)
				json.Unmarshal(rawcircuit, &params)

				workstep.Circuit, err = privacy.CreateCircuit(*token, params)
				if err != nil {
					common.Log.Warningf("failed to handle inbound sync protocol message; failed to create circuit; %s", err.Error())
					return
				}
				workstep.CircuitID = &workstep.Circuit.ID
				common.Log.Debugf("sync protocol message created circuit: %s", workstep.Circuit.ID)
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

	protomsg := &ProtocolMessage{}
	err := json.Unmarshal(msg.Data, &protomsg)
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

	url := lookupBaselineOrganizationMessagingEndpoint(*protomsg.Recipient)
	if url == nil {
		common.Log.Warningf("failed to lookup recipient messaging endpoint: %s", *protomsg.Recipient)
		msg.Nak()
		return
	}

	jwt := lookupBaselineOrganizationIssuedVC(*protomsg.Recipient)
	if jwt == nil {
		// request a VC from the counterparty
		jwt, err = requestBaselineOrganizationIssuedVC(*protomsg.Recipient)
		if err != nil {
			resolveBaselineCounterparties() // HACK-- this should not re-resolve all counterparties...

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

	conn, err := natsutil.GetNatsConnection(*url, time.Second*10, jwt)
	if err != nil {
		common.Log.Warningf("failed to establish NATS connection to recipient: %s; %s", *protomsg.Recipient, err.Error())
		msg.Nak()
		return
	}

	defer conn.Close()

	err = conn.Publish(natsBaselineProxySubject, msg.Data)
	if err != nil {
		// clear cached endpoint so it will be re-fetched...
		// counterparty := lookupBaselineOrganization(*protomsg.Recipient)
		// counterparty.MessagingEndpoint = nil
		// counterparty.Cache()

		resolveBaselineCounterparties() // HACK-- this should not re-resolve all counterparties...

		common.Log.Warningf("failed to publish protocol message to recipient: %s; %s", *protomsg.Recipient, err.Error())
		msg.Nak()
		return
	}

	common.Log.Debugf("broadcast %d-byte protocol message to recipient: %s", len(msg.Data), *protomsg.Recipient)
	msg.Ack()
}
