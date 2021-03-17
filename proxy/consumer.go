package proxy

import (
	"encoding/json"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	"github.com/nats-io/nats.go"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/providibright/common"
	"github.com/provideservices/provide-go/api/privacy"
)

const natsDispatchInvitationSubject = "providibright.invitation.outbound"
const natsDispatchInvitationMaxInFlight = 2048
const dispatchInvitationAckWait = time.Second * 30
const natsDispatchInvitationTimeout = int64(time.Minute * 5)

const natsDispatchProtocolMessageSubject = "providibright.protocolmessage.outbound"
const natsDispatchProtocolMessageMaxInFlight = 2048
const dispatchProtocolMessageAckWait = time.Second * 30
const natsDispatchProtocolMessageTimeout = int64(time.Minute * 5)

const natsBaselineProxySubject = "baseline.proxy"
const natsBaselineProxyMaxInFlight = 2048
const baselineProxyAckWait = time.Second * 30
const natsBaselineProxyTimeout = int64(time.Minute * 5)

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("proxy package consumer configured to skip NATS streaming subscription setup")
		return
	}

	var waitGroup sync.WaitGroup

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	createNatsBaselineProxySubscriptions(&waitGroup)
	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
}

func createNatsBaselineProxySubscriptions(wg *sync.WaitGroup) {
	conn, _ := natsutil.GetSharedNatsConnection(nil)
	conn.Subscribe(natsBaselineProxySubject, consumeBaselineProxySubscriptionsMsg)
	// for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
	// 	natsutil.RequireNatsStreamingSubscription(wg,
	// 		baselineProxyAckWait,
	// 		natsBaselineProxySubject,
	// 		natsBaselineProxySubject,
	// 		consumeBaselineProxySubscriptionsMsg,
	// 		baselineProxyAckWait,
	// 		natsBaselineProxyMaxInFlight,
	// 		nil,
	// 	)
	// }
}

func createNatsDispatchInvitationSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			dispatchInvitationAckWait,
			natsDispatchInvitationSubject,
			natsDispatchInvitationSubject,
			consumeDispatchInvitationSubscriptionsMsg,
			dispatchInvitationAckWait,
			natsDispatchInvitationMaxInFlight,
			nil,
		)
	}
}

func createNatsDispatchProtocolMessageSubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			dispatchProtocolMessageAckWait,
			natsDispatchProtocolMessageSubject,
			natsDispatchProtocolMessageSubject,
			consumeDispatchProtocolMessageSubscriptionsMsg,
			dispatchProtocolMessageAckWait,
			natsDispatchProtocolMessageMaxInFlight,
			nil,
		)
	}
}

func consumeBaselineProxySubscriptionsMsg(msg *nats.Msg) {
	common.Log.Debugf("consuming %d-byte NATS inbound protocol message on subject: %s", len(msg.Data), msg.Subject)

	protomsg := &ProtocolMessage{}
	err := json.Unmarshal(msg.Data, &protomsg)
	if err != nil {
		common.Log.Warningf("failed to umarshal inbound protocol message; %s", err.Error())
		// natsutil.Nack(msg)
		return
	}

	if protomsg.Opcode == nil {
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		// natsutil.Nack(msg)
		return
	}

	switch *protomsg.Opcode {
	case ProtocolMessageOpcodeBaseline:
		success := protomsg.baselineInbound()
		if !success {
			common.Log.Warning("failed to baseline inbound protocol message")
			// natsutil.AttemptNack(msg, natsBaselineProxyTimeout)
			return
		}
		break
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
		break
	case ProtocolMessageOpcodeSync:
		token, err := vendOrganizationAccessToken()
		if err != nil {
			common.Log.Warningf("failed to handle inbound sync protocol message; %s", err.Error())
			// natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
			return
		}

		// FIXME -- use switch and attempt nack if invalid sync type...
		if protomsg.Payload.Type != nil && *protomsg.Payload.Type == "circuit" {
			circuit, err := privacy.CreateCircuit(*token, protomsg.Payload.Object)
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to create circuit; %s", err.Error())
				// natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
				return
			}
			common.Log.Debugf("sync protocol message created circuit: %s", circuit.ID)
		} else if protomsg.Payload.Type != nil && *protomsg.Payload.Type == "workflow" {
			workflow := &Workflow{}
			raw, err := json.Marshal(protomsg.Payload.Object)
			json.Unmarshal(raw, &workflow)

			for _, circuit := range workflow.Circuits {
				params := map[string]interface{}{}
				rawcircuit, _ := json.Marshal(circuit)
				json.Unmarshal(rawcircuit, &params)

				circuit, err := privacy.CreateCircuit(*token, params)
				if err != nil {
					common.Log.Warningf("failed to handle inbound sync protocol message; failed to create circuit; %s", err.Error())
					// natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
					return
				}
				common.Log.Debugf("sync protocol message created workflow: %s", circuit.ID)
			}

			err := workflow.Cache()
			if err != nil {
				common.Log.Warningf("failed to handle inbound sync protocol message; failed to cache workflow; %s", err.Error())
				// natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
				return
			}
		}

		break
	default:
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		// natsutil.Nack(msg)
		return
	}

	// msg.Ack()
}

func consumeDispatchInvitationSubscriptionsMsg(msg *stan.Msg) {
	common.Log.Debugf("consuming %d-byte NATS dispatch invitation message on subject: %s", msg.Size(), msg.Subject)

	var params map[string]interface{}

	err := json.Unmarshal(msg.Data, &params)
	if err != nil {
		common.Log.Warningf("failed to umarshal dispatch invitation message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	// TODO!

	msg.Ack()
}

func consumeDispatchProtocolMessageSubscriptionsMsg(msg *stan.Msg) {
	common.Log.Debugf("consuming %d-byte NATS dispatch protocol message on subject: %s", msg.Size(), msg.Subject)

	protomsg := &ProtocolMessage{}
	err := json.Unmarshal(msg.Data, &protomsg)
	if err != nil {
		common.Log.Warningf("failed to umarshal dispatch protocol message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	url := lookupBaselineOrganizationMessagingEndpoint(*protomsg.Recipient)
	if url == nil {
		common.Log.Warningf("failed to lookup recipient endpoint: %s", *protomsg.Recipient)
		natsutil.Nack(msg)
		return
	}

	// FIXME!!!!
	// jwt := lookupBaselineOrganizationIssuedVC(*protomsg.Recipient)
	// if jwt == nil {
	// 	// TODO: request a VC from the counterparty

	// 	common.Log.Warningf("failed to dispatch protocol message to recipient: %s; no bearer token resolved", *protomsg.Recipient)
	// 	natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
	// 	return
	// }

	jwt, _ := vendOrganizationAccessToken()

	conn, err := natsutil.GetNatsConnection(*url, time.Second*10, jwt)
	if err != nil {
		common.Log.Warningf("failed to establish NATS connection to recipient: %s; %s", *protomsg.Recipient, err.Error())
		natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
		return
	}

	defer conn.Close()

	err = conn.Publish(natsBaselineProxySubject, msg.Data)
	if err != nil {
		// TODO-- clear cached endpoint so it will be re-fetched...

		common.Log.Warningf("failed to publish protocol message to recipient: %s; %s", *protomsg.Recipient, err.Error())
		natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
		return
	}

	common.Log.Debugf("broadcast %d-byte protocol message to recipient: %s", len(msg.Data), *protomsg.Recipient)
	msg.Ack()
}
