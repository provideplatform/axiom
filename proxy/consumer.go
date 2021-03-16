package proxy

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sync"
	"time"

	natsutil "github.com/kthomas/go-natsutil"
	stan "github.com/nats-io/stan.go"
	"github.com/provideapp/providibright/common"
	"github.com/provideservices/provide-go/api/nchain"
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

	// requireExternalNats(&waitGroup)
	natsutil.EstablishSharedNatsStreamingConnection(nil)

	createNatsBaselineProxySubscriptions(&waitGroup)
	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
}

func requireExternalNats(wg *sync.WaitGroup) {
	if os.Getenv("BASELINE_NATS_URL") == "" {
		panic("BASELINE_NATS_URL not provided")
	}
}

func createNatsBaselineProxySubscriptions(wg *sync.WaitGroup) {
	for i := uint64(0); i < natsutil.GetNatsConsumerConcurrency(); i++ {
		natsutil.RequireNatsStreamingSubscription(wg,
			baselineProxyAckWait,
			natsBaselineProxySubject,
			natsBaselineProxySubject,
			consumeBaselineProxySubscriptionsMsg,
			baselineProxyAckWait,
			natsBaselineProxyMaxInFlight,
			nil,
		)
	}
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

func consumeBaselineProxySubscriptionsMsg(msg *stan.Msg) {
	common.Log.Debugf("consuming %d-byte NATS inbound protocol message on subject: %s", msg.Size(), msg.Subject)

	protomsg := &ProtocolMessage{}
	err := json.Unmarshal(msg.Data, &protomsg)
	if err != nil {
		common.Log.Warningf("failed to umarshal inbound protocol message; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	if protomsg.Opcode == nil {
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	switch *protomsg.Opcode {
	case protocolMessageOpcodeBaseline:
		success := protomsg.baselineInbound()
		if !success {
			common.Log.Warningf("failed to baseline inbound protocol message; %s")
			natsutil.AttemptNack(msg, natsBaselineProxyTimeout)
			return
		}
		break
	case protocolMessageOpcodeJoin:
		common.Log.Warningf("JOIN opcode not yet implemented")
		break
	case protocolMessageOpcodeSync:
		common.Log.Warningf("SYNC opcode not yet implemented")
		break
	default:
		common.Log.Warningf("inbound protocol message specified invalid opcode; %s", err.Error())
		natsutil.Nack(msg)
		return
	}

	msg.Ack()
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

	token, err := vendOrganizationAccessToken()
	if err != nil {
		common.Log.Warningf("failed to dispatch protocol message for recipient: %s; %s", *protomsg.Recipient, err.Error())
		natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
		return
	}

	url := lookupBaselineOrganizationMessagingEndpoint(*protomsg.Recipient)
	if url == nil {
		common.Log.Warningf("failed to lookup recipient endpoint: %s", *protomsg.Recipient)

		// HACK! this account creation will go away with new nchain...
		account, _ := nchain.CreateAccount(*token, map[string]interface{}{
			"network_id": *common.NChainBaselineNetworkID,
		})

		resp, err := nchain.ExecuteContract(*token, *common.BaselineRegistryContractAddress, map[string]interface{}{
			"account_id": account.ID.String(),
			"method":     "getOrg",
			"params":     []string{*protomsg.Recipient},
			"value":      0,
		})

		if err != nil {
			common.Log.Warningf("failed to dispatch protocol message to recipient: %s; no endpoint resolved", *protomsg.Recipient)
			natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
			return
		}

		if endpoint, endpointOk := resp.Response.([]interface{})[2].(string); endpointOk {
			endpoint, err := base64.StdEncoding.DecodeString(endpoint)
			if err != nil {
				common.Log.Warningf("failed to dispatch protocol message to recipient: %s; failed to base64 decode endpoint", *protomsg.Recipient)
				natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
				return
			}
			org := &Participant{
				Address: protomsg.Recipient,
				URL:     common.StringOrNil(string(endpoint)),
			}

			err = org.cache()
			if err != nil {
				common.Log.Warningf("failed to dispatch protocol message to recipient: %s; failed to", *protomsg.Recipient)
				natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
				return
			}
		}
	}

	jwt := lookupBaselineOrganizationMessagingEndpoint(*protomsg.Recipient)
	if jwt == nil {
		// TODO: request a VC from the counterparty

		common.Log.Warningf("failed to dispatch protocol message to recipient: %s; no bearer token resolved", *protomsg.Recipient)
		natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
		return
	}

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
