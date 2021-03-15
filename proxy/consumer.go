package proxy

import (
	"encoding/json"
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

func init() {
	if !common.ConsumeNATSStreamingSubscriptions {
		common.Log.Debug("proxy package consumer configured to skip NATS streaming subscription setup")
		return
	}

	natsutil.EstablishSharedNatsStreamingConnection(nil)

	var waitGroup sync.WaitGroup

	createNatsDispatchInvitationSubscriptions(&waitGroup)
	createNatsDispatchProtocolMessageSubscriptions(&waitGroup)
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

	resp, err := nchain.ExecuteContract(*token, *common.BaselineRegistryContractAddress, map[string]interface{}{
		"method": "getOrg",
		"params": []string{*protomsg.Recipient},
		"value":  0,
	})

	if err != nil {
		common.Log.Warningf("failed to read organization details for recipient: %s; %s", *protomsg.Recipient, err.Error())
		natsutil.AttemptNack(msg, natsDispatchProtocolMessageTimeout)
		return
	}

	common.Log.Debugf("%v", resp)

	// lookup recipient by address in org registry contract

	// async fetchOrganization(address: string): Promise<Organization> {
	// 	const orgRegistryContract = await this.requireWorkgroupContract('organization-registry');

	// 	const nchain = nchainClientFactory(
	// 	  this.workgroupToken,
	// 	  this.baselineConfig?.nchainApiScheme,
	// 	  this.baselineConfig?.nchainApiHost,
	// 	);

	// 	const signerResp = (await nchain.createAccount({
	// 	  network_id: this.baselineConfig?.networkId,
	// 	}));

	// 	if (resp && resp['response'] && resp['response'][0] !== '0x0000000000000000000000000000000000000000') {
	// 	  const org = {} as Organization;
	// 	  org.name = resp['response'][1].toString();
	// 	  org['address'] = resp['response'][0];
	// 	  org['config'] = JSON.parse(atob(resp['response'][5]));
	// 	  org['config']['messaging_endpoint'] = atob(resp['response'][2]);
	// 	  org['config']['zk_public_key'] = atob(resp['response'][4]);
	// 	  return Promise.resolve(org);
	// 	}

	// 	return Promise.reject(`failed to fetch organization ${address}`);
	//   }

	msg.Ack()
}
