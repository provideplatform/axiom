package proxy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/providibright/common"
	privacy "github.com/provideservices/provide-go/api/privacy"
)

func baselineWorkflowFactory(objectType string) (*Workflow, error) {
	identifier, _ := uuid.NewV4()
	workflow := &Workflow{
		Circuits:     make([]*privacy.Circuit, 0),
		Identifier:   common.StringOrNil(identifier.String()),
		Participants: make([]*Participant, 0),
		Shield:       nil,
	}

	workflow.Participants = append(workflow.Participants, &Participant{
		Address: common.StringOrNil("0x3E8E1a128190f9628f918Ef407389e656daB5530"),
		URL:     common.StringOrNil("nats://kt.local:4222"),
	})

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil, err
	}

	switch objectType {
	case baselineWorkflowTypeProcureToPay:
		circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("PO", "purchase_order", nil))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("SO", "sales_order", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("SN", "shipment_notification", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("GR", "goods_receipt", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)

		circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("Invoice", "invoice", common.StringOrNil(circuit.StoreID.String())))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)
		break

	case baselineWorkflowTypeServiceNowIncident:
		circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("PO", "purchase_order", nil))
		if err != nil {
			common.Log.Debugf("failed to deploy circuit; %s", err.Error())
			return nil, err
		}
		workflow.Circuits = append(workflow.Circuits, circuit)
		break
	default:
		return nil, fmt.Errorf("failed to create workflow for type: %s", objectType)
	}

	for {
		if len(workflow.Circuits) > 0 {
			circuit, err := privacy.GetCircuitDetails(*token, workflow.Circuits[0].ID.String())
			if err != nil {
				common.Log.Debugf("failed to fetch circuit details; %s", err.Error())
				break
			}
			if circuit.Status != nil && *circuit.Status == "provisioned" {
				common.Log.Debugf("provisioned initial workflow circuit: %s", circuit.ID)
				break
			}
		} else {
			time.Sleep(time.Millisecond * 250)
		}
	}

	return workflow, nil
}

func lookupBaselineWorkflow(identifier string) *Workflow {
	var workflow *Workflow

	key := fmt.Sprintf("baseline.workflow.%s", identifier)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline workflow: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &workflow)
	return workflow
}
