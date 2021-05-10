package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideservices/provide-go/api/ident"
	privacy "github.com/provideservices/provide-go/api/privacy"
)

const requireCircuitTickerInterval = time.Second * 5
const requireCircuitSleepInterval = time.Millisecond * 500
const requireCircuitTimeout = time.Minute * 5

// Cache a workflow instance
func (w *Workflow) Cache() error {
	if w.Identifier == nil {
		return errors.New("failed to cache workflow with nil identifier")
	}

	key := fmt.Sprintf("baseline.workflow.%s", *w.Identifier)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(w)
		return redisutil.Set(key, raw, nil)
	})
}

func baselineWorkflowFactory(objectType string, identifier *string) (*Workflow, error) {
	var identifierUUID uuid.UUID
	if identifier != nil {
		identifierUUID, _ = uuid.FromString(*identifier)
	} else {
		identifierUUID, _ = uuid.NewV4()
	}

	workflow := &Workflow{
		Circuits:     make([]*privacy.Circuit, 0),
		Identifier:   &identifierUUID,
		Participants: make([]*Participant, 0),
		Shield:       nil,
	}

	for _, party := range common.DefaultCounterparties {
		workflow.Participants = append(workflow.Participants, &Participant{
			Address:           common.StringOrNil(party["address"]),
			MessagingEndpoint: common.StringOrNil(party["messaging_endpoint"]),
		})
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		return nil, err
	}

	// FIXME -- read all workgroup participants from cache
	workgroupID := os.Getenv("BASELINE_WORKGROUP_ID")
	orgs, err := ident.ListApplicationOrganizations(*token, workgroupID, map[string]interface{}{})
	for _, org := range orgs {
		workflow.Participants = append(workflow.Participants, &Participant{
			Address:           common.StringOrNil(org.Metadata["address"].(string)),
			APIEndpoint:       common.StringOrNil(org.Metadata["api_endpoint"].(string)),
			MessagingEndpoint: common.StringOrNil(org.Metadata["messaging_endpoint"].(string)),
		})
	}

	if identifier == nil {
		common.Log.Debugf("deploying circuit(s) for workflow: %s", identifierUUID.String())

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
			circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("Incident", "purchase_order", nil))
			if err != nil {
				common.Log.Debugf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Circuits = append(workflow.Circuits, circuit)
			break
		default:
			return nil, fmt.Errorf("failed to create workflow for type: %s", objectType)
		}

		err := requireCircuits(token, workflow)
		if err != nil {
			common.Log.Debugf("failed to provision circuit(s); %s", err.Error())
			return nil, err
		}
	}

	return workflow, nil
}

func requireCircuits(token *string, workflow *Workflow) error {
	wg := &sync.WaitGroup{}

	startTime := time.Now()
	timer := time.NewTicker(requireCircuitTickerInterval)
	defer timer.Stop()

	wg.Add(len(workflow.Circuits))
	go func() {
		for {
			select {
			case <-timer.C:
				for i, _circuit := range workflow.Circuits {
					circuit, err := privacy.GetCircuitDetails(*token, _circuit.ID.String())
					if err != nil {
						common.Log.Debugf("failed to fetch circuit details; %s", err.Error())
						break
					}
					if circuit.Status != nil && *circuit.Status == "provisioned" {
						common.Log.Debugf("provisioned workflow circuit: %s", circuit.ID)
						workflow.Circuits[i] = circuit
						wg.Done()
					}
				}
			default:
				if startTime.Add(requireCircuitTimeout).Before(time.Now()) {
					msg := fmt.Sprintf("failed to provision %d circuit(s)", len(workflow.Circuits))
					common.Log.Warning(msg)
					wg.Done()
				} else {
					time.Sleep(requireCircuitSleepInterval)
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

func LookupBaselineWorkflow(identifier string) *Workflow {
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
