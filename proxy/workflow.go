package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/compiler"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideapp/baseline-proxy/common"
	"github.com/provideservices/provide-go/api/ident"
	"github.com/provideservices/provide-go/api/nchain"
	privacy "github.com/provideservices/provide-go/api/privacy"
)

const requireContractSleepInterval = time.Second * 1
const requireContractTickerInterval = time.Second * 5
const requireContractTimeout = time.Minute * 10

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

// CacheByBaselineID caches a workflow identifier, indexed by baseline id for convenient lookup
func (w *Workflow) CacheByBaselineID(baselineID string) error {
	if w.Identifier == nil {
		return errors.New("failed to cache workflow with nil identifier")
	}

	key := fmt.Sprintf("baseline.id.%s.workflow.identifier", baselineID)
	return redisutil.WithRedlock(key, func() error {
		common.Log.Debugf("mapping baseline id to workflow identifier")
		return redisutil.Set(key, w.Identifier.String(), nil)
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
		case baselineWorkflowTypeGeneralConsistency:
			circuit, err := privacy.CreateCircuit(*token, circuitParamsFactory("General Consistency", "purchase_order", nil))
			if err != nil {
				common.Log.Debugf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Circuits = append(workflow.Circuits, circuit)
			break

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

	circuits := make([]bool, len(workflow.Circuits))
	wg.Add(len(workflow.Circuits))

	go func() {
		for {
			select {
			case <-timer.C:
				for i, _circuit := range workflow.Circuits {
					if !circuits[i] {
						circuit, err := privacy.GetCircuitDetails(*token, _circuit.ID.String())
						if err != nil {
							common.Log.Debugf("failed to fetch circuit details; %s", err.Error())
							break
						}
						if circuit.Status != nil && *circuit.Status == "provisioned" {
							common.Log.Debugf("provisioned workflow circuit: %s", circuit.ID)
							if circuit.VerifierContract != nil {
								if source, sourceOk := circuit.VerifierContract["source"].(string); sourceOk {
									contractRaw, _ := json.MarshalIndent(source, "", "  ")
									common.Log.Debugf("verifier contract: %s", string(contractRaw))

									contractName := fmt.Sprintf("%s Verifier", *circuit.Name)
									DeployContract([]byte(contractName), []byte(source))
								}
							}

							workflow.Circuits[i] = circuit
							circuits[i] = true
							wg.Done()
						}
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

// DeployContract compiles and deploys a raw solidity smart contract
// FIXME -- this presence of this as a dependency here should cause
// a check to happen during boot that ensures `which solc` resolves...
func DeployContract(name, raw []byte) (*nchain.Contract, error) {
	artifact, err := compiler.CompileSolidityString("./ops/solc.sh", string(raw)) // FIXME... parse pragma?
	if err != nil {
		common.Log.Warningf("failed to compile solidity contract: %s; %s", name, err.Error())
		return nil, err
	}

	token, err := vendOrganizationAccessToken()
	if err != nil {
		common.Log.Warningf("failed to vend organization access token; %s", err.Error())
		return nil, err
	}

	// deploy
	wallet, err := nchain.CreateWallet(*token, map[string]interface{}{
		"purpose": 44,
	})
	if err != nil {
		common.Log.Warningf("failed to initialize wallet for organization; %s", err.Error())
	} else {
		common.Log.Debugf("created HD wallet for organization: %s", wallet.ID)
	}

	cntrct, err := nchain.CreateContract(*token, map[string]interface{}{
		"address":    "0x",
		"name":       string(name),
		"network_id": common.NChainBaselineNetworkID,
		"params": map[string]interface{}{
			"argv":              []interface{}{},
			"compiled_artifact": artifact,
			"wallet_id":         wallet.ID,
		},
		"type": "verifier",
	})
	if err != nil {
		common.Log.Warningf("failed to deploy contract; %s", err.Error())
		return nil, err
	}

	err = RequireContract(common.StringOrNil(cntrct.ID.String()), common.StringOrNil("verifier"), token, true)
	if err != nil {
		common.Log.Warningf("failed to deploy contract; %s", err.Error())
		return nil, err
	}

	return cntrct, nil
}

func RequireContract(contractID, contractType, token *string, printCreationTxLink bool) error {
	startTime := time.Now()
	timer := time.NewTicker(requireContractTickerInterval)

	printed := false

	for {
		select {
		case <-timer.C:
			var contract *nchain.Contract
			var err error
			if contractID != nil {
				contract, err = nchain.GetContractDetails(*token, *contractID, map[string]interface{}{})
			} else if contractType != nil {
				contracts, _ := nchain.ListContracts(*token, map[string]interface{}{
					"type": contractType,
				})
				if len(contracts) > 0 {
					contract = contracts[0]
				}
			}

			if err == nil && contract != nil {
				if !printed && printCreationTxLink {
					tx, _ := nchain.GetTransactionDetails(*token, contract.TransactionID.String(), map[string]interface{}{})
					etherscanBaseURL := etherscanBaseURL(tx.NetworkID.String())
					if etherscanBaseURL != nil {
						common.Log.Debugf("View on Etherscan: %s/tx/%s", *etherscanBaseURL, *tx.Hash) // HACK
					}
					printed = true
				}

				if contract.Address != nil && *contract.Address != "0x" {
					tx, _ := nchain.GetTransactionDetails(*token, contract.TransactionID.String(), map[string]interface{}{})
					txraw, _ := json.MarshalIndent(tx, "", "  ")
					common.Log.Debugf(string(txraw))
					return nil
				}
			}
		default:
			if startTime.Add(requireContractTimeout).Before(time.Now()) {
				common.Log.Warning("workgroup contract deployment timed out")
				return errors.New("workgroup contract deployment timed out")
			} else {
				time.Sleep(requireContractSleepInterval)
			}
		}
	}
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

func LookupBaselineWorkflowByBaselineID(baselineID string) *Workflow {
	key := fmt.Sprintf("baseline.id.%s.workflow.identifier", baselineID)
	identifier, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline workflow identifier for baseline id: %s; %s", key, err.Error())
		return nil
	}

	return LookupBaselineWorkflow(*identifier)
}

func etherscanBaseURL(networkID string) *string {
	switch networkID {
	case "deca2436-21ba-4ff5-b225-ad1b0b2f5c59":
		return common.StringOrNil("https://etherscan.io")
	case "07102258-5e49-480e-86af-6d0c3260827d":
		return common.StringOrNil("https://rinkeby.etherscan.io")
	case "66d44f30-9092-4182-a3c4-bc02736d6ae5":
		return common.StringOrNil("https://ropsten.etherscan.io")
	case "8d31bf48-df6b-4a71-9d7c-3cb291111e27":
		return common.StringOrNil("https://kovan.etherscan.io")
	case "1b16996e-3595-4985-816c-043345d22f8c":
		return common.StringOrNil("https://goerli.etherscan.io")
	default:
		return nil
	}
}
