package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/compiler"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline-proxy/common"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
)

const workstepCircuitStatusProvisioned = "provisioned"

// Cache a workstep instance
func (w *Workstep) Cache() error {
	if w.ID == nil {
		return errors.New("failed to cache workstep with nil identifier")
	}

	key := fmt.Sprintf("baseline.workstep.%s", *w.ID)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(w)
		return redisutil.Set(key, raw, nil)
	})
}

func baselineWorkstepFactory(identifier *string, workflowID *string, circuit *privacy.Circuit) *Workstep {
	var identifierUUID uuid.UUID
	if identifier != nil {
		identifierUUID, _ = uuid.FromString(*identifier)
	} else {
		identifierUUID, _ = uuid.NewV4()
	}

	var workflowUUID uuid.UUID
	if workflowID != nil {
		workflowUUID, _ = uuid.FromString(*workflowID)
	}

	workstep := &Workstep{
		ID:           &identifierUUID,
		Circuit:      circuit,
		Participants: make([]*Participant, 0),
		WorkflowID:   &workflowUUID,
	}

	return workstep
}

// FIXME -- refactor to func (w *Workstep) requireCircuit(token *string, workflow *Workflow) error
func requireCircuits(token *string, workflow *Workflow) error {
	wg := &sync.WaitGroup{}

	startTime := time.Now()
	timer := time.NewTicker(requireCircuitTickerInterval)
	defer timer.Stop()

	circuits := make([]bool, len(workflow.Worksteps))
	wg.Add(len(workflow.Worksteps))

	go func() {
		for {
			select {
			case <-timer.C:
				for i, workstep := range workflow.Worksteps {
					if !circuits[i] {
						circuit, err := privacy.GetCircuitDetails(*token, workstep.Circuit.ID.String())
						if err != nil {
							common.Log.Debugf("failed to fetch circuit details; %s", err.Error())
							break
						}
						if circuit.Status != nil && *circuit.Status == workstepCircuitStatusProvisioned {
							common.Log.Debugf("provisioned workflow circuit: %s", circuit.ID)
							if circuit.VerifierContract != nil {
								if source, sourceOk := circuit.VerifierContract["source"].(string); sourceOk {
									// contractRaw, _ := json.MarshalIndent(source, "", "  ")
									src := strings.TrimSpace(strings.ReplaceAll(source, "\\n", "\n"))
									common.Log.Debugf("verifier contract: %s", src)
									contractName := fmt.Sprintf("%s Verifier", *circuit.Name)
									DeployContract([]byte(contractName), []byte(src))
								}
							}

							workflow.Worksteps[i].Circuit = circuit
							workflow.Worksteps[i].CircuitID = &circuit.ID
							circuits[i] = true

							wg.Done()
							break
						}
					}
				}
			default:
				if startTime.Add(requireCircuitTimeout).Before(time.Now()) {
					msg := fmt.Sprintf("failed to provision %d workstep circuit(s)", len(workflow.Worksteps))
					common.Log.Warning(msg)

					wg.Done()
					break
				} else {
					time.Sleep(requireCircuitSleepInterval)
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// LookupBaselineWorkstep by id
func LookupBaselineWorkstep(identifier string) *Workstep {
	var workstep *Workstep

	key := fmt.Sprintf("baseline.workstep.%s", identifier)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Warningf("failed to retrieve cached baseline workstep: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &workstep)
	return workstep
}

// DeployContract compiles and deploys a raw solidity smart contract
// FIXME -- this presence of this as a dependency here should cause
// a check to happen during boot that ensures `which solc` resolves...
func DeployContract(name, raw []byte) (*nchain.Contract, error) {
	artifact, err := compiler.CompileSolidityString("solc", string(raw)) // FIXME... parse pragma?
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
