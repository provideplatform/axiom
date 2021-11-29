package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/compiler"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
)

const workstepCircuitStatusProvisioned = "provisioned"

const workstepStatusDraft = "draft"
const workstepStatusDeployed = "deployed"
const workstepStatusDeprecated = "deprecated"

// workstep instance statuses
// FIXME? add 'pending'
const workstepStatusInit = "init"
const workstepStatusRunning = "running"
const workstepStatusCompleted = "completed"
const workstepStatusCanceled = "canceled"
const workstepStatusFailed = "failed"

// Workstep is a baseline workstep prototype
type Workstep struct {
	baseline.Workstep
	Participants []*Participant `gorm:"many2many:worksteps_participants" json:"participants,omitempty"`
	WorkstepID   *uuid.UUID     `json:"workstep_id"` // when nil, indicates the workstep is a prototype (not an instance)
}

// WorkstepInstance is a baseline workstep instance
type WorkstepInstance struct {
	baseline.WorkstepInstance
}

func (f *WorkstepInstance) TableName() string {
	return "worksteps"
}

// FindWorkstepByID retrieves a workstep for the given id
func FindWorkstepByID(id uuid.UUID) *Workstep {
	db := dbconf.DatabaseConnection()
	workstep := &Workstep{}
	db.Where("id = ?", id.String()).Find(&workstep)
	if workstep == nil || workstep.ID == uuid.Nil {
		return nil
	}
	return workstep
}

// FindWorkstepsByWorkflowID retrieves a list of worksteps for the given workflow id
func FindWorkstepsByWorkflowID(id uuid.UUID) []*Workstep {
	worksteps := make([]*Workstep, 0)
	db := dbconf.DatabaseConnection()
	db.Where("workflow_id = ?", id.String()).Find(&worksteps)
	return worksteps
}

// FindWorkstepInstanceByID retrieves a workflow instance for the given id
func FindWorkstepInstanceByID(id uuid.UUID) *WorkstepInstance {
	db := dbconf.DatabaseConnection()
	instance := &WorkstepInstance{}
	db.Where("id = ? AND workstep_id IS NOT NULL", id.String()).Find(&instance)
	if instance == nil || instance.ID == uuid.Nil {
		return nil
	}
	return instance
}

// Cache a workstep instance
func (w *Workstep) Cache() error {
	if w.ID == uuid.Nil {
		return errors.New("failed to cache workstep with nil identifier")
	}

	key := fmt.Sprintf("baseline.workstep.%s", w.ID)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(w)
		return redisutil.Set(key, raw, nil)
	})
}

func baselineWorkstepFactory(identifier *string, workflowID *string, circuit *privacy.Circuit) *baseline.WorkstepInstance {
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

	workstep := &baseline.WorkstepInstance{
		baseline.Workstep{
			Prover:       circuit,
			ProverID:     &circuit.ID,
			Participants: make([]*baseline.Participant, 0), // FIXME
			WorkflowID:   &workflowUUID,
		},
		nil,
	}

	workstep.ID = identifierUUID
	return workstep
}

// FIXME -- refactor to func (w *Workstep) requireCircuit(token *string, workflow *Workflow) error
func requireCircuits(token *string, workflow *WorkflowInstance) error {
	startTime := time.Now()
	timer := time.NewTicker(requireCircuitTickerInterval)
	defer timer.Stop()

	circuits := make([]bool, len(workflow.Worksteps))

	for {
		select {
		case <-timer.C:
			for i, workstep := range workflow.Worksteps {
				if !circuits[i] {
					circuit, err := privacy.GetCircuitDetails(*token, workstep.Prover.ID.String())
					if err != nil {
						common.Log.Warningf("failed to fetch circuit details; %s", err.Error())
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

						workflow.Worksteps[i].Prover = circuit
						workflow.Worksteps[i].ProverID = &circuit.ID
						circuits[i] = true
					}
				}
			}

			x := 0
			for i := range workflow.Worksteps {
				if circuits[i] {
					x++
				}
			}
			if x == len(circuits) {
				return nil
			}
		default:
			if startTime.Add(requireCircuitTimeout).Before(time.Now()) {
				msg := fmt.Sprintf("failed to provision %d workstep circuit(s)", len(workflow.Worksteps))
				common.Log.Errorf(msg)
				return errors.New(msg)
			} else {
				time.Sleep(requireCircuitSleepInterval)
			}
		}
	}
}

// LookupBaselineWorkstep by id
func LookupBaselineWorkstep(identifier string) *baseline.WorkstepInstance {
	var workstep *baseline.WorkstepInstance

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
	rawSoliditySource := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(raw), "^0.5.0", "^0.7.3"), "view", ""), "gas,", "gas(),"), "uint256[0]", "uint256[]") // HACK...
	artifact, err := compiler.CompileSolidityString("solc", rawSoliditySource)                                                                                                                    // FIXME... parse pragma?
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

func (w *Workstep) isPrototype() bool {
	return w.WorkstepID == nil
}

// Update the workstep
func (w *Workstep) Update(other *Workstep) bool {
	if !w.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	workflow := FindWorkflowByID(*w.WorkflowID)
	worksteps := FindWorkstepsByWorkflowID(*w.WorkflowID)

	if workflow.isPrototype() {
		if workflow.Status != nil && *workflow.Status != workflowStatusDraft {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; referenced workflow is not in a mutable state"),
			})
			return false
		}

		if *w.Status == workstepStatusDeployed && other.Status != nil && *other.Status != *w.Status && *w.Status != workstepStatusDeprecated {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition"),
			})
			return false
		} else if *w.Status == workflowStatusDeprecated && other.Status != nil && *w.Status != *other.Status {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; cannot modify status of deprecated workstep"),
			})
			return false
		}

		if other.Cardinality > len(worksteps) {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("cardinality out of bounds"),
			})
		}

		if other.Cardinality != 0 && w.Cardinality != other.Cardinality {
			worksteps := FindWorkstepsByWorkflowID(*w.WorkflowID)

			for i, workstep := range worksteps {
				if w.Cardinality > other.Cardinality {
					// adjust all cardinalities - 1
					if i < other.Cardinality-1 {
						workstep.Cardinality--
						tx.Save(&workstep)
					}
				} else if w.Cardinality < other.Cardinality {
					// adjust all cardinalities + 1
					if i > other.Cardinality-1 {
						workstep.Cardinality++
						tx.Save(&workstep)
					}
				}
			}
		}

		// modify the cardinality
		w.Cardinality = other.Cardinality
	} else if other.Cardinality != 0 && w.Cardinality != other.Cardinality {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot modify instantiated workstep cardinality"),
		})
		return false
	}

	// modify the status
	w.Status = other.Status

	result := tx.Save(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := rowsAffected >= 1 && len(errors) == 0
	if success {
		tx.Commit()
	}
	return success
}

func (w *Workstep) Create() bool {
	if !w.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()

	success := false
	if db.NewRecord(w) {
		result := db.Create(&w)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !db.NewRecord(w) {
			success = rowsAffected > 0
		}
	}

	return success
}

func (w *Workstep) Validate() bool {
	if w.ID == uuid.Nil && w.Status == nil {
		if w.WorkstepID == nil {
			w.Status = common.StringOrNil("draft")
		} else {
			w.Status = common.StringOrNil("init")
		}
	}

	workflow := FindWorkflowByID(*w.WorkflowID)
	worksteps := FindWorkstepsByWorkflowID(*w.WorkflowID)

	if w.Cardinality == 0 {
		if workflow.isPrototype() {
			w.Cardinality = len(worksteps) + 1
		}
	} else if w.Cardinality > len(worksteps) {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cardinality out of bounds"),
		})
	}

	if w.Status == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("status is required"),
		})
	}

	if w.WorkflowID == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("workflow reference is required"),
		})
	}

	if *w.Status != workstepStatusDraft &&
		*w.Status != workstepStatusDeployed &&
		*w.Status != workstepStatusDeprecated &&
		*w.Status != workstepStatusInit &&
		*w.Status != workstepStatusRunning &&
		*w.Status != workstepStatusCompleted &&
		*w.Status != workstepStatusCanceled &&
		*w.Status != workstepStatusFailed {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("invalid status: %s", *w.Status)),
		})
	}

	// switch *w.Status {
	// 	case workflowStatusDraft:
	// 	case workflowStatusDeployed:
	// 	case workflowStatusDeprecated:
	// 	case workflowStatusInit:
	// 	case workflowStatusRunning:
	// 	case workflowStatusCompleted:
	// 	case workflowStatusCanceled:
	// 	case workflowStatusFailed:
	// 	default:
	// 		// no-op
	// }

	return len(w.Errors) == 0
}
