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

package baseline

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	gnarkhash "github.com/consensys/gnark-crypto/hash"

	"github.com/ethereum/go-ethereum/common/compiler"
	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	natsutil "github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/nchain"
	"github.com/provideplatform/provide-go/api/privacy"
	"github.com/provideplatform/provide-go/api/vault"
)

const workstepCircuitStatusProvisioned = "provisioned"
const vaultSecretTypeWorkstepExecution = "workstep_participant_execution"

const workstepStatusDraft = "draft"
const workstepStatusDeployed = "deployed"
const workstepStatusDeprecated = "deprecated"
const workstepStatusPendingDeployment = "pending_deployment"

// workstep instance statuses
// FIXME? add 'pending'
const workstepStatusInit = "init"
const workstepStatusExecuting = "executing"
const workstepStatusCompleted = "completed"
const workstepStatusCanceled = "canceled"
const workstepStatusFailed = "failed"

// Workstep is a baseline workstep prototype
type Workstep struct {
	provide.Model
	Name            *string          `json:"name"`
	Cardinality     int              `json:"cardinality"`
	DeployedAt      *time.Time       `json:"deployed_at"`
	Metadata        *json.RawMessage `sql:"type:json not null" json:"metadata,omitempty"`
	Prover          *privacy.Prover  `json:"prover,omitempty"`
	ProverID        *uuid.UUID       `json:"prover_id"`
	Participants    []*Participant   `sql:"-" json:"participants,omitempty"`
	RequireFinality bool             `json:"require_finality"`
	Shield          *string          `json:"shield,omitempty"`
	Status          *string          `json:"status"`
	WorkflowID      *uuid.UUID       `json:"workflow_id,omitempty"`

	Description *string    `json:"description"`
	WorkstepID  *uuid.UUID `json:"workstep_id"` // when nil, indicates the workstep is a prototype (not an instance)

	userInputCardinality bool `json:"-"`
}

// WorkstepInstance is a baseline workstep instance
type WorkstepInstance struct {
	Workstep
	WorkstepID *uuid.UUID `json:"workstep_id,omitempty"` // references the workstep prototype identifier
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
func FindWorkstepsByWorkflowID(workflowID uuid.UUID) []*Workstep {
	worksteps := make([]*Workstep, 0)
	db := dbconf.DatabaseConnection()
	db.Where("workflow_id = ?", workflowID.String()).Order("cardinality ASC").Find(&worksteps)
	return worksteps
}

// FindWorkstepInstanceByID retrieves a workstep instance for the given id
func FindWorkstepInstanceByID(id uuid.UUID) *WorkstepInstance {
	db := dbconf.DatabaseConnection()
	instance := &WorkstepInstance{}
	db.Where("id = ? AND workstep_id IS NOT NULL", id.String()).Find(&instance)
	if instance == nil || instance.ID == uuid.Nil {
		return nil
	}
	return instance
}

// FindWorkstepInstancesByWorkflowID retrieves a list of workstep instances for the given workflow instance id
func FindWorkstepInstancesByWorkflowID(workflowID uuid.UUID) []*WorkstepInstance {
	db := dbconf.DatabaseConnection()
	worksteps := make([]*WorkstepInstance, 0)
	db.Where("workflow_id = ? AND workstep_id IS NOT NULL", workflowID.String()).Order("cardinality ASC").Find(&worksteps)
	return worksteps
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

func baselineWorkstepFactory(identifier *string, workflowID *string, prover *privacy.Prover) *WorkstepInstance {
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

	workstep := &WorkstepInstance{
		Workstep{
			Prover:       prover,
			ProverID:     &prover.ID,
			Participants: make([]*Participant, 0), // FIXME
			WorkflowID:   &workflowUUID,
		},
		nil,
	}

	workstep.ID = identifierUUID
	return workstep
}

// LookupBaselineWorkstep by id
func LookupBaselineWorkstep(identifier string) *WorkstepInstance {
	var workstep *WorkstepInstance

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
	var subjectAccount *SubjectAccount // FIXME!! subject account not resolved here...

	rawSoliditySource := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(string(raw), "^0.5.0", "^0.7.3"), "view", ""), "gas,", "gas(),"), "uint256[0]", "uint256[]") // HACK...
	artifact, err := compiler.CompileSolidityString("solc", rawSoliditySource)                                                                                                                    // FIXME... parse pragma?
	if err != nil {
		common.Log.Warningf("failed to compile solidity contract: %s; %s", name, err.Error())
		return nil, err
	}

	token, err := vendOrganizationAccessToken(subjectAccount)
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
		"network_id": subjectAccount.Metadata.NetworkID,
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

func (w *Workstep) enrich(token string) error {
	if w.ProverID == nil {
		return fmt.Errorf("failed to enrich workstep: %s", w.ID)
	}

	var err error
	w.Prover, err = privacy.GetProverDetails(token, w.ProverID.String())
	if err != nil {
		return err
	}

	return nil
}

func (w *Workstep) deploy(token string, organizationID uuid.UUID) bool {
	if w.Status != nil && *w.Status != workstepStatusDraft {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("cannot deploy workstep with status: %s", *w.Status)),
		})
		return false
	}

	var proverParams map[string]interface{}
	metadata := w.ParseMetadata()
	if params, paramsOk := metadata["prover"].(map[string]interface{}); paramsOk {
		proverParams = params
	}

	if proverParams == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("failed to deploy workstep; no prover specified"),
		})
		return false
	}

	prover, err := privacy.CreateProver(token, proverParams)
	if err != nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to deploy workstep; %s", err.Error())),
		})
		return false
	}

	w.ProverID = &prover.ID
	w.Status = common.StringOrNil(workstepStatusPendingDeployment)

	db := dbconf.DatabaseConnection()
	result := db.Save(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := rowsAffected > 0 && len(errors) == 0
	if success {
		common.Log.Debugf("deployed prover %s for workstep: %s", prover.ID, w.ID)

		params := map[string]interface{}{
			"organization_id": organizationID.String(),
			"workstep_id":     w.ID.String(),
		}
		payload, _ := json.Marshal(params)
		_, err := natsutil.NatsJetstreamPublish("baseline.workstep.deploy.finalize", payload)
		if err != nil {
			common.Log.Warningf("failed to deploy workflow; failed to publish finalize deploy message; %s", err.Error())
			return false
		}
	}

	return prover.ID != uuid.Nil && err == nil
}

func (w *Workstep) execute(
	subjectAccount *SubjectAccount,
	token string,
	payload *ProtocolMessagePayload,
) (*privacy.ProveResponse, error) {
	if w.isPrototype() {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot execute workstep prototype"),
		})
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	if w.Status != nil && *w.Status != workstepStatusInit && *w.Status != workstepStatusExecuting {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("cannot execute workstep with status: %s", *w.Status)),
		})
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	if w.ProverID == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot execute workstep without prover id"),
		})
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	var params map[string]interface{}
	raw, _ := json.Marshal(payload.Object)
	json.Unmarshal(raw, &params) // HACK

	db := dbconf.DatabaseConnection()
	constraints := w.listConstraints(db)
	executionRequirements := make([]*Constraint, 0)
	finalityRequirements := make([]*Constraint, 0)

	for _, constraint := range constraints {
		if constraint.ExecutionRequirement {
			executionRequirements = append(executionRequirements, constraint)
		}

		if constraint.FinalityRequirement {
			finalityRequirements = append(finalityRequirements, constraint)
		}
	}

	failedExecutionRequirements := make([]*Constraint, 0)
	failedFinalityRequirements := make([]*Constraint, 0)

	for _, constraint := range executionRequirements {
		err := constraint.evaluate(params)
		if err != nil {
			failedExecutionRequirements = append(failedExecutionRequirements, constraint)
		}
	}

	for _, constraint := range finalityRequirements {
		err := constraint.evaluate(params)
		if err != nil {
			failedFinalityRequirements = append(failedFinalityRequirements, constraint)
		}
	}

	execute := len(executionRequirements) == 0 || len(failedExecutionRequirements) == 0
	finality := len(finalityRequirements) == 0 || len(failedFinalityRequirements) == 0

	if !execute {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("execution failed due to %d constraint violation(s) on workstep: %s", len(failedExecutionRequirements), w.ID)),
		})
		// TODO-- add specific constraint failures to the errors list
		// for _, failedRequirement := range failedExecutionRequirements {
		// 	w.Errors = append(w.Errors, &provide.Error{
		// 		Message: common.StringOrNil(),
		// 	})
		// }
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	hash := gnarkhash.MIMC_BLS12_377.New()
	var i big.Int

	hash.Write(raw)
	preImage := hash.Sum(nil)
	preImageStr := i.SetBytes(preImage).String()

	_hash := gnarkhash.MIMC_BLS12_377.New()
	_hash.Write(preImage)
	hashStr := i.SetBytes(_hash.Sum(nil)).String()

	proof, err := privacy.Prove(token, w.ProverID.String(), map[string]interface{}{
		"witness": map[string]interface{}{
			"Preimage": preImageStr,
			"Hash":     hashStr,
		},
	})
	if err != nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to execute workstep; %s", err.Error())),
		})
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	if len(proof.Errors) > 0 || proof.Proof == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to execute workstep; %s", err.Error())),
		})
		return nil, fmt.Errorf(*w.Errors[0].Message)
	}

	workflow := FindWorkflowByID(*w.WorkflowID)
	workflowStatusChanged := false

	if workflow.Status == nil || *workflow.Status == workflowStatusInit {
		workflow.Status = common.StringOrNil(workflowStatusRunning)
		workflowStatusChanged = true
	}

	w.Status = common.StringOrNil(workstepStatusExecuting)
	// metadata := w.ParseMetadata()

	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

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
	success := rowsAffected > 0 && len(errors) == 0
	if success {
		common.Log.Debugf("executed workstep %s; proof: %s", w.ID, *proof.Proof)
		w.setParticipantExecutionPayload(token, subjectAccount, proof, payload, db)
		// FIXME-- this is just inserting executions for the participant running this baseline stack instance...
		// we need to also make sure the other witnesses are inserted upon processing by way of baseline inbound...

		pc := 0
		participants := w.listParticipants(db)
		for _, p := range participants {
			if p.Proof != nil {
				pc += 1
			}
		}
		if pc == len(participants) {
			if execute && !finality {
				common.Log.Debugf("workstep execution: %s", w.ID)
				w.Status = common.StringOrNil(workstepStatusExecuting)
			} else if finality {
				common.Log.Debugf("workstep execution completed: %s", w.ID)
				w.Status = common.StringOrNil(workstepStatusCompleted)
			}

			tx.Save(&w)
		}

		if *workflow.Status == workflowStatusRunning && w.Cardinality == workflow.WorkstepsCount {
			workflow.Status = common.StringOrNil(workflowStatusCompleted)
			workflowStatusChanged = true
		}

		if workflowStatusChanged {
			tx.Save(&workflow)
		}

		tx.Commit()

		func() {
			// TODO-- refactor the following into its own method
			for _, participant := range participants {
				// TODO-- workflow.sync()

				if strings.EqualFold(*participant.Participant, strings.ToLower(*subjectAccount.Metadata.OrganizationAddress)) {
					common.Log.Debugf("skipping no-op protocol message broadcast to self: %s", *participant.Participant)
					continue
				}

				payload, err := json.Marshal(&ProtocolMessage{
					// BaselineID:       ,
					Opcode:    common.StringOrNil(baseline.ProtocolMessageOpcodeBaseline),
					Sender:    subjectAccount.Metadata.OrganizationAddress,
					Recipient: participant.Participant,
					// Signature:        m.Signature,
					Payload:          payload,
					SubjectAccountID: subjectAccount.ID,
					WorkflowID:       w.WorkflowID,
					WorkgroupID:      workflow.WorkgroupID,
					WorkstepID:       &w.ID,
				})

				if err != nil {
					common.Log.Warningf("failed to broadcast %d-byte protocol message; %s", len(payload), err.Error())
				}

				common.Log.Debugf("attempting to broadcast %d-byte protocol message", len(payload))
				_, err = natsutil.NatsJetstreamPublish(natsDispatchProtocolMessageSubject, payload)
				if err != nil {
					common.Log.Warningf("failed to broadcast %d-byte protocol message; %s", len(payload), err.Error())
				}

			}
		}()
	}

	return proof, nil
}

func (w *Workstep) finalizeDeploy(token string) bool {
	if w.Status != nil && *w.Status != workstepStatusPendingDeployment {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("cannot finalize workstep deployment with status: %s", *w.Status)),
		})
		return false
	}

	if w.ProverID == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot finalize workstep deployment without prover id"),
		})
		return false
	}

	prover, err := privacy.GetProverDetails(token, w.ProverID.String())
	if err != nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to finalize workstep deployment; %s", err.Error())),
		})
		return false
	}

	if prover.Status != nil && *prover.Status != "provisioned" {
		common.Log.Debugf("deployment still pending for workstep: %s", w.ID)
		return false
	}

	deployedAt := time.Now()
	w.DeployedAt = &deployedAt
	w.Status = common.StringOrNil(workstepStatusDeployed)

	db := dbconf.DatabaseConnection()
	result := db.Save(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	success := rowsAffected > 0 && len(errors) == 0
	if success {
		common.Log.Debugf("deployed prover %s for workstep: %s", prover.ID, w.ID)
	}

	return success
}

func (w *Workstep) isPrototype() bool {
	return w.WorkstepID == nil
}

func (w *Workstep) participantsCount(tx *gorm.DB) int {
	rows, err := tx.Raw("SELECT count(*) FROM worksteps_participants WHERE worksteps_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to read worksteps participants count; %s", err.Error())
		return 0
	}

	var len int
	for rows.Next() {
		err = rows.Scan(&len)
		if err != nil {
			common.Log.Warningf("failed to read worksteps participants count; %s", err.Error())
			return 0
		}
	}

	return len
}

func (w *Workstep) listConstraints(tx *gorm.DB) []*Constraint {
	return FindConstraintsByWorkstepID(w.ID)
}

func (w *Workstep) listParticipants(tx *gorm.DB) []*WorkstepParticipant {
	participants := make([]*WorkstepParticipant, 0)
	rows, err := tx.Raw("SELECT * FROM worksteps_participants WHERE workstep_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to list workstep participants; %s", err.Error())
		return participants
	}

	for rows.Next() {
		p := &WorkstepParticipant{}
		err = tx.ScanRows(rows, &p)
		if err != nil {
			common.Log.Warningf("failed to list workstep participants; %s", err.Error())
			return participants
		}
		participants = append(participants, p)
	}

	return participants
}

func (w *Workstep) setParticipantExecutionPayload(
	token string,
	subjectAccount *SubjectAccount,
	proof *privacy.ProveResponse,
	payload *ProtocolMessagePayload,
	tx *gorm.DB,
) error {
	address := *subjectAccount.Metadata.OrganizationAddress

	participating := false
	for _, p := range w.listParticipants(tx) {
		if p.Participant != nil && strings.EqualFold(strings.ToLower(*p.Participant), strings.ToLower(address)) {
			participating = true
		}
	}

	if !participating {
		err := fmt.Errorf("failed to set workstep execution proof and witness data for participant: %s; invalid participant", address)
		common.Log.Warningf(err.Error())
		return err
	}

	rawWitness, _ := json.Marshal(payload.Witness)
	secret, err := vault.CreateSecret(
		token,
		subjectAccount.VaultID.String(),
		map[string]interface{}{
			"description": fmt.Sprintf("baseline workstep execution by participant %s", address),
			"name":        fmt.Sprintf("baseline.workstep.%s.participant.%s.execution", w.ID, address),
			"type":        vaultSecretTypeWorkstepExecution,
			"value":       hex.EncodeToString(rawWitness),
		},
	)
	if err != nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("failed to deploy workstep; %s", err.Error())),
		})
		return nil
	}

	witnessedAt := time.Now()
	result := tx.Exec("UPDATE worksteps_participants SET proof=?, witness_secret_id=?, witnessed_at=? WHERE workstep_id=? AND participant=?", *proof.Proof, secret.ID, witnessedAt, w.ID, address)
	success := result.RowsAffected == 1
	if !success {
		err := fmt.Errorf("failed to set workstep execution proof and witness data for participant: %s", address)
		common.Log.Warningf(err.Error())
		return err
	}

	common.Log.Debugf("set workstep execution proof and witness data for participant: %s", address)
	return nil
}

func (w *Workstep) addParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("adding participant %s to workstep: %s", participant, w.ID)
	result := tx.Exec("INSERT INTO worksteps_participants (workstep_id, participant) VALUES (?, ?)", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added participant %s from workstep: %s", participant, w.ID)
	} else {
		common.Log.Tracef("participant %s not added to workstep: %s", participant, w.ID)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}

	return len(w.Errors) == 0
}

func (w *Workstep) hasParticipant(address string, tx *gorm.DB) bool {
	for _, p := range w.listParticipants(tx) {
		if p.Participant != nil && *p.Participant == address {
			return true
		}
	}

	return false
}

func (w *Workstep) removeParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("removing participant %s to workstep: %s", participant, w.ID)
	result := tx.Exec("DELETE FROM worksteps_participants WHERE workstep_id=? AND participant=?", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed participant %s from workstep: %s", participant, w.ID)
	} else {
		common.Log.Tracef("participant %s not removed from workstep: %s", participant, w.ID)
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
	}

	return len(w.Errors) == 0
}

// Update the workstep
func (w *Workstep) Update(other *Workstep) bool {
	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	workflow := FindWorkflowByID(*w.WorkflowID)
	worksteps := FindWorkstepsByWorkflowID(*w.WorkflowID)
	adjustsCardinality := false
	previousCardinality := w.Cardinality
	newCardinality := other.Cardinality

	if !workflow.isPrototype() {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("invalid state transition; referenced workflow is not mutable"),
		})
		return false
	}

	if workflow.isPrototype() {
		if workflow.Status != nil && *workflow.Status != workflowStatusDraft && other.Status != nil && *other.Status != *w.Status {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; referenced workflow is not in a mutable state"),
			})
			return false
		} else if *w.Status == workstepStatusDeployed && other.Status != nil && *other.Status != *w.Status && *other.Status != workstepStatusDeprecated {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition"),
			})
			return false
		} else if *w.Status == workstepStatusDeprecated && other.Status != nil && *w.Status != *other.Status {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; cannot modify status of deprecated workstep"),
			})
			return false
		} else if *w.Status != workstepStatusDraft {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; referenced workstep is not mutable"),
			})
			return false
		}

		if newCardinality > len(worksteps) || (newCardinality < 1 && other.userInputCardinality) {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("cardinality out of bounds"),
			})
		}

		common.Log.Tracef("updating workstep id: %s; previous cardinality: %d; new cardinality: %d", w.ID, previousCardinality, newCardinality)

		if newCardinality != 0 && w.Cardinality != newCardinality {
			adjustsCardinality = true
			for i, workstep := range worksteps {
				if previousCardinality > newCardinality {
					// cardinality moved left... adjust all affectedcardinalities + 1
					if i >= newCardinality-1 && i < previousCardinality-1 {
						workstep.Cardinality++
						common.Log.Tracef("updating workstep id: %s; new cardinality %d (right to left)", workstep.ID, workstep.Cardinality)
						workstep.Cardinality *= -1
						tx.Save(&workstep)
					}
				} else if previousCardinality < newCardinality {
					// cardinality moved right... adjust all affected cardinalities - 1
					if i > previousCardinality-1 && i <= newCardinality-1 {
						workstep.Cardinality--
						common.Log.Tracef("updating workstep id: %s; new cardinality %d (left to right)", workstep.ID, workstep.Cardinality)
						workstep.Cardinality *= -1
						tx.Save(&workstep)
					}
				}
			}

			// modify the cardinality
			w.Cardinality = newCardinality
		}
	} else if newCardinality != 0 && previousCardinality != newCardinality {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot modify instantiated workstep cardinality"),
		})
		return false
	}

	if len(w.Errors) > 0 {
		return false
	}

	// modify the status
	w.Name = other.Name
	w.Description = other.Description
	w.RequireFinality = other.RequireFinality
	w.Status = other.Status
	w.Metadata = other.Metadata

	if !w.Validate(tx) {
		return false
	}

	result := tx.Save(&w)

	if adjustsCardinality {
		for i, workstep := range worksteps {
			if previousCardinality > newCardinality {
				// cardinality moved left... adjust all affectedcardinalities + 1
				if i >= newCardinality-1 && i < previousCardinality-1 {
					common.Log.Tracef("updating workstep id: %s; new cardinality ABS(%d)", workstep.ID, workstep.Cardinality)
					workstep.Cardinality *= -1
					tx.Save(&workstep)
				}
			} else if previousCardinality < newCardinality {
				// cardinality moved right... adjust all affected cardinalities - 1
				if i > previousCardinality-1 && i <= newCardinality-1 {
					common.Log.Tracef("updating workstep id: %s; new cardinality ABS(%d)", workstep.ID, workstep.Cardinality)
					workstep.Cardinality *= -1
					tx.Save(&workstep)
				}
			}
		}
	}

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
		updatedAt := time.Now()
		workflow.UpdatedAt = &updatedAt
		tx.Save(&workflow)
		tx.Commit()
	}
	return success
}

func (w *Workstep) Create(tx *gorm.DB) bool {
	_tx := tx
	if _tx == nil {
		db := dbconf.DatabaseConnection()
		_tx = db.Begin()
		defer _tx.RollbackUnlessCommitted()
	}

	if !w.Validate(_tx) {
		return false
	}

	success := false
	if _tx.NewRecord(w) {
		result := _tx.Create(&w)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				w.Errors = append(w.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}
		if !_tx.NewRecord(w) {
			success = rowsAffected > 0
		}
	}

	if success {
		workflow := FindWorkflowByID(*w.WorkflowID)
		if w.Participants == nil || len(w.Participants) == 0 {
			participants := workflow.listParticipants(_tx)
			common.Log.Debugf("no participants added to workstep; defaulting to %d workflow participant(s)", len(participants))
			for _, p := range participants {
				w.addParticipant(*p.Participant, _tx)
			}
		}

		updatedAt := time.Now()
		workflow.UpdatedAt = &updatedAt
		workflow.WorkstepsCount = w.Cardinality
		_tx.Save(&workflow)

		_tx.Commit()
	}

	return success
}

func (w *Workstep) Delete() bool {
	if !w.isPrototype() {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot delete workstep instance"),
		})
		return false
	}

	if w.Status != nil && *w.Status != workstepStatusDraft {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("non-draft workstep cannot be deleted"),
		})
		return false
	}

	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	result := tx.Delete(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	success := rowsAffected > 0
	if success {
		x := w.Cardinality
		for _, workstep := range FindWorkstepsByWorkflowID(*w.WorkflowID) {
			if workstep.Cardinality > x {
				workstep.Cardinality--
				tx.Save(&workstep)
			}
		}

		updatedAt := time.Now()
		workflow := FindWorkflowByID(*w.WorkflowID)
		workflow.WorkstepsCount = workflow.WorkstepsCount - 1
		workflow.UpdatedAt = &updatedAt
		tx.Save(&workflow)
	}

	tx.Commit()
	return success
}

// ParseMetadata parse the metadeta
func (w *Workstep) ParseMetadata() map[string]interface{} {
	metadata := map[string]interface{}{}
	if w.Metadata != nil {
		err := json.Unmarshal(*w.Metadata, &metadata)
		if err != nil {
			common.Log.Warningf("failed to unmarshal workstep metadata; %s", err.Error())
			return nil
		}
	}
	return metadata
}

func (w *Workstep) Validate(tx *gorm.DB) bool {
	if w.ID == uuid.Nil && w.Status == nil {
		if w.WorkstepID == nil {
			w.Status = common.StringOrNil("draft")
		} else {
			w.Status = common.StringOrNil("init")
		}
	}

	workflow := &Workflow{}
	tx.Where("id = ?", w.WorkflowID.String()).Find(&workflow)
	if workflow == nil || workflow.ID == uuid.Nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("invalid workflow"),
		})
		return false
	}

	if workflow == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("invalid workflow"),
		})
		return false
	}

	worksteps := make([]*Workstep, 0)
	tx.Where("workflow_id = ?", workflow.ID.String()).Find(&worksteps)

	if w.Cardinality < 0 {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cardinality out of bounds"),
		})
	} else if w.Cardinality == 0 {
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

	if w.Status == nil ||
		(*w.Status != workstepStatusDraft &&
			*w.Status != workstepStatusDeployed &&
			*w.Status != workstepStatusDeprecated &&
			*w.Status != workstepStatusPendingDeployment &&
			*w.Status != workstepStatusInit &&
			*w.Status != workstepStatusExecuting &&
			*w.Status != workstepStatusCompleted &&
			*w.Status != workstepStatusCanceled &&
			*w.Status != workstepStatusFailed) {
		if w.Status != nil {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(fmt.Sprintf("invalid status: %s", *w.Status)),
			})
		}
	}

	return len(w.Errors) == 0
}
