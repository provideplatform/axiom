package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-natsutil"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
	privacy "github.com/provideplatform/provide-go/api/privacy"
)

const requireContractSleepInterval = time.Second * 1
const requireContractTickerInterval = time.Second * 5
const requireContractTimeout = time.Minute * 10

const requireCircuitTickerInterval = time.Second * 5
const requireCircuitSleepInterval = time.Millisecond * 500
const requireCircuitTimeout = time.Minute * 5

const workflowStatusDraft = "draft"
const workflowStatusDeployed = "deployed"
const workflowStatusPendingDeployment = "pending_deployment"
const workflowStatusDeprecated = "deprecated"

// workflow instance statuses
const workflowStatusInit = "init"
const workflowStatusRunning = "running"
const workflowStatusCompleted = "completed"
const workflowStatusCanceled = "canceled"
const workflowStatusFailed = "failed"

// Workflow is a baseline workflow prototype
type Workflow struct {
	baseline.Workflow
	Name           *string        `json:"name"`
	Description    *string        `json:"description"`
	UpdatedAt      *time.Time     `json:"updated_at"`
	Participants   []*Participant `sql:"-" json:"participants,omitempty"`
	WorkgroupID    *uuid.UUID     `json:"workgroup_id"`
	WorkflowID     *uuid.UUID     `json:"workflow_id"` // when nil, indicates the workflow is a prototype (not an instance)
	Worksteps      []*Workstep    `json:"worksteps,omitempty"`
	WorkstepsCount int            `json:"worksteps_count,omitempty"`
}

// WorkflowInstance is a baseline workflow instance
type WorkflowInstance struct {
	baseline.WorkflowInstance
	Worksteps []*baseline.WorkstepInstance `json:"worksteps,omitempty"`
}

func (f *WorkflowInstance) TableName() string {
	return "workflows"
}

// FindWorkflowByID retrieves a workflow instance for the given id
func FindWorkflowByID(id uuid.UUID) *Workflow {
	db := dbconf.DatabaseConnection()
	workflow := &Workflow{}
	db.Where("id = ?", id.String()).Find(&workflow)
	if workflow == nil || workflow.ID == uuid.Nil {
		return nil
	}
	return workflow
}

// FindWorkflowInstanceByID retrieves a workflow instance for the given id
func FindWorkflowInstanceByID(id uuid.UUID) *WorkflowInstance {
	db := dbconf.DatabaseConnection()
	instance := &WorkflowInstance{}
	db.Where("id = ? AND workflow_id IS NOT NULL", id.String()).Find(&instance)
	if instance == nil || instance.ID == uuid.Nil {
		return nil
	}
	return instance
}

// enrich a workflow
func (w *Workflow) enrich() error {
	// the next line enriching worksteps is not the preferred methods... use workflows/:id/worksteps list endpoint
	// w.Worksteps = FindWorkstepsByWorkflowID(w.ID)
	return nil
}

// Cache a workflow instance
func (w *WorkflowInstance) Cache() error {
	if w.ID == uuid.Nil {
		return errors.New("failed to cache workflow with nil identifier")
	}

	key := fmt.Sprintf("baseline.workflow.%s", w.ID)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(w)
		return redisutil.Set(key, raw, nil)
	})
}

// CacheByBaselineID caches a workflow identifier, indexed by baseline id for convenient lookup
func (w *WorkflowInstance) CacheByBaselineID(baselineID string) error {
	if w.ID == uuid.Nil {
		return errors.New("failed to cache workflow with nil identifier")
	}

	key := fmt.Sprintf("baseline.id.%s.workflow.identifier", baselineID)
	return redisutil.WithRedlock(key, func() error {
		common.Log.Debugf("mapping baseline id to workflow identifier")
		return redisutil.Set(key, w.ID.String(), nil)
	})
}

func baselineWorkflowFactory(objectType string, identifier *string) (*WorkflowInstance, error) {
	var identifierUUID uuid.UUID
	if identifier != nil {
		identifierUUID, _ = uuid.FromString(*identifier)
	} else {
		identifierUUID, _ = uuid.NewV4()
	}

	workflow := &WorkflowInstance{
		baseline.WorkflowInstance{
			Worksteps: make([]*baseline.WorkstepInstance, 0),
		},
		make([]*baseline.WorkstepInstance, 0),
	}
	workflow.ID = identifierUUID

	for _, party := range common.DefaultCounterparties {
		workflow.Participants = append(workflow.Participants, &baseline.Participant{
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
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		workflow.Participants = append(workflow.Participants, &baseline.Participant{
			Address:           common.StringFromInterface(org.Metadata["address"]),
			APIEndpoint:       common.StringFromInterface(org.Metadata["api_endpoint"]),
			MessagingEndpoint: common.StringFromInterface(org.Metadata["messaging_endpoint"]),
		})
	}

	if identifier == nil {
		common.Log.Debugf("deploying workstep circuit(s) for workflow: %s", identifierUUID.String())

		var circuit *privacy.Circuit
		var err error

		switch objectType {
		case baselineWorkflowTypeGeneralConsistency:
			circuit, err = privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"General Consistency",
					"purchase_order",
					nil,
					nil,
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

		case baselineWorkflowTypeProcureToPay:
			circuit, err := privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"PO",
					"purchase_order",
					nil,
					nil,
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

			circuit, err = privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"SO",
					"sales_order",
					common.StringOrNil(circuit.NoteStoreID.String()),
					common.StringOrNil(circuit.NullifierStoreID.String()),
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

			circuit, err = privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"SN",
					"shipment_notification",
					common.StringOrNil(circuit.NoteStoreID.String()),
					common.StringOrNil(circuit.NullifierStoreID.String()),
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

			circuit, err = privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"GR",
					"goods_receipt",
					common.StringOrNil(circuit.NoteStoreID.String()),
					common.StringOrNil(circuit.NullifierStoreID.String()),
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

			circuit, err = privacy.CreateCircuit(
				*token,
				circuitParamsFactory(
					"Invoice",
					"invoice",
					common.StringOrNil(circuit.NoteStoreID.String()),
					common.StringOrNil(circuit.NullifierStoreID.String()),
				),
			)
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

		case baselineWorkflowTypeServiceNowIncident:
			circuit, err = privacy.CreateCircuit(*token, circuitParamsFactory("Incident", "purchase_order", nil, nil))
			if err != nil {
				common.Log.Errorf("failed to deploy circuit; %s", err.Error())
				return nil, err
			}
			workflow.Worksteps = append(workflow.Worksteps, baselineWorkstepFactory(nil, common.StringOrNil(workflow.ID.String()), circuit))

		default:
			return nil, fmt.Errorf("failed to create workflow for type: %s", objectType)
		}

		err = requireCircuits(token, workflow)
		if err != nil {
			common.Log.Errorf("failed to provision circuit(s); %s", err.Error())
			return nil, err
		}
	}

	return workflow, nil
}

func LookupBaselineWorkflow(identifier string) *WorkflowInstance {
	var workflow *WorkflowInstance

	key := fmt.Sprintf("baseline.workflow.%s", identifier)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("no baseline workflow cached for key: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &workflow)
	return workflow
}

func LookupBaselineWorkflowByBaselineID(baselineID string) *WorkflowInstance {
	key := fmt.Sprintf("baseline.id.%s.workflow.identifier", baselineID)
	identifier, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("no baseline workflow identifier cached for key: %s; %s", key, err.Error())
		return nil
	}

	return LookupBaselineWorkflow(*identifier)
}

func circuitParamsFactory(name, identifier string, noteStoreID, nullifierStoreID *string) map[string]interface{} {
	params := map[string]interface{}{
		"curve":          "BN254",
		"identifier":     identifier,
		"name":           name,
		"provider":       "gnark",
		"proving_scheme": "groth16",
	}

	if noteStoreID != nil {
		params["note_store_id"] = noteStoreID
	}

	if nullifierStoreID != nil {
		params["nullifier_store_id"] = nullifierStoreID
	}

	return params
}

// deploy the workflow
func (w *Workflow) deploy() bool {
	if w.Status != nil && *w.Status != workflowStatusDraft {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("cannot deploy workflow with status: %s", *w.Status)),
		})
		return false
	}

	w.Status = common.StringOrNil(workflowStatusPendingDeployment)
	worksteps := FindWorkstepsByWorkflowID(w.ID)

	if len(worksteps) == 0 {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot deploy workflow with zero worksteps"),
		})
		return false
	}

	finalWorkstep := worksteps[len(worksteps)-1]
	if !finalWorkstep.RequireFinality {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot deploy workflow without exit on the final workstep"),
		})
		return false
	}

	for _, workstep := range worksteps {
		params := map[string]interface{}{
			"workstep_id": workstep.ID.String(),
		}
		payload, _ := json.Marshal(params)

		_, err := natsutil.NatsJetstreamPublish("baseline.workstep.deploy", payload)
		if err != nil {
			common.Log.Warningf("failed to deploy workstep; failed to publish deploy message; %s", err.Error())
			return false
		}
	}

	params := map[string]interface{}{
		"workflow_id": w.ID.String(),
	}
	payload, _ := json.Marshal(params)

	_, err := natsutil.NatsJetstreamPublish("baseline.workflow.deploy", payload)
	if err != nil {
		common.Log.Warningf("failed to deploy workflow; failed to publish deploy message; %s", err.Error())
		return false
	}

	return true
}

func (w *Workflow) isPrototype() bool {
	return w.WorkflowID == nil
}

func (w *Workflow) participantsCount(tx *gorm.DB) int {
	rows, err := tx.Raw("SELECT count(*) FROM workflows_participants WHERE workflow_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to read workflow participants count; %s", err.Error())
		return 0
	}

	var len int
	for rows.Next() {
		err = rows.Scan(&len)
		if err != nil {
			common.Log.Warningf("failed to read workflow participants count; %s", err.Error())
			return 0
		}
	}

	return len
}

func (w *Workflow) listParticipants(tx *gorm.DB) []*WorkflowParticipant {
	participants := make([]*WorkflowParticipant, 0)
	rows, err := tx.Raw("SELECT * FROM workflows_participants WHERE workflow_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to list workflow participants; %s", err.Error())
		return participants
	}

	for rows.Next() {
		p := &WorkflowParticipant{}
		err = tx.ScanRows(rows, &p)
		if err != nil {
			common.Log.Warningf("failed to list workflow participants; %s", err.Error())
			return participants
		}
		participants = append(participants, p)
	}

	return participants
}

func (w *Workflow) addParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("adding participant %s to workflow: %s", participant, w.ID)
	result := tx.Exec("INSERT INTO workflows_participants (workflow_id, participant) VALUES (?, ?)", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added participant %s to workflow: %s", participant, w.ID)
	} else {
		common.Log.Warningf("failed to add participant %s to workflow: %s", participant, w.ID)
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

func (w *Workflow) removeParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("removing participant %s to workflow: %s", participant, w.ID)
	result := tx.Exec("DELETE FROM workflows_participants WHERE workflow_id=? AND participant=?", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed participant %s from workflow: %s", participant, w.ID)
	} else {
		common.Log.Warningf("failed to remove participant %s from workflow: %s", participant, w.ID)
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

func (w *Workflow) Create(tx *gorm.DB) bool {
	if !w.Validate() {
		return false
	}

	_tx := tx
	if _tx == nil {
		db := dbconf.DatabaseConnection()
		_tx = db.Begin()
	}
	defer _tx.RollbackUnlessCommitted()

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

			if success {
				if w.Participants == nil || len(w.Participants) == 0 {
					workgroup := FindWorkgroupByID(*w.WorkgroupID)
					participants := workgroup.listParticipants(_tx)
					common.Log.Debugf("no participants added to workflow; defaulting to %d workgroup participant(s)", len(participants))
					for _, p := range participants {
						w.addParticipant(*p.Participant, _tx)
					}
				}
			}

			if success && !w.isPrototype() {
				for _, workstep := range FindWorkstepsByWorkflowID(*w.WorkflowID) {
					raw, _ := json.Marshal(workstep)
					instance := &Workstep{}
					json.Unmarshal(raw, &instance)
					instance.ID = uuid.Nil
					instance.Status = common.StringOrNil(workstepStatusInit)
					instance.WorkflowID = &w.ID
					instance.WorkstepID = &workstep.ID
					_tx.Create(&instance)

					if len(instance.Errors) == 0 {
						common.Log.Debugf("spawned workstep instance %s for workflow: %s; cardinality: %d; workstep prototype: %s", instance.ID, instance.WorkflowID, instance.Cardinality, instance.WorkstepID)
						if instance.Participants == nil || len(instance.Participants) == 0 {
							workstep := FindWorkstepByID(workstep.ID)
							participants := workstep.listParticipants(_tx)
							common.Log.Debugf("no participants added to workstep; defaulting to %d workstep prototype participant(s)", len(participants))
							for _, p := range participants {
								instance.addParticipant(*p.Participant, _tx)
							}
						}
					} else {
						err := fmt.Errorf("failed to spawn workstep instance for workflow: %s; workstep cardinality: %d; %s", w.ID, instance.Cardinality, *instance.Errors[0].Message)
						common.Log.Warningf(err.Error())
						w.Errors = append(w.Errors, &provide.Error{
							Message: common.StringOrNil(err.Error()),
						})
						return false
					}
				}
			}
		}
	}

	if success {
		_tx.Commit()
	}

	return success
}

// Update the workflow
func (w *Workflow) Update(other *Workflow) bool {
	if !w.Validate() {
		return false
	}

	// these validations are for update only...
	if w.isPrototype() {
		if *w.Status == workflowStatusDeployed && other.Status != nil && *other.Status != *w.Status && *other.Status != workflowStatusDeprecated {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition"),
			})
			return false
		} else if *w.Status == workflowStatusPendingDeployment && other.Status != nil && *other.Status != *w.Status && *other.Status != workflowStatusDeployed {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition"),
			})
			return false
		} else if *w.Status == workflowStatusDeprecated && other.Status != nil && *w.Status != *other.Status {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("invalid state transition; cannot modify status of deprecated workflow"),
			})
			return false
		}

		if *w.Status != workflowStatusDeployed && *w.Status != workflowStatusPendingDeployment && *w.Status != workflowStatusDeprecated {
			w.Version = other.Version

			if *w.Status == workflowStatusDraft && other.Status != nil && *other.Status == workflowStatusDeployed {
				if !w.deploy() { // deploy the workflow...
					return false
				}
			}
		}
	}

	if w.Status != nil && *w.Status != workflowStatusPendingDeployment {
		// modify the status
		w.Status = other.Status
	}

	if other.Name != nil {
		w.Name = other.Name
	}

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
	return rowsAffected == 1 && len(errors) == 0
}

func (w *Workflow) Delete() bool {
	if !w.isPrototype() {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("cannot delete workstep instance"),
		})
		return false
	}

	if w.Status != nil && *w.Status != workstepStatusDraft {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("non-draft workflow cannot be deleted"),
		})
		return false
	}

	db := dbconf.DatabaseConnection()
	result := db.Delete(&w)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return rowsAffected > 0
}

// ParseConfig parse the metadeta
func (w *Workflow) ParseMetadata() map[string]interface{} {
	metadata := map[string]interface{}{}
	if w.Metadata != nil {
		err := json.Unmarshal(*w.Metadata, &metadata)
		if err != nil {
			common.Log.Warningf("failed to unmarshal workflow metadata; %s", err.Error())
			return nil
		}
	}
	return metadata
}

func (w *Workflow) Validate() bool {
	if w.ID == uuid.Nil && w.Status == nil {
		if w.WorkflowID == nil {
			w.Status = common.StringOrNil("draft")
		} else {
			w.Status = common.StringOrNil("init")
		}
	}

	if w.Status == nil {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil("status is required"),
		})
	}

	if *w.Status != workflowStatusDraft &&
		*w.Status != workflowStatusDeployed &&
		*w.Status != workflowStatusPendingDeployment &&
		*w.Status != workflowStatusDeprecated &&
		*w.Status != workflowStatusInit &&
		*w.Status != workflowStatusRunning &&
		*w.Status != workflowStatusCompleted &&
		*w.Status != workflowStatusCanceled &&
		*w.Status != workflowStatusFailed {
		w.Errors = append(w.Errors, &provide.Error{
			Message: common.StringOrNil(fmt.Sprintf("invalid status: %s", *w.Status)),
		})
	}

	if !w.isPrototype() {
		proto := FindWorkflowByID(*w.WorkflowID)
		if !proto.isPrototype() {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("ineligible prototype"),
			})
		} else if *proto.Status == workflowStatusDraft {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("attempted to instantiate draft prototype"),
			})
		} else if proto.Version == nil {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("attempted to instantiate unversioned prototype"),
			})
		} else if *proto.Status == workflowStatusDeprecated {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("attempted to instantiate deprecated prototype"),
			})
		} else if *proto.Status != workflowStatusDeployed {
			w.Errors = append(w.Errors, &provide.Error{
				Message: common.StringOrNil("ineligible prototype - this is likely an ephemeral failure; please try again"),
			})
		}
	}

	return len(w.Errors) == 0
}
