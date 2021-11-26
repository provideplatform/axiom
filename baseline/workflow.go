package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	dbconf "github.com/kthomas/go-db-config"
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
	Name         *string        `json:"name"`
	Participants []*Participant `gorm:"many2many:workflows_participants" json:"participants"`
	WorkgroupID  *uuid.UUID     `json:"workgroup_id"`
	WorkflowID   *uuid.UUID     `json:"workflow_id"` // when nil, indicates the workflow is a prototype (not an instance)
	Worksteps    []*Workstep    `gorm:"many2many:workflows_worksteps" json:"worksteps,omitempty"`
}

// WorkflowInstance is a baseline workflow instance
type WorkflowInstance struct {
	baseline.WorkflowInstance
	Worksteps []*baseline.WorkstepInstance `gorm:"many2many:workflowinstances_worksteps" json:"worksteps,omitempty"`
}

func (f *WorkflowInstance) TableName() string {
	return "workflows"
}

// FindWorkflowByID retrieves a workflow instance for the given id
func FindWorkflowByID(id uuid.UUID) *Workflow {
	db := dbconf.DatabaseConnection()
	workflow := &Workflow{}
	db.Where("id = ?", id.String()).Find(&id)
	if workflow == nil || workflow.ID == uuid.Nil {
		return nil
	}
	return workflow
}

// FindWorkflowInstanceByID retrieves a workflow instance for the given id
func FindWorkflowInstanceByID(id uuid.UUID) *WorkflowInstance {
	db := dbconf.DatabaseConnection()
	instance := &WorkflowInstance{}
	db.Where("id = ? AND workflow_id IS NOT NULL", id.String()).Find(&id)
	if instance == nil || instance.ID == uuid.Nil {
		return nil
	}
	return instance
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

func (w *Workflow) isPrototype() bool {
	return w.WorkflowID != nil
}

func (w *Workflow) Create() bool {
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
