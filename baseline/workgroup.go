package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	dbconf "github.com/kthomas/go-db-config"
	"github.com/kthomas/go-redisutil"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/api/baseline"
	"github.com/provideplatform/provide-go/api/ident"
)

const requireCounterpartiesSleepInterval = time.Second * 15
const requireCounterpartiesTickerInterval = time.Second * 30 // HACK

// Workgroup is a baseline workgroup prototype
type Workgroup struct {
	baseline.Workgroup
	Name         *string        `json:"name"`
	Participants []*Participant `gorm:"many2many:workgroups_participants" json:"participants,omitempty"`
	Workflows    []*Workflow    `gorm:"many2many:workgroups_workflows" json:"workflows,omitempty"`
}

// FindWorkgroupByID retrieves a workgroup for the given id
func FindWorkgroupByID(id uuid.UUID) *Workgroup {
	db := dbconf.DatabaseConnection()
	workgroup := &Workgroup{}
	db.Where("id = ?", id.String()).Find(&id)
	if workgroup == nil || workgroup.ID == uuid.Nil {
		return nil
	}
	return workgroup
}

func init() {
	redisutil.RequireRedis()

	common.Log.Debug("attempting to resolve baseline counterparties")
	resolveBaselineCounterparties()

	go func() {
		timer := time.NewTicker(requireCounterpartiesTickerInterval)
		for {
			select {
			case <-timer.C:
				resolveBaselineCounterparties()
			default:
				time.Sleep(requireCounterpartiesSleepInterval)
			}
		}
	}()
}

func resolveBaselineCounterparties() {
	workgroupID, err := uuid.FromString(os.Getenv("BASELINE_WORKGROUP_ID"))
	if err != nil {
		common.Log.Panicf("failed to read BASELINE_WORKGROUP_ID from environment; %s", err.Error())
	}

	workgroup := FindWorkgroupByID(workgroupID)
	if workgroup == nil {
		common.Log.Debugf("persisting workgroup: %s", workgroupID)
		workgroup = &Workgroup{}
		workgroup.ID = workgroupID
		workgroup.Name = common.StringOrNil(fmt.Sprintf("Baseline workgroup %s", workgroupID))

		if !workgroup.Create() {
			common.Log.Warningf("failed to persist workgroup")
		}
	}

	db := dbconf.DatabaseConnection()
	participants := db.Model(workgroup).Association("Participants")

	go func() {
		common.Log.Trace("attempting to resolve baseline counterparties")

		token, err := ident.CreateToken(*common.OrganizationRefreshToken, map[string]interface{}{
			"grant_type":      "refresh_token",
			"organization_id": *common.OrganizationID,
		})
		if err != nil {
			common.Log.Warningf("failed to vend organization access token; %s", err.Error())
			return
		}

		counterparties := make([]*Participant, 0)

		for _, party := range common.DefaultCounterparties {
			p := &Participant{
				baseline.Participant{
					Address:           common.StringOrNil(party["address"]),
					APIEndpoint:       common.StringOrNil(party["api_endpoint"]),
					MessagingEndpoint: common.StringOrNil(party["messaging_endpoint"]),
				},
				common.StringOrNil(party["address"]),
				make([]*Workgroup, 0),
				make([]*Workflow, 0),
				make([]*Workstep, 0),
			}

			counterparties = append(counterparties, p)
		}

		orgs, err := ident.ListApplicationOrganizations(*token.AccessToken, workgroupID.String(), map[string]interface{}{})
		if err != nil {
			common.Log.Warningf("failed to list organizations for workgroup: %s; %s", workgroupID, err.Error())
			return
		}

		for _, org := range orgs {
			addr, addrOk := org.Metadata["address"].(string)
			apiEndpoint, _ := org.Metadata["api_endpoint"].(string)
			messagingEndpoint, _ := org.Metadata["messaging_endpoint"].(string)

			if addrOk {
				p := &Participant{
					baseline.Participant{
						Address:           common.StringOrNil(addr),
						APIEndpoint:       common.StringOrNil(apiEndpoint),
						MessagingEndpoint: common.StringOrNil(messagingEndpoint),
					},
					common.StringOrNil(addr),
					make([]*Workgroup, 0),
					make([]*Workflow, 0),
					make([]*Workstep, 0),
				}

				counterparties = append(counterparties, p)
			}
		}

		for _, participant := range counterparties {
			if participant.Address != nil && !strings.EqualFold(strings.ToLower(*participant.Address), strings.ToLower(*common.BaselineOrganizationAddress)) {
				exists := lookupBaselineOrganization(*participant.Address) != nil

				participants.Append(&participant)
				err := participant.Cache()
				if err != nil {
					common.Log.Warningf("failed to cache counterparty; %s", err.Error())
					continue
				}
				if !exists {
					common.Log.Debugf("cached baseline counterparty: %s", *participant.Address)
				}
			}
		}
	}()
}

func LookupBaselineWorkgroup(identifier string) *Workgroup {
	var workgroup *Workgroup

	key := fmt.Sprintf("baseline.workgroup.%s", identifier)
	raw, err := redisutil.Get(key)
	if err != nil {
		common.Log.Debugf("no baseline workgroup cached for key: %s; %s", key, err.Error())
		return nil
	}

	json.Unmarshal([]byte(*raw), &workgroup)
	return workgroup
}

func (w *Workgroup) Create() bool {
	if !w.Validate() {
		return false
	}

	newRecord := w.ID == uuid.Nil || FindWorkgroupByID(w.ID) == nil
	success := false

	if newRecord {
		db := dbconf.DatabaseConnection()
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
		if FindWorkgroupByID(w.ID) == nil {
			success = rowsAffected > 0
		}
	}

	return success
}

func (w *Workgroup) Validate() bool {
	return true
}
