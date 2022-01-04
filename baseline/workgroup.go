package baseline

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
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
	Description  *string        `json:"description"`
	Participants []*Participant `sql:"-" json:"participants,omitempty"`
	Workflows    []*Workflow    `sql:"-" json:"workflows,omitempty"`
}

// FindWorkgroupByID retrieves a workgroup for the given id
func FindWorkgroupByID(id uuid.UUID) *Workgroup {
	db := dbconf.DatabaseConnection()
	workgroup := &Workgroup{}
	db.Where("id = ?", id.String()).Find(&workgroup)
	if workgroup == nil || workgroup.ID == uuid.Nil {
		return nil
	}
	return workgroup
}

func init() {
	redisutil.RequireRedis()

	common.Log.Debug("attempting to resolve baseline counterparties")
	resolveWorkgroupParticipants()

	go func() {
		timer := time.NewTicker(requireCounterpartiesTickerInterval)
		for {
			select {
			case <-timer.C:
				resolveWorkgroupParticipants()
			default:
				time.Sleep(requireCounterpartiesSleepInterval)
			}
		}
	}()
}

func resolveWorkgroupParticipants() {
	if common.WorkgroupID == nil {
		common.Log.Warningf("workgroup id not configured")
		return
	}

	workgroupID, err := uuid.FromString(*common.WorkgroupID)
	if err != nil {
		common.Log.Warningf("failed to require workgroupID; %s", err.Error())
		return
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
				p := &Participant{}
				p.Address = common.StringOrNil(addr)
				p.APIEndpoint = common.StringOrNil(apiEndpoint)
				p.MessagingEndpoint = common.StringOrNil(messagingEndpoint)

				counterparties = append(counterparties, p)
			}
		}

		for _, participant := range counterparties {
			if participant.Address != nil {
				exists := lookupBaselineOrganization(*participant.Address) != nil

				workgroup.addParticipant(*participant.Address, db)
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

func (w *Workgroup) participantsCount(tx *gorm.DB) int {
	rows, err := tx.Raw("SELECT count(*) FROM workgroups_participants WHERE workgroup_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to read workgroup participants count; %s", err.Error())
		return 0
	}

	var len int
	for rows.Next() {
		err = rows.Scan(&len)
		if err != nil {
			common.Log.Warningf("failed to read workgroup participants count; %s", err.Error())
			return 0
		}
	}

	return len
}

func (w *Workgroup) listParticipants(tx *gorm.DB) []*WorkgroupParticipant {
	participants := make([]*WorkgroupParticipant, 0)
	rows, err := tx.Raw("SELECT * FROM workgroups_participants WHERE workgroup_id=?", w.ID).Rows()
	if err != nil {
		common.Log.Warningf("failed to list workgroup participants; %s", err.Error())
		return participants
	}

	for rows.Next() {
		p := &WorkgroupParticipant{}
		err = tx.ScanRows(rows, &p)
		if err != nil {
			common.Log.Warningf("failed to list workgroup participants; %s", err.Error())
			return participants
		}
		participants = append(participants, p)
	}

	return participants
}

func (w *Workgroup) addParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("adding participant %s to workgroup: %s", participant, w.ID)
	result := tx.Exec("INSERT INTO workgroups_participants (workgroup_id, participant) VALUES (?, ?)", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("added participant %s from workgroup: %s", participant, w.ID)
	} else {
		common.Log.Warningf("failed to add participant %s from workgroup: %s", participant, w.ID)
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

func (w *Workgroup) removeParticipant(participant string, tx *gorm.DB) bool {
	common.Log.Debugf("removing participant %s to workgroup: %s", participant, w.ID)
	result := tx.Exec("DELETE FROM workgroups_participants WHERE workgroup_id=? AND participant=?", w.ID, participant)
	success := result.RowsAffected == 1
	if success {
		common.Log.Debugf("removed participant %s from workgroup: %s", participant, w.ID)
	} else {
		common.Log.Warningf("failed to remove participant %s from workgroup: %s", participant, w.ID)
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

func (w *Workgroup) Validate() bool {
	return true
}
