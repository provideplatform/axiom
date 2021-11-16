package baseline

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kthomas/go-redisutil"
	"github.com/provideplatform/provide-go/api/baseline"
)

// Participant is a party to a baseline workgroup or workflow context
type Participant struct {
	baseline.Participant
	Address    *string      `json:"address"`
	Workgroups []*Workgroup `gorm:"many2many:workgroups_participants;References:address" json:"workgroups,omitempty"`
	Workflows  []*Workflow  `gorm:"many2many:workflows_participants;References:address" json:"workflows,omitempty"`
	Worksteps  []*Workstep  `gorm:"many2many:worksteps_participants;References:address" json:"worksteps,omitempty"`
}

func (p *Participant) Cache() error {
	if p.Address == nil {
		return errors.New("failed to cache participant with nil address")
	}

	key := fmt.Sprintf("baseline.organization.%s", *p.Address)
	return redisutil.WithRedlock(key, func() error {
		raw, _ := json.Marshal(p)
		return redisutil.Set(key, raw, nil)
	})
}
