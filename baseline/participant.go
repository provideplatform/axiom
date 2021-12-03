package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/kthomas/go-redisutil"
	"github.com/provideplatform/provide-go/api/baseline"
)

// Participant is a party to a baseline workgroup or workflow context
type Participant struct {
	baseline.Participant
	Address    *string      `json:"address"`
	Workgroups []*Workgroup `sql:"-" json:"workgroups,omitempty"`
	Workflows  []*Workflow  `sql:"-" json:"workflows,omitempty"`
	Worksteps  []*Workstep  `sql:"-" json:"worksteps,omitempty"`
}

// WorkstepParticipant is a party to a baseline workstep
type WorkstepParticipant struct {
	Address     *string     `json:"address"`
	Proof       *string     `json:"proof"`
	Witness     interface{} `json:"witness"`
	WitnessedAt *time.Time  `json:"witnessed_at"`
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
