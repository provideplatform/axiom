package baseline

import (
	"encoding/json"
	"time"

	uuid "github.com/kthomas/go.uuid"
)

// WorkgroupDashboardAPIResponse is a general response containing data related to the current workgroup and organization context
type WorkgroupDashboardAPIResponse struct {
	Activity     []*ActivityAPIResponseItem `json:"activity"`
	Analytics    *AnalyticsAPIResponse      `json:"analytics"`
	Participants *ParticipantsAPIResponse   `json:"participants"`
	Workflows    *WorkflowsAPIResponse      `json:"workflows"`
}

// ActivityAPIResponseItem is a single activity item for inclusion in the `WorkgroupDashboardAPIResponse`
type ActivityAPIResponseItem struct {
	Metadata  *json.RawMessage `json:"metadata,omitempty"`
	Subtitle  *string          `json:"subtitle"`
	Timestamp *time.Time       `json:"timestamp"`
	Title     *string          `json:"title"`

	WorkflowID *uuid.UUID `json:"workflow_id"`
	WorkstepID *uuid.UUID `json:"workstep_id"`
}

// AnalyticsAPIResponse is the analytics item for inclusion in the `WorkgroupDashboardAPIResponse`
type AnalyticsAPIResponse struct {
	Metadata *json.RawMessage          `json:"metadata,omitempty"`
	Tree     *TreeAnalyticsAPIResponse `json:"tree"`
}

// TreeAnalyticsAPIResponse is the tree analtics time-series item for inclusion in the `AnalyticsAPIResponse`
type TreeAnalyticsAPIResponse struct {
	StartAt *time.Time `json:"start_at"`
	EndAt   *time.Time `json:"end_at"`

	Items    []*TreeAnalyticsAPIResponseItem `json:"items"`
	Metadata *json.RawMessage                `json:"metadata,omitempty"`
}

// TreeAnalyticsAPIResponseItem is the tree analtics time-series item for inclusion in the `AnalyticsAPIResponse`
type TreeAnalyticsAPIResponseItem struct {
	Date     *time.Time       `json:"date"`
	Metadata *json.RawMessage `json:"metadata,omitempty"`
	Size     uint64           `json:"size"` // in bytes
	Subtitle *string          `json:"subtitle"`
	Title    *string          `json:"title"`
}

// ParticipantsAPIResponse is the participants item for inclusion in the `WorkgroupDashboardAPIResponse`
type ParticipantsAPIResponse struct {
	ActionItemsCount   *uint64 `json:"action_items_count"`
	UsersCount         *uint64 `json:"users_count"`
	OrganizationsCount *uint64 `json:"organizations_count"`
}

// WorkflowsAPIResponse is the workflows item for inclusion in the `WorkgroupDashboardAPIResponse`
type WorkflowsAPIResponse struct {
	DelayedCount   *uint64 `json:"delayed_count"`
	DraftCount     *uint64 `json:"draft_count"`
	PublishedCount *uint64 `json:"published_count"`
}

// queryAnalytics calculates or retrieves high-level analytics for the given BPI workgroup id
func (w *Workgroup) queryAnalytics() (*WorkgroupDashboardAPIResponse, error) {
	activity := make([]*ActivityAPIResponseItem, 0)
	tree := &TreeAnalyticsAPIResponse{
		Items: make([]*TreeAnalyticsAPIResponseItem, 0),
	}

	participants := &ParticipantsAPIResponse{
		ActionItemsCount:   nil,
		UsersCount:         nil,
		OrganizationsCount: nil,
	}

	workflows := &WorkflowsAPIResponse{
		DelayedCount:   nil,
		DraftCount:     nil,
		PublishedCount: nil,
	}

	return &WorkgroupDashboardAPIResponse{
		Activity: activity,
		Analytics: &AnalyticsAPIResponse{
			Tree: tree,
		},
		Participants: participants,
		Workflows:    workflows,
	}, nil
}
