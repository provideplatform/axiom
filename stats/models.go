package stats

// LogMessage -- FIXME -- move to stats package
type LogMessage struct {
	BaselineID *string `json:"baseline_id,omitempty"`
	Message    *string `json:"message"`
	ObjectID   *string `json:"object_id"`
	Severity   *string `json:"severity"`
	Timestamp  *string `json:"timestamp"`
	Type       *string `json:"type,omitempty"`
}
