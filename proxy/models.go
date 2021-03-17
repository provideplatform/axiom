package proxy

import (
	uuid "github.com/kthomas/go.uuid"
	provide "github.com/provideservices/provide-go/api"
	privacy "github.com/provideservices/provide-go/api/privacy"
)

const ProtocolMessageOpcodeBaseline = "BLINE"
const ProtocolMessageOpcodeJoin = "JOIN"
const ProtocolMessageOpcodeSync = "SYNC"

// BaselineRecord represents a link between an object in the internal system of record
// and the external baseline workflow context
type BaselineRecord struct {
	BaselineID *uuid.UUID `sql:"-" json:"baseline_id,omitempty"`
	ID         *string    `sql:"-" json:"id,omitempty"`
	Type       *string    `sql:"-" json:"type,omitempty"`
	WorkflowID *uuid.UUID `sql:"-" json:"workflow_id"`
	Workflow   *Workflow  `sql:"-" json:"-"`
}

// Message is a proxy-internal wrapper for protocol message handling
type Message struct {
	BaselineID      *uuid.UUID       `sql:"-" json:"baseline_id,omitempty"` // optional; when included, can be used to map outbound message just-in-time
	Errors          []*provide.Error `sql:"-" json:"errors,omitempty"`
	ID              *string          `sql:"-" json:"id,omitempty"`
	MessageID       *string          `sql:"-" json:"message_id,omitempty"`
	Payload         interface{}      `sql:"-" json:"payload,omitempty"`
	ProtocolMessage *ProtocolMessage `sql:"-" json:"protocol_message,omitempty"`
	Recipients      []*Participant   `sql:"-" json:"recipients"`
	Status          *string          `sql:"-" json:"status,omitempty"`
	Type            *string          `sql:"-" json:"type,omitempty"`
}

// Participant is a party to a baseline workgroup or workflow context
type Participant struct {
	Address  *string                `sql:"-" json:"address"`
	Metadata map[string]interface{} `sql:"-" json:"metadata,omitempty"`
	URL      *string                `sql:"-" json:"url,omitempty"`
}

// ProtocolMessage is a baseline protocol message
// see https://github.com/ethereum-oasis/baseline/blob/master/core/types/src/protocol.ts
type ProtocolMessage struct {
	BaselineID *uuid.UUID              `sql:"-" json:"baseline_id,omitempty"`
	Opcode     *string                 `sql:"-" json:"opcode,omitempty"`
	Sender     *string                 `sql:"-" json:"sender,omitempty"`
	Recipient  *string                 `sql:"-" json:"recipient,omitempty"`
	Shield     *string                 `sql:"-" json:"shield,omitempty"`
	Identifier *uuid.UUID              `sql:"-" json:"identifier,omitempty"`
	Signature  *string                 `sql:"-" json:"signature,omitempty"`
	Type       *string                 `sql:"-" json:"type,omitempty"`
	Payload    *ProtocolMessagePayload `sql:"-" json:"payload,omitempty"`
}

// ProtocolMessagePayload is a baseline protocol message payload
type ProtocolMessagePayload struct {
	Object  map[string]interface{} `json:"-" json:"object,omitempty"`
	Proof   *string                `sql:"-" json:"proof,omitempty"`
	Type    *string                `json:"-" json:"type,omitempty"`
	Witness interface{}            `sql:"-" json:"witness,omitempty"`
}

// Workgroup is a baseline workgroup context
type Workgroup struct {
	Workflows []*Workflow `json:"workflows,omitempty"`
}

// Workflow is a baseline workflow context
type Workflow struct {
	Circuits      []*privacy.Circuit `sql:"-" json:"circuits,omitempty"`
	Identifier    *uuid.UUID         `sql:"-" json:"identifier,omitempty"`
	Participants  []*Participant     `sql:"-" json:"participants"`
	Shield        *string            `sql:"-" json:"shield,omitempty"`
	WorkstepIndex uint64             `sql:"-" json:"workstep_index,omitempty"`
}
