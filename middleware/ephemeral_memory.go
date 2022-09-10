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

package middleware

import (
	"fmt"
	"sync"

	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/provide-go/common"
)

// EphemeralMemoryService
type EphemeralMemoryService struct {
	mutex   sync.Mutex
	records map[string]interface{}
	status  map[string]interface{}
}

// EphemeralMemoryFactory initializes a EphemeralMemory instance
func EphemeralMemoryFactory(params *SystemMetadata) *EphemeralMemoryService {
	common.Log.Warningf("EphemeralMemory not implemented")
	return nil
}

// InitEphemeralMemoryService convenience method to initialize a EphemeralMemory instance
func InitEphemeralMemoryService(token *string) *EphemeralMemoryService {
	return &EphemeralMemoryService{
		mutex:   sync.Mutex{},
		records: map[string]interface{}{},
		status:  map[string]interface{}{},
	}
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *EphemeralMemoryService) Authenticate() error {
	return nil
}

// ConfigureTenant configures a new proxy instance in EphemeralMemory for a given organization
func (s *EphemeralMemoryService) ConfigureTenant(params map[string]interface{}) error {
	return nil
}

// ListSchemas retrieves a list of available schemas
func (s *EphemeralMemoryService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// GetSchema retrieves a business object model by type
func (s *EphemeralMemoryService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateObject is a generic way to create a business object in the EphemeralMemory environment
func (s *EphemeralMemoryService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; %s", err.Error())
	}

	params["id"] = id.String()
	s.records[id.String()] = params

	return params, nil
}

// UpdateObject updates a business object
func (s *EphemeralMemoryService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.records[id] = params
	return nil
}

// UpdateObjectStatus updates the status of a business object
func (s *EphemeralMemoryService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.status[id] = params
	return nil
}

// DeleteTenant drops a proxy configuration for the given organization
func (s *EphemeralMemoryService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the EphemeralMemory instance
func (s *EphemeralMemoryService) HealthCheck() error {
	return nil
}

// TenantHealthCheck
func (s *EphemeralMemoryService) TenantHealthCheck(organizationID string) error {
	return nil
}
