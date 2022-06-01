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

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

// ExcelService
type ExcelService struct {
	api.Client
	mutex sync.Mutex
}

// ExcelFactory initializes an Excel instance
func ExcelFactory(params *System) *ExcelService {
	common.Log.Warningf("ExcelFactory not implemented")
	return nil
}

// InitExcelService convenience method to initialize a default `ExcelService` instance
func InitExcelService(token *string) *ExcelService {
	return &ExcelService{
		api.Client{
			Token: token,
		},
		sync.Mutex{},
	}
}

// Authenticate is not implemented for Excel at this time
func (s *ExcelService) Authenticate() error {
	return nil
}

// ConfigureTenant configures a new proxy instance - not implemented for Excel at this time
func (s *ExcelService) ConfigureTenant(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ListSchemas retrieves a list of available schemas
func (s *ExcelService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// GetSchema retrieves a business object model by type
func (s *ExcelService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateObject is a generic way to create a business object in the Excel environment
func (s *ExcelService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// UpdateObject updates a business object
func (s *ExcelService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// UpdateObjectStatus updates the status of a business object
func (s *ExcelService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// DeleteTenant drops a proxy configuration for the given organization
func (s *ExcelService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the instance - not implemented for Excel at this time
func (s *ExcelService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ProxyHealthCheck
func (s *ExcelService) TenantHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
