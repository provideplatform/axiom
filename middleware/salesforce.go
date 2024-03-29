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
	"os"
	"sync"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultSalesforceHost = "testnet.dappsuite.network"
const defaultSalesforcePath = "api"
const defaultSalesforceScheme = "https"

// SalesforceService for the SAP API
type SalesforceService struct {
	api.Client
	mutex sync.Mutex
}

// SalesforceService initializes a Salesforce instance
func SalesforceFactory(params *SystemMetadata) *SalesforceService {
	common.Log.Warningf("SalesforceNowFactory not implemented")
	return nil
}

// InitSalesforceService convenience method to initialize a Salesforce instance
func InitSalesforceService(token *string) *SalesforceService {
	host := defaultSalesforceHost
	if os.Getenv("SALESFORCE_API_HOST") != "" {
		host = os.Getenv("SALESFORCE_API_HOST")
	}

	path := defaultSalesforcePath
	if os.Getenv("SALESFORCE_API_PATH") != "" {
		path = os.Getenv("SALESFORCE_API_PATH")
	}

	scheme := defaultSalesforceScheme
	if os.Getenv("SALESFORCE_API_SCHEME") != "" {
		scheme = os.Getenv("SALESFORCE_API_SCHEME")
	}

	return &SalesforceService{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
		sync.Mutex{},
	}
}

// Authenticate a user not implemented for Salesforce
func (s *SalesforceService) Authenticate() error {
	return nil
}

// ConfigureTenant configures a new proxy instance in Salesforce for a given organization
func (s *SalesforceService) ConfigureTenant(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ListSchemas retrieves a list of available schemas
func (s *SalesforceService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// GetSchema retrieves a business object model by type
func (s *SalesforceService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateObject is a generic way to create a business object in the Salesforce environment
func (s *SalesforceService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	status, resp, err := s.Post("objects", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create business object; status: %v", status)
	}

	return resp, nil
}

// UpdateObject updates a business object
func (s *SalesforceService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	uri := fmt.Sprintf("objects/%s", id)
	status, _, err := s.Patch(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to update business object; status: %v", status)
	}

	return nil
}

// UpdateObjectStatus updates the status of a business object
func (s *SalesforceService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil
}

// DeleteTenant drops a proxy configuration for the given organization
func (s *SalesforceService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the Salesforce instance
func (s *SalesforceService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// TenantHealthCheck
func (s *SalesforceService) TenantHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
