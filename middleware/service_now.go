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
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultServiceNowReachabilityTimeout = time.Second * 5

// ServiceNowService for the SAP API
type ServiceNowService struct {
	api.Client
	mutex sync.Mutex

	path              *string
	listSchemasPath   *string
	schemaDetailsPath *string
	healthcheckPath   *string
}

// ServiceNowFactory initializes a ServiceNow instance
func ServiceNowFactory(params *SystemMetadata) *ServiceNowService {
	var endpoint *url.URL
	var err error

	if params.EndpointURL != nil {
		endpoint, err = url.Parse(*params.EndpointURL)
		if err != nil {
			common.Log.Warningf("failed to parse endpoint url: %s", *params.EndpointURL)
			return nil
		}
	}

	if params.Auth == nil {
		// HACK
		params.Auth = &SystemAuth{}
	}

	var username *string
	if params.Auth.Username != nil {
		username = params.Auth.Username
	}

	var password *string
	if params.Auth.Password != nil {
		password = params.Auth.Password
	}

	var path string
	if params.Path != nil {
		path = *params.Path
	} else {
		path = endpoint.Path
	}

	var listSchemasPath *string
	if os.Getenv("SERVICENOW_LIST_SCHEMAS_API_PATH") != "" {
		listSchemasPath = common.StringOrNil(fmt.Sprintf("%s/%s", path, os.Getenv("SERVICENOW_LIST_SCHEMAS_API_PATH")))
	}

	var schemaDetailsPath *string
	if os.Getenv("SERVICENOW_SCHEMA_DETAILS_API_PATH") != "" {
		schemaDetailsPath = common.StringOrNil(fmt.Sprintf("%s/%s", path, os.Getenv("SERVICENOW_SCHEMA_DETAILS_API_PATH")))
	}

	var healthcheckPath *string
	if os.Getenv("SERVICENOW_HEALTHCHECK_API_PATH") != "" {
		healthcheckPath = common.StringOrNil(os.Getenv("SERVICENOW_HEALTHCHECK_API_PATH"))
	}

	return &ServiceNowService{
		api.Client{
			Host:     endpoint.Host,
			Path:     endpoint.Path,
			Scheme:   endpoint.Scheme,
			Token:    params.Auth.Token,
			Username: username,
			Password: password,
		},
		sync.Mutex{},
		common.StringOrNil(path),
		listSchemasPath,
		schemaDetailsPath,
		healthcheckPath,
	}
}

// InitServiceNowService convenience method to initialize a ServiceNow instance
func InitServiceNowService(token *string) *ServiceNowService {
	var host string
	if os.Getenv("SERVICENOW_API_HOST") != "" {
		host = os.Getenv("SERVICENOW_API_HOST")
	}

	var path string
	if os.Getenv("SERVICENOW_API_PATH") != "" {
		path = os.Getenv("SERVICENOW_API_PATH")
	}

	var scheme string
	if os.Getenv("SERVICENOW_API_SCHEME") != "" {
		scheme = os.Getenv("SERVICENOW_API_SCHEME")
	}

	var username string
	if os.Getenv("SERVICENOW_API_USERNAME") != "" {
		username = os.Getenv("SERVICENOW_API_USERNAME")
	}

	var password string
	if os.Getenv("SERVICENOW_API_PASSWORD") != "" {
		password = os.Getenv("SERVICENOW_API_PASSWORD")
	}

	var listSchemasPath *string
	if os.Getenv("SERVICENOW_LIST_SCHEMAS_API_PATH") != "" {
		listSchemasPath = common.StringOrNil(fmt.Sprintf("%s/%s", path, os.Getenv("SERVICENOW_LIST_SCHEMAS_API_PATH")))
	}

	var schemaDetailsPath *string
	if os.Getenv("SERVICENOW_SCHEMA_DETAILS_API_PATH") != "" {
		schemaDetailsPath = common.StringOrNil(fmt.Sprintf("%s/%s", path, os.Getenv("SERVICENOW_SCHEMA_DETAILS_API_PATH")))
	}

	var healthcheckPath *string
	if os.Getenv("SERVICENOW_HEALTHCHECK_API_PATH") != "" {
		healthcheckPath = common.StringOrNil(os.Getenv("SERVICENOW_HEALTHCHECK_API_PATH"))
	}

	return &ServiceNowService{
		api.Client{
			Host:     host,
			Path:     path,
			Scheme:   scheme,
			Token:    token,
			Username: common.StringOrNil(username),
			Password: common.StringOrNil(password),
		},
		sync.Mutex{},
		common.StringOrNil(path),
		listSchemasPath,
		schemaDetailsPath,
		healthcheckPath,
	}
}

// ConfigureTenant configures a new proxy instance in ServiceNow for a given organization
func (s *ServiceNowService) ConfigureTenant(params map[string]interface{}) error {
	return nil
}

// ListSchemas retrieves a list of available schemas
func (s *ServiceNowService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.listSchemasPath == nil {
		return nil, fmt.Errorf("failed to fetch business object models; SERVICENOW_LIST_SCHEMAS_API_PATH not set")
	}

	status, resp, err := s.Get(*s.listSchemasPath, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object models; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch business object models; status: %v", status)
	}

	if arr, ok := resp.([]interface{}); ok {
		schemas := make([]interface{}, 0)

		for _, item := range arr {
			var systemSchema map[string]interface{}
			raw, _ := json.Marshal(item)

			err = json.Unmarshal(raw, &systemSchema)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal; status: %v; %s", status, err.Error())
			}

			schemas = append(schemas, map[string]interface{}{
				"description": systemSchema["table"],
				"name":        systemSchema["table"],
				"system_type": "servicenow",
				"type":        systemSchema["id"],
			})
		}

		return schemas, nil
	}

	return nil, fmt.Errorf("failed to fetch business object models; failed to parse response")
}

// GetSchema retrieves a business object model by type
func (s *ServiceNowService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.schemaDetailsPath == nil {
		return nil, fmt.Errorf("failed to fetch business object model; SERVICENOW_SCHEMA_DETAILS_API_PATH not set")
	}

	uri := fmt.Sprintf("%s?table=%s", *s.schemaDetailsPath, recordType)
	status, resp, err := s.Get(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v", status)
	}

	var _resp map[string]interface{}
	raw, _ := json.Marshal(resp)

	err = json.Unmarshal(raw, &_resp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object model; %s", err.Error())
	}

	if arr, ok := _resp["fields"].([]interface{}); ok {
		fields := make([]interface{}, 0)

		for _, item := range arr {
			var _item map[string]interface{}
			raw, _ := json.Marshal(item)

			err = json.Unmarshal(raw, &_item)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch business object model; %s", err.Error())
			}

			fields = append(fields, map[string]interface{}{
				"name":        _item["internal_value"],
				"description": _item["display_value"],
				"type":        _item["internal_type"],
			})
		}

		return map[string]interface{}{
			"description": _resp["table"],
			"fields":      fields,
			"name":        _resp["table"],
			"system_type": "servicenow",
			"type":        _resp["table"],
		}, nil
	}

	return nil, fmt.Errorf("failed to fetch business object model; failed to parse response")
}

// CreateObject is a generic way to create a business object in the ServiceNow environment
func (s *ServiceNowService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_params := params
	if payload, payloadOk := params["payload"].(map[string]interface{}); payloadOk {
		if replicate, replicateOk := payload["replicate"].(map[string]interface{}); replicateOk {
			_params = replicate
		}
	}

	status, resp, err := s.Post("incident", _params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create business object; status: %v", status)
	}

	if result, resultOk := resp.(map[string]interface{})["result"]; resultOk {
		if sysId, sysIdOk := result.(map[string]interface{})["sys_id"].(string); sysIdOk {
			resp.(map[string]interface{})["id"] = sysId
		}
	}

	return resp, nil
}

// UpdateObject updates a business object
func (s *ServiceNowService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_params := params
	if payload, payloadOk := params["payload"].(map[string]interface{}); payloadOk {
		if replicate, replicateOk := payload["replicate"].(map[string]interface{}); replicateOk {
			_params = replicate
		}
	}

	uri := fmt.Sprintf("incident/%s", id)
	status, _, err := s.Patch(uri, _params)
	if err != nil {
		return fmt.Errorf("failed to update business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to update business object; status: %v", status)
	}

	return nil
}

// UpdateObjectStatus updates the status of a business object
func (s *ServiceNowService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil
}

// DeleteTenant drops a proxy configuration for the given organization
func (s *ServiceNowService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the ServiceNow instance
func (s *ServiceNowService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	conn, err := net.DialTimeout("tcp", s.Host, defaultServiceNowReachabilityTimeout)
	if err == nil {
		defer conn.Close()
		return nil
	}

	if s.healthcheckPath == nil {
		return fmt.Errorf("failed to complete health check; SERVICENOW_HEALTHCHECK_API_PATH not set")
	}

	status, _, err := s.Head(*s.healthcheckPath, map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to complete health check; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to complete health check; status: %v", status)
	}

	return nil
}

// TenantHealthCheck
func (s *ServiceNowService) TenantHealthCheck(organizationID string) error {
	return nil
}
