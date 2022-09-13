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
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
	provide "github.com/provideplatform/provide-go/common"
)

const defaultAuthenticatePath = "proubc/auth"
const defaultTenantPath = "proubc/tenants"
const defaultListSchemasPath = "proubc/schemas"
const defaultSchemaDetailsPath = "proubc/schemas"
const defaultObjectsPath = "proubc/objects"
const defaultHealthcheckPath = "proubc/status"

// SAPService for the SAP API
type SAPService struct {
	api.Client
	mutex        sync.Mutex

	authenticateEndpoint *string
	tenantPath *string
	listSchemasPath *string
	schemaDetailsPath *string
	objectsPath *string
	healthcheckPath *string

	clientID     *string
	clientSecret *string
}

// SAPFactory initializes a SAPService instance
func SAPFactory(params *SystemMetadata) *SAPService {
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

	authenticatePath := common.StringOrNil(defaultAuthenticatePath)
	if os.Getenv("SAP_AUTHENTICATE_API_PATH") != "" {
		authenticatePath = common.StringOrNil(os.Getenv("SAP_AUTHENTICATE_API_PATH"))
	}

	tenantPath := common.StringOrNil(defaultTenantPath)
	if os.Getenv("SAP_TENANT_API_PATH") != "" {
		tenantPath = common.StringOrNil(os.Getenv("SAP_TENANT_API_PATH"))
	}

	listSchemasPath := common.StringOrNil(defaultListSchemasPath)
	if os.Getenv("SAP_LIST_SCHEMAS_API_PATH") != "" {
		listSchemasPath = common.StringOrNil(os.Getenv("SAP_LIST_SCHEMAS_API_PATH"))
	}

	schemaDetailsPath := common.StringOrNil(defaultSchemaDetailsPath)
	if os.Getenv("SAP_SCHEMA_DETAILS_API_PATH") != "" {
		schemaDetailsPath = common.StringOrNil(os.Getenv("SAP_SCHEMA_DETAILS_API_PATH"))
	}

	objectsPath := common.StringOrNil(defaultObjectsPath)
	if os.Getenv("SAP_OBJECTS_API_PATH") != "" {
		objectsPath = common.StringOrNil(os.Getenv("SAP_OBJECTS_API_PATH"))
	}

	healthcheckPath := common.StringOrNil(defaultHealthcheckPath)
	if os.Getenv("SAP_HEALTHCHECK_API_PATH") != "" {
		healthcheckPath = common.StringOrNil(os.Getenv("SAP_HEALTHCHECK_API_PATH"))
	}

	return &SAPService{
		api.Client{
			Host:     endpoint.Host,
			Path:     endpoint.Path,
			Scheme:   endpoint.Scheme,
			Token:    params.Auth.Token,
			Username: provide.StringOrNil(*params.Auth.Username),
			Password: provide.StringOrNil(*params.Auth.Password),
		},
		sync.Mutex{},
		authenticatePath,
		tenantPath,
		listSchemasPath,
		schemaDetailsPath,
		objectsPath,
		healthcheckPath,
		params.Auth.ClientID,
		params.Auth.ClientSecret,
	}
}

// InitSAPService convenience method to initialize an `ident.SAPService` instance
func InitSAPService(token *string) *SAPService {
	var host string
	var path string
	var scheme string
	var username string
	var password string

	if os.Getenv("SAP_API_HOST") != "" {
		host = os.Getenv("SAP_API_HOST")
	}

	if os.Getenv("SAP_API_PATH") != "" {
		path = os.Getenv("SAP_API_PATH")
	}

	if os.Getenv("SAP_API_SCHEME") != "" {
		scheme = os.Getenv("SAP_API_SCHEME")
	}

	if os.Getenv("SAP_API_USERNAME") != "" {
		username = os.Getenv("SAP_API_USERNAME")
	}

	if os.Getenv("SAP_API_PASSWORD") != "" {
		password = os.Getenv("SAP_API_PASSWORD")
	}

	authenticatePath := common.StringOrNil(defaultAuthenticatePath)
	if os.Getenv("SAP_AUTHENTICATE_API_PATH") != "" {
		authenticatePath = common.StringOrNil(os.Getenv("SAP_AUTHENTICATE_API_PATH"))
	}

	tenantPath := common.StringOrNil(defaultTenantPath)
	if os.Getenv("SAP_TENANT_API_PATH") != "" {
		tenantPath = common.StringOrNil(os.Getenv("SAP_TENANT_API_PATH"))
	}

	listSchemasPath := common.StringOrNil(defaultListSchemasPath)
	if os.Getenv("SAP_LIST_SCHEMAS_API_PATH") != "" {
		listSchemasPath = common.StringOrNil(os.Getenv("SAP_LIST_SCHEMAS_API_PATH"))
	}

	schemaDetailsPath := common.StringOrNil(defaultSchemaDetailsPath)
	if os.Getenv("SAP_SCHEMA_DETAILS_API_PATH") != "" {
		schemaDetailsPath = common.StringOrNil(os.Getenv("SAP_SCHEMA_DETAILS_API_PATH"))
	}

	objectsPath := common.StringOrNil(defaultObjectsPath)
	if os.Getenv("SAP_OBJECTS_API_PATH") != "" {
		objectsPath = common.StringOrNil(os.Getenv("SAP_OBJECTS_API_PATH"))
	}

	healthcheckPath := common.StringOrNil(defaultHealthcheckPath)
	if os.Getenv("SAP_HEALTHCHECK_API_PATH") != "" {
		healthcheckPath = common.StringOrNil(os.Getenv("SAP_HEALTHCHECK_API_PATH"))
	}

	var clientID *string
	if os.Getenv("SAP_API_CLIENT_ID") != "" {
		clientID = common.StringOrNil(os.Getenv("SAP_API_CLIENT_ID"))
	}

	var clientSecret *string
	if os.Getenv("SAP_API_CLIENT_SECRET") != "" {
		clientSecret = common.StringOrNil(os.Getenv("SAP_API_CLIENT_SECRET"))
	}

	return &SAPService{
		api.Client{
			Host:     host,
			Path:     path,
			Scheme:   scheme,
			Token:    token,
			Username: provide.StringOrNil(username),
			Password: provide.StringOrNil(password),
		},
		sync.Mutex{},
		authenticatePath,
		tenantPath,
		listSchemasPath,
		schemaDetailsPath,
		objectsPath,
		healthcheckPath,
		clientID,
		clientSecret,
	}
}

func (s *SAPService) requestURI(uri string) string {
	_uri := string(uri)
	if s.clientID != nil || s.clientSecret != nil {
		_uri = fmt.Sprintf("%s?", _uri)

		if s.clientID != nil {
			_uri = fmt.Sprintf("%sclient_id=%s&", _uri, url.QueryEscape(*s.clientID))
		}

		if s.clientSecret != nil {
			_uri = fmt.Sprintf("%sclient_secret=%s&", _uri, url.QueryEscape(*s.clientSecret))
		}

		_uri = _uri[0 : len(_uri)-2]
	}

	return _uri
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *SAPService) Authenticate() error {
	s.Cookie = nil
	s.Headers = map[string][]string{
		"X-CSRF-Token": {"Fetch"},
	}

	if s.authenticateEndpoint == nil {
		return fmt.Errorf("failed to authenticate user; SAP authenticate path not set")
	}

	status, resp, err := s.Head(s.requestURI(*s.authenticateEndpoint), map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
	}
	s.Headers = nil

	var cookies *string
	if setCookie, setCookieOk := resp["Set-Cookie"]; setCookieOk {
		cookies = provide.StringOrNil(strings.Join(setCookie, "; "))
	}
	s.Cookie = cookies
	if s.Cookie == nil {
		return fmt.Errorf("failed to authenticate user; no set-cookie header; status: %v", status)
	}

	for name, val := range resp {
		resp[strings.ToLower(name)] = val
	}

	var csrfToken *string
	if len(resp["x-csrf-token"]) == 1 {
		csrfToken = provide.StringOrNil(resp["x-csrf-token"][0])
	}
	if csrfToken == nil {
		return fmt.Errorf("failed to authenticate user; no x-csrf-token header; status: %v", status)
	}
	s.Headers = map[string][]string{
		"X-CSRF-Token": {*csrfToken},
	}

	return nil
}

// ConfigureTenant configures a new tenant instance in SAP for a given organization
func (s *SAPService) ConfigureTenant(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	// if companyCode, companyCodeOk := sor["organization_code"].(string); companyCodeOk {
	// 	params["company_code"] = companyCode
	// }

	if s.tenantPath == nil {
		return fmt.Errorf("failed to authenticate user; SAP tenant path not set")
	}

	status, _, err := s.Post(s.requestURI(*s.tenantPath), params)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("failed to configure tenant; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return fmt.Errorf("failed to configure tenant; status: %v", status)
	}

	return nil
}

// ListSchemas retrieves a list of available schemas
func (s *SAPService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	if s.listSchemasPath == nil {
		return nil, fmt.Errorf("failed to fetch business object model; SAP list schemas path not set")
	}

	uri := s.requestURI(*s.listSchemasPath)
	status, resp, err := s.Get(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v", status)
	}

	schemas := make([]interface{}, 0)

	if items, ok := resp.([]interface{}); ok {
		for _, item := range items {
			raw, _ := json.Marshal(item)
			systemSchema := map[string]interface{}{}

			err = json.Unmarshal(raw, &systemSchema)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal; status: %v; %s", status, err.Error())
			}

			schemas = append(schemas, map[string]interface{}{
				"description": systemSchema["idoctypedescr"],
				"name":        systemSchema["idoctype"],
				"system_type": "sap",
				"type":        systemSchema["idoctype"],
			})
		}

		return schemas, nil
	}

	return resp, nil
}

// GetSchema retrieves a business object data model by type
func (s *SAPService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	if s.schemaDetailsPath == nil {
		return nil, fmt.Errorf("failed to fetch business object model; SAP schema details path not set")
	}

	uri := s.requestURI(fmt.Sprintf("%s/%s", *s.schemaDetailsPath, recordType))
	status, resp, err := s.Get(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v", status)
	}

	var schema interface{}

	if _resp, respOk := resp.(map[string]interface{}); respOk {
		basicType, _ := _resp["basictype"].(map[string]interface{})
		if segmentsStruct, segmentsStructOk := _resp["segmentstruct"].([]interface{}); segmentsStructOk {
			fields := make([]interface{}, 0)

			for _, item := range segmentsStruct {
				raw, _ := json.Marshal(item)
				systemField := map[string]interface{}{}
				err = json.Unmarshal(raw, &systemField)
				if err != nil {
					return nil, fmt.Errorf("failed to unmarshal idoc segment struct; status: %v; %s", status, err.Error())
				}

				attributes := systemField["field_attrib"].(map[string]interface{})
				fields = append(fields, map[string]interface{}{
					"name":        systemField["fieldname"],
					"description": attributes["descrp"],
					"type":        attributes["datatype"],
				})
			}

			schema = map[string]interface{}{
				"description": basicType["idoctypedescr"],
				"fields":      fields,
				"name":        basicType["idoctype"],
				"system_type": "sap",
				"type":        basicType["idoctype"],
			}
		}
	}

	return schema, nil
}

// CreateObject is a generic way to create a business object in the SAP environment
func (s *SAPService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	if s.objectsPath == nil {
		return nil, fmt.Errorf("failed to create business object; SAP objects path not set")
	}

	status, resp, err := s.Post(s.requestURI(*s.objectsPath), params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create business object; status: %v", status)
	}

	return resp, nil
}

// UpdateObject updates a business object
func (s *SAPService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if s.objectsPath == nil {
		return fmt.Errorf("failed to update business object; SAP objects path not set")
	}

	uri := s.requestURI(fmt.Sprintf("%s/%s", *s.objectsPath, id))
	status, _, err := s.Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update business object; status: %v; %s", status, err.Error())
	}

	if status != 200 && status != 204 {
		return fmt.Errorf("failed to update business object; status: %v", status)
	}

	return nil
}

// UpdateObjectStatus updates the status of a business object
func (s *SAPService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if s.objectsPath == nil {
		return fmt.Errorf("failed to update business object status; SAP objects path not set")
	}

	uri := s.requestURI(fmt.Sprintf("%s/%s/status", *s.objectsPath, id))
	status, _, err := s.Put(uri, params)
	if err != nil {
		provide.Log.Warningf("failed to update business object status; status: %v; %s", status, err.Error())
		return fmt.Errorf("failed to update business object status; status: %v; %s", status, err.Error())
	}

	if status != 200 && status != 204 {
		return fmt.Errorf("failed to update business object status; status: %v", status)
	}

	provide.Log.Debugf("received %d status from SAP status endpoint", status)

	return nil
}

// DeleteTenant drops a BPI tenant configuration for the given organization
func (s *SAPService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if s.tenantPath == nil {
		return fmt.Errorf("failed to authenticate user; SAP tenant path not set")
	}

	uri := s.requestURI(fmt.Sprintf("%s/%s", *s.tenantPath, organizationID))
	status, _, err := s.Delete(uri)
	if err != nil {
		return fmt.Errorf("failed to delete tenant config for organization %s; status: %v; %s", organizationID, status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to delete tenant config for organization %s; status: %v", organizationID, status)
	}

	return nil
}

// HealthCheck checks the health of the SAP instance
func (s *SAPService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if s.healthcheckPath == nil {
		return fmt.Errorf("failed to complete health check; SAP healthcheck path not set")
	}

	status, _, err := s.Get(s.requestURI(*s.healthcheckPath), map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to complete health check; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to complete health check; status: %v", status)
	}

	return nil
}

// TenantHealthCheck checks the health of the tenant configuration for the given organization
func (s *SAPService) TenantHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if s.tenantPath == nil {
		return fmt.Errorf("failed to authenticate user; SAP tenant path not set")
	}

	uri := s.requestURI(fmt.Sprintf("%s/%s", *s.tenantPath, organizationID))
	status, _, err := s.Get(uri, map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to complete tenant health check for organization %s; status: %v; %s", organizationID, status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to complete tenant health check for organization %s; status: %v", organizationID, status)
	}

	return nil
}
