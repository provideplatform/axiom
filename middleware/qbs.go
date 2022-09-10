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
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
	provide "github.com/provideplatform/provide-go/common"
)

// QBSService for the QBS API
type QBSService struct {
	api.Client
	mutex        sync.Mutex
	clientID     *string
	clientSecret *string
}

// QBSFactory initializes a QBSService instance
func QBSFactory(params *SystemMetadata) *QBSService {
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

	return &QBSService{
		api.Client{
			Host:     endpoint.Host,
			Path:     endpoint.Path,
			Scheme:   endpoint.Scheme,
			Token:    params.Auth.Token,
			Username: provide.StringOrNil(*params.Auth.Username),
			Password: provide.StringOrNil(*params.Auth.Password),
		},
		sync.Mutex{},
		params.Auth.ClientID,
		params.Auth.ClientSecret,
	}
}

// InitQBSService convenience method to initialize a `QBSService` instance
func InitQBSService(token *string) *QBSService {
	var host string
	var path string
	var scheme string
	var username string
	var password string

	if os.Getenv("QBS_API_HOST") != "" {
		host = os.Getenv("QBS_API_HOST")
	}

	if os.Getenv("QBS_API_PATH") != "" {
		path = os.Getenv("QBS_API_PATH")
	}

	if os.Getenv("QBS_API_SCHEME") != "" {
		scheme = os.Getenv("QBS_API_SCHEME")
	}

	if os.Getenv("QBS_API_USERNAME") != "" {
		username = os.Getenv("QBS_API_USERNAME")
	}

	if os.Getenv("QBS_API_PASSWORD") != "" {
		password = os.Getenv("QBS_API_PASSWORD")
	}

	var clientID *string
	if os.Getenv("QBS_API_CLIENT_ID") != "" {
		_clientID := os.Getenv("QBS_API_CLIENT_ID")
		clientID = &_clientID
	}

	var clientSecret *string
	if os.Getenv("QBS_API_CLIENT_SECRET") != "" {
		_clientSecret := os.Getenv("QBS_API_CLIENT_SECRET")
		clientSecret = &_clientSecret
	}

	return &QBSService{
		api.Client{
			Host:     host,
			Path:     path,
			Scheme:   scheme,
			Token:    token,
			Username: provide.StringOrNil(username),
			Password: provide.StringOrNil(password),
		},
		sync.Mutex{},
		clientID,
		clientSecret,
	}
}

func (s *QBSService) requestURI(uri string) string {
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
func (s *QBSService) Authenticate() error {
	return errors.New("not implemented")
}

// ConfigureTenant configures a new tenant instance in QBS for a given organization
func (s *QBSService) ConfigureTenant(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

// ListSchemas retrieves a list of available schemas
func (s *QBSService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

// GetSchema retrieves a business object data model by type
func (s *QBSService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

// CreateObject is a generic way to create a business object in the QBS environment
func (s *QBSService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	return nil, errors.New("not implemented")
}

// UpdateObject updates a business object
func (s *QBSService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

// UpdateObjectStatus updates the status of a business object
func (s *QBSService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

// DeleteTenant drops a BPI tenant configuration for the given organization
func (s *QBSService) DeleteTenant(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

// HealthCheck checks the health of the QBS instance
func (s *QBSService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}

// TenantHealthCheck checks the health of the tenant configuration for the given organization
func (s *QBSService) TenantHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	return errors.New("not implemented")
}
