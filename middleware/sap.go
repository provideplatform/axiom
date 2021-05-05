package middleware

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultSAPHost = "s4h.rp.concircle.com"
const defaultSAPPath = "ubc"
const defaultSAPScheme = "https"
const defaultSAPUsername = "unibright"
const defaultSAPPassword = "unibright"

// SAPService for the SAP API
type SAPService struct {
	api.Client
	mutex sync.Mutex
}

// InitDefaultSAPService convenience method to initialize a default `sap.SAPService` (i.e., production) instance
func InitDefaultSAPService(token *string) *SAPService {
	return &SAPService{
		api.Client{
			Host:     defaultSAPHost,
			Path:     defaultSAPPath,
			Scheme:   defaultSAPScheme,
			Token:    token,
			Username: common.StringOrNil(defaultSAPUsername),
			Password: common.StringOrNil(defaultSAPPassword),
		},
		sync.Mutex{},
	}
}

// InitSAPService convenience method to initialize an `ident.SAPService` instance
func InitSAPService(token *string) *SAPService {
	host := defaultSAPHost
	if os.Getenv("SAP_API_HOST") != "" {
		host = os.Getenv("SAP_API_HOST")
	}

	path := defaultSAPPath
	if os.Getenv("SAP_API_PATH") != "" {
		path = os.Getenv("SAP_API_PATH")
	}

	scheme := defaultSAPScheme
	if os.Getenv("SAP_API_SCHEME") != "" {
		scheme = os.Getenv("SAP_API_SCHEME")
	}

	username := defaultSAPUsername
	if os.Getenv("SAP_API_USERNAME") != "" {
		username = os.Getenv("SAP_API_USERNAME")
	}

	password := defaultSAPPassword
	if os.Getenv("SAP_API_PASSWORD") != "" {
		password = os.Getenv("SAP_API_PASSWORD")
	}

	return &SAPService{
		api.Client{
			Host:     host,
			Path:     path,
			Scheme:   scheme,
			Token:    token,
			Username: common.StringOrNil(username),
			Password: common.StringOrNil(password),
		},
		sync.Mutex{},
	}
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *SAPService) Authenticate() error {
	s.Cookie = nil
	s.Headers = map[string][]string{
		"X-CSRF-Token": {"Fetch"},
	}
	status, resp, err := s.Head("ubc/auth", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
	}
	s.Headers = nil

	var cookies *string
	if setCookie, setCookieOk := resp["Set-Cookie"]; setCookieOk {
		cookies = common.StringOrNil(strings.Join(setCookie, "; "))
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
		csrfToken = common.StringOrNil(resp["x-csrf-token"][0])
	}
	if csrfToken == nil {
		return fmt.Errorf("failed to authenticate user; no x-csrf-token header; status: %v", status)
	}
	s.Headers = map[string][]string{
		"X-CSRF-Token": {*csrfToken},
	}

	return nil
}

// ConfigureProxy configures a new proxy instance in SAP for a given organization
func (s *SAPService) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	organizationID, organizationIDOk := params["organization_id"].(string)
	if !organizationIDOk {
		return errors.New("failed to configure proxy; organization_id required")
	}

	uri := fmt.Sprintf("ubc/organizations/%s/proxy", organizationID)
	status, _, err := s.Post(uri, params)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("failed to configure proxy; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to configure proxy; status: %v", status)
	}

	return nil
}

// CreateBusinessObject is a generic way to create a business object in the SAP environment
func (s *SAPService) CreateBusinessObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	status, resp, err := s.Post("ubc/business_objects", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create business object; status: %v", status)
	}

	return resp, nil
}

// UpdateBusinessObject updates a business object
func (s *SAPService) UpdateBusinessObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	uri := fmt.Sprintf("ubc/business_objects/%s", id)
	status, _, err := s.Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to update business object; status: %v", status)
	}

	return nil
}

// UpdateBusinessObjectStatus updates the status of a business object
func (s *SAPService) UpdateBusinessObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	uri := fmt.Sprintf("ubc/business_objects/%s/status", id)
	status, _, err := s.Put(uri, params)
	if err != nil {
		common.Log.Warningf("failed to update business object status; status: %v; %s", status, err.Error())
		return fmt.Errorf("failed to update business object status; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to update business object status; status: %v", status)
	}

	common.Log.Debugf("received %d status from SAP status endpoint", status)

	return nil
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *SAPService) DeleteProxyConfiguration(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	uri := fmt.Sprintf("ubc/organizations/%s/proxy", organizationID)
	status, _, err := s.Delete(uri)
	if err != nil {
		return fmt.Errorf("failed to delete proxy config for organization %s; status: %v; %s", organizationID, status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to delete proxy config for organization %s; status: %v", organizationID, status)
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

	status, _, err := s.Get("ubc/status", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to complete health check; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to complete health check; status: %v", status)
	}

	return nil
}

// ProxyHealthCheck checks the health of the proxy configuration for the given organization
func (s *SAPService) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	uri := fmt.Sprintf("ubc/organizations/%s/proxy", organizationID)
	status, _, err := s.Get(uri, map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to complete proxy health check for organization %s; status: %v; %s", organizationID, status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to complete proxy health check for organization %s; status: %v", organizationID, status)
	}

	return nil
}

// InitiateBusinessObject is a method for integration testing to initiate a business object from the SAP environment
func (s *SAPService) InitiateBusinessObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	status, resp, err := s.Post("zcona/test", params)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to initiate business object; status: %v", status)
	}

	return resp, nil
}
