package middleware

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/provideplatform/baseline/common"
	"github.com/provideplatform/provide-go/api"
	provide "github.com/provideplatform/provide-go/common"
)

const defaultSAPHost = "s4h.rp.concircle.com"
const defaultSAPPath = "ubc"
const defaultSAPScheme = "https"
const defaultSAPUsername = "unibright"
const defaultSAPPassword = "unibright"

// SAPService for the SAP API
type SAPService struct {
	api.Client
	mutex        sync.Mutex
	clientID     *string
	clientSecret *string
}

// InitDefaultSAPService convenience method to initialize a default `sap.SAPService` (i.e., production) instance
func InitDefaultSAPService(token *string) *SAPService {
	return &SAPService{
		api.Client{
			Host:     defaultSAPHost,
			Path:     defaultSAPPath,
			Scheme:   defaultSAPScheme,
			Token:    token,
			Username: provide.StringOrNil(defaultSAPUsername),
			Password: provide.StringOrNil(defaultSAPPassword),
		},
		sync.Mutex{},
		nil,
		nil,
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

	var clientID *string
	if os.Getenv("SAP_API_CLIENT_ID") != "" {
		_clientID := os.Getenv("SAP_API_CLIENT_ID")
		clientID = &_clientID
	}

	var clientSecret *string
	if os.Getenv("SAP_API_CLIENT_SECRET") != "" {
		_clientSecret := os.Getenv("SAP_API_CLIENT_SECRET")
		clientSecret = &_clientSecret
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
	status, resp, err := s.Head(s.requestURI("ubc/auth"), map[string]interface{}{})
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

// ConfigureProxy configures a new proxy instance in SAP for a given organization
func (s *SAPService) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	if companyCode, companyCodeOk := common.InternalSOR["organization_code"].(string); companyCodeOk {
		params["company_code"] = companyCode
	}

	status, _, err := s.Post(s.requestURI("ubc/proxies"), params)
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

// GetSchema retrieves a business object data model by type
func (s *SAPService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	uri := s.requestURI(fmt.Sprintf("ubc/business_object_models/%s", recordType))
	status, resp, err := s.Get(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch business object model; status: %v", status)
	}

	return resp, nil
}

// CreateObject is a generic way to create a business object in the SAP environment
func (s *SAPService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	status, resp, err := s.Post(s.requestURI("ubc/business_objects"), params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
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

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	uri := s.requestURI(fmt.Sprintf("ubc/business_objects/%s", id))
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

	if baselineID, baselineIDOk := params["baseline_id"].(string); baselineIDOk {
		params["object_connection_id"] = baselineID
	}

	uri := s.requestURI(fmt.Sprintf("ubc/business_objects/%s/status", id))
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

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *SAPService) DeleteProxyConfiguration(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return err
	}

	uri := s.requestURI(fmt.Sprintf("ubc/organizations/%s/proxy", organizationID))
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

	status, _, err := s.Get(s.requestURI("ubc/status"), map[string]interface{}{})
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

	uri := s.requestURI(fmt.Sprintf("ubc/organizations/%s/proxy", organizationID))
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

	status, resp, err := s.Post(s.requestURI("zcona/test"), params)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to initiate business object; status: %v", status)
	}

	return resp, nil
}
