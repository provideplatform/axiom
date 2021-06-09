package middleware

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultServiceNowHost = "base2demo.service-now.com"
const defaultServiceNowPath = "api/now/table"
const defaultServiceNowScheme = "https"
const defaultServiceNowUsername = "admin"
const defaultServiceNowPassword = "providenow"
const defaultServiceNowReachabilityTimeout = time.Second * 5

// ServiceNowService for the SAP API
type ServiceNowService struct {
	api.Client
	mutex sync.Mutex
}

// InitServiceNowService convenience method to initialize a ServiceNow instance
func InitServiceNowService(token *string) *ServiceNowService {
	host := defaultServiceNowHost
	if os.Getenv("SERVICENOW_API_HOST") != "" {
		host = os.Getenv("SERVICENOW_API_HOST")
	}

	path := defaultServiceNowPath
	if os.Getenv("SERVICENOW_API_PATH") != "" {
		path = os.Getenv("SERVICENOW_API_PATH")
	}

	scheme := defaultServiceNowScheme
	if os.Getenv("SERVICENOW_API_SCHEME") != "" {
		scheme = os.Getenv("SERVICENOW_API_SCHEME")
	}

	username := defaultServiceNowUsername
	if os.Getenv("SERVICENOW_API_USERNAME") != "" {
		username = os.Getenv("SERVICENOW_API_USERNAME")
	}

	password := defaultServiceNowPassword
	if os.Getenv("SERVICENOW_API_PASSWORD") != "" {
		password = os.Getenv("SERVICENOW_API_PASSWORD")
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
	}
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *ServiceNowService) Authenticate() error {
	return nil
}

// ConfigureProxy configures a new proxy instance in ServiceNow for a given organization
func (s *ServiceNowService) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// GetBusinessObjectModel retrieves a business object model by type
func (s *ServiceNowService) GetBusinessObjectModel(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateBusinessObject is a generic way to create a business object in the ServiceNow environment
func (s *ServiceNowService) CreateBusinessObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	err := s.Authenticate()
	if err != nil {
		return nil, err
	}

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

	return resp, nil
}

// UpdateBusinessObject updates a business object
func (s *ServiceNowService) UpdateBusinessObject(id string, params map[string]interface{}) error {
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

// UpdateBusinessObjectStatus updates the status of a business object
func (s *ServiceNowService) UpdateBusinessObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *ServiceNowService) DeleteProxyConfiguration(organizationID string) error {
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

	return err
}

// ProxyHealthCheck
func (s *ServiceNowService) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
