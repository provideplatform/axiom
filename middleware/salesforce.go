package middleware

import (
	"fmt"
	"os"
	"sync"

	"github.com/provideplatform/provide-go/api"
)

const defaultSalesforceHost = "testnet.dappsuite.network"
const defaultSalesforcePath = "api"
const defaultSalesforceScheme = "https"

// SalesforceService for the SAP API
type SalesforceService struct {
	api.Client
	mutex sync.Mutex
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

// ConfigureProxy configures a new proxy instance in Salesforce for a given organization
func (s *SalesforceService) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// GetObjectModel retrieves a business object model by type
func (s *SalesforceService) GetObjectModel(recordType string, params map[string]interface{}) (interface{}, error) {
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

	_params := params
	if payload, payloadOk := params["payload"].(map[string]interface{}); payloadOk {
		if replicate, replicateOk := payload["replicate"].(map[string]interface{}); replicateOk {
			_params = replicate
		}
	}

	status, resp, err := s.Post("business_objects", _params)
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

	_params := params
	if payload, payloadOk := params["payload"].(map[string]interface{}); payloadOk {
		if replicate, replicateOk := payload["replicate"].(map[string]interface{}); replicateOk {
			_params = replicate
		}
	}

	uri := fmt.Sprintf("business_objects/%s", id)
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
func (s *SalesforceService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *SalesforceService) DeleteProxyConfiguration(organizationID string) error {
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

// ProxyHealthCheck
func (s *SalesforceService) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
