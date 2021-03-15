package middleware

import (
	"fmt"
	"sync"

	"github.com/provideservices/provide-go/api"
)

// ServiceNowService for the SAP API
type ServiceNowService struct {
	api.Client
	mutex sync.Mutex
}

// InitServiceNowService convenience method to initialize an `ServiceNowService` instance
func InitServiceNowService(token *string) *ServiceNowService {
	return &ServiceNowService{
		api.Client{
			Token: token,
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

// CreateBusinessObject is a generic way to create a business object in the ServiceNow environment
func (s *ServiceNowService) CreateBusinessObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// UpdateBusinessObject updates a business object
func (s *ServiceNowService) UpdateBusinessObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// UpdateBusinessObjectStatus updates the status of a business object
func (s *ServiceNowService) UpdateBusinessObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
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

	return fmt.Errorf("not implemented")
}

// ProxyHealthCheck
func (s *ServiceNowService) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
