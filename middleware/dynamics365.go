package middleware

import (
	"fmt"
	"sync"

	"github.com/provideservices/provide-go/api"
)

// Dynamics365Service for the D365 API
type Dynamics365Service struct {
	api.Client
	mutex sync.Mutex
}

// InitDefaultDynamics365Service convenience method to initialize a default `sap.Dynamics365Service` (i.e., production) instance
func InitDefaultDynamics365Service(token *string) *Dynamics365Service {
	return &Dynamics365Service{
		api.Client{
			Token: token,
		},
		sync.Mutex{},
	}
}

// Authenticate a user by email address and password, returning a newly-authorized X-CSRF-Token token
func (s *Dynamics365Service) Authenticate() error {
	return nil
}

// ConfigureProxy configures a new proxy instance in D365 for a given organization
func (s *Dynamics365Service) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// CreateBusinessObject is a generic way to create a business object in the D365 environment
func (s *Dynamics365Service) CreateBusinessObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// UpdateBusinessObject updates a business object
func (s *Dynamics365Service) UpdateBusinessObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// UpdateBusinessObjectStatus updates the status of a business object
func (s *Dynamics365Service) UpdateBusinessObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *Dynamics365Service) DeleteProxyConfiguration(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the D365 instance
func (s *Dynamics365Service) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ProxyHealthCheck
func (s *Dynamics365Service) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
