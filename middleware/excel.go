package middleware

import (
	"fmt"
	"sync"

	"github.com/provideplatform/provide-go/api"
)

// ExcelService
type ExcelService struct {
	api.Client
	mutex sync.Mutex
}

// InitExcelService convenience method to initialize a default `ExcelService` instance
func InitExcelService(token *string) *ExcelService {
	return &ExcelService{
		api.Client{
			Token: token,
		},
		sync.Mutex{},
	}
}

// Authenticate is not implemented for Excel at this time
func (s *ExcelService) Authenticate() error {
	return nil
}

// ConfigureProxy configures a new proxy instance - not implemented for Excel at this time
func (s *ExcelService) ConfigureProxy(params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ListSchemas retrieves a list of available schemas
func (s *ExcelService) ListSchemas(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// GetSchema retrieves a business object model by type
func (s *ExcelService) GetSchema(recordType string, params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// CreateObject is a generic way to create a business object in the Excel environment
func (s *ExcelService) CreateObject(params map[string]interface{}) (interface{}, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return nil, fmt.Errorf("not implemented")
}

// UpdateObject updates a business object
func (s *ExcelService) UpdateObject(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// UpdateObjectStatus updates the status of a business object
func (s *ExcelService) UpdateObjectStatus(id string, params map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// DeleteProxyConfiguration drops a proxy configuration for the given organization
func (s *ExcelService) DeleteProxyConfiguration(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// HealthCheck checks the health of the instance - not implemented for Excel at this time
func (s *ExcelService) HealthCheck() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}

// ProxyHealthCheck
func (s *ExcelService) ProxyHealthCheck(organizationID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Errorf("not implemented")
}
