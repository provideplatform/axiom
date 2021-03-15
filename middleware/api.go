package middleware

const sorIdentifierDynamics365 = "dynamics365"
const sorIdentifierExcel = "excel"
const sorIdentifierSAP = "sap"
const sorIdentifierServiceNow = "servicenow"

const SORBusinessObjectStatusError = "error"
const SORBusinessObjectStatusSuccess = "success"

// SOR defines an interface for system of record backends
type SOR interface {
	ConfigureProxy(params map[string]interface{}) error
	CreateBusinessObject(params map[string]interface{}) (interface{}, error)
	DeleteProxyConfiguration(organizationID string) error
	HealthCheck() error
	ProxyHealthCheck(organizationID string) error
	UpdateBusinessObject(id string, params map[string]interface{}) error
	UpdateBusinessObjectStatus(id string, params map[string]interface{}) error
}

// SORFactory initializes and returns a system of record interface impl
func SORFactory(params map[string]interface{}, token *string) SOR {
	switch params["identifier"].(string) {
	case sorIdentifierDynamics365:
		return InitDefaultDynamics365Service(token)
	case sorIdentifierSAP:
		return InitSAPService(token)
	case sorIdentifierServiceNow:
		return InitServiceNowService(token)
	default:
		break
	}

	return nil
}
