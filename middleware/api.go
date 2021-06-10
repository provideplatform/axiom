package middleware

import "github.com/provideapp/baseline-proxy/common"

const sorIdentifierDynamics365 = "dynamics365"
const sorIdentifierEphemeralMemory = "ephemeral"
const sorIdentifierExcel = "excel"
const sorIdentifierSalesforce = "salesforce"
const sorIdentifierSAP = "sap"
const sorIdentifierServiceNow = "servicenow"

const sorTypeGeneralConsistency = "general_consistency"
const sorTypeServiceNowIncident = "servicenow_incident"

const SORBusinessObjectStatusError = "error"
const SORBusinessObjectStatusSuccess = "success"

// SOR defines an interface for system of record backends
type SOR interface {
	ConfigureProxy(params map[string]interface{}) error
	CreateObject(params map[string]interface{}) (interface{}, error)
	DeleteProxyConfiguration(organizationID string) error
	GetObjectModel(recordType string, params map[string]interface{}) (interface{}, error)
	HealthCheck() error
	ProxyHealthCheck(organizationID string) error
	UpdateObject(id string, params map[string]interface{}) error
	UpdateObjectStatus(id string, params map[string]interface{}) error
}

// SORFactory initializes and returns a system of record interface impl
func SORFactory(params map[string]interface{}, token *string) SOR {
	switch params["identifier"].(string) {
	case sorIdentifierDynamics365:
		return InitDynamics365Service(token)
	case sorIdentifierEphemeralMemory:
		return InitEphemeralMemoryService(token)
	case sorIdentifierSAP:
		return InitSAPService(token)
	case sorIdentifierSalesforce:
		return InitSalesforceService(token)
	case sorIdentifierServiceNow:
		return InitServiceNowService(token)
	default:
		break
	}

	return nil
}

// SORFactoryByType initializes and returns a system of record interface impl for the given type
func SORFactoryByType(recordType string, token *string) SOR {
	switch recordType {
	case sorTypeGeneralConsistency:
		return InitEphemeralMemoryService(token)
	case sorTypeServiceNowIncident:
		return InitServiceNowService(token)
	default:
		break
	}

	return SORFactory(common.InternalSOR, token)
}
