package middleware

import "github.com/provideplatform/provide-go/common"

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

type System struct {
	Auth        *SystemAuthentication `json:"auth"`
	EndpointURL *string               `json:"endpoint_url"`
	Name        *string               `json:"name"`
	System      *string               `json:"system"`
	Type        *string               `json:"type"`
}

type SystemAuthentication struct {
	Method                   *string `json:"method"`
	Username                 *string `json:"username"`
	Password                 *string `json:"password"`
	RequireClientCredentials bool    `json:"require_client_credentials"`
	ClientID                 *string `json:"client_id"`
	ClientSecret             *string `json:"client_secret"`
	Token                    *string `json:"token"`
}

// SOR defines an interface for system of record backends
type SOR interface {
	ConfigureTenant(params map[string]interface{}) error
	CreateObject(params map[string]interface{}) (interface{}, error)
	DeleteTenant(organizationID string) error
	ListSchemas(params map[string]interface{}) (interface{}, error)
	GetSchema(recordType string, params map[string]interface{}) (interface{}, error)
	HealthCheck() error
	TenantHealthCheck(organizationID string) error
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
	case sorIdentifierExcel:
		return InitExcelService(token)
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
func SORFactoryByType(params map[string]interface{}, recordType string, token *string) SOR {
	switch recordType {
	case sorTypeGeneralConsistency:
		return InitEphemeralMemoryService(token)
	case sorTypeServiceNowIncident:
		return InitServiceNowService(token)
	default:
		break
	}

	return SORFactory(params, token)
}

// SystemFactory initializes and returns a system using the given middleware params
func SystemFactory(params *System) SOR {
	if params.Name == nil && params.System == nil {
		common.Log.Warningf("middleware system factory called with invalid system identifier")
	}

	identifier := params.Name
	if identifier == nil {
		// HACK!!!
		identifier = params.System
	}

	switch *identifier {
	case sorIdentifierDynamics365:
		return Dynamics365Factory(params)
	case sorIdentifierEphemeralMemory:
		return EphemeralMemoryFactory(params)
	case sorIdentifierExcel:
		return ExcelFactory(params)
	case sorIdentifierSAP:
		return SAPFactory(params)
	case sorIdentifierSalesforce:
		return SalesforceFactory(params)
	case sorIdentifierServiceNow:
		return ServiceNowFactory(params)
	default:
		break
	}

	return nil
}
