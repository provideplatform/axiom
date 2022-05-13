/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package middleware

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
	ListSchemas(params map[string]interface{}) (interface{}, error)
	GetSchema(recordType string, params map[string]interface{}) (interface{}, error)
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
