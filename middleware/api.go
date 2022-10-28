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

import "github.com/provideplatform/provide-go/common"

const systemTypeDynamics365 = "dynamics365"
const systemTypeEphemeralMemory = "ephemeral"
const systemTypeExcel = "excel"
const systemTypeSalesforce = "salesforce"
const systemTypeSAP = "sap"
const systemTypeServiceNow = "servicenow"

const SORBusinessObjectStatusError = "error"
const SORBusinessObjectStatusSuccess = "success"

// SystemMetadata is a convenience wrapper for parsing encrypted secret
type SystemMetadata struct {
	Auth        *SystemAuth       `sql:"-" json:"auth,omitempty"`
	EndpointURL *string           `sql:"-" json:"endpoint_url"`
	Middleware  *SystemMiddleware `sql:"-" json:"middleware,omitempty"`
	Name        *string           `sql:"-" json:"name"`
	Type        *string           `sql:"-" json:"type"`
}

// SystemAuth defines authn/authz params
type SystemAuth struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Method      *string `json:"method"`
	Username    *string `json:"username"`
	Password    *string `json:"password,omitempty"`
	Token       *string `json:"token,omitempty"`

	RequireClientCredentials bool    `json:"require_client_credentials"`
	ClientID                 *string `json:"client_id,omitempty"`
	ClientSecret             *string `json:"client_secret,omitempty"`
}

// SystemMiddleware defines middleware for inbound and outbound middleware
type SystemMiddlewarePolicy struct {
	Auth *SystemAuth `json:"auth"`
	Name *string     `json:"name"`
	URL  *string     `json:"url"`
}

// SystemMiddleware defines middleware for inbound and outbound middleware
type SystemMiddleware struct {
	Inbound  *SystemMiddlewarePolicy `json:"inbound,omitempty"`
	Outbound *SystemMiddlewarePolicy `json:"outbound,omitempty"`
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

// SystemFactory initializes and returns a system using the given middleware params
func SystemFactory(params *SystemMetadata) SOR {
	if params.Name == nil {
		common.Log.Warningf("middleware factory requires a name parameter")
		return nil
	}

	if params.Type == nil {
		common.Log.Warningf("middleware factory requires a type parameter for system: %s", *params.Name)
		return nil
	}

	switch *params.Type {
	case systemTypeDynamics365:
		return Dynamics365Factory(params)
	case systemTypeEphemeralMemory:
		return EphemeralMemoryFactory(params)
	case systemTypeExcel:
		return ExcelFactory(params)
	case systemTypeSAP:
		return SAPFactory(params)
	case systemTypeSalesforce:
		return SalesforceFactory(params)
	case systemTypeServiceNow:
		return ServiceNowFactory(params)
	default:
		break
	}

	return nil
}
