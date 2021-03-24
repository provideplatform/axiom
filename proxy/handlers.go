package proxy

import (
	"encoding/json"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/provideapp/baseline-proxy/common"
	provide "github.com/provideservices/provide-go/common"
	"github.com/provideservices/provide-go/common/util"
)

// InstallProxyAPI installs system of record proxy API
func InstallProxyAPI(r *gin.Engine) {
	r.POST("/api/v1/business_objects", createBusinessObjectHandler)
	r.PUT("/api/v1/business_objects/:id", updateBusinessObjectHandler)

	r.PUT("/api/v1/config", configurationHandler)
}

func configurationHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	cfg := &Config{}
	err = json.Unmarshal(buf, cfg)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if cfg.OrganizationID != nil && cfg.OrganizationID.String() != organizationID.String() {
		provide.RenderError("forbidden", 403, c)
		return
	}

	if cfg.apply() {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = cfg.Errors
		provide.Render(obj, 422, c)
	}
}

func createBusinessObjectHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	message := &Message{}
	err = json.Unmarshal(buf, message)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if message.baselineOutbound() {
		message.ProtocolMessage.Payload.Object = nil
		provide.Render(message.ProtocolMessage, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = message.Errors
		provide.Render(obj, 422, c)
	}
}

func updateBusinessObjectHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	record := lookupBaselineRecordByInternalID(c.Param("id"))
	if record == nil {
		provide.RenderError(fmt.Sprintf("baseline record not found"), 404, c)
		return
	}

	message := &Message{}
	err = json.Unmarshal(buf, message)
	if err != nil {
		provide.RenderError(err.Error(), 422, c)
		return
	}

	if message.baselineOutbound() {
		message.ProtocolMessage.Payload.Object = nil
		provide.Render(message.ProtocolMessage, 202, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = message.Errors
		provide.Render(obj, 422, c)
	}
}
