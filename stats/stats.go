package stats

import (
	"encoding/json"
	"fmt"

	// FIXME
	// FIXME
	"github.com/gin-gonic/gin"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/common"
	"github.com/provideplatform/provide-go/common/util"
)

// InstallStatsAPI installs stats logging APIs
func InstallStatsAPI(r *gin.Engine) {
	r.POST("/api/v1/stats", statsLogHandler)
}

func statsLogHandler(c *gin.Context) {
	organizationID := util.AuthorizedSubjectID(c, "organization")
	if organizationID == nil {
		provide.RenderError("unauthorized", 401, c)
		return
	} else if common.OrganizationID != nil && organizationID.String() != *common.OrganizationID {
		provide.RenderError("forbidden", 403, c)
		return
	}

	var msg *LogMessage

	buf, err := c.GetRawData()
	if err != nil {
		provide.RenderError(err.Error(), 400, c)
		return
	}

	err = json.Unmarshal(buf, &msg)
	if err != nil {
		msg := fmt.Sprintf("failed to umarshal log message; %s", err.Error())
		common.Log.Warning(msg)
		provide.RenderError(msg, 422, c)
		return
	}

	if err == nil {
		provide.Render(nil, 204, c)
	} else {
		obj := map[string]interface{}{}
		obj["errors"] = []interface{}{} // FIXME
		provide.Render(obj, 422, c)
	}
}
