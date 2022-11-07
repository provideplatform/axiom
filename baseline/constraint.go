package baseline

import (
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/baseline/common"
	provide "github.com/provideplatform/provide-go/api"
)

// Constraint is a workstep constraint
type Constraint struct {
	provide.Model
	Expression           *string `json:"expression"`
	ExecutionRequirement bool    `json:"execution_requirement"`
	FinalityRequirement  bool    `json:"finality_requirement"`

	Description *string    `json:"description"`
	WorkstepID  *uuid.UUID `json:"workstep_id"`
}

// FindConstraintByID retrieves a constraint for the given id
func FindConstraintByID(id uuid.UUID) *Constraint {
	db := dbconf.DatabaseConnection()
	constraint := &Constraint{}
	db.Where("id = ?", id.String()).Find(&constraint)
	if constraint == nil || constraint.ID == uuid.Nil {
		return nil
	}
	return constraint
}

// FindConstraintsByWorkstepID retrieves a list of constraints for the given workstep id
func FindConstraintsByWorkstepID(workstepID uuid.UUID) []*Constraint {
	constraints := make([]*Constraint, 0)
	db := dbconf.DatabaseConnection()
	db.Where("workstep_id = ?", workstepID.String()).Order("created_at ASC").Find(&constraints)
	return constraints
}

// Validate a constraint
func (c *Constraint) Validate() bool {
	if c.Expression == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("expression is required"),
		})
	}

	if !c.ExecutionRequirement && !c.FinalityRequirement {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("at least one of execution or finality requirement must be true"),
		})
	}

	if c.WorkstepID == nil {
		c.Errors = append(c.Errors, &provide.Error{
			Message: common.StringOrNil("workstep_id is required"),
		})
	}

	return len(c.Errors) == 0
}

// Create a constraint
func (c *Constraint) Create() bool {
	if !c.Validate() {
		return false
	}

	success := false
	db := dbconf.DatabaseConnection()
	tx := db.Begin()
	defer tx.RollbackUnlessCommitted()

	if tx.NewRecord(&c) {
		result := tx.Create(&c)
		rowsAffected := result.RowsAffected
		errors := result.GetErrors()
		if len(errors) > 0 {
			for _, err := range errors {
				c.Errors = append(c.Errors, &provide.Error{
					Message: common.StringOrNil(err.Error()),
				})
			}
		}

		success = rowsAffected > 0
	}

	if success {
		tx.Commit()
	}

	return success
}

// Update the constraint
func (c *Constraint) Update() bool {
	if !c.Validate() {
		return false
	}

	db := dbconf.DatabaseConnection()
	result := db.Save(&c)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}
	return rowsAffected == 1 && len(errors) == 0
}

// Delete the underlying constraint
func (c *Constraint) Delete() bool {
	db := dbconf.DatabaseConnection()
	result := db.Delete(&c)
	rowsAffected := result.RowsAffected
	errors := result.GetErrors()
	if len(errors) > 0 {
		for _, err := range errors {
			c.Errors = append(c.Errors, &provide.Error{
				Message: common.StringOrNil(err.Error()),
			})
		}
	}

	return rowsAffected > 0
}
