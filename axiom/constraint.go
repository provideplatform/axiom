package axiom

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	dbconf "github.com/kthomas/go-db-config"
	uuid "github.com/kthomas/go.uuid"
	"github.com/provideplatform/axiom/common"
	provide "github.com/provideplatform/provide-go/api"
)

const constraintOperatorEqual = "=="
const constraintOperatorLessThan = "<"
const constraintOperatorLessThanOrEqual = "<="
const constraintOperatorGreaterThan = ">"
const constraintOperatorGreaterThanOrEqual = ">="
const constraintOperandNil = "nil"

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
func (c *Constraint) Create(tx *gorm.DB) bool {
	_tx := tx
	if _tx == nil {
		db := dbconf.DatabaseConnection()
		_tx = db.Begin()
		defer _tx.RollbackUnlessCommitted()
	}

	if !c.Validate() {
		return false
	}

	success := false

	if _tx.NewRecord(c) {
		result := _tx.Create(&c)
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

	if success && tx == nil {
		_tx.Commit()
	}

	return success
}

// Update the constraint
func (c *Constraint) Update(constraint *Constraint) bool {
	if !c.Validate() {
		return false
	}

	c.Description = constraint.Description
	c.Expression = constraint.Expression
	c.ExecutionRequirement = constraint.ExecutionRequirement
	c.FinalityRequirement = constraint.FinalityRequirement

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

func (c *Constraint) evaluate(params map[string]interface{}) error {
	if c.Expression == nil {
		return errors.New("cannot evaluate constraint with nil expression")
	}

	tokens := make([]string, 0)
	for _, token := range strings.Fields(*c.Expression) {
		if len(token) == 0 {
			continue
		}

		tokens = append(tokens, token)
	}

	if len(tokens) != 3 {
		return errors.New("cannot evaluate malformed constraint; should have exactly two operands and one operator")
	}

	loperand := tokens[0]
	operator := tokens[1]
	roperand := tokens[2]

	common.Log.Debugf("attempting to evaluate constraint %s %s %s", loperand, operator, roperand)

	// TODO-- extract value from field pointed to by `loperand``
	// val := params[loperand]

	switch operator {
	case constraintOperatorEqual:
	case constraintOperatorGreaterThan:
	case constraintOperatorGreaterThanOrEqual:
	case constraintOperatorLessThan:
	case constraintOperatorLessThanOrEqual:
	default:
		return fmt.Errorf("cannot evaluate malformed constraint; invalid operator: %s", operator)
	}

	return nil
}
