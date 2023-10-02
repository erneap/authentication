package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/erneap/go-models/config"
	"github.com/erneap/go-models/employees"
	"github.com/erneap/go-models/users"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// Every service will have functions for completing the CRUD functions
// the retrieve functions will be for individual employee and the whole list of
// site's employees

// Create Employee
// Most employees will have a log in account to allow them to view the
// schedule data.  So a comparison of their possible authentication account is
// made to ensure their object ID is the same.
func CreateEmployee(emp employees.Employee, passwd, workgroup, teamID,
	siteid string) (*employees.Employee, error) {
	userCol := config.GetCollection(config.DB, "authenticate", "users")
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	teamid, err := primitive.ObjectIDFromHex(teamID)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"name.firstName": emp.Name.FirstName,
		"name.lastName":  emp.Name.LastName,
		"team":           teamid,
	}

	// first check to see of an employee already exists for this first and last
	// name.  If present, change filter to include middle if not blank, but if
	// middle is blank, return old employee record
	var tEmp employees.Employee
	err = empCol.FindOne(context.TODO(), filter).Decode(&tEmp)
	if err == nil || err != mongo.ErrNoDocuments {
		if emp.Name.MiddleName == "" {
			return &emp, nil
		}
		filter = bson.M{
			"name.firstName":  emp.Name.FirstName,
			"name.middleName": emp.Name.MiddleName,
			"name.lastName":   emp.Name.LastName,
			"team":            teamid,
		}

		err = empCol.FindOne(context.TODO(), filter).Decode(&emp)
		if err == nil || err != mongo.ErrNoDocuments {
			return &emp, nil
		}
	}

	// check user collection for new employee
	filter = bson.M{
		"firstName": emp.Name.FirstName,
		"lastName":  emp.Name.LastName,
	}

	var user users.User

	err = userCol.FindOne(context.TODO(), filter).Decode(&user)
	if err == mongo.ErrNoDocuments {
		emp.ID = primitive.NewObjectID()
		// create user record with provided password.
		user = users.User{
			ID:           emp.ID,
			EmailAddress: emp.Email,
			FirstName:    emp.Name.FirstName,
			MiddleName:   emp.Name.MiddleName,
			LastName:     emp.Name.LastName,
			Workgroups: []string{
				"scheduler-employee",
			},
		}
		if workgroup != "" {
			user.Workgroups = append(user.Workgroups, workgroup)
		}
		user.SetPassword(passwd)
		userCol.InsertOne(context.TODO(), user)
	} else {
		emp.ID = user.ID
	}

	emp.TeamID = teamid
	emp.SiteID = siteid

	empCol.InsertOne(context.TODO(), emp)
	return &emp, nil
}

func GetEmployee(id string) (*employees.Employee, error) {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	oEmpID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	filter := bson.M{
		"_id": oEmpID,
	}

	var emp employees.Employee
	err = empCol.FindOne(context.TODO(), filter).Decode(&emp)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}
	var user users.User
	userCol.FindOne(context.TODO(), filter).Decode(&user)
	emp.User = &user
	return &emp, nil
}

func GetEmployeeByName(first, middle, last string) (*employees.Employee, error) {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	filter := bson.M{
		"name.firstname":  first,
		"name.middlename": middle,
		"name.lastname":   last,
	}

	var emp employees.Employee
	err := empCol.FindOne(context.TODO(), filter).Decode(&emp)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			filter = bson.M{
				"name.firstname":  first,
				"name.middlename": middle[:1],
				"name.lastname":   last,
			}
			err = empCol.FindOne(context.TODO(), filter).Decode(&emp)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	var user users.User
	filter = bson.M{
		"_id": emp.ID,
	}
	userCol.FindOne(context.TODO(), filter).Decode(&user)
	emp.User = &user

	return &emp, nil
}

func GetEmployees(teamid, siteid string) ([]employees.Employee, error) {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	oTID, _ := primitive.ObjectIDFromHex(teamid)
	filter := bson.M{
		"team": oTID,
		"site": siteid,
	}

	var employees []employees.Employee

	cursor, err := empCol.Find(context.TODO(), filter)
	if err != nil {
		return employees[:0], err
	}

	if err = cursor.All(context.TODO(), &employees); err != nil {
		log.Println(err)
	}

	for i, emp := range employees {
		filter = bson.M{
			"_id": emp.ID,
		}
		var user users.User
		userCol.FindOne(context.TODO(), filter).Decode(&user)
		emp.User = &user
		employees[i] = emp
	}

	return employees, nil
}

func GetEmployeesForTeam(teamid string) ([]employees.Employee, error) {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	oTID, _ := primitive.ObjectIDFromHex(teamid)
	filter := bson.M{
		"team": oTID,
	}

	var employees []employees.Employee

	cursor, err := empCol.Find(context.TODO(), filter)
	if err != nil {
		return employees[:0], err
	}

	if err = cursor.All(context.TODO(), &employees); err != nil {
		log.Println(err)
	}

	for i, emp := range employees {
		filter = bson.M{
			"_id": emp.ID,
		}
		var user users.User
		userCol.FindOne(context.TODO(), filter).Decode(&user)
		emp.User = &user
		employees[i] = emp
	}

	return employees, nil
}

func UpdateEmployee(emp *employees.Employee) error {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")

	filter := bson.M{
		"_id": emp.ID,
	}

	_, err := empCol.ReplaceOne(context.TODO(), filter, emp)
	return err
}

func DeleteEmployee(empID string) error {
	empCol := config.GetCollection(config.DB, "scheduler", "employees")
	userCol := config.GetCollection(config.DB, "authenticate", "users")

	oEmpID, _ := primitive.ObjectIDFromHex(empID)
	filter := bson.M{
		"_id": oEmpID,
	}

	result, err := empCol.DeleteOne(context.TODO(), filter)
	if err != nil {
		return err
	}
	if result.DeletedCount <= 0 {
		return errors.New("employee not found")
	}

	var user users.User
	err = userCol.FindOne(context.TODO(), filter).Decode(&user)
	if err == nil {
		found := false
		for i := len(user.Workgroups) - 1; i >= 0; i-- {
			parts := strings.Split(user.Workgroups[i], "-")
			if strings.EqualFold(parts[0], "scheduler") {
				found = true
				user.Workgroups = append(user.Workgroups[:i], user.Workgroups[i+1:]...)
			}
		}
		if found && len(user.Workgroups) > 0 {
			userCol.UpdateOne(context.TODO(), filter, user)
		} else {
			_, err = userCol.DeleteOne(context.TODO(), filter)
			if err != nil {
				fmt.Println(err.Error())
			}
		}
	}
	return nil
}
