package main

import (
	"reflect"
	"fmt"
)

func main() {

	var stu Student
	t := reflect.TypeOf(stu)
	field, b := t.FieldByName("Name")
	fmt.Println(field,b)
}


type Student struct {
	Name    string  `json:"name"`
	Age     int		`json:"age"`
	Grade   int     `json:"grade"`
}
