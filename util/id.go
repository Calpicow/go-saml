package util

import "github.com/nu7hatch/gouuid"

//ID generate a new V4 UUID
func ID() string {
	u, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}
	return "_" + u.String()
}
