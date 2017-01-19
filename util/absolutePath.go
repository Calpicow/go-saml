package util

import (
	"fmt"
	"path"

	"github.com/kardianos/osext"
)

//AbsolutePath get absolute path from string file path
//Panics if path is a directory
func AbsolutePath(aPath string) string {
	if path.IsAbs(aPath) {
		return aPath
	}
	wd, err := osext.ExecutableFolder()
	if err != nil {
		panic(err)
	}
	fmt.Println("Working directory", wd)
	return path.Join(wd, aPath)
}
