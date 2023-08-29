package main

import (
	"fmt"
	"os"

	"github.com/Velocidex/Audit/src/generator"
)

var (
	build_vql_cmd = app.Command(
		"vql", "Build the VQL statements")
	build_vql_file_arg = build_vql_cmd.Arg(
		"file", "The model file to compile",
	).Required().String()
	build_vql_name = build_vql_cmd.Flag("name", "Artifact name").
			Default("Audit").String()
)

func doBuildVQL() error {
	old_model, err := generator.LoadModel(*build_vql_file_arg)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	fmt.Println(old_model.BuildArtifact(*build_vql_name))

	return nil
}

func init() {
	command_handlers = append(command_handlers, func(command string) bool {
		switch command {
		case build_vql_cmd.FullCommand():
			FatalIfError(build_vql_cmd, doBuildVQL)
		}
		return false
	})
}
