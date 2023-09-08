package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Velocidex/Audit/src/generator"
)

var (
	build_vql_cmd = app.Command(
		"vql", "Build the VQL statements")
	build_vql_file_arg = build_vql_cmd.Arg(
		"file", "The model file to compile",
	).Required().String()

	build_vql_output_dir = build_vql_cmd.Arg(
		"output", "The output directory").Required().String()
)

func doBuildVQL() error {
	old_model, err := generator.LoadModel(*build_vql_file_arg)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	artifact_name := old_model.ArtifactName
	if artifact_name == "" {
		artifact_name = "Audit"
	}

	output_file := filepath.Join(*build_vql_output_dir, artifact_name+".yaml")
	fmt.Printf("Will write file to %v\n", output_file)

	out_fd, err := os.OpenFile(output_file,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out_fd.Close()

	_, err = out_fd.Write([]byte(old_model.BuildArtifact()))
	return err
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
