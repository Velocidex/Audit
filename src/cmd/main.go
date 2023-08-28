package main

import (
	"os"

	kingpin "github.com/alecthomas/kingpin/v2"
)

type CommandHandler func(command string) bool

var (
	app              = kingpin.New("scaparse", "Parse SCA rules and produce VQL.")
	command_handlers []CommandHandler
)

func main() {
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	for _, command_handler := range command_handlers {
		if command_handler(command) {
			break
		}
	}
}

func FatalIfError(command *kingpin.CmdClause, cb func() error) {
	err := cb()
	kingpin.FatalIfError(err, command.FullCommand())
}
