package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

var (
	globalOutput = os.Stdout
	globalError  = os.Stderr
)

func main() {

	app := &cli.App{
		Name: "cenobite",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Value:    "/var/cenobite/config",
				Usage:    "specify path for cenobite configuration",
				Required: false,
			},
		},
		Action: func(c *cli.Context) error {
			return entry(c)
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintln(globalError, err)
		fmt.Fprintln(globalError, "Try cenobite --help")
		os.Exit(-1)
	}
}

func entry(c *cli.Context) error {
	configPath := c.String("config")
	config, err := readConfig(configPath)
	if err != nil {
		return err
	}

	return nil
}
