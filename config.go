package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type config struct {
	EventsToTrace []event
}

type event struct {
	FunctionName string
}

func (e event) getFunctionName() string {
	return e.FunctionName
}

func (e event) normalizeName() {}

func readConfigFromFile(path string) (*config, error) {

	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %s: %s", path, err.Error())
	}

	config := &config{}
	err = json.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("could not parse config: %s", err.Error())
	}

	// Normalize names of specified events (for syscalls)
	for _, e := range config.EventsToTrace {
		e.normalizeName()
	}

	return config, nil
}
