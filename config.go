package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/iovisor/gobpf/bcc"
)

type config struct {
	EventsToTrace []event `json:"events_to_trace"`
}

type event struct {
	FunctionName string `json:"function_name"`
}

func (e *event) getFunctionName() string {
	return e.FunctionName
}

func (e *event) normalizeName() {
	e.FunctionName = bcc.GetSyscallFnName(e.FunctionName)
}

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
	for i := range config.EventsToTrace {
		config.EventsToTrace[i].normalizeName()
	}

	return config, nil
}
