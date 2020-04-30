package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

	return config, nil
}
