package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/iovisor/gobpf/bcc"
)

type config struct {
	EventsToTrace []event
}

type event_type uint8

const (
	EVENT_INVALID       = 0
	EVENT_SYSCALL uint8 = iota
	EVENT_KPROBE
)

type event interface {
	getNormalizedName()
}

type syscall_event struct {
	SpecifiedName string
	FunctionName  string
	Number        uint16
}

type kprobe_event struct {
	SpecifiedName string
	FunctionName  string
	Address       uint64
}

func (s syscall_event) getNormalizedName() {
	s.FunctionName = bcc.GetSyscallFnName(s.SpecifiedName)
}

func (k kprobe_event) getNormalizedName() {
	//TODO:
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

	// Normalize names of specified events

	for _, e := range config.EventsToTrace {
		e.getNormalizedName()
	}

	return config, nil
}
