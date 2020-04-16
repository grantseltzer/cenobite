package main

type event_type uint8

const (
	EVENT_INVALID       = 0
	EVENT_SYSCALL uint8 = iota
	EVENT_KPROBE
)

type event interface{}

type syscall_event struct {
	Name   string
	Number uint16
}
type kprobe_event struct {
	SymbolName string
	Address    uint64
}

type config struct {
	EventsToTrace []event
}

func readConfig(path string) (*config, error) {
	return nil, nil
}
