package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type procInfo struct {
	Pid      uint32 `json:"pid,omitempty"`
	Ppid     uint32 `json:"ppid,omitempty"`
	Comm     string `json:"comm,omitempty"`
	Function string `json:"function,omitempty"`
}

// unmarshalBinary for procInfo
func (i *procInfo) unmarshalBinary(data []byte) error {

	data = bytes.Trim(data, "\x00")
	// proc info struct is 24 bytes long and should at least be 8 bytes long
	if len(data) < 8 {
		return fmt.Errorf("error decoding process info")
	}
	i.Pid = binary.LittleEndian.Uint32(data[0:4])
	i.Ppid = binary.LittleEndian.Uint32(data[4:8])
	i.Comm = string(data[8:15])
	i.Function = string(data[16:])

	return nil
}
