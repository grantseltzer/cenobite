package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type procInfo struct {
	Pid      uint32 `json:"pid,omitempty"`
	Ppid     uint32 `json:"ppid,omitempty"`
	NewUID   uint32 `json:"new_uid,omitempty"`
	NewGID   uint32 `json:"new_gid,omitempty"`
	Comm     string `json:"comm,omitempty"`
	Function string `json:"function,omitempty"`
}

// unmarshalBinary for procInfo
func (i *procInfo) unmarshalBinary(data []byte) error {

	data = bytes.Trim(data, "\x00")
	if len(data) < 16 {
		return fmt.Errorf("error decoding process info")
	}

	i.Pid = binary.LittleEndian.Uint32(data[0:4])
	i.Ppid = binary.LittleEndian.Uint32(data[4:8])
	i.NewUID = binary.LittleEndian.Uint32(data[8:12])
	i.NewGID = binary.LittleEndian.Uint32(data[12:16])
	i.Comm = string(data[16:32])
	i.Function = string(data[32:])

	return nil
}
