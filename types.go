package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

type procInfo struct {
	Pid      uint32 `json:"pid,omitempty"`
	Ppid     uint32 `json:"ppid,omitempty"`
	OldEUID  uint32 `json:"old_euid"`
	OldEGID  uint32 `json:"old_egid"`
	NewEUID  uint32 `json:"new_euid"`
	NewEGID  uint32 `json:"new_egid"`
	Comm     string `json:"comm,omitempty"`
	Function string `json:"function,omitempty"`
}

// unmarshalBinary for procInfo
func (i *procInfo) unmarshalBinary(data []byte) error {

	data = bytes.Trim(data, "\x00")

	i.Pid = binary.LittleEndian.Uint32(data[0:4])
	i.Ppid = binary.LittleEndian.Uint32(data[4:8])

	i.OldEUID = binary.LittleEndian.Uint32(data[8:12])
	i.OldEGID = binary.LittleEndian.Uint32(data[12:16])

	i.NewEUID = binary.LittleEndian.Uint32(data[16:20])
	i.NewEGID = binary.LittleEndian.Uint32(data[20:24])

	i.Comm = strings.SplitN(string(data[24:40]), "\u0000", 2)[0]
	i.Function = strings.SplitN(string(data[40:]), "\u0000", 2)[0]

	return nil
}
