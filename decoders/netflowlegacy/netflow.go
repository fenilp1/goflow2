// Package netflowlegacy decodes NetFlow v5 packets.
package netflowlegacy

import (
	"bytes"
	"fmt"

	"github.com/netsampler/goflow2/v2/decoders/utils"
)

// netFlowV5RecordSize is the wire size of one NetFlow v5 flow record.
const netFlowV5RecordSize = 48

// DecoderError wraps a NetFlow legacy decode error.
type DecoderError struct {
	Err error
}

func (e *DecoderError) Error() string {
	return fmt.Sprintf("NetFlowLegacy %s", e.Err.Error())
}

func (e *DecoderError) Unwrap() error {
	return e.Err
}

// DecodeMessageVersion reads the version and decodes a NetFlow v5 message.
func DecodeMessageVersion(payload *bytes.Buffer, packet *PacketNetFlowV5) error {
	var version uint16
	if err := utils.BinaryDecoder(payload, &version); err != nil {
		return err
	}
	packet.Version = version
	if packet.Version != 5 {
		return &DecoderError{fmt.Errorf("unknown version %d", version)}
	}
	return DecodeMessage(payload, packet)
}

// DecodeMessage decodes the NetFlow v5 header and records from the payload.
func DecodeMessage(payload *bytes.Buffer, packet *PacketNetFlowV5) error {
	if err := utils.BinaryDecoder(payload,
		&packet.Count,
		&packet.SysUptime,
		&packet.UnixSecs,
		&packet.UnixNSecs,
		&packet.FlowSequence,
		&packet.EngineType,
		&packet.EngineId,
		&packet.SamplingInterval,
	); err != nil {
		return &DecoderError{err}
	}

	// Size the slice from the records the payload can hold, not from Count:
	// a short payload with a large Count must not yield zero-value records.
	count := min(int(packet.Count), payload.Len()/netFlowV5RecordSize)
	packet.Records = make([]RecordsNetFlowV5, count)
	for i := 0; i < count; i++ {
		record := RecordsNetFlowV5{}
		var srcAddr, dstAddr, nextHop uint32

		if err := utils.BinaryDecoder(payload,
			&srcAddr,
			&dstAddr,
			&nextHop,
			&record.Input,
			&record.Output,
			&record.DPkts,
			&record.DOctets,
			&record.First,
			&record.Last,
			&record.SrcPort,
			&record.DstPort,
			&record.Pad1,
			&record.TCPFlags,
			&record.Proto,
			&record.Tos,
			&record.SrcAS,
			&record.DstAS,
			&record.SrcMask,
			&record.DstMask,
			&record.Pad2,
		); err != nil {
			return &DecoderError{err}
		}
		record.SrcAddr = IPAddress(srcAddr)
		record.DstAddr = IPAddress(dstAddr)
		record.NextHop = IPAddress(nextHop)
		packet.Records[i] = record
	}

	return nil
}
