package netlib

import (
	"bytes"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type DnsStreamFactory struct {
	// Channel to send reassembled DNS data
	Reassembled    chan DnsPacket
	IpDefragmented bool
}

func (s *DnsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &stream{
		net:            net,
		transport:      transport,
		data:           make([]byte, 0),
		reassembled:    s.Reassembled,
		ipDefragmented: s.IpDefragmented,
	}
}

type stream struct {
	net, transport gopacket.Flow
	data           []byte
	lenDns         int
	LastSeen       time.Time
	reassembled    chan DnsPacket
	tcpReassembled bool
	ipDefragmented bool
}

func (s *stream) Reassembled(rs []tcpassembly.Reassembly) {
	for _, r := range rs {
		if r.Skip > 0 {
			continue
		}
		// Append the reassembled data to the existing data
		s.data = append(s.data, r.Bytes...)

		// If the length of the DNS message has not been read yet, try to read it from the TCP stream
		if s.lenDns == 0 {
			lenBuf := make([]byte, 2)

			reader := bytes.NewReader(s.data)
			nRead, err := io.ReadFull(reader, lenBuf)
			if err != nil {
				continue
			}
			if nRead < 2 {
				continue
			}

			// Convert the length of the DNS message from the buffer to a uint
			s.lenDns = int(uint(lenBuf[0])<<8 | uint(lenBuf[1]))
			s.tcpReassembled = false
		}

		if len(s.data) == s.lenDns+2 {
			s.LastSeen = r.Seen

			// send the reassembled data to the channel
			s.reassembled <- DnsPacket{
				Payload:        s.data[2 : s.lenDns+2],
				IpLayer:        s.net,
				TransportLayer: s.transport,
				Timestamp:      s.LastSeen,
				IpDefragmented: s.ipDefragmented,
				TcpReassembled: s.tcpReassembled,
			}

			//Reset the buffer.
			s.data = s.data[s.lenDns+2:]
			s.lenDns = 0

		} else {
			s.tcpReassembled = true
		}
	}
}

func (s *stream) ReassemblyComplete() {}
