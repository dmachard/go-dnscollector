package collectors

import (
	"bytes"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

// DnsDataStruct is a struct that holds DNS data
type DnsDataStruct struct {
	// DNS payload
	Payload []byte
	// IP layer
	IpLayer gopacket.Flow
	// Transport layer
	TransportLayer gopacket.Flow
	// Timestamp
	Timestamp time.Time
}

type DnsStreamFactory struct {
	// Channel to send reassembled DNS data
	reassembled chan DnsDataStruct
}

func (s *DnsStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	return &stream{
		net:         net,
		transport:   transport,
		data:        make([]byte, 0),
		reassembled: s.reassembled,
	}
}

type stream struct {
	net, transport gopacket.Flow
	data           []byte
	lenDns         int
	LastSeen       time.Time
	reassembled    chan DnsDataStruct
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

		}

		if len(s.data) == s.lenDns+2 {
			s.LastSeen = r.Seen

			// send the reassembled data to the channel
			s.reassembled <- DnsDataStruct{
				Payload:        s.data[2 : s.lenDns+2],
				IpLayer:        s.net,
				TransportLayer: s.transport,
				Timestamp:      s.LastSeen,
			}

			//Reset the buffer.
			s.data = s.data[s.lenDns+2:]
			s.lenDns = 0

		}
	}
}

func (s *stream) ReassemblyComplete() {}
