package dnsmessage

import (
	"bytes"
	"fmt"
	"strconv"
	"time"
)

type DnsMessage struct {
	Operation    string
	Identity     string
	Family       string
	Protocol     string
	QueryIp      string
	QueryPort    string
	ResponseIp   string
	ResponsePort string
	Type         string
	Payload      []byte
	Length       int
	Id           int
	Rcode        string
	Qname        string
	Qtype        string
	Latency      float64
	Timestamp    float64
	Timesec      int
	Timensec     int
}

func (dm *DnsMessage) Init() {
	dm.Operation, dm.Type = "-", "-"
	dm.Identity = "-"
	dm.Family, dm.Protocol = "-", "-"
	dm.QueryIp, dm.QueryPort = "-", "-"
	dm.ResponseIp, dm.ResponsePort = "-", "-"
	dm.Rcode, dm.Qtype = "-", "-"
	dm.Qname = "-"
}

func (dm *DnsMessage) Bytes() []byte {
	var s bytes.Buffer

	ts := time.Unix(int64(dm.Timesec), int64(dm.Timensec))
	s.WriteString(ts.UTC().Format(time.RFC3339Nano) + " ")

	s.WriteString(dm.Identity + " ")
	s.WriteString(dm.Operation + " ")
	s.WriteString(dm.Rcode + " ")
	s.WriteString(dm.QueryIp + " ")
	s.WriteString(dm.QueryPort + " ")
	s.WriteString(dm.Family + " ")
	s.WriteString(dm.Protocol + " ")
	s.WriteString(strconv.Itoa(dm.Length) + "b ")
	s.WriteString(dm.Qname + " ")
	s.WriteString(dm.Qtype + " ")
	s.WriteString(fmt.Sprintf("%.6f", dm.Latency) + "\n")

	return s.Bytes()
}

func (dm *DnsMessage) String() string {
	return string(dm.Bytes())
}
