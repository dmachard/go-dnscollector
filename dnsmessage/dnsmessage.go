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

func (d *DnsMessage) Init() {
	d.Operation, d.Type = "-", "-"
	d.Identity = "-"
	d.Family, d.Protocol = "-", "-"
	d.QueryIp, d.QueryPort = "-", "-"
	d.ResponseIp, d.ResponsePort = "-", "-"
	d.Rcode, d.Qtype = "-", "-"
	d.Qname = "-"
}

func TransformToText(dm DnsMessage) []byte {
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
