package dnsutils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dmachard/go-dnscollector/pkgconfig"
	"github.com/dmachard/go-netutils"
	"github.com/miekg/dns"
)

func GetFakeDNS() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)
	return dnsmsg.Pack()
}

func GetDNSResponsePacket() ([]byte, error) {
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dns.collector.", dns.TypeA)

	// Build a fake response for the question
	rr, err := dns.NewRR("dns.collector. 3600 IN A 192.168.1.1")
	if err != nil {
		return nil, err
	}

	// Add the resource record (the answer) to the message
	dnsmsg.Answer = append(dnsmsg.Answer, rr)

	// Build an authoritative NS record (Authoritative section)
	nsRR, err := dns.NewRR("collector. 3600 IN NS ns1.collector.")
	if err != nil {
		return nil, err
	}
	dnsmsg.Ns = append(dnsmsg.Ns, nsRR)

	// Build an additional A record for the authoritative NS (Additional section)
	additionalRR, err := dns.NewRR("ns1.collector. 3600 IN A 192.168.2.1")
	if err != nil {
		return nil, err
	}
	dnsmsg.Extra = append(dnsmsg.Extra, additionalRR)

	return dnsmsg.Pack()
}

func GetFakeDNSMessage() DNSMessage {
	dm := DNSMessage{}
	dm.Init()
	dm.DNSTap.Identity = "collector"
	dm.DNSTap.Version = "dnscollector 1.0.0"
	dm.DNSTap.Operation = "CLIENT_QUERY"
	dm.DNSTap.PeerName = "localhost (127.0.0.1)"
	dm.DNS.Type = DNSQuery
	dm.DNS.Qname = pkgconfig.ProgQname
	dm.NetworkInfo.QueryIP = "1.2.3.4"
	dm.NetworkInfo.QueryPort = "1234"
	dm.NetworkInfo.ResponseIP = "4.3.2.1"
	dm.NetworkInfo.ResponsePort = "4321"
	dm.DNS.Rcode = "NOERROR"
	dm.DNS.Qtype = "A"
	return dm
}

func GetFakeDNSMessageWithPayload() DNSMessage {
	// fake dns query payload
	dnsmsg := new(dns.Msg)
	dnsmsg.SetQuestion("dnscollector.dev.", dns.TypeAAAA)
	dnsquestion, _ := dnsmsg.Pack()

	dm := GetFakeDNSMessage()
	dm.NetworkInfo.Family = netutils.ProtoIPv4
	dm.NetworkInfo.Protocol = netutils.ProtoUDP
	dm.DNS.Payload = dnsquestion
	dm.DNS.Length = len(dnsquestion)
	return dm
}

func GetFlatDNSMessage() (ret map[string]interface{}, err error) {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()
	ret, err = dm.Flatten()
	return
}

func GetReferenceDNSMessage() DNSMessage {
	dm := DNSMessage{}
	dm.Init()
	dm.InitTransforms()
	return dm
}

func GetIPPort(dm *DNSMessage) (string, int, string, int) {
	srcIP, srcPort := "0.0.0.0", 53
	dstIP, dstPort := "0.0.0.0", 53
	if dm.NetworkInfo.Family == "INET6" {
		srcIP, dstIP = "::", "::"
	}

	if dm.NetworkInfo.QueryIP != "-" {
		srcIP = dm.NetworkInfo.QueryIP
		srcPort, _ = strconv.Atoi(dm.NetworkInfo.QueryPort)
	}
	if dm.NetworkInfo.ResponseIP != "-" {
		dstIP = dm.NetworkInfo.ResponseIP
		dstPort, _ = strconv.Atoi(dm.NetworkInfo.ResponsePort)
	}

	// reverse destination and source
	if dm.DNS.Type == DNSReply {
		srcIPTmp, srcPortTmp := srcIP, srcPort
		srcIP, srcPort = dstIP, dstPort
		dstIP, dstPort = srcIPTmp, srcPortTmp
	}
	return srcIP, srcPort, dstIP, dstPort
}

func ConvertToString(value interface{}) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func QuoteStringAndWrite(s *strings.Builder, fieldString, fieldDelimiter, fieldBoundary string) {
	// Handle the case where the field string is empty and boundaries are specified
	if fieldString == "" && len(fieldBoundary) > 0 {
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldString, fieldBoundary))
		return
	}

	switch {
	case len(fieldDelimiter) > 0 && strings.Contains(fieldString, fieldDelimiter):
		// Case where the field string contains the delimiter
		fieldEscaped := fieldString
		if len(fieldBoundary) > 0 && strings.Contains(fieldEscaped, fieldBoundary) {
			fieldEscaped = strings.ReplaceAll(fieldEscaped, fieldBoundary, "\\"+fieldBoundary)
		}
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldEscaped, fieldBoundary))

	case len(fieldBoundary) > 0 && strings.Contains(fieldString, fieldBoundary):
		// Case where the field string contains the boundary character
		fieldEscaped := strings.ReplaceAll(fieldString, fieldBoundary, "\\"+fieldBoundary)
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldEscaped, fieldBoundary))

	default:
		// Default case: simply write the field string as is
		s.WriteString(fieldString)
	}
}
