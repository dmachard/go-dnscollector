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
	// If the field string is empty and boundaries are specified, write empty boundaries (e.g., "")
	if fieldString == "" && len(fieldBoundary) > 0 {
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldString, fieldBoundary))
		return
	}

	// Check if a field delimiter is present and the fieldString contains this delimiter.
	if len(fieldDelimiter) > 0 && strings.Contains(fieldString, fieldDelimiter) {
		fieldEscaped := fieldString

		// If the field string contains the boundary character (e.g., quotes), escape it.
		if len(fieldBoundary) > 0 && strings.Contains(fieldEscaped, fieldBoundary) {
			fieldEscaped = strings.ReplaceAll(fieldEscaped, fieldBoundary, "\\"+fieldBoundary)
		}

		// Surround the escaped field string with the boundary character.
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldEscaped, fieldBoundary))

	} else if len(fieldBoundary) > 0 && strings.Contains(fieldString, fieldBoundary) {
		// If the field string contains only the boundary character, escape it and surround it.
		fieldEscaped := strings.ReplaceAll(fieldString, fieldBoundary, "\\"+fieldBoundary)
		s.WriteString(fmt.Sprintf("%s%s%s", fieldBoundary, fieldEscaped, fieldBoundary))

	} else {
		// If no conditions are met, write the field string as is.
		s.WriteString(fieldString)
	}
}
