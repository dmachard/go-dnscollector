package dnsutils

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

func TestDecodeQuery_EDNS(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	e := &dns.OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = dns.TypeOPT
	e.SetUDPSize(1024)
	e.SetDo()
	e.SetVersion(2)
	e.SetZ(23)
	fmt.Println(e)

	dm.Extra = append(dm.Extra, e)

	payload, _ := dm.Pack()

	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, _, err := DecodeEDNS(len(dm.Extra), offset_rr, payload)

	if err != nil {
		t.Errorf("edns error returned: %v", err)
	}
}

func TestDecodeReply_EDNS(t *testing.T) {
	fqdn := "dnstapcollector.test."

	dm := new(dns.Msg)
	dm.SetQuestion(fqdn, dns.TypeA)

	rrA, _ := dns.NewRR(fmt.Sprintf("%s A 127.0.0.1", fqdn))

	m := new(dns.Msg)
	m.SetReply(dm)
	m.Answer = append(m.Answer, rrA)

	e := &dns.OPT{}
	e.Hdr.Name = "."
	e.Hdr.Rrtype = dns.TypeOPT
	e.SetUDPSize(1024)
	e.SetDo()
	e.SetVersion(2)
	e.SetZ(23)

	o := &dns.EDNS0_COOKIE{Code: 10, Cookie: "aaaa"}
	e.Option = append(e.Option, o)

	m.Extra = append(dm.Extra, e)

	m.SetRcode(dm, 42) // 32(extended rcode) + 10(rcode)

	payload, _ := m.Pack()
	_, _, offset_rr, _ := DecodeQuestion(payload)
	_, offset_rr, _ = DecodeAnswer(len(m.Answer), offset_rr, payload)

	_, _, err := DecodeEDNS(len(m.Extra), offset_rr, payload)
	if err != nil {
		t.Errorf("edns error returned: %v", err)
	}
}
