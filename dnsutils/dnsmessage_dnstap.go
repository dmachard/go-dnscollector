package dnsutils

import (
	"errors"
	"net/netip"
	"strconv"

	dnstap "github.com/dmachard/go-dnstap-protobuf"
	"github.com/dmachard/go-netutils"
	"google.golang.org/protobuf/proto"
)

func (dm *DNSMessage) ToDNSTap(extended bool) ([]byte, error) {
	if len(dm.DNSTap.Payload) > 0 {
		return dm.DNSTap.Payload, nil
	}

	dt := &dnstap.Dnstap{}
	t := dnstap.Dnstap_MESSAGE
	dt.Identity = []byte(dm.DNSTap.Identity)
	dt.Version = []byte("-")
	dt.Type = &t

	mt := dnstap.Message_Type(dnstap.Message_Type_value[dm.DNSTap.Operation])

	var sf dnstap.SocketFamily
	if ipNet, valid := netutils.IPToInet[dm.NetworkInfo.Family]; valid {
		sf = dnstap.SocketFamily(dnstap.SocketFamily_value[ipNet])
	} else if dm.NetworkInfo.Family == "INET" {
		sf = dnstap.SocketFamily_INET
	} else if dm.NetworkInfo.Family == "INET6" {
		sf = dnstap.SocketFamily_INET6
	}
	sp := dnstap.SocketProtocol(dnstap.SocketProtocol_value[dm.NetworkInfo.Protocol])
	tsec := uint64(dm.DNSTap.TimeSec)
	tnsec := uint32(dm.DNSTap.TimeNsec)

	var rport uint32
	var qport uint32
	if dm.NetworkInfo.ResponsePort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.ResponsePort); err != nil {
			return nil, err
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid response port value")
		} else {
			rport = uint32(port)
		}
	}

	if dm.NetworkInfo.QueryPort != "-" {
		if port, err := strconv.Atoi(dm.NetworkInfo.QueryPort); err != nil {
			return nil, err
		} else if port < 0 || port > 65535 {
			return nil, errors.New("invalid query port value")
		} else {
			qport = uint32(port)
		}
	}

	msg := &dnstap.Message{Type: &mt}

	msg.SocketFamily = &sf
	msg.SocketProtocol = &sp

	var reqIP4, rspIP4 [4]byte
	var reqIP16, rspIP16 [16]byte

	if dm.NetworkInfo.QueryIPLen > 0 {
		msg.QueryAddress = dm.NetworkInfo.QueryIPBuf[:dm.NetworkInfo.QueryIPLen]
	} else if dm.NetworkInfo.QueryIP != "-" {
		if addr, err := netip.ParseAddr(dm.NetworkInfo.GetQueryIP()); err == nil {
			if addr.Is4() {
				reqIP4 = addr.As4()
				msg.QueryAddress = reqIP4[:]
			} else {
				reqIP16 = addr.As16()
				msg.QueryAddress = reqIP16[:]
			}
		}
	}
	msg.QueryPort = &qport

	if dm.NetworkInfo.ResponseIPLen > 0 {
		msg.ResponseAddress = dm.NetworkInfo.ResponseIPBuf[:dm.NetworkInfo.ResponseIPLen]
	} else if dm.NetworkInfo.ResponseIP != "-" {
		if addr, err := netip.ParseAddr(dm.NetworkInfo.GetResponseIP()); err == nil {
			if addr.Is4() {
				rspIP4 = addr.As4()
				msg.ResponseAddress = rspIP4[:]
			} else {
				rspIP16 = addr.As16()
				msg.ResponseAddress = rspIP16[:]
			}
		}
	}
	msg.ResponsePort = &rport

	if dm.DNS.Type == DNSQuery {
		msg.QueryMessage = dm.DNS.Payload
		msg.QueryTimeSec = &tsec
		msg.QueryTimeNsec = &tnsec
	} else {
		msg.ResponseTimeSec = &tsec
		msg.ResponseTimeNsec = &tnsec
		msg.ResponseMessage = dm.DNS.Payload
	}

	dt.Message = msg

	// add dnstap extra
	if len(dm.DNSTap.Extra) > 0 {
		dt.Extra = []byte(dm.DNSTap.Extra)
	}

	// construct new dnstap field with all transformations
	// the original extra field is kept if exist
	if extended {
		ednstap := &ExtendedDnstap{}

		// add original dnstap value if exist
		if len(dm.DNSTap.Extra) > 0 {
			ednstap.OriginalDnstapExtra = []byte(dm.DNSTap.Extra)
		}

		// add additional tags ?
		if dm.ATags != nil {
			ednstap.Atags = &ExtendedATags{
				Tags: dm.ATags.Tags,
			}
		}

		// add public suffix
		if dm.PublicSuffix != nil {
			ednstap.Normalize = &ExtendedNormalize{
				Tld:         dm.PublicSuffix.QnamePublicSuffix,
				EtldPlusOne: dm.PublicSuffix.QnameEffectiveTLDPlusOne,
			}
		}

		// add filtering
		if dm.Filtering != nil {
			ednstap.Filtering = &ExtendedFiltering{
				SampleRate: uint32(dm.Filtering.SampleRate),
			}
		}

		// add geo
		if dm.Geo != nil {
			ednstap.Geo = &ExtendedGeo{
				City:      dm.Geo.City,
				Continent: dm.Geo.Continent,
				Isocode:   dm.Geo.CountryIsoCode,
				AsNumber:  dm.Geo.AutonomousSystemNumber,
				AsOrg:     dm.Geo.AutonomousSystemOrg,
			}
		}

		extendedData, err := proto.Marshal(ednstap)
		if err != nil {
			return nil, err
		}
		dt.Extra = extendedData
	}

	data, err := proto.Marshal(dt)
	if err != nil {
		return nil, err
	}
	return data, nil
}
