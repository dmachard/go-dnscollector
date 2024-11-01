package dnsutils

import (
	"errors"
	"net"
	"strconv"

	"github.com/dmachard/go-dnstap-protobuf"
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

	reqIP := net.ParseIP(dm.NetworkInfo.QueryIP)
	if dm.NetworkInfo.Family == netutils.ProtoIPv4 {
		msg.QueryAddress = reqIP.To4()
	} else {
		msg.QueryAddress = reqIP.To16()
	}
	msg.QueryPort = &qport

	rspIP := net.ParseIP(dm.NetworkInfo.ResponseIP)
	if dm.NetworkInfo.Family == netutils.ProtoIPv4 {
		msg.ResponseAddress = rspIP.To4()
	} else {
		msg.ResponseAddress = rspIP.To16()
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

	// contruct new dnstap field with all tranformations
	// the original extra field is kept if exist
	if extended {
		ednstap := &ExtendedDnstap{}

		// add original dnstap value if exist
		if len(dm.DNSTap.Extra) > 0 {
			ednstap.OriginalDnstapExtra = []byte(dm.DNSTap.Extra)
		}

		// add additionnals tags ?
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
