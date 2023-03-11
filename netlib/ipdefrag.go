package netlib

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	IPv6MinimumFragmentSize    = 1280
	IPv6MaximumSize            = 65535
	IPv6MaximumFragmentOffset  = 8189
	IPv6MaximumFragmentListLen = 52

	IPv4MinimumFragmentSize    = 8     // Minimum size of a single fragment
	IPv4MaximumSize            = 65535 // Maximum size of a fragment (2^16)
	IPv4MaximumFragmentOffset  = 8183  // Maximum offset of a fragment
	IPv4MaximumFragmentListLen = 8192  // Back out if we get more than this many fragments
)

type fragments struct {
	List     list.List
	Highest  uint16
	Current  uint16
	LastSeen time.Time
}

func (f *fragments) insert(in gopacket.Packet) (gopacket.Packet, error) {
	var inFragOffset uint16
	var inFragLength uint16
	var inFragMore bool

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		inIp6 := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		inFrag6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
		inFragOffset = inFrag6.FragmentOffset * 8
		inFragLength = inIp6.Length - 8
		inFragMore = inFrag6.MoreFragments
	}
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		inIp4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		inFragOffset = inIp4.FragOffset * 8
		inFragLength = inIp4.Length - 20
		inFragMore = inIp4.Flags&layers.IPv4MoreFragments > 0
	}

	if inFragOffset >= f.Highest {
		f.List.PushBack(in)
	} else {
		for e := f.List.Front(); e != nil; e = e.Next() {
			packet, _ := e.Value.(gopacket.Packet)

			var fragOffset uint16

			frag6 := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
			ip4, _ := e.Value.(*layers.IPv4)
			if frag6 != nil {
				fragOffset = frag6.FragmentOffset * 8
			} else {
				fragOffset = ip4.FragOffset * 8
			}

			if inFragOffset == fragOffset {
				return nil, nil
			}
			if inFragOffset <= fragOffset {
				f.List.InsertBefore(in, e)
				break
			}
		}
	}

	f.LastSeen = in.Metadata().Timestamp

	// After inserting the Fragment, we update the counters
	if f.Highest < inFragOffset+inFragLength {
		f.Highest = inFragOffset + inFragLength
	}
	f.Current = f.Current + inFragLength

	// Final Fragment ?
	if !inFragMore && f.Highest == f.Current {
		return f.build(in)
	}
	return nil, nil
}

func (f *fragments) build(in gopacket.Packet) (gopacket.Packet, error) {
	var final []byte
	var currentOffset uint16

	for e := f.List.Front(); e != nil; e = e.Next() {
		pack, _ := e.Value.(gopacket.Packet)

		var fragOffset uint16
		var fragLength uint16
		var fragPayload []byte
		var ipOffset uint16

		if pack.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
			frag6 := pack.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
			ip6 := pack.Layer(layers.LayerTypeIPv6).(*layers.IPv6)

			fragOffset = frag6.FragmentOffset
			fragLength = ip6.Length
			fragPayload = frag6.Payload
			ipOffset = 8
		}
		if pack.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
			ip4 := pack.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			fragOffset = ip4.FragOffset
			fragLength = ip4.Length
			fragPayload = ip4.Payload
			ipOffset = 20
		}

		if fragOffset*8 == currentOffset {
			final = append(final, fragPayload...)
			currentOffset = currentOffset + fragLength - ipOffset

		} else if fragOffset*8 < currentOffset {
			startAt := currentOffset - fragOffset*8
			if startAt > fragLength-ipOffset {
				return nil, fmt.Errorf("defrag: invalid fragment")
			}
			final = append(final, fragPayload[startAt:]...)
			currentOffset = currentOffset + fragOffset*8

		} else {
			// Houston - we have an hole !
			return nil, fmt.Errorf("defrag: hole found")
		}
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		out := &layers.IPv4{
			Version:    ip4.Version,
			IHL:        ip4.IHL,
			TOS:        ip4.TOS,
			Length:     f.Highest,
			Id:         ip4.Id,
			Flags:      0,
			FragOffset: 0,
			TTL:        ip4.TTL,
			Protocol:   ip4.Protocol,
			Checksum:   0,
			SrcIP:      ip4.SrcIP,
			DstIP:      ip4.DstIP,
			Options:    ip4.Options,
			Padding:    ip4.Padding,
		}
		out.Payload = final

		buf := gopacket.NewSerializeBuffer()
		ops := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		ip4Payload, _ := buf.PrependBytes(len(final))
		copy(ip4Payload, final)
		out.SerializeTo(buf, ops)

		outPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		outPacket.Metadata().CaptureLength = len(outPacket.Data())
		outPacket.Metadata().Length = len(outPacket.Data())
		outPacket.Metadata().Timestamp = in.Metadata().Timestamp

		// workaround to mark the packet as reassembled
		outPacket.Metadata().Truncated = true
		return outPacket, nil
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ip6 := in.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		frag6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
		out := &layers.IPv6{
			Version:      ip6.Version,
			TrafficClass: ip6.TrafficClass,
			FlowLabel:    ip6.FlowLabel,
			Length:       f.Highest,
			NextHeader:   frag6.NextHeader,
			HopLimit:     ip6.HopLimit,
			SrcIP:        ip6.SrcIP,
			DstIP:        ip6.DstIP,
			HopByHop:     ip6.HopByHop,
		}
		out.Payload = final

		buf := gopacket.NewSerializeBuffer()
		ops := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		v6Payload, _ := buf.PrependBytes(len(final))
		copy(v6Payload, final)

		out.SerializeTo(buf, ops)
		outPacket := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
		outPacket.Metadata().CaptureLength = len(outPacket.Data())
		outPacket.Metadata().Length = len(outPacket.Data())
		outPacket.Metadata().Timestamp = in.Metadata().Timestamp

		// workaround to mark the packet as reassembled
		outPacket.Metadata().Truncated = true

		return outPacket, nil
	}
	return nil, nil
}

type ipFlow struct {
	flow gopacket.Flow
	id   uint32
}

func newIPv4(packet gopacket.Packet) ipFlow {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	return ipFlow{
		flow: ip4.NetworkFlow(),
		id:   uint32(ip4.Id),
	}
}

func newIPv6(packet gopacket.Packet) ipFlow {
	frag := packet.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)
	ip6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	return ipFlow{
		flow: ip6.NetworkFlow(),
		id:   frag.Identification,
	}
}

type IpDefragmenter struct {
	sync.RWMutex
	ipFlows map[ipFlow]*fragments
}

func NewIPDefragmenter() *IpDefragmenter {
	return &IpDefragmenter{
		ipFlows: make(map[ipFlow]*fragments),
	}
}

func (d *IpDefragmenter) DefragIP(in gopacket.Packet) (gopacket.Packet, error) {
	// check if we need to defrag
	if st := d.dontDefrag(in); st {
		return in, nil
	}

	// perfom security checks
	if err := d.securityChecks(in); err != nil {
		return nil, err
	}

	// ok, got a fragment
	// have we already seen a flow between src/dst with that Id?
	var ipf ipFlow
	var fl *fragments
	var exist bool
	var maxFrag int

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ipf = newIPv4(in)
		maxFrag = IPv4MaximumFragmentListLen
	}
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		ipf = newIPv6(in)
		maxFrag = IPv6MaximumFragmentListLen
	}
	d.Lock()
	fl, exist = d.ipFlows[ipf]
	if !exist {
		fl = new(fragments)
		d.ipFlows[ipf] = fl
	}
	d.Unlock()

	// insert, and if final build it
	out, err2 := fl.insert(in)

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if out == nil && fl.List.Len()+1 > maxFrag {
		d.flush(ipf)
		return nil, fmt.Errorf("fragment List hits its maximum")
	}

	// if we got a packet, it's a new one, and he is defragmented
	// when defrag is done for a flow between two ip clean the list
	if out != nil {
		d.flush(ipf)
		return out, nil
	}
	return nil, err2
}

func (d *IpDefragmenter) dontDefrag(in gopacket.Packet) bool {
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		// check if we need to defrag
		frag := in.Layer(layers.LayerTypeIPv6Fragment)
		if frag == nil {
			return true
		}
	}

	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		// don't defrag packet with DF flag
		if ip4.Flags&layers.IPv4DontFragment != 0 {
			return true
		}
		// don't defrag not fragmented ones
		if ip4.Flags&layers.IPv4MoreFragments == 0 && ip4.FragOffset == 0 {
			return true
		}
	}

	return false
}

func (d *IpDefragmenter) securityChecks(in gopacket.Packet) error {
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv6 {
		frag6 := in.Layer(layers.LayerTypeIPv6Fragment).(*layers.IPv6Fragment)

		// don't allow too big fragment offset
		if frag6.FragmentOffset > IPv6MaximumFragmentOffset {
			return fmt.Errorf("fragment offset too big (handcrafted? %d > %d)", frag6.FragmentOffset, IPv6MaximumFragmentOffset)
		}
		fragOffset := uint32(frag6.FragmentOffset * 8)

		// don't allow fragment that would oversize an IP packet
		if fragOffset+uint32(len(frag6.Payload)) > IPv6MaximumSize {
			return fmt.Errorf("fragment will overrun (handcrafted? %d > %d)", fragOffset+uint32(len(frag6.Payload)), IPv6MaximumFragmentOffset)
		}
	}
	if in.NetworkLayer().LayerType() == layers.LayerTypeIPv4 {
		ip4 := in.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		fragSize := ip4.Length - uint16(ip4.IHL)*4

		// don't allow small fragments outside of specification
		if fragSize < IPv4MinimumFragmentSize {
			return fmt.Errorf("fragment too small(handcrafted? %d < %d)", fragSize, IPv4MinimumFragmentSize)
		}

		// don't allow too big fragment offset
		if ip4.FragOffset > IPv4MaximumFragmentOffset {
			return fmt.Errorf("fragment offset too big (handcrafted? %d > %d)", ip4.FragOffset, IPv4MaximumFragmentOffset)
		}
		fragOffset := ip4.FragOffset * 8

		// don't allow fragment that would oversize an IP packet
		if fragOffset+ip4.Length > IPv4MaximumSize {
			return fmt.Errorf("fragment will overrun (handcrafted? %d > %d)", fragOffset+ip4.Length, IPv4MaximumSize)
		}
	}

	return nil
}

func (d *IpDefragmenter) flush(ipf ipFlow) {
	d.Lock()
	delete(d.ipFlows, ipf)
	d.Unlock()
}

func (d *IpDefragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for k, v := range d.ipFlows {
		if v.LastSeen.Before(t) {
			nb = nb + 1
			delete(d.ipFlows, k)
		}
	}
	d.Unlock()
	return nb
}
