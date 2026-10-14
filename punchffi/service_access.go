package main

// Service policy runs after WG authentication and before native TUN delivery.
// Outbound-origin tuples are tracked so replies do not require ephemeral ports
// in the inbound whitelist. Inbound-origin tuples never gain that exemption.
import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type servicePortRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
type serviceAccessPolicy struct {
	Mode      string             `json:"mode"`
	TCP       []servicePortRange `json:"tcp"`
	UDP       []servicePortRange `json:"udp"`
	AllowPing bool               `json:"allow_ping"`
}
type serviceTuple struct {
	src, dst     netip.Addr
	sport, dport uint16
	protocol     byte
}

func (t serviceTuple) reverse() serviceTuple {
	return serviceTuple{t.dst, t.src, t.dport, t.sport, t.protocol}
}

// ICMP errors quote only part of the original datagram. Never treat the quote
// as a new connection; it must match a live locally initiated flow.
func serviceQuotedTuple(packet []byte) (serviceTuple, bool) {
	var tuple serviceTuple
	if len(packet) < 20 {
		return tuple, false
	}
	offset := 0
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset+4 || binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			return tuple, false
		}
		tuple.src = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		tuple.dst = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		tuple.protocol = packet[9]
	case 6:
		if len(packet) < 44 {
			return tuple, false
		}
		var src, dst [16]byte
		copy(src[:], packet[8:24])
		copy(dst[:], packet[24:40])
		tuple.src, tuple.dst = netip.AddrFrom16(src), netip.AddrFrom16(dst)
		offset, tuple.protocol = 40, packet[6]
		for n := 0; tuple.protocol == 0 || tuple.protocol == 43 || tuple.protocol == 60; n++ {
			if n >= 8 || offset+2 > len(packet) {
				return tuple, false
			}
			next := packet[offset]
			offset += (int(packet[offset+1]) + 1) * 8
			if offset+4 > len(packet) {
				return tuple, false
			}
			tuple.protocol = next
		}
	default:
		return tuple, false
	}
	if tuple.protocol != 6 && tuple.protocol != 17 {
		return tuple, false
	}
	tuple.sport, tuple.dport = binary.BigEndian.Uint16(packet[offset:offset+2]), binary.BigEndian.Uint16(packet[offset+2:offset+4])
	return tuple, true
}

type serviceFlow struct {
	outbound bool
	expires  time.Time
}
type serviceFilter struct {
	sync.Mutex
	policy  serviceAccessPolicy
	flows   map[serviceTuple]serviceFlow
	sweepAt time.Time
}

var localServiceFilter = serviceFilter{policy: serviceAccessPolicy{Mode: "deny"}, flows: make(map[serviceTuple]serviceFlow)}

// Matches core::health::HEALTH_PORT. This listener validates the authenticated
// tunnel peer identity; it carries heartbeat/stop controls, not application data.
const serviceHealthControlPort = 41119

func (f *serviceFilter) forgetPeer(ip netip.Addr) {
	f.Lock()
	defer f.Unlock()
	for tuple := range f.flows {
		if tuple.src == ip || tuple.dst == ip {
			delete(f.flows, tuple)
		}
	}
}

func (p serviceAccessPolicy) validate() error {
	if p.Mode != "all" && p.Mode != "allowlist" && p.Mode != "deny" {
		return fmt.Errorf("invalid service access mode")
	}
	for _, ranges := range [][]servicePortRange{p.TCP, p.UDP} {
		if len(ranges) > 256 {
			return fmt.Errorf("too many port ranges")
		}
		for _, r := range ranges {
			if r.Start < 1 || r.End > 65535 || r.Start > r.End {
				return fmt.Errorf("invalid service port range")
			}
		}
	}
	return nil
}
func handleServiceAccessJSON(input string) string {
	var policy serviceAccessPolicy
	if err := json.Unmarshal([]byte(input), &policy); err != nil {
		return encodeJSON(&windowsWgPeerResult{Error: err.Error()})
	}
	if err := policy.validate(); err != nil {
		return encodeJSON(&windowsWgPeerResult{Error: err.Error()})
	}
	localServiceFilter.Lock()
	localServiceFilter.policy = policy
	// Retain origin information, but re-evaluate inbound ports on every packet.
	localServiceFilter.Unlock()
	return encodeJSON(&windowsWgPeerResult{OK: true})
}

// Reject fragments under restrictions rather than interpreting fragment bytes
// as transport headers. IPv6 extension chains are bounded and length checked.
func servicePacket(packet []byte) (serviceTuple, []byte, bool) {
	var t serviceTuple
	if len(packet) < 1 {
		return t, nil, false
	}
	var offset, length int
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return t, nil, false
		}
		offset = int(packet[0]&15) * 4
		length = int(binary.BigEndian.Uint16(packet[2:4]))
		if offset < 20 || length < offset || length > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return t, nil, false
		}
		t.src = netip.AddrFrom4([4]byte{packet[12], packet[13], packet[14], packet[15]})
		t.dst = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		t.protocol = packet[9]
	case 6:
		if len(packet) < 40 {
			return t, nil, false
		}
		length = 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if length > len(packet) {
			return t, nil, false
		}
		var src, dst [16]byte
		copy(src[:], packet[8:24])
		copy(dst[:], packet[24:40])
		t.src, t.dst = netip.AddrFrom16(src), netip.AddrFrom16(dst)
		offset, t.protocol = 40, packet[6]
		for n := 0; t.protocol == 0 || t.protocol == 43 || t.protocol == 60; n++ {
			if n >= 8 || offset+2 > length {
				return t, nil, false
			}
			next := packet[offset]
			offset += (int(packet[offset+1]) + 1) * 8
			if offset > length {
				return t, nil, false
			}
			t.protocol = next
		}
		if t.protocol == 44 {
			return t, nil, false
		}
	default:
		return t, nil, false
	}
	payload := packet[offset:length]
	switch t.protocol {
	case 6:
		if len(payload) < 20 || int(payload[12]>>4)*4 < 20 || int(payload[12]>>4)*4 > len(payload) {
			return t, nil, false
		}
		t.sport, t.dport = binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:4])
	case 17:
		if len(payload) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) < 8 || int(binary.BigEndian.Uint16(payload[4:6])) > len(payload) {
			return t, nil, false
		}
		t.sport, t.dport = binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:4])
	case 1, 58:
		if len(payload) < 8 {
			return t, nil, false
		}
		t.sport = binary.BigEndian.Uint16(payload[4:6]) // echo identifier
		t.dport = t.sport
	default:
		return t, nil, false
	}
	return t, payload, true
}

func (f *serviceFilter) maintain(now time.Time) {
	if now.Before(f.sweepAt) {
		return
	}
	for key, value := range f.flows {
		if !now.Before(value.expires) {
			delete(f.flows, key)
		}
	}
	f.sweepAt = now.Add(30 * time.Second)
}
func (f *serviceFilter) remember(key serviceTuple, outbound bool, now time.Time) {
	if _, exists := f.flows[key]; !exists && len(f.flows) >= 65536 {
		return
	}
	ttl := 2 * time.Minute
	if key.protocol == 6 {
		ttl = 24 * time.Hour
	}
	f.flows[key] = serviceFlow{outbound, now.Add(ttl)}
}
func echoRequest(protocol byte, payload []byte) bool {
	return (protocol == 1 && payload[0] == 8 || protocol == 58 && payload[0] == 128) && payload[1] == 0
}
func echoReply(protocol byte, payload []byte) bool {
	return (protocol == 1 && payload[0] == 0 || protocol == 58 && payload[0] == 129) && payload[1] == 0
}
func (f *serviceFilter) observeOutbound(packet []byte) {
	tuple, payload, ok := servicePacket(packet)
	if !ok {
		return
	}
	f.Lock()
	defer f.Unlock()
	now := time.Now()
	f.maintain(now)
	if flow, exists := f.flows[tuple.reverse()]; exists && !flow.outbound && now.Before(flow.expires) {
		return
	}
	// ACK/SYN-ACK and echo replies never establish outbound-origin state.
	if tuple.protocol == 6 && payload[13]&0x12 != 0x02 {
		return
	}
	if (tuple.protocol == 1 || tuple.protocol == 58) && !echoRequest(tuple.protocol, payload) {
		return
	}
	f.remember(tuple, true, now)
}
func (f *serviceFilter) allowInbound(packet []byte) bool {
	tuple, payload, ok := servicePacket(packet)
	f.Lock()
	defer f.Unlock()
	now := time.Now()
	f.maintain(now)
	if !ok {
		return f.policy.Mode == "all"
	}
	if tuple.protocol == 6 && tuple.dport == serviceHealthControlPort {
		f.remember(tuple, false, now)
		return true
	}
	if (tuple.protocol == 1 && (payload[0] == 3 || payload[0] == 11 || payload[0] == 12)) || (tuple.protocol == 58 && payload[0] >= 1 && payload[0] <= 4) {
		quoted, valid := serviceQuotedTuple(payload[8:])
		if valid && quoted.src == tuple.dst {
			flow, exists := f.flows[quoted]
			if exists && flow.outbound && now.Before(flow.expires) {
				return true
			}
		}
		return f.policy.Mode == "all"
	}
	if flow, exists := f.flows[tuple.reverse()]; exists && flow.outbound && now.Before(flow.expires) {
		if tuple.protocol == 6 && payload[13]&0x12 == 0x02 {
			return false
		}
		if (tuple.protocol == 1 || tuple.protocol == 58) && !echoReply(tuple.protocol, payload) {
			return false
		}
		f.remember(tuple.reverse(), true, now)
		return true
	}
	allowed := f.policy.Mode == "all"
	if f.policy.Mode == "allowlist" {
		var ranges []servicePortRange
		switch tuple.protocol {
		case 6:
			ranges = f.policy.TCP
		case 17:
			ranges = f.policy.UDP
		case 1, 58:
			allowed = f.policy.AllowPing && echoRequest(tuple.protocol, payload)
		}
		for _, r := range ranges {
			if int(tuple.dport) >= r.Start && int(tuple.dport) <= r.End {
				allowed = true
				break
			}
		}
	}
	if allowed {
		f.remember(tuple, false, now)
	}
	return allowed
}
