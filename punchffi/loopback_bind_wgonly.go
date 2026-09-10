//go:build windows && wgonly

package main

import (
	"fmt"
	"github.com/tailscale/wireguard-go/conn"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

const userspaceWGBatchSize = 32

type endpointPacketCounters struct{ rx, tx atomic.Int64 }
type loopbackBind struct {
	mu                   sync.Mutex
	conn                 *net.UDPConn
	counters             sync.Map
	rxBatches, txBatches atomic.Int64
}

func newLoopbackBind() *loopbackBind { return &loopbackBind{} }
func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, fmt.Errorf("wireguard receive batch is empty")
		}
		n, a, e := c.ReadFromUDP(packets[0])
		if e != nil {
			return 0, e
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return 0, fmt.Errorf("invalid udp source ip: %v", a.IP)
		}
		ap := netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: ap}
		b.counter(ap).rx.Add(1)
		b.rxBatches.Add(1)
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	e := b.conn.Close()
	b.conn = nil
	return e
}
func (b *loopbackBind) SetMark(uint32) error { return nil }

// Old wireguard-go (Go 1.20 baseline) has no offset parameter.
func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	c := b.conn
	b.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	ap, e := netip.ParseAddrPort(ep.DstToString())
	if e != nil {
		return e
	}
	d := net.UDPAddrFromAddrPort(ap)
	for _, buf := range bufs {
		if _, e = c.WriteToUDP(buf, d); e != nil {
			return e
		}
	}
	x := b.counter(ap)
	x.tx.Add(int64(len(bufs)))
	b.txBatches.Add(1)
	return nil
}
func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	a, e := netip.ParseAddrPort(s)
	if e != nil {
		return nil, e
	}
	return &conn.StdNetEndpoint{AddrPort: a}, nil
}
func (*loopbackBind) BatchSize() int { return 1 }
func (b *loopbackBind) counter(a netip.AddrPort) *endpointPacketCounters {
	if v, ok := b.counters.Load(a); ok {
		return v.(*endpointPacketCounters)
	}
	v := &endpointPacketCounters{}
	x, _ := b.counters.LoadOrStore(a, v)
	return x.(*endpointPacketCounters)
}
func (b *loopbackBind) endpointPackets(s string) (int64, int64) {
	a, e := netip.ParseAddrPort(s)
	if e != nil {
		return 0, 0
	}
	v, ok := b.counters.Load(a)
	if !ok {
		return 0, 0
	}
	x := v.(*endpointPacketCounters)
	return x.rx.Load(), x.tx.Load()
}
func (b *loopbackBind) batchStats() (int64, int64) { return b.rxBatches.Load(), b.txBatches.Load() }
