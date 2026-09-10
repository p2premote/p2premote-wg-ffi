//go:build (windows || darwin) && !wgonly

// p2premote extension: this entire file manages Windows loopback bindings required by the WGVPN FFI.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/tailscale/wireguard-go/conn"
)

// userspaceWGBatchSize bounds custom TUN batches. 32 is large enough to
// amortize Go scheduling and wireguard-go queue hand-offs without retaining
// the 128 maximum-sized packet buffers used by conn.IdealBatchSize for every
// device. The Windows UDP Bind remains single-message on receive (see
// loopbackBind.BatchSize), while Send still accepts the TUN-produced batches.
const userspaceWGBatchSize = 32

type endpointPacketCounters struct {
	rx atomic.Int64
	tx atomic.Int64
}

type loopbackBind struct {
	mu        sync.Mutex
	conn      *net.UDPConn
	counters  sync.Map // map[netip.AddrPort]*endpointPacketCounters
	rxPackets atomic.Int64
	txPackets atomic.Int64
	rxBatches atomic.Int64
	txBatches atomic.Int64
}

func newLoopbackBind() *loopbackBind {
	return &loopbackBind{}
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: int(port),
	})
	if err != nil {
		return nil, 0, err
	}
	b.conn = udpConn
	actualPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
	recv := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
			return 0, fmt.Errorf("wireguard receive batch is empty")
		}
		n, addr, err := udpConn.ReadFromUDP(packets[0])
		if err != nil {
			return 0, err
		}
		addrIP, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			return 0, fmt.Errorf("invalid udp source ip: %v", addr.IP)
		}
		addrPort := netip.AddrPortFrom(addrIP.Unmap(), uint16(addr.Port))
		b.recordRx(addrPort)
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addrPort}
		b.rxBatches.Add(1)
		return 1, nil
	}
	return []conn.ReceiveFunc{recv}, actualPort, nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

func (b *loopbackBind) SetMark(mark uint32) error {
	_ = mark
	return nil
}

func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return net.ErrClosed
	}
	addrPort, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return err
	}
	dst := net.UDPAddrFromAddrPort(addrPort)
	sent := 0
	for _, buf := range bufs {
		if _, err := udpConn.WriteToUDP(buf[offset:], dst); err != nil {
			return err
		}
		sent++
	}
	b.recordTx(addrPort, int64(sent))
	b.txBatches.Add(1)
	return nil
}

func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: addrPort}, nil
}

func (b *loopbackBind) BatchSize() int {
	// net.UDPConn has no portable non-blocking multi-message receive API on
	// Windows. TUN-side batching still lets wireguard-go encrypt and Send
	// several packets together; advertising a receive batch here would require
	// extra deadline syscalls or an additional copy queue.
	return 1
}

func (b *loopbackBind) endpointCounter(endpoint netip.AddrPort) *endpointPacketCounters {
	if value, ok := b.counters.Load(endpoint); ok {
		return value.(*endpointPacketCounters)
	}
	created := &endpointPacketCounters{}
	actual, _ := b.counters.LoadOrStore(endpoint, created)
	return actual.(*endpointPacketCounters)
}

func (b *loopbackBind) recordRx(endpoint netip.AddrPort) {
	b.rxPackets.Add(1)
	b.endpointCounter(endpoint).rx.Add(1)
}

func (b *loopbackBind) recordTx(endpoint netip.AddrPort, packets int64) {
	b.txPackets.Add(packets)
	b.endpointCounter(endpoint).tx.Add(packets)
}

func (b *loopbackBind) endpointPackets(endpoint string) (int64, int64) {
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return 0, 0
	}
	value, ok := b.counters.Load(addrPort)
	if !ok {
		return 0, 0
	}
	counters := value.(*endpointPacketCounters)
	return counters.rx.Load(), counters.tx.Load()
}

func (b *loopbackBind) batchStats() (int64, int64) {
	return b.rxBatches.Load(), b.txBatches.Load()
}
