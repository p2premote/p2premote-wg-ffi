//go:build windows || darwin

// p2premote extension: userspace subnet netstack for Windows and macOS WGVPN.
package main

/*
Adapted from github.com/tailscale/wireguard-go/tun/netstack/tun.go
SPDX-License-Identifier: MIT
*/

import (
	"fmt"
	"net/netip"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const subnetNetstackNICID = 1

// subnetNetPacketQueueSize 缓冲 wg 解密包（gVisor→wg 方向 + ICMP reply 注入方向）。
// 足够大以吸收突发，避免非阻塞注入（injectToWireGuard）在正常负载下丢包。
const subnetNetPacketQueueSize = 256

const (
	gvisorTCPBufferMin     = 256 << 10
	gvisorTCPBufferDefault = 1 << 20
	gvisorTCPBufferMax     = 4 << 20
)

type subnetNetTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
	closeOnce      sync.Once
	// closed 在 Close 时关闭，用于让 WriteNotify/injectToWireGuard 的阻塞发送
	// 能够通过 select 及时退出，避免向已 close 的 incomingPacket 发送导致 panic。
	// 用 RWMutex 保护：发送方 RLock（允许并发），Close 方 Lock（独占）。
	closedMu sync.RWMutex
	closed   chan struct{}
}

type subnetNet struct {
	stack *stack.Stack
}

func createSubnetNetTUN(localAddresses []netip.Addr, mtu int) (tun.Device, *subnetNet, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	linkEndpoint := channel.New(1024, uint32(mtu), "")
	// Let gVisor aggregate TCP work internally and perform software
	// segmentation before packets reach this channel endpoint. sendTCPBatch
	// still emits MTU-sized IP packets, so wireguard-go never receives a GSO
	// super-packet that its custom TUN cannot represent.
	linkEndpoint.SupportedGSOKind = stack.GvisorGSOSupported
	dev := &subnetNetTun{
		ep:             linkEndpoint,
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View, subnetNetPacketQueueSize),
		mtu:            mtu,
		closed:         make(chan struct{}),
	}
	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		return nil, nil, fmt.Errorf("could not enable TCP SACK: %v", err)
	}
	sendBufferOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min: gvisorTCPBufferMin, Default: gvisorTCPBufferDefault, Max: gvisorTCPBufferMax,
	}
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sendBufferOpt); err != nil {
		return nil, nil, fmt.Errorf("could not configure TCP send buffers: %v", err)
	}
	receiveBufferOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		Min: gvisorTCPBufferMin, Default: gvisorTCPBufferDefault, Max: gvisorTCPBufferMax,
	}
	if err := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &receiveBufferOpt); err != nil {
		return nil, nil, fmt.Errorf("could not configure TCP receive buffers: %v", err)
	}
	dev.ep.AddNotify(dev)
	if err := dev.stack.CreateNIC(subnetNetstackNICID, dev.ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}
	for _, ip := range localAddresses {
		var protoNumber tcpip.NetworkProtocolNumber
		if ip.Is4() {
			protoNumber = ipv4.ProtocolNumber
		} else if ip.Is6() {
			protoNumber = ipv6.ProtocolNumber
		} else {
			continue
		}
		protoAddr := tcpip.ProtocolAddress{
			Protocol:          protoNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if err := dev.stack.AddProtocolAddress(subnetNetstackNICID, protoAddr, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress(%v): %v", ip, err)
		}
	}
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: subnetNetstackNICID})
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: subnetNetstackNICID})
	dev.events <- tun.EventUp
	return dev, &subnetNet{stack: dev.stack}, nil
}

func (tunDev *subnetNetTun) Name() (string, error) {
	return "p2premote-netstack", nil
}

func (tunDev *subnetNetTun) File() *os.File {
	return nil
}

func (tunDev *subnetNetTun) Events() <-chan tun.Event {
	return tunDev.events
}

func (tunDev *subnetNetTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	limit := minInt(userspaceWGBatchSize, len(buf), len(sizes))
	if limit == 0 {
		return 0, fmt.Errorf("wireguard TUN read batch is empty")
	}
	count := 0
	for count < limit {
		var view *buffer.View
		var ok bool
		if count == 0 {
			view, ok = <-tunDev.incomingPacket
		} else {
			select {
			case view, ok = <-tunDev.incomingPacket:
			default:
				return count, nil
			}
		}
		if !ok {
			if count > 0 {
				return count, nil
			}
			return 0, os.ErrClosed
		}
		n, err := view.Read(buf[count][offset:])
		view.Release()
		if err != nil {
			return count, err
		}
		sizes[count] = n
		count++
	}
	return count, nil
}

func (tunDev *subnetNetTun) Write(buf [][]byte, offset int) (int, error) {
	for _, packetBuf := range buf {
		packet := packetBuf[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tunDev.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tunDev.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, fmt.Errorf("unsupported ip version nibble %d", packet[0]>>4)
		}
	}
	return len(buf), nil
}

func (tunDev *subnetNetTun) injectToWireGuard(packet []byte) error {
	view := buffer.NewViewWithData(append([]byte(nil), packet...))
	tunDev.closedMu.RLock()
	defer tunDev.closedMu.RUnlock()
	select {
	case <-tunDev.closed:
		view.Release()
		return fmt.Errorf("wireguard netstack is closed")
	case tunDev.incomingPacket <- view:
		return nil
	default:
		view.Release()
		return fmt.Errorf("wireguard receive queue is full")
	}
}

func (tunDev *subnetNetTun) WriteNotify() {
	pkt := tunDev.ep.Read()
	if pkt == nil {
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	tunDev.closedMu.RLock()
	defer tunDev.closedMu.RUnlock()
	select {
	case <-tunDev.closed:
		view.Release()
		return
	case tunDev.incomingPacket <- view:
	}
}

func (tunDev *subnetNetTun) Close() error {
	tunDev.closeOnce.Do(func() {
		// 先标记关闭并唤醒所有阻塞在 incomingPacket 发送的 goroutine。
		tunDev.closedMu.Lock()
		close(tunDev.closed)
		tunDev.closedMu.Unlock()
		// 此时 WriteNotify/injectToWireGuard 会通过 closed 分支退出，
		// 再安全地关闭 channel 和底层资源。
		tunDev.stack.RemoveNIC(subnetNetstackNICID)
		if tunDev.events != nil {
			close(tunDev.events)
		}
		tunDev.ep.Close()
		if tunDev.incomingPacket != nil {
			close(tunDev.incomingPacket)
		}
	})
	return nil
}

func (tunDev *subnetNetTun) MTU() (int, error) {
	return tunDev.mtu, nil
}

func (tunDev *subnetNetTun) BatchSize() int {
	return userspaceWGBatchSize
}
