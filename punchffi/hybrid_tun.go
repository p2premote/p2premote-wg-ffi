//go:build windows || darwin

// p2premote extension: hybrid native-TUN + gVisor netstack used by the
// Windows and macOS userspace WireGuard engines.
package main

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
)

const hybridNativeQueueSize = 512

const pooledNativePacketSize = 2048

type pooledNativePacket struct {
	buf     []byte
	storage []byte
	pooled  bool
}

// hybridTun combines a userspace gVisor TUN with an optional Wintun adapter.
// The WireGuard device always sees one tun.Device, so active and passive peers
// can share one key, listen port and peer table.
type hybridTun struct {
	netstack *subnetNetTun
	events   chan tun.Event
	closed   chan struct{}
	close    sync.Once

	mu             sync.RWMutex
	natives        map[string]tun.Device
	nativeGen      map[string]uint64
	nativeOutgoing chan pooledNativePacket
	nativePool     sync.Pool
	nativeWriteMu  sync.Mutex
	packetHandler  func([]byte, int) hybridPacketDisposition
}

type hybridPacketDisposition uint8

const (
	hybridPacketNetstack hybridPacketDisposition = iota
	hybridPacketNative
	hybridPacketConsumed
)

func newHybridTun(netstack *subnetNetTun) *hybridTun {
	h := &hybridTun{
		netstack:       netstack,
		events:         make(chan tun.Event, 8),
		closed:         make(chan struct{}),
		nativeOutgoing: make(chan pooledNativePacket, hybridNativeQueueSize),
		natives:        make(map[string]tun.Device),
		nativeGen:      make(map[string]uint64),
	}
	h.nativePool.New = func() any {
		return make([]byte, pooledNativePacketSize+hybridNativePacketOffset)
	}
	h.events <- tun.EventUp
	return h
}

func (h *hybridTun) Name() (string, error)    { return "p2premote-hybrid", nil }
func (h *hybridTun) File() *os.File           { return nil }
func (h *hybridTun) Events() <-chan tun.Event { return h.events }
func (h *hybridTun) MTU() (int, error)        { return h.netstack.MTU() }
func (h *hybridTun) BatchSize() int           { return userspaceWGBatchSize }

func (h *hybridTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, fmt.Errorf("hybrid tun read buffers are empty")
	}
	limit := minInt(userspaceWGBatchSize, len(bufs), len(sizes))
	count := 0
	for count < limit {
		if count == 0 {
			select {
			case <-h.closed:
				return 0, os.ErrClosed
			case packet := <-h.nativeOutgoing:
				if err := h.copyNativePacket(bufs[count], offset, sizes, count, packet); err != nil {
					return count, err
				}
			case view, ok := <-h.netstack.incomingPacket:
				if !ok {
					return 0, os.ErrClosed
				}
				if err := copyView(bufs[count], offset, sizes, count, view); err != nil {
					return count, err
				}
			}
		} else {
			select {
			case packet := <-h.nativeOutgoing:
				if err := h.copyNativePacket(bufs[count], offset, sizes, count, packet); err != nil {
					return count, err
				}
			case view, ok := <-h.netstack.incomingPacket:
				if !ok {
					return count, nil
				}
				if err := copyView(bufs[count], offset, sizes, count, view); err != nil {
					return count, err
				}
			default:
				return count, nil
			}
		}
		count++
	}
	return count, nil
}

func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	result := values[0]
	for _, value := range values[1:] {
		if value < result {
			result = value
		}
	}
	return result
}

func copyView(dst []byte, offset int, sizes []int, index int, view *buffer.View) error {
	defer view.Release()
	if view.Size()+offset > len(dst) {
		return io.ErrShortBuffer
	}
	n, err := view.Read(dst[offset:])
	if err == nil {
		sizes[index] = n
	}
	return err
}

func (h *hybridTun) copyNativePacket(dst []byte, offset int, sizes []int, index int, packet pooledNativePacket) error {
	defer h.releaseNativePacket(packet)
	if len(packet.buf)+offset > len(dst) {
		return io.ErrShortBuffer
	}
	copy(dst[offset:], packet.buf)
	sizes[index] = len(packet.buf)
	return nil
}

func (h *hybridTun) releaseNativePacket(packet pooledNativePacket) {
	if packet.pooled {
		h.nativePool.Put(packet.storage[:pooledNativePacketSize+hybridNativePacketOffset])
	}
}

func (h *hybridTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, raw := range bufs {
		if offset > len(raw) {
			return 0, io.ErrShortBuffer
		}
		packet := raw[offset:]
		if len(packet) == 0 {
			continue
		}
		disposition := hybridPacketNetstack
		if h.packetHandler != nil {
			disposition = h.packetHandler(raw, offset)
		}
		switch disposition {
		case hybridPacketNative:
			return 0, fmt.Errorf("native packet must be handled by the classifier")
		case hybridPacketConsumed:
			continue
		default:
			if _, err := h.netstack.Write([][]byte{raw}, offset); err != nil {
				return 0, err
			}
		}
	}
	return len(bufs), nil
}

func (h *hybridTun) attachNative(key string, device tun.Device) error {
	if device == nil {
		return fmt.Errorf("native tun is nil")
	}
	h.mu.Lock()
	if h.natives[key] != nil {
		h.mu.Unlock()
		_ = device.Close()
		return nil
	}
	h.natives[key] = device
	h.nativeGen[key]++
	generation := h.nativeGen[key]
	h.mu.Unlock()
	go h.pumpNative(key, device, generation)
	return nil
}

func (h *hybridTun) detachNative(key string) error {
	h.mu.Lock()
	device := h.natives[key]
	delete(h.natives, key)
	h.nativeGen[key]++
	h.mu.Unlock()
	if device == nil {
		return nil
	}
	return device.Close()
}

func (h *hybridTun) nativeDevice(key string) tun.Device {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.natives[key]
}

func (h *hybridTun) nativeKeys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, len(h.natives))
	for key := range h.natives {
		keys = append(keys, key)
	}
	return keys
}

func (h *hybridTun) pumpNative(key string, device tun.Device, generation uint64) {
	mtu, mtuErr := device.MTU()
	// Native TUN devices are single-packet readers on Windows and macOS. For
	// normal MTUs, read into the queued pool buffer directly so pumpNative does
	// not copy every packet through a reusable staging buffer first.
	directPoolRead := mtuErr == nil && mtu > 0 && mtu <= pooledNativePacketSize
	var staging []byte
	if !directPoolRead {
		staging = make([]byte, 65535+hybridNativePacketOffset)
	}
	bufs := make([][]byte, 1)
	sizes := make([]int, 1)
	for {
		var readBuffer []byte
		if directPoolRead {
			readBuffer = h.nativePool.Get().([]byte)
		} else {
			readBuffer = staging
		}
		bufs[0] = readBuffer
		sizes[0] = 0
		n, err := device.Read(bufs, sizes, hybridNativePacketOffset)
		if err != nil {
			if directPoolRead {
				h.nativePool.Put(readBuffer[:pooledNativePacketSize+hybridNativePacketOffset])
			}
			return
		}
		if n < 0 || n > len(bufs) || n > len(sizes) {
			if directPoolRead {
				h.nativePool.Put(readBuffer[:pooledNativePacketSize+hybridNativePacketOffset])
			}
			return
		}
		if n == 0 {
			if directPoolRead {
				h.nativePool.Put(readBuffer[:pooledNativePacketSize+hybridNativePacketOffset])
			}
			continue
		}
		for i := 0; i < n; i++ {
			if sizes[i] < 0 || hybridNativePacketOffset+sizes[i] > len(bufs[i]) {
				if directPoolRead {
					h.nativePool.Put(readBuffer[:pooledNativePacketSize+hybridNativePacketOffset])
				}
				return
			}
			source := bufs[i][hybridNativePacketOffset : hybridNativePacketOffset+sizes[i]]
			packet := pooledNativePacket{}
			if directPoolRead {
				packet.buf = source
				packet.storage = readBuffer
				packet.pooled = true
			} else if len(source) <= pooledNativePacketSize {
				storage := h.nativePool.Get().([]byte)
				packet.buf = storage[hybridNativePacketOffset : hybridNativePacketOffset+len(source)]
				packet.storage = storage
				packet.pooled = true
				copy(packet.buf, source)
			} else {
				packet.buf = make([]byte, len(source))
				copy(packet.buf, source)
			}
			h.mu.RLock()
			current := h.natives[key] == device && h.nativeGen[key] == generation
			h.mu.RUnlock()
			if !current {
				h.releaseNativePacket(packet)
				return
			}
			select {
			case <-h.closed:
				h.releaseNativePacket(packet)
				return
			case h.nativeOutgoing <- packet:
			}
		}
	}
}

func (h *hybridTun) writeNative(key string, raw []byte, offset int) error {
	// wireguard-go leaves transport-header headroom in raw. Preserve that
	// buffer and offset so Darwin NativeTun can prepend its four-byte address
	// family header without allocating and copying the decrypted packet.
	if offset < hybridNativePacketOffset || offset > len(raw) {
		return io.ErrShortBuffer
	}
	h.mu.RLock()
	device := h.natives[key]
	h.mu.RUnlock()
	if device == nil {
		return fmt.Errorf("native TUN is not attached")
	}
	h.nativeWriteMu.Lock()
	defer h.nativeWriteMu.Unlock()
	_, err := device.Write([][]byte{raw}, offset)
	return err
}

func (h *hybridTun) Close() error {
	var closeErr error
	h.close.Do(func() {
		close(h.closed)
		for _, key := range h.nativeKeys() {
			if err := h.detachNative(key); closeErr == nil && err != nil {
				closeErr = err
			}
		}
		if err := h.netstack.Close(); closeErr == nil && err != nil {
			closeErr = err
		}
		close(h.events)
	})
	return closeErr
}

var _ tun.Device = (*hybridTun)(nil)
