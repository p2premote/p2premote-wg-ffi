//go:build (windows || darwin) && !wgonly

package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
)

type offsetCheckingTun struct {
	readPacket  []byte
	readBuffer  []byte
	writeBuffer []byte
	writeOffset int
	readDone    bool
	mtu         int
}

func (t *offsetCheckingTun) File() *os.File        { return nil }
func (t *offsetCheckingTun) Name() (string, error) { return "test", nil }
func (t *offsetCheckingTun) MTU() (int, error) {
	if t.mtu > 0 {
		return t.mtu, nil
	}
	return 1280, nil
}
func (t *offsetCheckingTun) Events() <-chan tun.Event { return nil }
func (t *offsetCheckingTun) Close() error             { return nil }
func (t *offsetCheckingTun) BatchSize() int           { return 1 }
func (t *offsetCheckingTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if offset != hybridNativePacketOffset {
		return 0, errors.New("unexpected native read offset")
	}
	if t.readDone {
		return 0, os.ErrClosed
	}
	t.readDone = true
	t.readBuffer = bufs[0]
	copy(bufs[0][offset:], t.readPacket)
	sizes[0] = len(t.readPacket)
	return 1, nil
}
func (t *offsetCheckingTun) Write(bufs [][]byte, offset int) (int, error) {
	t.writeBuffer = bufs[0]
	t.writeOffset = offset
	return 1, nil
}

func newOffsetTestHybrid(device tun.Device) *hybridTun {
	h := &hybridTun{
		closed:         make(chan struct{}),
		natives:        map[string]tun.Device{"native": device},
		nativeGen:      map[string]uint64{"native": 1},
		nativeOutgoing: make(chan pooledNativePacket, 1),
	}
	h.nativePool.New = func() any {
		return make([]byte, pooledNativePacketSize+hybridNativePacketOffset)
	}
	return h
}

func TestPumpNativeUsesPlatformPacketOffset(t *testing.T) {
	want := []byte{0x45, 0, 0, 20}
	device := &offsetCheckingTun{readPacket: want}
	h := newOffsetTestHybrid(device)
	h.pumpNative("native", device, 1)
	packet := <-h.nativeOutgoing
	defer h.releaseNativePacket(packet)
	if !bytes.Equal(packet.buf, want) {
		t.Fatalf("native packet = %x, want %x", packet.buf, want)
	}
	if len(packet.buf) == 0 || &packet.buf[0] != &device.readBuffer[hybridNativePacketOffset] {
		t.Fatal("native packet was copied instead of retaining the pooled read buffer")
	}
}

func TestPumpNativeFallsBackForLargeMTU(t *testing.T) {
	want := bytes.Repeat([]byte{0x45}, pooledNativePacketSize+1)
	device := &offsetCheckingTun{readPacket: want, mtu: 9000}
	h := newOffsetTestHybrid(device)
	h.pumpNative("native", device, 1)
	packet := <-h.nativeOutgoing
	defer h.releaseNativePacket(packet)
	if !bytes.Equal(packet.buf, want) {
		t.Fatalf("native packet length = %d, want %d", len(packet.buf), len(want))
	}
	if packet.pooled {
		t.Fatal("large native packet unexpectedly used the small packet pool")
	}
}

func TestWriteNativePreservesWireGuardHeadroom(t *testing.T) {
	want := []byte{0x45, 0, 0, 20}
	device := &offsetCheckingTun{}
	h := newOffsetTestHybrid(device)
	const wireGuardOffset = 16
	raw := make([]byte, wireGuardOffset+len(want))
	copy(raw[wireGuardOffset:], want)
	if err := h.writeNative("native", raw, wireGuardOffset); err != nil {
		t.Fatalf("writeNative: %v", err)
	}
	if device.writeOffset != wireGuardOffset {
		t.Fatalf("native write offset = %d, want %d", device.writeOffset, wireGuardOffset)
	}
	if len(device.writeBuffer) == 0 || &device.writeBuffer[0] != &raw[0] {
		t.Fatal("native write copied the WireGuard buffer")
	}
	if !bytes.Equal(device.writeBuffer[device.writeOffset:], want) {
		t.Fatalf("native packet = %x, want %x", device.writeBuffer[device.writeOffset:], want)
	}
}

func TestHybridWritePassesOriginalBufferToClassifier(t *testing.T) {
	h := newOffsetTestHybrid(&offsetCheckingTun{})
	const wireGuardOffset = 16
	raw := make([]byte, wireGuardOffset+20)
	raw[wireGuardOffset] = 0x45
	called := false
	h.packetHandler = func(handlerRaw []byte, handlerOffset int) hybridPacketDisposition {
		called = true
		if handlerOffset != wireGuardOffset {
			t.Fatalf("classifier offset = %d, want %d", handlerOffset, wireGuardOffset)
		}
		if len(handlerRaw) == 0 || &handlerRaw[0] != &raw[0] {
			t.Fatal("classifier did not receive the original WireGuard buffer")
		}
		return hybridPacketConsumed
	}
	if _, err := h.Write([][]byte{raw}, wireGuardOffset); err != nil {
		t.Fatalf("hybrid Write: %v", err)
	}
	if !called {
		t.Fatal("packet classifier was not called")
	}
}
