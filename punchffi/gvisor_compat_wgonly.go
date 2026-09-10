//go:build windows && wgonly

package main

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

func gvisorGSOSupported() stack.SupportedGSO { return stack.GvisorGSOSupported }
func newGonetUDPConn(s *stack.Stack, wq *waiter.Queue, ep tcpip.Endpoint) *gonet.UDPConn {
	return gonet.NewUDPConn(s, wq, ep)
}
