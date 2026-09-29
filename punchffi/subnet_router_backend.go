// p2premote extension: this file implements p2premote's subnet-router
// backend: the cross-platform handle registry shared by the Windows and
// darwin userspace engine platform layers.
package main

import (
	"sync"
)

type subnetRouterHandle struct {
	result   subnetRouterResult
	stopFn   func()
	statusFn func(*subnetRouterResult)
}

var (
	subnetRoutersMu sync.Mutex
	subnetRouters   = map[string]*subnetRouterHandle{}
)

func startSubnetRouter(req startSubnetRouterInput) *subnetRouterResult {
	return startPlatformSubnetRouter(req)
}

func stopSubnetRouter(handleID string) *subnetRouterResult {
	subnetRoutersMu.Lock()
	handle := subnetRouters[handleID]
	delete(subnetRouters, handleID)
	subnetRoutersMu.Unlock()
	if handle == nil {
		return &subnetRouterResult{OK: true}
	}
	if handle.stopFn != nil {
		handle.stopFn()
	}
	return &subnetRouterResult{OK: true}
}

func getSubnetRouterStatus(handleID string) *subnetRouterResult {
	subnetRoutersMu.Lock()
	handle := subnetRouters[handleID]
	subnetRoutersMu.Unlock()
	if handle == nil {
		return &subnetRouterResult{OK: false, Error: "subnet router handle not found"}
	}
	result := handle.result
	if handle.statusFn != nil {
		handle.statusFn(&result)
	}
	return &result
}
