//go:build windows

package main

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWithWintunFirewall(t *testing.T) {
	queryErr := errors.New("service query denied")
	updateErr := errors.New("firewall rule access denied")
	for _, test := range []struct {
		name      string
		state     uint32
		queryErr  error
		updateErr error
		wantCalls int
		wantErr   error
	}{
		{name: "stopped", state: windows.SERVICE_STOPPED},
		{name: "running", state: windows.SERVICE_RUNNING, wantCalls: 1},
		{name: "rule failure preserved", state: windows.SERVICE_RUNNING, updateErr: updateErr, wantCalls: 1, wantErr: updateErr},
		{name: "query failure preserved", queryErr: queryErr, wantErr: queryErr},
		{name: "starting is not stopped", state: windows.SERVICE_START_PENDING, updateErr: updateErr, wantCalls: 1, wantErr: updateErr},
		{name: "stopping is not stopped", state: windows.SERVICE_STOP_PENDING, updateErr: updateErr, wantCalls: 1, wantErr: updateErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			err := withWintunFirewall(func() (uint32, error) {
				return test.state, test.queryErr
			}, func() error {
				calls++
				return test.updateErr
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if calls != test.wantCalls {
				t.Fatalf("update calls = %d, want %d", calls, test.wantCalls)
			}
		})
	}
}

func TestWintunFirewallRetriesAfterServiceResumes(t *testing.T) {
	state := uint32(windows.SERVICE_STOPPED)
	// Stand in for both OS rule synchronization and its ownership ledger.
	updates := 0
	query := func() (uint32, error) { return state, nil }
	update := func() error { updates++; return nil }
	if err := withWintunFirewall(query, update); err != nil {
		t.Fatal(err)
	}
	if updates != 0 {
		t.Fatal("stopped service must not change rules or ownership")
	}
	state = windows.SERVICE_RUNNING
	if err := withWintunFirewall(query, update); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Fatal("rule synchronization must resume on the next reconciliation")
	}
}
