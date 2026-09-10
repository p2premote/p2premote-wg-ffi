//go:build !cgo

package main

// Allows platform backends to be type-checked with CGO disabled. Release FFI
// libraries always compile main.go and its exported C ABI instead.
func main() {}
