package net

import (
	"encoding/binary"
	"testing"
)

func TestPortNetworkByteOrder(t *testing.T) {
	// Port 443 = 0x01BB stored as network-order bytes at the start of the DWORD.
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], 443)
	got := binary.BigEndian.Uint16(buf[:])
	if got != 443 {
		t.Fatalf("BigEndian port decode: got %d want 443", got)
	}
	// LittleEndian would mis-read the on-wire layout used by MIB_*ROW port fields.
	le := binary.LittleEndian.Uint16(buf[:])
	if le == 443 {
		t.Fatal("expected LittleEndian to differ from host port 443 for network-order bytes")
	}
}
