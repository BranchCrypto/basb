//go:build windows

package net

import (
	"testing"
)

func TestListDNSCacheNamesSmoke(t *testing.T) {
	// Best-effort: API may return empty on clean caches; must not panic / hang.
	_ = listDNSCacheNames()
}
