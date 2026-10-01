//go:build windows

package net

import (
	"strings"
	"unsafe"

	"basb/internal/event"
	"golang.org/x/sys/windows"
)

var (
	modDnsapi            = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsGetCacheDataTable = modDnsapi.NewProc("DnsGetCacheDataTable")
	procDnsApiFree       = modDnsapi.NewProc("DnsApiFree")
)

// dnsCacheEntry mirrors the undocumented DNS_CACHE_ENTRY used by DnsGetCacheDataTable.
type dnsCacheEntry struct {
	next       uintptr
	name       uintptr
	typ        uint16
	dataLength uint16
	flags      uint32
}

func listDNSCacheNames() []string {
	var head uintptr
	r1, _, _ := procDnsGetCacheDataTable.Call(uintptr(unsafe.Pointer(&head)))
	if r1 == 0 || head == 0 {
		return nil
	}

	var out []string
	for p := head; p != 0; {
		e := (*dnsCacheEntry)(unsafe.Pointer(p))
		next := e.next
		if e.name != 0 {
			name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(e.name)))
			name = strings.TrimSpace(strings.TrimSuffix(name, "."))
			if name != "" {
				out = append(out, name)
			}
			_, _, _ = procDnsApiFree.Call(e.name)
		}
		_, _, _ = procDnsApiFree.Call(p)
		p = next
	}
	return out
}

func (w *Watcher) pollDNSCache() {
	names := listDNSCacheNames()
	if names == nil {
		return
	}

	w.mu.Lock()
	emit := w.dnsBaselined
	if !w.dnsBaselined {
		w.dnsBaselined = true
	}
	var fresh []string
	for _, name := range names {
		key := strings.ToLower(name)
		if _, ok := w.dnsSeen[key]; ok {
			continue
		}
		w.dnsSeen[key] = struct{}{}
		if emit {
			fresh = append(fresh, name)
		}
	}
	w.mu.Unlock()

	for _, name := range fresh {
		ev := event.New(w.sessionID, event.CatNetwork, event.TypeDNS)
		ev.Target.Type = "host"
		ev.Target.Value = name
		ev.Network = &event.Network{
			Domain:   name,
			Protocol: "dns",
		}
		ev.Meta["via"] = "dns_cache"
		_ = w.em.Emit(ev)
	}
}
