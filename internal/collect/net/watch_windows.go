//go:build windows

package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"basb/internal/event"
	"golang.org/x/sys/windows"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	afInet              = 2
	afInet6             = 23
)

// Emitter writes net audit events.
type Emitter interface {
	Emit(ev event.Event) error
}

// PIDSource lists live PIDs in the sandbox job.
type PIDSource interface {
	ListPIDs() ([]uint32, error)
}

// Watcher polls TCP/UDP connection tables for job member processes.
// Also diffs the system DNS client cache so outbound UDP DNS names are visible
// (UDP owner-PID tables have no remote endpoint).
type Watcher struct {
	pids      PIDSource
	em        Emitter
	sessionID string
	interval  time.Duration

	mu           sync.Mutex
	seen         map[string]struct{}
	dnsSeen      map[string]struct{}
	dnsBaselined bool
	stopCh       chan struct{}
	doneCh       chan struct{}
	started      atomic.Bool
	stopOnce     sync.Once
}

// NewWatcher creates a network connection watcher.
func NewWatcher(pids PIDSource, em Emitter, sessionID string) *Watcher {
	return &Watcher{
		pids:      pids,
		em:        em,
		sessionID: sessionID,
		interval:  500 * time.Millisecond,
		seen:      map[string]struct{}{},
		dnsSeen:   map[string]struct{}{},
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start begins polling. Idempotent: a second call is a no-op.
func (w *Watcher) Start() {
	if !w.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer close(w.doneCh)
		t := time.NewTicker(w.interval)
		defer t.Stop()
		w.poll()
		for {
			select {
			case <-w.stopCh:
				w.poll()
				return
			case <-t.C:
				w.poll()
			}
		}
	}()
}

// Stop ends polling. No-op if Start was never called.
func (w *Watcher) Stop() {
	if !w.started.Load() {
		return
	}
	w.stopOnce.Do(func() { close(w.stopCh) })
	<-w.doneCh
}

func (w *Watcher) poll() {
	w.pollDNSCache()

	allow, err := w.pids.ListPIDs()
	if err != nil || len(allow) == 0 {
		return
	}
	set := map[uint32]struct{}{}
	for _, p := range allow {
		set[p] = struct{}{}
	}

	conns := append(listTCP4(), listUDP4()...)
	conns = append(conns, listTCP6()...)
	conns = append(conns, listUDP6()...)

	for _, c := range conns {
		if _, ok := set[c.pid]; !ok {
			continue
		}
		key := fmt.Sprintf("%s|%d|%s|%d|%s", c.proto, c.pid, c.remote, c.rport, c.state)
		w.mu.Lock()
		_, known := w.seen[key]
		if !known {
			w.seen[key] = struct{}{}
		}
		w.mu.Unlock()
		if known {
			continue
		}

		target := fmt.Sprintf("%s://%s:%d", c.proto, c.remote, c.rport)
		if c.proto == "udp" {
			target = fmt.Sprintf("udp://%s:%d", c.remote, c.lport)
		}

		actionType := event.TypeConnect
		// Heuristic DNS: UDP/53 or TCP/53
		if c.rport == 53 || (c.proto == "udp" && c.lport == 53) {
			actionType = event.TypeDNS
		}

		ev := event.New(w.sessionID, event.CatNetwork, actionType)
		ev.WithActorPID(c.pid, 0)
		ev.Target.Type = "host"
		ev.Target.Value = target
		ev.Network = &event.Network{
			DestinationIP:   c.remote,
			DestinationPort: int(c.rport),
			LocalPort:       int(c.lport),
			Protocol:        c.proto,
			State:           c.state,
		}
		if actionType == event.TypeDNS {
			ev.Network.Domain = c.remote
		}
		if c.rport == 80 || c.rport == 443 || c.rport == 8080 || c.rport == 8443 {
			scheme := "http"
			if c.rport == 443 || c.rport == 8443 {
				scheme = "https"
			}
			ev.Network.Scheme = scheme
			ev.Meta["http_heuristic"] = true
		}
		_ = w.em.Emit(ev)

		if c.rport == 22 {
			ssh := event.New(w.sessionID, event.CatSSH, event.TypeConnect)
			ssh.WithActorPID(c.pid, 0)
			ssh.Target.Type = "host"
			ssh.Target.Value = target
			ssh.Network = &event.Network{
				DestinationIP:   c.remote,
				DestinationPort: 22,
				Protocol:        c.proto,
				State:           c.state,
			}
			_ = w.em.Emit(ssh)
		}
	}
}

type connRow struct {
	proto  string
	pid    uint32
	remote string
	rport  uint16
	lport  uint16
	state  string
}

// MIB_TCPROW_OWNER_PID: State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid
func listTCP4() []connRow {
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r1, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, tcpTableOwnerPIDAll, 0)
	if r1 != 0 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	off := 4
	const rowSize = 24
	var out []connRow
	for i := uint32(0); i < n; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		state := binary.LittleEndian.Uint32(row[0:4])
		// dwLocalPort / dwRemotePort are network byte order (see MIB_TCPROW_OWNER_PID).
		lport := binary.BigEndian.Uint16(row[8:10])
		remote := net.IPv4(row[12], row[13], row[14], row[15]).String()
		rport := binary.BigEndian.Uint16(row[16:18])
		pid := binary.LittleEndian.Uint32(row[20:24])
		if remote == "0.0.0.0" || rport == 0 {
			off += rowSize
			continue
		}
		out = append(out, connRow{
			proto:  "tcp",
			pid:    pid,
			remote: remote,
			rport:  rport,
			lport:  lport,
			state:  tcpState(state),
		})
		off += rowSize
	}
	return out
}

// MIB_UDPROW_OWNER_PID: LocalAddr, LocalPort, OwningPid (+4 padding).
// OWNER_PID UDP table has no remote endpoint — only local binds (outbound DNS peers are invisible).
func listUDP4() []connRow {
	var size uint32
	_, _, _ = procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPID, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r1, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet, udpTableOwnerPID, 0)
	if r1 != 0 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	off := 4
	const rowSize = 12
	var out []connRow
	for i := uint32(0); i < n; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		local := net.IPv4(row[0], row[1], row[2], row[3]).String()
		// dwLocalPort is network byte order (see MIB_UDPROW_OWNER_PID).
		lport := binary.BigEndian.Uint16(row[4:6])
		pid := binary.LittleEndian.Uint32(row[8:12])
		out = append(out, connRow{
			proto:  "udp",
			pid:    pid,
			remote: local,
			rport:  0,
			lport:  lport,
			state:  "bound",
		})
		off += rowSize
	}
	return out
}

// MIB_TCP6ROW_OWNER_PID (56 bytes): LocalAddr[16], LocalScopeId, LocalPort,
// RemoteAddr[16], RemoteScopeId, RemotePort, State, OwningPid.
func listTCP6() []connRow {
	var size uint32
	_, _, _ = procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet6, tcpTableOwnerPIDAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r1, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet6, tcpTableOwnerPIDAll, 0)
	if r1 != 0 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	off := 4
	const rowSize = 56
	var out []connRow
	for i := uint32(0); i < n; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		remoteIP := net.IP(row[24:40])
		remote := remoteIP.String()
		lport := binary.BigEndian.Uint16(row[20:22])
		rport := binary.BigEndian.Uint16(row[44:46])
		state := binary.LittleEndian.Uint32(row[48:52])
		pid := binary.LittleEndian.Uint32(row[52:56])
		if remoteIP.IsUnspecified() || rport == 0 {
			off += rowSize
			continue
		}
		out = append(out, connRow{
			proto:  "tcp",
			pid:    pid,
			remote: remote,
			rport:  rport,
			lport:  lport,
			state:  tcpState(state),
		})
		off += rowSize
	}
	return out
}

// MIB_UDP6ROW_OWNER_PID (28 bytes): LocalAddr[16], LocalScopeId, LocalPort, OwningPid.
func listUDP6() []connRow {
	var size uint32
	_, _, _ = procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, afInet6, udpTableOwnerPID, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r1, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1, afInet6, udpTableOwnerPID, 0)
	if r1 != 0 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	off := 4
	const rowSize = 28
	var out []connRow
	for i := uint32(0); i < n; i++ {
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		localIP := net.IP(row[0:16])
		lport := binary.BigEndian.Uint16(row[20:22])
		pid := binary.LittleEndian.Uint32(row[24:28])
		out = append(out, connRow{
			proto:  "udp",
			pid:    pid,
			remote: localIP.String(),
			rport:  0,
			lport:  lport,
			state:  "bound",
		})
		off += rowSize
	}
	return out
}

func tcpState(s uint32) string {
	names := []string{
		"", "closed", "listen", "syn_sent", "syn_recv", "estab",
		"fin_wait1", "fin_wait2", "close_wait", "closing", "last_ack", "time_wait", "delete_tcb",
	}
	if int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("state_%d", s)
}
