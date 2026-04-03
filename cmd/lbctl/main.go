package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	pb "lb/proto"

	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	pinDir     = "/sys/fs/bpf/lbxdp"
	daemonSock = "/var/run/lbxdp-wlc.sock"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "add", "del", "list", "addsvc", "delsvc", "listsvc":
		runMapMode()
	case "weight":
		runGRPCCmd()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `lbctl — XDP load balancer control

Backend commands (pinned map access, works with lc and wlc):
  lbctl add    <ip> <port> [weight]   add backend (weight ignored in lc algo)
  lbctl del    <ip> <port>            remove backend (refused if active conns > 0)
  lbctl list                          list backends with connection counts

Service commands (pinned map access, works with lc and wlc):
  lbctl addsvc  <vip> <port>          register a virtual IP
  lbctl delsvc  <vip> <port>          deregister a virtual IP
  lbctl listsvc                       list registered VIPs

Weight command (gRPC, wlc algo only):
  lbctl weight <ip> <port> <weight>   update a backend's weight live`)
}

// ── gRPC path (wlc weight updates) ───────────────────────────────────────────

func runGRPCCmd() {
	if len(os.Args) < 5 {
		fatalf("usage: lbctl weight <ip> <port> <weight>")
	}
	ip     := os.Args[2]
	port   := mustPort(os.Args[3])
	weight := mustUint16(os.Args[4], "weight")

	conn, err := grpc.NewClient("unix://"+daemonSock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fatalf("connect to wlc daemon: %v", err)
	}
	defer conn.Close()

	c := pb.NewWeightControlClient(conn)
	_, err = c.UpdateWeight(context.Background(), &pb.WeightRequest{
		Ip:     ip,
		Port:   uint32(port),
		Weight: uint32(weight),
	})
	if err != nil {
		fatalf("UpdateWeight: %v", err)
	}
	fmt.Printf("weight updated: %s:%d → %d\n", ip, port, weight)
}

// ── pinned map path (backends + services) ─────────────────────────────────────

// lcBackend matches lbBackend/lb2Backend — no Weight field.
// C layout: ip(4) port(2) pad(2) conns(4)
type lcBackend struct {
	Ip    uint32
	Port  uint16
	Pad   uint16
	Conns uint32
}

// wlcBackend matches lb3Backend/lb4Backend.
// Actual compiled C layout: ip(4) port(2) pad(2) conns(4) weight(2) pad(2)
// __u32 conns is aligned to offset 8 by the compiler, pushing weight after it.
type wlcBackend struct {
	Ip     uint32
	Port   uint16
	Pad0   uint16
	Conns  uint32
	Weight uint16
	Pad1   uint16
}

// serviceKey matches lbIpPort/lb2IpPort/lb3IpPort/lb4IpPort.
// C layout: ip(4) port(2) pad(2)
type serviceKey struct {
	Ip   uint32
	Port uint16
	Pad  uint16
}

func runMapMode() {
	mode := readMode()

	backendsMap, err := ebpf.LoadPinnedMap(pinDir+"/backends", nil)
	if err != nil {
		fatalf("open backends map: %v\n(is the daemon running?)", err)
	}
	defer backendsMap.Close()

	countMap, err := ebpf.LoadPinnedMap(pinDir+"/backend_count", nil)
	if err != nil {
		fatalf("open backend_count map: %v", err)
	}
	defer countMap.Close()

	servicesMap, err := ebpf.LoadPinnedMap(pinDir+"/services", nil)
	if err != nil {
		fatalf("open services map: %v", err)
	}
	defer servicesMap.Close()

	// conntrack is only needed for wlc del (to patch BackendIdx after swap).
	// We find it by looking up the XDP program's map list, matching by name,
	// so we always get the map the running BPF program actually uses.
	var conntrackMap *ebpf.Map
	if mode == "wlc" && len(os.Args) >= 2 && os.Args[1] == "del" {
		conntrackMap = findConntrackMap()
		if conntrackMap != nil {
			defer conntrackMap.Close()
		} else {
			fmt.Fprintln(os.Stderr, "warning: could not find conntrack map, BackendIdx will not be patched")
		}
	}

	switch os.Args[1] {

	// ── backend commands ───────────────────────────────────────────────────────

	case "add":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl add <ip> <port> [weight]")
		}
		ip     := parseIPv4(os.Args[2])
		port   := mustPort(os.Args[3])
		weight := uint16(1)
		if len(os.Args) >= 5 {
			weight = mustUint16(os.Args[4], "weight")
		}
		addBackend(backendsMap, countMap, ip, port, weight, mode)

	case "del":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl del <ip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		delBackend(backendsMap, countMap, conntrackMap, ip, port, mode)

	case "list":
		listBackends(backendsMap, countMap, mode)

	// ── service commands ───────────────────────────────────────────────────────

	case "addsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl addsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		val  := true
		if err := servicesMap.Update(&key, &val, ebpf.UpdateAny); err != nil {
			fatalf("addsvc: %v", err)
		}
		fmt.Printf("service added: %s:%d\n", os.Args[2], port)

	case "delsvc":
		if len(os.Args) < 4 {
			fatalf("usage: lbctl delsvc <vip> <port>")
		}
		ip   := parseIPv4(os.Args[2])
		port := mustPort(os.Args[3])
		key  := serviceKey{Ip: ip, Port: htons(port)}
		if err := servicesMap.Delete(&key); err != nil {
			fatalf("delsvc: %v", err)
		}
		fmt.Printf("service deleted: %s:%d\n", os.Args[2], port)

	case "listsvc":
		iter := servicesMap.Iterate()
		var k serviceKey
		var v bool
		found := false
		for iter.Next(&k, &v) {
			fmt.Printf("service: %s  port: %d\n", ipToStr(k.Ip), ntohs(k.Port))
			found = true
		}
		if err := iter.Err(); err != nil {
			fatalf("iterate services: %v", err)
		}
		if !found {
			fmt.Println("no services registered")
		}
	}
}

// readMode reads the sentinel written by the daemon at startup.
// Returns "lc" or "wlc". Defaults to "lc" if the file is missing.
func readMode() string {
	data, err := os.ReadFile("/run/lbxdp.mode")
	if err != nil {
		return "lc"
	}
	return string(data)
}

// ── backend operations ────────────────────────────────────────────────────────

func addBackend(backendsMap, countMap *ebpf.Map, ip uint32, port, weight uint16, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	if mode == "wlc" {
		if wlcFindIdx(backendsMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), ntohs(port))
		}
		be := wlcBackend{Ip: ip, Port: htons(port), Conns: 0, Weight: weight}
		if err := backendsMap.Update(count, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
	} else {
		if lcFindIdx(backendsMap, count, ip, port) >= 0 {
			fatalf("backend %s:%d already exists", ipToStr(ip), ntohs(port))
		}
		be := lcBackend{Ip: ip, Port: htons(port), Conns: 0}
		if err := backendsMap.Update(count, &be, ebpf.UpdateAny); err != nil {
			fatalf("insert backend: %v", err)
		}
	}

	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		fatalf("update count: %v", err)
	}
	fmt.Printf("backend added: %s:%d\n", ipToStr(ip), ntohs(port))
}

// delBackend performs a swap-delete on the dense array and patches conntrack
// (for wlc mode) so existing connections keep pointing at the correct backend slot.
func delBackend(backendsMap, countMap, conntrackMap *ebpf.Map, ip uint32, port uint16, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}

	if mode == "wlc" {
		idx := wlcFindIdx(backendsMap, count, ip, port)
		if idx < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), ntohs(port))
		}
		var cur wlcBackend
		if err := backendsMap.Lookup(uint32(idx), &cur); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if cur.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", cur.Conns)
		}
		last := count - 1
		if uint32(idx) != last {
			var lb wlcBackend
			if err := backendsMap.Lookup(last, &lb); err != nil {
				fatalf("lookup last: %v", err)
			}
			if err := backendsMap.Update(uint32(idx), &lb, ebpf.UpdateExist); err != nil {
				fatalf("swap: %v", err)
			}
			// Patch conntrack: every entry with BackendIdx==last must now use idx.
			if conntrackMap != nil {
				if err := patchConntrackRaw(conntrackMap, last, uint32(idx)); err != nil {
					fatalf("patch conntrack: %v", err)
				}
			}
		}
		zero := wlcBackend{}
		if err := backendsMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero last slot: %v", err)
		}
	} else {
		idx := lcFindIdx(backendsMap, count, ip, port)
		if idx < 0 {
			fatalf("backend %s:%d not found", ipToStr(ip), ntohs(port))
		}
		var cur lcBackend
		if err := backendsMap.Lookup(uint32(idx), &cur); err != nil {
			fatalf("lookup backend: %v", err)
		}
		if cur.Conns != 0 {
			fatalf("backend has %d active connections — refusing delete", cur.Conns)
		}
		last := count - 1
		if uint32(idx) != last {
			var lb lcBackend
			if err := backendsMap.Lookup(last, &lb); err != nil {
				fatalf("lookup last: %v", err)
			}
			if err := backendsMap.Update(uint32(idx), &lb, ebpf.UpdateExist); err != nil {
				fatalf("swap: %v", err)
			}
		}
		zero := lcBackend{}
		if err := backendsMap.Update(last, &zero, ebpf.UpdateExist); err != nil {
			fatalf("zero last slot: %v", err)
		}
	}

	count--
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		fatalf("update count: %v", err)
	}
	fmt.Printf("backend deleted: %s:%d\n", ipToStr(ip), ntohs(port))
}

func listBackends(backendsMap, countMap *ebpf.Map, mode string) {
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		fatalf("lookup count: %v", err)
	}
	if count == 0 {
		fmt.Println("no backends registered")
		return
	}
	if mode == "wlc" {
		for i := uint32(0); i < count; i++ {
			var b wlcBackend
			if err := backendsMap.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  weight=%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Weight, b.Conns)
		}
	} else {
		for i := uint32(0); i < count; i++ {
			var b lcBackend
			if err := backendsMap.Lookup(i, &b); err != nil {
				continue
			}
			fmt.Printf("%d: %s:%d  conns=%d\n",
				i, ipToStr(b.Ip), ntohs(b.Port), b.Conns)
		}
	}
}

// wlcFindIdx scans backends[0..count) for ip:port, returns index or -1.
func wlcFindIdx(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
	for i := uint32(0); i < count; i++ {
		var b wlcBackend
		if err := backendsMap.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// lcFindIdx is the linear scan for lc mode.
func lcFindIdx(backendsMap *ebpf.Map, count uint32, ip uint32, port uint16) int {
	for i := uint32(0); i < count; i++ {
		var b lcBackend
		if err := backendsMap.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == ip && b.Port == htons(port) {
			return int(i)
		}
	}
	return -1
}

// ── conntrack patching ────────────────────────────────────────────────────────

// findConntrackMap finds the conntrack map used by the attached XDP program
// by iterating all loaded BPF programs, finding xdp_load_balancer, then
// iterating its map ids and returning the one named "conntrack".
func findConntrackMap() *ebpf.Map {
	// Walk all programs looking for xdp_load_balancer
	progID := ebpf.ProgramID(0)
	for {
		nextID, err := ebpf.ProgramGetNextID(progID)
		if err != nil {
			break
		}
		progID = nextID

		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		prog.Close()
		if err != nil || !strings.HasPrefix(info.Name, "xdp_load_bal") {
			continue
		}

		// Found the XDP program — get its map IDs
		mapIDs, _ := info.MapIDs()
		for _, mid := range mapIDs {
			m, err := ebpf.NewMapFromID(mid)
			if err != nil {
				continue
			}
			minfo, err := m.Info()
			if err != nil {
				m.Close()
				continue
			}
			if minfo.Name == "conntrack" {
				return m
			}
			m.Close()
		}
	}
	return nil
}

// ctKey mirrors struct ip_port used as conntrack map key.
type ctKey struct {
	Ip   uint32
	Port uint16
	Pad  uint16
}

// ctVal mirrors struct conn_meta.
// C layout: ip(4) port(2) pad(2) backend_idx(4) state(1) pad(1) service_port(2)
type ctVal struct {
	Ip          uint32
	Port        uint16
	Pad0        uint16
	BackendIdx  uint32
	State       uint8
	Pad1        uint8
	ServicePort uint16
}

// patchConntrackRaw scans the conntrack map and rewrites every entry whose
// BackendIdx == oldIdx to newIdx. Uses named padding fields so encoding/binary
// reads all fields at the correct offsets.
func patchConntrackRaw(conntrackMap *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		k ctKey
		v ctVal
	}
	var patches []kv
	iter := conntrackMap.Iterate()
	var k ctKey
	var v ctVal
	count := 0
	for iter.Next(&k, &v) {
		count++
		fmt.Printf("  conntrack entry: key={ip=%d port=%d} val={BackendIdx=%d State=%d}\n",
			k.Ip, k.Port, v.BackendIdx, v.State)
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	fmt.Printf("scanned %d conntrack entries, patched %d: BackendIdx %d → %d\n", count, len(patches), oldIdx, newIdx)
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.k, p.v
		if err := conntrackMap.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update: %w", err)
		}
	}
	return nil
}

// ── net / parse helpers ───────────────────────────────────────────────────────

func parseIPv4(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		fatalf("invalid IP address: %q", s)
	}
	return binary.LittleEndian.Uint32(ip)
}

func ipToStr(i uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b).String()
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }
func ntohs(p uint16) uint16 { return htons(p) }

func mustPort(s string) uint16 {
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		fatalf("invalid port: %q", s)
	}
	return uint16(p)
}

func mustUint16(s, name string) uint16 {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 || v > 65535 {
		fatalf("invalid %s: %q", name, s)
	}
	return uint16(v)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "lbctl: "+format+"\n", args...)
	os.Exit(1)
}