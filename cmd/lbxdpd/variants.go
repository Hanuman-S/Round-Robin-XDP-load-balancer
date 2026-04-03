package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
)

// ── config types ──────────────────────────────────────────────────────────────

// backendCfg covers both lc (weight ignored) and wlc (weight honoured).
type backendCfg struct {
	IP     string `json:"ip"`
	Port   uint16 `json:"port"`
	Weight uint16 `json:"weight"` // optional; defaults to 1 in wlc mode
}

type serviceCfg struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
}

type config struct {
	Service  serviceCfg   `json:"service"`
	Backends []backendCfg `json:"backends"`
}

// ── shared helpers ────────────────────────────────────────────────────────────

func parseIPv4Cfg(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4: %q", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func htons(p uint16) uint16 { return (p<<8)&0xff00 | p>>8 }

func defaultWeight(w uint16) uint16 {
	if w == 0 {
		return 1
	}
	return w
}

const (
	pinDir       = "/sys/fs/bpf/lbxdp"
	sentinelPath = "/run/lbxdp.mode"
)

func pinMaps(pins map[string]*ebpf.Map, modeName string) error {
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", pinDir, err)
	}
	for path, m := range pins {
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin %s: %w", path, err)
		}
	}
	return os.WriteFile(sentinelPath, []byte(modeName), 0644)
}

func loadConfig(cfgPath string) (config, error) {
	var cfg config
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", cfgPath, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", cfgPath, err)
	}
	return cfg, nil
}

// patchConntrackLb3 scans the lb3 conntrack map and rewrites every entry
// whose BackendIdx == oldIdx to newIdx. Called after a swap-delete so
// existing connections keep pointing at the correct backend slot.
func patchConntrackLb3(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb3IpPort
		val lb3ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb3IpPort
	var v lb3ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendIdx == oldIdx {
			v.BackendIdx = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// patchConntrackLb4 is identical to patchConntrackLb3 but uses lb4 types.
func patchConntrackLb4(conntrack *ebpf.Map, oldIdx, newIdx uint32) error {
	type kv struct {
		key lb4IpPort
		val lb4ConnMeta
	}
	var patches []kv
	iter := conntrack.Iterate()
	var k lb4IpPort
	var v lb4ConnMeta
	for iter.Next(&k, &v) {
		if v.BackendId == oldIdx {
			v.BackendId = newIdx
			patches = append(patches, kv{k, v})
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate conntrack: %w", err)
	}
	for _, p := range patches {
		pk, pv := p.key, p.val
		if err := conntrack.Update(&pk, &pv, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("patch conntrack entry: %w", err)
		}
	}
	return nil
}

// ── generic array-backend helpers (used by both lc and wlc) ──────────────────

type (
	makeEntryFn   func(ip uint32, port, weight uint16) interface{}
	getIPPortFn   func(m *ebpf.Map, idx uint32) (ip uint32, port uint16, err error)
	getConnsFn    func(m *ebpf.Map, idx uint32) (conns uint32, err error)
	swapEntryFn   func(m *ebpf.Map, dst, src uint32) error
	zeroEntryFn   func() interface{}
)

func arrayAddBackend(backends, countMap *ebpf.Map,
	ip string, port, weight uint16,
	getIPPort getIPPortFn,
	make makeEntryFn,
	portXform func(uint16) uint16) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	storedPort := portXform(port)
	// Duplicate check.
	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip == pip && bport == storedPort {
			return fmt.Errorf("backend %s:%d already exists", ip, port)
		}
	}
	be := make(pip, storedPort, weight)
	if err := backends.Update(count, be, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("insert backend: %w", err)
	}
	count++
	if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update count: %w", err)
	}
	return nil
}

// arrayDeleteBackend performs a swap-delete on the dense backends array and
// patches the conntrack map so existing connections keep working.
// patchCT is called with (oldIdx=last, newIdx=deletedSlot) after the swap;
// pass nil for lc variants which share conntrack with the kernel but don't
// need patching (lc uses the same index scheme and has no weighted routing).
func arrayDeleteBackend(backends, countMap *ebpf.Map,
	ip string, port uint16,
	getIPPort getIPPortFn,
	getConns getConnsFn,
	swap swapEntryFn,
	zero zeroEntryFn,
	portXform func(uint16) uint16,
	patchCT func(oldIdx, newIdx uint32) error) error {

	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := countMap.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	storedPort := portXform(port)

	for i := uint32(0); i < count; i++ {
		bip, bport, err := getIPPort(backends, i)
		if err != nil {
			continue
		}
		if bip != pip || bport != storedPort {
			continue
		}
		conns, err := getConns(backends, i)
		if err != nil {
			return fmt.Errorf("lookup conns: %w", err)
		}
		if conns != 0 {
			return fmt.Errorf("backend %s:%d has %d active connections", ip, port, conns)
		}

		last := count - 1
		if i != last {
			// Swap last backend into the deleted slot.
			if err := swap(backends, i, last); err != nil {
				return fmt.Errorf("swap: %w", err)
			}
			// Patch conntrack: every entry pointing at 'last' must now point at 'i'.
			if patchCT != nil {
				if err := patchCT(last, i); err != nil {
					return fmt.Errorf("patch conntrack: %w", err)
				}
			}
		}

		// Zero the vacated last slot.
		if err := backends.Update(last, zero(), ebpf.UpdateExist); err != nil {
			return fmt.Errorf("zero last slot: %w", err)
		}
		count--
		if err := countMap.Update(uint32(0), &count, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("update count: %w", err)
		}
		return nil
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

// ── LC-EST variant (lb / lb_lc_est.c) ────────────────────────────────────────

type lcEstVariant struct{ objs lbObjects }

func newLcEstVariant() (*lcEstVariant, error) {
	v := &lcEstVariant{}
	if err := loadLbObjects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (lc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lbMaps.Backends,
		pinDir + "/backend_count": v.objs.lbMaps.BackendCount,
		pinDir + "/services":      v.objs.lbMaps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *lcEstVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *lcEstVariant) Close()                                          { v.objs.Close() }
func (v *lcEstVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *lcEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lbMaps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lbBackend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lbMaps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lbMaps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *lcEstVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lbBackend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *lcEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lbMaps.Backends, v.objs.lbMaps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lbBackend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lbBackend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lbBackend{} },
		htons, nil)
}

func (v *lcEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lbMaps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *lcEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lbIpPort{Ip: pip, Port: htons(port)}
	return v.objs.lbMaps.Services.Delete(&key)
}

// ── LC-SYN variant (lb2 / lb_lc_syn.c) ───────────────────────────────────────

type lcSynVariant struct{ objs lb2Objects }

func newLcSynVariant() (*lcSynVariant, error) {
	v := &lcSynVariant{}
	if err := loadLb2Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (lc-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb2Maps.Backends,
		pinDir + "/backend_count": v.objs.lb2Maps.BackendCount,
		pinDir + "/services":      v.objs.lb2Maps.Services,
	}, "lc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *lcSynVariant) Program() *ebpf.Program                          { return v.objs.XdpLoadBalancer }
func (v *lcSynVariant) Close()                                          { v.objs.Close() }
func (v *lcSynVariant) UpdateWeight(_ string, _ uint16, _ uint16) error { return nil }

func (v *lcSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb2Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb2Backend{Ip: ip, Port: htons(b.Port), Conns: 0}
		if err := v.objs.lb2Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb2Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *lcSynVariant) AddBackend(ip string, port uint16, _ uint16) error {
	return arrayAddBackend(v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount, ip, port, 0,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, _ uint16) interface{} {
			return &lb2Backend{Ip: ip, Port: port, Conns: 0}
		},
		htons)
}

func (v *lcSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb2Maps.Backends, v.objs.lb2Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb2Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb2Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb2Backend{} },
		htons, nil)
}

func (v *lcSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb2Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *lcSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb2IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb2Maps.Services.Delete(&key)
}

// ── WLC-EST variant (lb3 / lb_wlc_est.c) ─────────────────────────────────────
// backends is now BPF_MAP_TYPE_ARRAY keyed by index (no selection_array, no next_id).
// struct backend layout: { ip, port, conns, weight }

type wlcEstVariant struct{ objs lb3Objects }

func newWlcEstVariant() (*wlcEstVariant, error) {
	v := &wlcEstVariant{}
	if err := loadLb3Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-est): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb3Maps.Backends,
		pinDir + "/backend_count": v.objs.lb3Maps.BackendCount,
		pinDir + "/services":      v.objs.lb3Maps.Services,
		pinDir + "/conntrack":     v.objs.lb3Maps.Conntrack,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcEstVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcEstVariant) Close()                 { v.objs.Close() }

func (v *wlcEstVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb3Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb3Backend{Ip: ip, Port: b.Port, Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb3Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb3Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcEstVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb3Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb3Backend
		if err := v.objs.lb3Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == port {
			b.Weight = weight
			return v.objs.lb3Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wlcEstVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb3Backend{Ip: ip, Port: port, Conns: 0, Weight: w}
		},
		func(p uint16) uint16 { return p })
}

func (v *wlcEstVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb3Maps.Backends, v.objs.lb3Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb3Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb3Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb3Backend{} },
		func(p uint16) uint16 { return p },
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb3(v.objs.lb3Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wlcEstVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb3Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wlcEstVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb3IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb3Maps.Services.Delete(&key)
}

// ── WLC-SYN variant (lb4 / lb_wlc_syn.c) ─────────────────────────────────────

type wlcSynVariant struct{ objs lb4Objects }

func newWlcSynVariant() (*wlcSynVariant, error) {
	v := &wlcSynVariant{}
	if err := loadLb4Objects(&v.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects (wlc-syn): %w", err)
	}
	if err := pinMaps(map[string]*ebpf.Map{
		pinDir + "/backends":      v.objs.lb4Maps.Backends,
		pinDir + "/backend_count": v.objs.lb4Maps.BackendCount,
		pinDir + "/services":      v.objs.lb4Maps.Services,
		pinDir + "/conntrack":     v.objs.lb4Maps.Conntrack,
	}, "wlc"); err != nil {
		v.objs.Close()
		return nil, err
	}
	return v, nil
}

func (v *wlcSynVariant) Program() *ebpf.Program { return v.objs.XdpLoadBalancer }
func (v *wlcSynVariant) Close()                 { v.objs.Close() }

func (v *wlcSynVariant) Init(cfgPath string) error {
	if err := initPorts(func(p uint16) error {
		return v.objs.lb4Maps.FreePorts.Update(nil, &p, ebpf.UpdateAny)
	}); err != nil {
		return fmt.Errorf("init ports: %w", err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := v.AddService(cfg.Service.VIP, cfg.Service.Port); err != nil {
		return fmt.Errorf("add service: %w", err)
	}
	for i, b := range cfg.Backends {
		ip, err := parseIPv4Cfg(b.IP)
		if err != nil {
			return fmt.Errorf("backend[%d] IP: %w", i, err)
		}
		be := lb4Backend{Ip: ip, Port: b.Port, Conns: 0, Weight: defaultWeight(b.Weight)}
		if err := v.objs.lb4Maps.Backends.Update(uint32(i), &be, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update backends[%d]: %w", i, err)
		}
	}
	cnt := uint32(len(cfg.Backends))
	return v.objs.lb4Maps.BackendCount.Update(uint32(0), &cnt, ebpf.UpdateAny)
}

func (v *wlcSynVariant) UpdateWeight(ip string, port, weight uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	var count uint32
	if err := v.objs.lb4Maps.BackendCount.Lookup(uint32(0), &count); err != nil {
		return fmt.Errorf("lookup count: %w", err)
	}
	for i := uint32(0); i < count; i++ {
		var b lb4Backend
		if err := v.objs.lb4Maps.Backends.Lookup(i, &b); err != nil {
			continue
		}
		if b.Ip == pip && b.Port == port {
			b.Weight = weight
			return v.objs.lb4Maps.Backends.Update(i, &b, ebpf.UpdateExist)
		}
	}
	return fmt.Errorf("backend %s:%d not found", ip, port)
}

func (v *wlcSynVariant) AddBackend(ip string, port, weight uint16) error {
	return arrayAddBackend(v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount, ip, port, defaultWeight(weight),
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(ip uint32, port, w uint16) interface{} {
			return &lb4Backend{Ip: ip, Port: port, Conns: 0, Weight: w}
		},
		func(p uint16) uint16 { return p })
}

func (v *wlcSynVariant) DeleteBackend(ip string, port uint16) error {
	return arrayDeleteBackend(
		v.objs.lb4Maps.Backends, v.objs.lb4Maps.BackendCount,
		ip, port,
		func(m *ebpf.Map, idx uint32) (uint32, uint16, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, 0, err
			}
			return b.Ip, b.Port, nil
		},
		func(m *ebpf.Map, idx uint32) (uint32, error) {
			var b lb4Backend
			if err := m.Lookup(idx, &b); err != nil {
				return 0, err
			}
			return b.Conns, nil
		},
		func(m *ebpf.Map, dst, src uint32) error {
			var b lb4Backend
			if err := m.Lookup(src, &b); err != nil {
				return err
			}
			return m.Update(dst, &b, ebpf.UpdateExist)
		},
		func() interface{} { return &lb4Backend{} },
		func(p uint16) uint16 { return p },
		func(oldIdx, newIdx uint32) error {
			return patchConntrackLb4(v.objs.lb4Maps.Conntrack, oldIdx, newIdx)
		})
}

func (v *wlcSynVariant) AddService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	val := true
	return v.objs.lb4Maps.Services.Update(&key, &val, ebpf.UpdateAny)
}

func (v *wlcSynVariant) DeleteService(ip string, port uint16) error {
	pip, err := parseIPv4Cfg(ip)
	if err != nil {
		return err
	}
	key := lb4IpPort{Ip: pip, Port: htons(port)}
	return v.objs.lb4Maps.Services.Delete(&key)
}