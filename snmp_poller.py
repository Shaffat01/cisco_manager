"""
SNMP-based real-time traffic monitor (pysnmp 4.x sync API).
Polls all switches in a background thread, computes per-port bandwidth (bps).
Also tracks in-memory history + DB save callback for long-term charts.
"""
import time
import threading
from collections import deque

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)

SNMP_PORT          = 161
DEFAULT_COMMUNITY  = "WhilDc321"
DEFAULT_VERSION    = 1

OID_IF_NAME   = '1.3.6.1.2.1.31.1.1.1.1'
OID_IF_DESCR  = '1.3.6.1.2.1.2.2.1.2'
OID_IF_HC_IN  = '1.3.6.1.2.1.31.1.1.1.6'
OID_IF_HC_OUT = '1.3.6.1.2.1.31.1.1.1.10'
OID_IF_IN     = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT    = '1.3.6.1.2.1.2.2.1.16'
OID_IF_SPEED  = '1.3.6.1.2.1.31.1.1.1.15'
OID_IF_OPER   = '1.3.6.1.2.1.2.2.1.8'


def _walk(ip, community, oid_base, version=DEFAULT_VERSION):
    out = {}
    try:
        for (err, status, idx, varBinds) in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=version),
            UdpTransportTarget((ip, SNMP_PORT), timeout=1.5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid_base)),
            lexicographicMode=False,
        ):
            if err or status:
                break
            for varBind in varBinds:
                oid_str = str(varBind[0])
                prefix  = oid_base + '.'
                if not oid_str.startswith(prefix):
                    continue
                sub = oid_str[len(prefix):]
                try:
                    if_index = int(sub.split('.')[0])
                except ValueError:
                    continue
                out[if_index] = varBind[1]
    except Exception as e:
        print(f"[SNMP {ip}] walk {oid_base} error: {e}")
    return out


def read_port_counters(ip, community=DEFAULT_COMMUNITY, version=DEFAULT_VERSION):
    names  = _walk(ip, community, OID_IF_NAME, version)
    if not names:
        names = _walk(ip, community, OID_IF_DESCR, version)

    descrs = _walk(ip, community, OID_IF_DESCR,  version)
    hc_in  = _walk(ip, community, OID_IF_HC_IN,   version)
    hc_out = _walk(ip, community, OID_IF_HC_OUT,  version)

    in32  = {} if hc_in  else _walk(ip, community, OID_IF_IN,  version)
    out32 = {} if hc_out else _walk(ip, community, OID_IF_OUT, version)

    speeds = _walk(ip, community, OID_IF_SPEED, version)
    opers  = _walk(ip, community, OID_IF_OPER,  version)

    ports = {}
    for idx, name in names.items():
        key = str(name).lower().strip()
        in_oct  = int(hc_in.get(idx)  or in32.get(idx)  or 0)
        out_oct = int(hc_out.get(idx) or out32.get(idx) or 0)
        ports[key] = {
            'if_index':   idx,
            'name':       key,
            'descr':      str(descrs.get(idx, '') or ''),
            'in_octets':  in_oct,
            'out_octets': out_oct,
            'speed_mbps': int(speeds.get(idx) or 0),
            'oper_up':    str(opers.get(idx) or '') == '1',
        }
    return ports


def compute_rates(prev, curr, elapsed):
    rates = {}
    for port, c in curr.items():
        p = prev.get(port)
        if not p:
            continue
        d_in  = (c['in_octets']  - p['in_octets'])  % (2**64)
        d_out = (c['out_octets'] - p['out_octets']) % (2**64)
        if d_in  > 2**63: d_in  = 0
        if d_out > 2**63: d_out = 0

        in_bps  = int(d_in  * 8 / elapsed)
        out_bps = int(d_out * 8 / elapsed)
        sp      = c['speed_mbps'] or 0

        rates[port] = {
            'name':         port,
            'descr':        c['descr'],
            'speed_mbps':   sp,
            'oper_up':      c['oper_up'],
            'in_bps':       in_bps,
            'out_bps':      out_bps,
            'in_util_pct':  round(in_bps  / (sp * 1_000_000) * 100, 1) if sp else 0.0,
            'out_util_pct': round(out_bps / (sp * 1_000_000) * 100, 1) if sp else 0.0,
        }
    return rates


class TrafficMonitor:
    def __init__(self, interval=5, community=DEFAULT_COMMUNITY,
                 version=DEFAULT_VERSION, history_size=60,
                 alert_threshold_pct=80, save_callback=None, save_every=60):
        self.interval      = interval
        self.community     = community
        self.version       = version
        self.history_size  = history_size
        self.alert_thresh  = alert_threshold_pct
        self.save_callback = save_callback
        self.save_every    = save_every
        self._last_save    = 0

        self.latest    = {}
        self.prev      = {}
        self.history   = {}
        self.errors    = {}
        self._switches = []
        self._lock     = threading.Lock()
        self._stop     = threading.Event()
        self._thread   = None

    def set_switches(self, switch_list):
        with self._lock:
            self._switches = list(switch_list)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="snmp-traffic")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        print(f"[TrafficMonitor] started (interval={self.interval}s, "
              f"community={self.community}, save_every={self.save_every}s)")
        while not self._stop.is_set():
            started = time.time()
            with self._lock:
                switches = list(self._switches)

            for sw in switches:
                if self._stop.is_set():
                    break
                self._poll_one(sw['id'], sw['ip'])

            if self.save_callback and time.time() - self._last_save >= self.save_every:
                self._save_snapshot()
                self._last_save = time.time()

            elapsed = time.time() - started
            self._stop.wait(max(0.5, self.interval - elapsed))

    def _poll_one(self, sw_id, ip):
        snap = read_port_counters(ip, self.community, self.version)
        if not snap:
            self.errors[sw_id] = "No SNMP response (community/ACL?)"
            return

        now = time.time()
        prev_entry = self.prev.get(sw_id)
        if prev_entry:
            prev_ts, prev_snap = prev_entry
            elapsed = max(0.1, now - prev_ts)
            rates = compute_rates(prev_snap, snap, elapsed)

            with self._lock:
                self.latest[sw_id] = {'ts': now, 'rates': rates}
                hist = self.history.setdefault(sw_id, {})
                for port, r in rates.items():
                    dq = hist.setdefault(port, deque(maxlen=self.history_size))
                    dq.append((now, r['in_bps'], r['out_bps']))
                self.errors.pop(sw_id, None)

        self.prev[sw_id] = (now, snap)

    def _save_snapshot(self):
        samples = []
        ts = int(time.time())
        with self._lock:
            for sw_id, entry in self.latest.items():
                for port_name, rate in entry['rates'].items():
                    samples.append((sw_id, port_name,
                                    int(rate['in_bps']),
                                    int(rate['out_bps']),
                                    ts))
        if samples:
            try:
                self.save_callback(samples)
                print(f"[TrafficMonitor] saved {len(samples)} samples to DB")
            except Exception as e:
                print(f"[TrafficMonitor] save error: {e}")

    def get(self, sw_id):
        with self._lock:
            return self.latest.get(sw_id), self.errors.get(sw_id)

    def get_all_latest(self):
        with self._lock:
            return {sw_id: dict(entry) for sw_id, entry in self.latest.items()}

    def get_history(self, sw_id, port=None):
        with self._lock:
            hist = self.history.get(sw_id, {})
            if port:
                return list(hist.get(port, []))
            return {p: list(dq) for p, dq in hist.items()}

    def get_top_talkers(self, sw_id, n=5):
        with self._lock:
            entry = self.latest.get(sw_id)
            if not entry:
                return []
            ports = sorted(entry['rates'].values(),
                           key=lambda p: (p['in_bps'] + p['out_bps']),
                           reverse=True)
            return ports[:n]

    def get_alerts(self, threshold_pct=None):
        thr = threshold_pct if threshold_pct is not None else self.alert_thresh
        with self._lock:
            alerts = []
            for sw_id, entry in self.latest.items():
                for port in entry['rates'].values():
                    util = max(port['in_util_pct'], port['out_util_pct'])
                    if util >= thr:
                        alerts.append({
                            'sw_id':      sw_id,
                            'port':       port['name'],
                            'descr':      port['descr'],
                            'util_pct':   util,
                            'in_bps':     port['in_bps'],
                            'out_bps':    port['out_bps'],
                            'speed_mbps': port['speed_mbps'],
                        })
            alerts.sort(key=lambda a: a['util_pct'], reverse=True)
            return alerts

    def status(self):
        with self._lock:
            return {
                'switches':     len(self._switches),
                'polling':      self._thread is not None and self._thread.is_alive(),
                'interval':     self.interval,
                'community':    self.community,
                'history_size': self.history_size,
                'alert_thresh': self.alert_thresh,
                'save_every':   self.save_every,
            }


monitor = TrafficMonitor(interval=5, community=DEFAULT_COMMUNITY, version=1,
                         history_size=60, alert_threshold_pct=80,
                         save_every=60)


if __name__ == "__main__":
    import sys
    test_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.102.6"
    print(f"Testing SNMP on {test_ip} with community '{DEFAULT_COMMUNITY}'...")
    snap = read_port_counters(test_ip)
    if not snap:
        print("❌ No ports read.")
    else:
        print(f"✅ Got {len(snap)} ports:")
        for k, v in sorted(snap.items()):
            print(f"  {k:15} speed={v['speed_mbps']:>5} Mbps  "
                  f"up={v['oper_up']}  in={v['in_octets']}  out={v['out_octets']}")