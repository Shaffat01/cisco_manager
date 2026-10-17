"""
SNMP monitor — two pollers in one file.

  1) TrafficMonitor     — on-demand live view (5s), per-switch ON/OFF
  2) AccountingMonitor  — always-on, LOW-freq, staggered, skip-live

Key changes vs. previous version:
  * Accounting starts after 60s warmup (app boots first)
  * Accounting runs in BATCHES over its interval (not all-at-once)
  * Accounting SKIPS switches currently being live-polled
  * Accounting default workers 32 → 12 (less thread/GIL pressure)
  * Accounting interval 300 → 600s (10 min, still fine for 24h totals)
  * Better logging: per-cycle success/fail counts
  * Dead-switch backoff prevents wasted polls
"""
import os
import time
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, nextCmd
)


# ---------------- Config ----------------
SNMP_PORT          = 161
DEFAULT_COMMUNITY  = os.environ.get("SNMP_COMMUNITY", "WhilDc321")
_SNMP_VERSION_USER = int(os.environ.get("SNMP_VERSION", "2"))


def _user_to_mpmodel(v):
    return 0 if v == 1 else 1          # 0=v1, 1=v2c


DEFAULT_VERSION   = _user_to_mpmodel(_SNMP_VERSION_USER)
SNMP_VERSION_STR  = "v1" if _SNMP_VERSION_USER == 1 else "v2c"

DEFAULT_TIMEOUT   = float(os.environ.get("SNMP_TIMEOUT", "1.5"))
DEFAULT_RETRIES   = int(os.environ.get("SNMP_RETRIES", "1"))

# Live poller
POLL_INTERVAL     = int(os.environ.get("SNMP_INTERVAL", "5"))
ENABLE_TTL        = int(os.environ.get("SNMP_ENABLE_TTL", "300"))
SAVE_EVERY        = int(os.environ.get("SNMP_SAVE_EVERY", "60"))
HISTORY_SIZE      = int(os.environ.get("SNMP_HISTORY", "60"))
ALERT_THRESHOLD   = float(os.environ.get("SNMP_ALERT_PCT", "80"))
STATIC_TTL        = int(os.environ.get("SNMP_STATIC_TTL", "300"))
MAX_WORKERS       = int(os.environ.get("SNMP_WORKERS", "16"))

# Accounting poller — LESS aggressive by default
ACCOUNT_INTERVAL  = int(os.environ.get("SNMP_ACCOUNT_INTERVAL", "600"))   # 10 min
ACCOUNT_WORKERS   = int(os.environ.get("SNMP_ACCOUNT_WORKERS", "12"))
ACCOUNT_BATCH     = int(os.environ.get("SNMP_ACCOUNT_BATCH", "40"))       # switches/batch
ACCOUNT_START_DELAY = int(os.environ.get("SNMP_ACCOUNT_START_DELAY", "60"))
NAMES_TTL         = int(os.environ.get("SNMP_NAMES_TTL", "3600"))

BACKOFF_BASE      = int(os.environ.get("SNMP_BACKOFF_BASE", "30"))
BACKOFF_MAX       = int(os.environ.get("SNMP_BACKOFF_MAX", "600"))


# ---------------- OIDs ----------------
OID_IF_NAME   = '1.3.6.1.2.1.31.1.1.1.1'
OID_IF_DESCR  = '1.3.6.1.2.1.2.2.1.2'
OID_IF_HC_IN  = '1.3.6.1.2.1.31.1.1.1.6'
OID_IF_HC_OUT = '1.3.6.1.2.1.31.1.1.1.10'
OID_IF_IN     = '1.3.6.1.2.1.2.2.1.10'
OID_IF_OUT    = '1.3.6.1.2.1.2.2.1.16'
OID_IF_SPEED  = '1.3.6.1.2.1.31.1.1.1.15'
OID_IF_OPER   = '1.3.6.1.2.1.2.2.1.8'


# ---------------- Thread-local SNMP engine ----------------
_engine_local = threading.local()


def _get_engine():
    if not hasattr(_engine_local, 'engine'):
        _engine_local.engine = SnmpEngine()
    return _engine_local.engine


# ---------------- Walks ----------------
def _walk(ip, community, oid_base, version=DEFAULT_VERSION,
          timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    out = {}
    try:
        for (err, status, idx, varBinds) in nextCmd(
            _get_engine(),
            CommunityData(community, mpModel=version),
            UdpTransportTarget((ip, SNMP_PORT), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(oid_base)),
            lexicographicMode=False,
        ):
            if err or status:
                break
            for varBind in varBinds:
                oid_str = str(varBind[0])
                prefix = oid_base + '.'
                if not oid_str.startswith(prefix):
                    continue
                try:
                    if_index = int(oid_str[len(prefix):].split('.')[0])
                except ValueError:
                    continue
                out[if_index] = varBind[1]
    except Exception as e:
        print(f"[SNMP {ip}] walk {oid_base} error: {e}")
    return out


def _walk_multi(ip, community, oid_bases, version=DEFAULT_VERSION,
                timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES):
    out = {oid: {} for oid in oid_bases}
    try:
        for (err, status, idx, varBinds) in nextCmd(
            _get_engine(),
            CommunityData(community, mpModel=version),
            UdpTransportTarget((ip, SNMP_PORT), timeout=timeout, retries=retries),
            ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oid_bases],
            lexicographicMode=False,
        ):
            if err or status:
                break
            for varBind in varBinds:
                oid_str = str(varBind[0])
                for base in oid_bases:
                    prefix = base + '.'
                    if oid_str.startswith(prefix):
                        try:
                            if_index = int(oid_str[len(prefix):].split('.')[0])
                        except ValueError:
                            continue
                        out[base][if_index] = varBind[1]
                        break
    except Exception as e:
        print(f"[SNMP {ip}] walk_multi error: {e}")
    return out


# ---------------- High-level reads ----------------
def read_port_counters_full(ip, community=DEFAULT_COMMUNITY,
                            version=DEFAULT_VERSION):
    names  = _walk(ip, community, OID_IF_NAME,  version)
    if not names:
        names = _walk(ip, community, OID_IF_DESCR, version)
    descrs = _walk(ip, community, OID_IF_DESCR, version)
    speeds = _walk(ip, community, OID_IF_SPEED, version)

    data   = _walk_multi(ip, community,
                         [OID_IF_HC_IN, OID_IF_HC_OUT, OID_IF_IN,
                          OID_IF_OUT, OID_IF_OPER], version)
    hc_in, hc_out = data[OID_IF_HC_IN], data[OID_IF_HC_OUT]
    in32,  out32  = data[OID_IF_IN],    data[OID_IF_OUT]
    opers         = data[OID_IF_OPER]

    ports = {}
    for idx, name in names.items():
        key = str(name).lower().strip()
        ports[idx] = {
            'if_index':   idx,
            'name':       key,
            'descr':      str(descrs.get(idx, '') or ''),
            'speed_mbps': int(speeds.get(idx) or 0),
            'in_octets':  int(hc_in.get(idx)  or in32.get(idx)  or 0),
            'out_octets': int(hc_out.get(idx) or out32.get(idx) or 0),
            'oper_up':    str(opers.get(idx) or '') == '1',
        }
    return ports


def read_port_counters_only(ip, static_data, community=DEFAULT_COMMUNITY,
                            version=DEFAULT_VERSION):
    data   = _walk_multi(ip, community,
                         [OID_IF_HC_IN, OID_IF_HC_OUT, OID_IF_IN,
                          OID_IF_OUT, OID_IF_OPER], version)
    hc_in, hc_out = data[OID_IF_HC_IN], data[OID_IF_HC_OUT]
    in32,  out32  = data[OID_IF_IN],    data[OID_IF_OUT]
    opers         = data[OID_IF_OPER]

    if not (hc_in or hc_out or in32 or out32 or opers):
        return {}

    merged = {}
    for idx, s in static_data.items():
        merged[idx] = {
            'if_index':   idx,
            'name':       s['name'],
            'descr':      s['descr'],
            'speed_mbps': s['speed_mbps'],
            'in_octets':  int(hc_in.get(idx)  or in32.get(idx)  or 0),
            'out_octets': int(hc_out.get(idx) or out32.get(idx) or 0),
            'oper_up':    str(opers.get(idx) or '') == '1',
        }
    return merged


def read_counters_only(ip, community=DEFAULT_COMMUNITY, version=DEFAULT_VERSION):
    data   = _walk_multi(ip, community, [OID_IF_HC_IN, OID_IF_HC_OUT], version)
    hc_in  = data[OID_IF_HC_IN]
    hc_out = data[OID_IF_HC_OUT]
    if not hc_in and not hc_out:
        data   = _walk_multi(ip, community, [OID_IF_IN, OID_IF_OUT], version)
        hc_in  = data[OID_IF_IN]
        hc_out = data[OID_IF_OUT]

    out = {}
    for idx in set(hc_in) | set(hc_out):
        out[idx] = (int(hc_in.get(idx) or 0), int(hc_out.get(idx) or 0))
    return out


def _zero_rates(snap):
    out = {}
    for idx, p in snap.items():
        sp = p['speed_mbps'] or 0
        out[p['name']] = {
            'name': p['name'], 'if_index': idx, 'descr': p['descr'],
            'speed_mbps': sp, 'oper_up': p['oper_up'],
            'in_bps': 0, 'out_bps': 0,
            'in_util_pct': 0.0, 'out_util_pct': 0.0,
        }
    return out


def compute_rates(prev, curr, elapsed):
    rates = {}
    for idx, c in curr.items():
        p = prev.get(idx)
        if not p:
            continue
        d_in  = (c['in_octets']  - p['in_octets'])  % (2**64)
        d_out = (c['out_octets'] - p['out_octets']) % (2**64)
        if d_in  > 2**63: d_in  = 0
        if d_out > 2**63: d_out = 0

        in_bps  = int(d_in  * 8 / elapsed)
        out_bps = int(d_out * 8 / elapsed)
        sp      = c['speed_mbps'] or 0

        rates[c['name']] = {
            'name': c['name'], 'if_index': idx, 'descr': c['descr'],
            'speed_mbps': sp, 'oper_up': c['oper_up'],
            'in_bps': in_bps, 'out_bps': out_bps,
            'in_util_pct':  round(in_bps  / (sp * 1_000_000) * 100, 1) if sp else 0.0,
            'out_util_pct': round(out_bps / (sp * 1_000_000) * 100, 1) if sp else 0.0,
        }
    return rates


# ============================================================
# LIVE MONITOR — on-demand, per-switch 5s polling
# ============================================================
class TrafficMonitor:
    def __init__(self, interval=POLL_INTERVAL, community=DEFAULT_COMMUNITY,
                 version=DEFAULT_VERSION, history_size=HISTORY_SIZE,
                 alert_threshold_pct=ALERT_THRESHOLD, save_callback=None,
                 save_every=SAVE_EVERY, max_workers=MAX_WORKERS,
                 static_ttl=STATIC_TTL, enable_ttl=ENABLE_TTL):
        self.interval      = interval
        self.community     = community
        self.version       = version
        self.history_size  = history_size
        self.alert_thresh  = alert_threshold_pct
        self.save_callback = save_callback
        self.save_every    = save_every
        self.max_workers   = max_workers
        self.static_ttl    = static_ttl
        self.enable_ttl    = enable_ttl
        self._last_save    = 0

        self._enabled      = {}
        self.prev          = {}
        self.latest        = {}
        self.history       = {}
        self.errors        = {}
        self._static_cache = {}
        self._fail_count   = {}
        self._next_try     = {}

        self._lock         = threading.Lock()
        self._stop         = threading.Event()
        self._thread       = None
        self._executor     = None

    def enable(self, sw_id, ip, ttl=None):
        ttl = ttl if ttl is not None else self.enable_ttl
        now = time.time()
        with self._lock:
            self._enabled[sw_id] = {
                'ip': ip, 'enabled_at': now, 'expires_at': now + ttl,
            }
            for d in (self.prev, self.latest, self.history, self.errors,
                      self._static_cache, self._fail_count, self._next_try):
                d.pop(sw_id, None)
        print(f"[TrafficMonitor] ENABLED sw_id={sw_id} ({ip}) TTL={ttl}s")
        return True

    def disable(self, sw_id, reason="manual"):
        with self._lock:
            was = self._enabled.pop(sw_id, None)
            for d in (self.prev, self.latest, self.history, self.errors,
                      self._static_cache, self._fail_count, self._next_try):
                d.pop(sw_id, None)
        if was:
            print(f"[TrafficMonitor] DISABLED sw_id={sw_id} ({reason})")
        return bool(was)

    def state(self, sw_id):
        with self._lock:
            e = self._enabled.get(sw_id)
            if not e:
                return {'enabled': False}
            now = time.time()
            remaining = max(0, int(e['expires_at'] - now))
            if remaining <= 0:
                return {'enabled': False}
            return {
                'enabled': True,
                'enabled_at': e['enabled_at'],
                'expires_at': e['expires_at'],
                'remaining':  remaining,
                'ttl':        self.enable_ttl,
            }

    def is_enabled(self, sw_id):
        return self.state(sw_id).get('enabled', False)

    def enabled_ids(self):
        with self._lock:
            return list(self._enabled.keys())

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="snmp-live",
            )
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="snmp-traffic")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        print(f"[TrafficMonitor] started | interval={self.interval}s "
              f"ttl={self.enable_ttl}s workers={self.max_workers} "
              f"version={SNMP_VERSION_STR} community={self.community}")
        while not self._stop.is_set():
            started = time.time()

            now = time.time()
            with self._lock:
                expired = [sid for sid, e in self._enabled.items()
                           if now >= e['expires_at']]
            for sid in expired:
                self.disable(sid, reason="auto-off (TTL)")

            with self._lock:
                items = [(sid, info['ip']) for sid, info in self._enabled.items()]

            if items:
                futures = {self._executor.submit(self._poll_one, sid, ip): sid
                           for sid, ip in items}
                for f in as_completed(futures, timeout=60):
                    try:
                        f.result()
                    except Exception as e:
                        print(f"[TrafficMonitor] poll error: {e}")
                    if self._stop.is_set():
                        break

            if self.save_callback and \
               (time.time() - self._last_save) >= self.save_every:
                self._save_snapshot()
                self._last_save = time.time()

            elapsed = time.time() - started
            self._stop.wait(max(0.5, self.interval - elapsed))

    def _poll_one(self, sw_id, ip):
        now = time.time()
        with self._lock:
            if sw_id not in self._enabled:
                return
            next_try = self._next_try.get(sw_id, 0)
        if now < next_try:
            return

        try:
            snap = self._fetch_snapshot(sw_id, ip, now)
        except Exception as e:
            snap = None
            print(f"[TrafficMonitor] {ip} fetch error: {e}")

        if not snap:
            self._register_failure(sw_id, now)
            return

        with self._lock:
            if sw_id not in self._enabled:
                return
            self._fail_count.pop(sw_id, None)
            self._next_try.pop(sw_id, None)

            prev_entry = self.prev.get(sw_id)
            if prev_entry:
                prev_ts, prev_snap = prev_entry
                elapsed = max(0.1, now - prev_ts)
                rates = compute_rates(prev_snap, snap, elapsed)
            else:
                rates = _zero_rates(snap)

            self.latest[sw_id] = {'ts': now, 'rates': rates}
            hist = self.history.setdefault(sw_id, {})
            for port, r in rates.items():
                dq = hist.setdefault(port, deque(maxlen=self.history_size))
                dq.append((now, r['in_bps'], r['out_bps']))
            self.errors.pop(sw_id, None)
            self.prev[sw_id] = (now, snap)

    def _fetch_snapshot(self, sw_id, ip, now):
        with self._lock:
            cache = self._static_cache.get(sw_id)

        use_cache = cache and (now - cache['ts']) < self.static_ttl

        if use_cache:
            snap = read_port_counters_only(ip, cache['data'],
                                           self.community, self.version)
            if not snap:
                with self._lock:
                    self._static_cache.pop(sw_id, None)
                return None
            return snap

        full = read_port_counters_full(ip, self.community, self.version)
        if not full:
            return None

        static = {idx: {'if_index': idx, 'name': p['name'],
                        'descr': p['descr'], 'speed_mbps': p['speed_mbps']}
                  for idx, p in full.items()}
        with self._lock:
            self._static_cache[sw_id] = {'ts': now, 'data': static}
        return full

    def _register_failure(self, sw_id, now):
        with self._lock:
            if sw_id not in self._enabled:
                return
            fails = self._fail_count.get(sw_id, 0) + 1
            self._fail_count[sw_id] = fails
            self.errors[sw_id] = f"No SNMP response (fail #{fails})"
            backoff = min(BACKOFF_BASE * (2 ** (fails - 1)), BACKOFF_MAX)
            self._next_try[sw_id] = now + backoff
        print(f"[TrafficMonitor] sw_id={sw_id} SNMP fail #{fails}, "
              f"retry in {backoff}s")

    def _save_snapshot(self):
        samples = []
        ts = int(time.time())
        with self._lock:
            for sw_id, entry in self.latest.items():
                for port_name, rate in entry['rates'].items():
                    if rate['in_bps'] == 0 and rate['out_bps'] == 0:
                        continue
                    samples.append((sw_id, port_name,
                                    int(rate['in_bps']),
                                    int(rate['out_bps']), ts))
        if samples:
            try:
                self.save_callback(samples)
                print(f"[TrafficMonitor] saved {len(samples)} samples")
            except Exception as e:
                print(f"[TrafficMonitor] save error: {e}")

    def get(self, sw_id):
        with self._lock:
            return self.latest.get(sw_id), self.errors.get(sw_id)

    def get_all_latest(self):
        with self._lock:
            return {sid: dict(e) for sid, e in self.latest.items()}

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
                            'sw_id': sw_id, 'port': port['name'],
                            'descr': port['descr'], 'util_pct': util,
                            'in_bps': port['in_bps'], 'out_bps': port['out_bps'],
                            'speed_mbps': port['speed_mbps'],
                        })
            alerts.sort(key=lambda a: a['util_pct'], reverse=True)
            return alerts

    def status(self):
        with self._lock:
            return {
                'polling':      self._thread is not None and self._thread.is_alive(),
                'interval':     self.interval,
                'enable_ttl':   self.enable_ttl,
                'community':    self.community,
                'version':      SNMP_VERSION_STR,
                'history_size': self.history_size,
                'alert_thresh': self.alert_thresh,
                'save_every':   self.save_every,
                'max_workers':  self.max_workers,
                'enabled_count': len(self._enabled),
                'enabled_ids':   list(self._enabled.keys()),
            }


# ============================================================
# ACCOUNTING MONITOR — always-on, LOW-freq, staggered, skip-live
# ============================================================
class AccountingMonitor:
    """
    Background byte-accounting poller:
      * Warmup delay before first cycle (lets web app boot)
      * Processes switches in small batches across the interval
      * Skips switches currently being live-polled (avoid double work)
      * Only counters read on most polls (names cached for 1h)
      * Stores byte DELTAS — exact 24h totals
      * Dead-switch exponential backoff
    """
    def __init__(self, interval=ACCOUNT_INTERVAL, community=DEFAULT_COMMUNITY,
                 version=DEFAULT_VERSION, max_workers=ACCOUNT_WORKERS,
                 save_callback=None, names_ttl=NAMES_TTL,
                 batch_size=ACCOUNT_BATCH, start_delay=ACCOUNT_START_DELAY):
        self.interval      = interval
        self.community     = community
        self.version       = version
        self.max_workers   = max_workers
        self.save_callback = save_callback
        self.names_ttl     = names_ttl
        self.batch_size    = batch_size
        self.start_delay   = start_delay

        self._switches     = []
        self._prev         = {}
        self._names        = {}
        self._names_ts     = {}
        self._fail_count   = {}
        self._next_try     = {}
        self._skip_sw_ids  = set()      # live-enabled, don't double-poll
        self._cursor       = 0          # round-robin cursor

        self._lock         = threading.Lock()
        self._stop         = threading.Event()
        self._thread       = None
        self._executor     = None

    def set_switches(self, switch_list):
        with self._lock:
            self._switches = list(switch_list)
            active = {s['id'] for s in switch_list}
            for sw_id in list(self._prev.keys()):
                if sw_id not in active:
                    self._prev.pop(sw_id, None)
                    self._names.pop(sw_id, None)
                    self._names_ts.pop(sw_id, None)
                    self._fail_count.pop(sw_id, None)
                    self._next_try.pop(sw_id, None)

    def set_skip_ids(self, ids):
        """Switches currently being live-polled — skip them here."""
        with self._lock:
            self._skip_sw_ids = set(ids)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="snmp-account",
            )
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="snmp-accounting")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        print(f"[AccountingMonitor] started | interval={self.interval}s "
              f"workers={self.max_workers} batch={self.batch_size} "
              f"start_delay={self.start_delay}s "
              f"version={SNMP_VERSION_STR} community={self.community}")
        # Warmup — let web app boot first
        self._stop.wait(self.start_delay)

        while not self._stop.is_set():
            cycle_start = time.time()

            with self._lock:
                switches   = list(self._switches)
                skip_ids   = set(self._skip_sw_ids)
                cursor     = self._cursor

            # Filter out live-enabled switches
            eligible = [s for s in switches if s['id'] not in skip_ids]

            if not eligible:
                print(f"[AccountingMonitor] no eligible switches (all live or empty)")
                self._stop.wait(self.interval)
                continue

            # Round-robin batch selection
            n = len(eligible)
            if n <= self.batch_size:
                batch = eligible
                new_cursor = 0
            else:
                # Take batch_size starting at cursor, wrapping around
                batch = []
                for i in range(self.batch_size):
                    batch.append(eligible[(cursor + i) % n])
                new_cursor = (cursor + self.batch_size) % n

            with self._lock:
                self._cursor = new_cursor

            # How long to wait between batches: interval / (n / batch_size)
            batches_per_cycle = max(1, (n + self.batch_size - 1) // self.batch_size)
            batch_gap = max(1.0, self.interval / batches_per_cycle)

            ok = 0
            fail = 0
            t0 = time.time()
            futures = [self._executor.submit(self._poll_one, s['id'], s['ip'])
                       for s in batch]
            for f in as_completed(futures, timeout=self.max_workers * 30):
                try:
                    r = f.result()
                    if r:
                        ok += 1
                    else:
                        fail += 1
                except Exception as e:
                    fail += 1
                    print(f"[AccountingMonitor] poll error: {e}")
                if self._stop.is_set():
                    break
            batch_elapsed = time.time() - t0

            print(f"[AccountingMonitor] batch done | {ok} ok, {fail} fail "
                  f"| {batch_elapsed:.1f}s | {len(batch)}/{n} switches "
                  f"| next batch in {batch_gap:.0f}s")

            # Wait before next batch
            self._stop.wait(batch_gap)

    def _poll_one(self, sw_id, ip):
        now = time.time()

        with self._lock:
            next_try = self._next_try.get(sw_id, 0)
        if now < next_try:
            return False

        with self._lock:
            need_names = (
                sw_id not in self._names or
                (now - self._names_ts.get(sw_id, 0)) > self.names_ttl
            )

        try:
            if need_names:
                full = read_port_counters_full(ip, self.community, self.version)
                if not full:
                    self._register_failure(sw_id, now)
                    return False
                with self._lock:
                    self._names[sw_id]    = {idx: p['name'] for idx, p in full.items()}
                    self._names_ts[sw_id] = now
                counters = {idx: (p['in_octets'], p['out_octets'])
                            for idx, p in full.items()}
            else:
                counters = read_counters_only(ip, self.community, self.version)
                if not counters:
                    self._register_failure(sw_id, now)
                    return False
        except Exception as e:
            print(f"[AccountingMonitor] {ip} error: {e}")
            self._register_failure(sw_id, now)
            return False

        with self._lock:
            self._fail_count.pop(sw_id, None)
            self._next_try.pop(sw_id, None)

            prev  = self._prev.get(sw_id)
            names = self._names.get(sw_id, {})

            if prev:
                deltas = []
                ts_int = int(now)
                for idx, (cin, cout) in counters.items():
                    if idx not in prev:
                        continue
                    pin, pout = prev[idx]
                    d_in  = (cin  - pin)  % (2**64)
                    d_out = (cout - pout) % (2**64)
                    if d_in > 2**63 or d_out > 2**63:
                        continue
                    if d_in == 0 and d_out == 0:
                        continue
                    port_name = names.get(idx, f'if{idx}')
                    deltas.append((sw_id, port_name, int(d_in), int(d_out), ts_int))

                if deltas and self.save_callback:
                    try:
                        self.save_callback(deltas)
                    except Exception as e:
                        print(f"[AccountingMonitor] save error: {e}")

            self._prev[sw_id] = counters

        return True

    def _register_failure(self, sw_id, now):
        with self._lock:
            fails = self._fail_count.get(sw_id, 0) + 1
            self._fail_count[sw_id] = fails
            backoff = min(BACKOFF_BASE * (2 ** (fails - 1)), BACKOFF_MAX)
            self._next_try[sw_id] = now + backoff

    def status(self):
        with self._lock:
            return {
                'running':      self._thread is not None and self._thread.is_alive(),
                'interval':     self.interval,
                'batch_size':   self.batch_size,
                'start_delay':  self.start_delay,
                'switch_count': len(self._switches),
                'skip_count':   len(self._skip_sw_ids),
                'max_workers':  self.max_workers,
                'names_ttl':    self.names_ttl,
            }


# ---------------- Singletons ----------------
monitor = TrafficMonitor(
    interval=POLL_INTERVAL,
    community=DEFAULT_COMMUNITY,
    version=DEFAULT_VERSION,
    history_size=HISTORY_SIZE,
    alert_threshold_pct=ALERT_THRESHOLD,
    save_every=SAVE_EVERY,
    max_workers=MAX_WORKERS,
    static_ttl=STATIC_TTL,
    enable_ttl=ENABLE_TTL,
)

accounting = AccountingMonitor(
    interval=ACCOUNT_INTERVAL,
    community=DEFAULT_COMMUNITY,
    version=DEFAULT_VERSION,
    max_workers=ACCOUNT_WORKERS,
    names_ttl=NAMES_TTL,
    batch_size=ACCOUNT_BATCH,
    start_delay=ACCOUNT_START_DELAY,
)


if __name__ == "__main__":
    import sys
    test_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.102.6"
    print(f"Testing SNMP on {test_ip} with community '{DEFAULT_COMMUNITY}' "
          f"({SNMP_VERSION_STR})...")
    t0 = time.time()
    snap = read_port_counters_full(test_ip)
    dt = time.time() - t0
    if not snap:
        print(f"❌ No ports ({dt:.2f}s).")
    else:
        print(f"✅ {len(snap)} ports in {dt:.2f}s:")
        for idx, v in sorted(snap.items())[:10]:
            print(f"  idx={idx:<5} {v['name']:15} "
                  f"speed={v['speed_mbps']:>6} Mbps  up={v['oper_up']}")
        if len(snap) > 10:
            print(f"  ... and {len(snap) - 10} more")
