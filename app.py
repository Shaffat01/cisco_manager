from flask import (Flask, render_template, request, jsonify, redirect,
                   url_for, flash, Response, session)
import csv
import io
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps

from snmp_poller import monitor, accounting, read_port_counters_full
from database import (init_db, add_switch, get_all_switches, get_switch,
                      search_switches, get_stats,
                      delete_switch, bulk_delete_switches, update_model,
                      update_switch_status, save_scan, get_scan,
                      save_traffic_samples, get_traffic_history_bucketed,
                      prune_traffic_history,
                      save_volume_samples, get_volume_totals,
                      get_volume_totals_all, prune_volume_history,
                      get_core_switches, set_core_status, get_available_for_core)
from ssh_engine import CiscoSSH
from parser import (parse_overview, parse_vlans, parse_vlan_ips, parse_radius,
                    parse_snmp, parse_logging, parse_cdp, parse_interfaces,
                    parse_interface_usage, parse_live_status_map)


# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "cisco_secret_key_change_this")

SW_USER        = os.environ.get("SW_USER", "root")
SW_PASS        = os.environ.get("SW_PASS", "WhqAcc*&^8u7y")
SW_ENABLE_PASS = os.environ.get("SW_ENABLE_PASS", "WhqAcc*&^8u7y")
SW_PORT        = int(os.environ.get("SW_PORT", "22"))

# Core Network credentials
CORE_USER   = os.environ.get("CORE_USER", "admin")
CORE_PASS   = os.environ.get("CORE_PASS", "CoreNet@2026")
app.config['PERMANENT_SESSION_LIFETIME'] = 3600 * 8   # 8 hours


init_db()


# ============================================================
# SNMP MONITORS — live (on-demand) + accounting (low-freq)
# ============================================================
monitor.save_callback    = save_traffic_samples
accounting.save_callback = save_volume_samples


def _refresh_accounting_switches():
    """Register all switches with accounting poller AND update skip list."""
    try:
        sws = get_all_switches()
        accounting.set_switches([{'id': s['id'], 'ip': s['ip']} for s in sws])
        accounting.set_skip_ids(monitor.enabled_ids())
        print(f"[AccountingMonitor] registered {len(sws)} switches, "
              f"skipping {len(monitor.enabled_ids())} live-enabled")
    except Exception as e:
        print(f"[AccountingMonitor] refresh error: {e}")


monitor.start()
_refresh_accounting_switches()
accounting.start()


def _prune_worker():
    while True:
        try:
            cutoff = int(time.time()) - 7 * 86400
            n1 = prune_traffic_history(cutoff)
            n2 = prune_volume_history(cutoff)
            if n1 or n2:
                print(f"[Prune] history={n1} volume={n2}")
        except Exception as e:
            print(f"[Prune] error: {e}")
        time.sleep(3600)


threading.Thread(target=_prune_worker, daemon=True, name="prune").start()


# ============================================================
# SCAN QUEUE
# ============================================================
MAX_CONCURRENT  = int(os.environ.get("SCAN_MAX_CONCURRENT", "8"))
JOB_TTL_SECONDS = 300

scan_jobs  = {}
queued_ids = []
active_ids = set()
scan_lock  = threading.Lock()
executor   = ThreadPoolExecutor(max_workers=MAX_CONCURRENT,
                                thread_name_prefix="scan")


def _update_job(sw_id, **kwargs):
    with scan_lock:
        if sw_id in scan_jobs:
            scan_jobs[sw_id].update(kwargs)
            scan_jobs[sw_id]["updated_at"] = time.time()


def _get_job(sw_id):
    with scan_lock:
        job = scan_jobs.get(sw_id)
        if not job:
            return None
        if job.get("status") in ("done", "error"):
            if time.time() - job.get("finished_at", time.time()) > JOB_TTL_SECONDS:
                scan_jobs.pop(sw_id, None)
                return None
        return dict(job)


def _enqueue_scan(sw_id):
    with scan_lock:
        if sw_id in queued_ids or sw_id in active_ids:
            return False
        job = scan_jobs.get(sw_id)
        if job and job.get("status") == "running":
            return False
        queued_ids.append(sw_id)
        scan_jobs[sw_id] = {
            "status": "queued", "progress": 0, "message": "Queued...",
            "started_at": time.time(), "updated_at": time.time(), "model": ""
        }
    executor.submit(_queue_worker, sw_id)
    return True


def _queue_worker(sw_id):
    with scan_lock:
        if sw_id in queued_ids:
            queued_ids.remove(sw_id)
    while True:
        with scan_lock:
            if len(active_ids) < MAX_CONCURRENT:
                active_ids.add(sw_id)
                break
        time.sleep(0.5)
    try:
        _update_job(sw_id, status="running", message="Starting...")
        update_switch_status(sw_id, "scanning")
        _run_scan(sw_id)
    finally:
        with scan_lock:
            active_ids.discard(sw_id)


def _cmd(ssh, command, timeout=30):
    try:
        out = ssh.send_command(command, timeout=timeout) or ""
    except Exception as e:
        print(f"    [CMD ERROR] '{command}' -> {e}")
        return ""
    return out


def _run_scan(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        _update_job(sw_id, status="error", progress=0,
                    message="Switch not found", finished_at=time.time())
        return
    ssh = CiscoSSH()
    try:
        _update_job(sw_id, progress=5, message="Connecting...")
        enable_pw = sw.get('enable_pass') or SW_ENABLE_PASS
        ssh.connect(sw['ip'], SW_USER, SW_PASS, SW_PORT, enable_pw)

        _update_job(sw_id, progress=15, message="Running-config...")
        running = _cmd(ssh, "show running-config", timeout=60)
        _update_job(sw_id, progress=35, message="Interface status...")
        int_status = _cmd(ssh, "show interfaces status", timeout=30)
        if len(int_status.strip()) < 30:
            int_status = _cmd(ssh, "show interface status", timeout=30)
        _update_job(sw_id, progress=50, message="Version...")
        version = _cmd(ssh, "show version", timeout=20)
        _update_job(sw_id, progress=60, message="VLANs...")
        vlan_db = _cmd(ssh, "show vlan", timeout=25)
        _update_job(sw_id, progress=70, message="CDP...")
        cdp = _cmd(ssh, "show cdp neighbors detail", timeout=25)
        _update_job(sw_id, progress=80, message="Logs...")
        syslogs = _cmd(ssh, "show logging", timeout=40)
        _update_job(sw_id, progress=88, message="Parsing...")

        update_model(sw_id, ssh.model)
        overview = parse_overview(running, version)
        overview["model"] = ssh.model
        status_map = parse_live_status_map(int_status) if int_status else {}

        _update_job(sw_id, progress=94, message="Saving...")
        save_scan(sw_id, 'overview', version, overview)
        save_scan(sw_id, 'vlans', vlan_db, parse_vlans(vlan_db))
        save_scan(sw_id, 'vlan_ips', running, parse_vlan_ips(running))
        save_scan(sw_id, 'radius', running, parse_radius(running))
        save_scan(sw_id, 'snmp', running, parse_snmp(running))
        save_scan(sw_id, 'cdp', cdp, parse_cdp(cdp))
        save_scan(sw_id, 'interfaces', running,
                  parse_interfaces(running, int_status, status_map=status_map))
        save_scan(sw_id, 'interface_usage', int_status,
                  parse_interface_usage(int_status, running,
                                        status_map=status_map))
        save_scan(sw_id, 'raw_config', running, {"config": running})
        save_scan(sw_id, 'raw_int_status', int_status, {})
        save_scan(sw_id, 'logging', syslogs, parse_logging(running, syslogs))

        ssh.disconnect()
        update_switch_status(sw_id, "online")
        _update_job(sw_id, status="done", progress=100,
                    message="Scan completed!", model=ssh.model,
                    finished_at=time.time())
    except Exception as e:
        import traceback
        traceback.print_exc()
        try:
            ssh.disconnect()
        except Exception:
            pass
        update_switch_status(sw_id, "offline")
        _update_job(sw_id, status="error", message=str(e),
                    finished_at=time.time())


# ============================================================
# CORE NETWORK AUTH DECORATOR
# ============================================================
def core_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('core_auth'):
            if request.path.startswith('/api/'):
                return jsonify({"status": "unauthorized",
                                "message": "Login required"}), 401
            return redirect(url_for('core_login', next=request.path))
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# PAGES
# ============================================================
@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        ok, msg = add_switch(request.form['name'], request.form['ip'],
                             request.form.get('enable_pass', ''))
        flash(msg, 'success' if ok else 'danger')
        _refresh_accounting_switches()
        return redirect(url_for('dashboard'))
    return render_template('add_switch.html')


@app.route('/upload-csv', methods=['POST'])
def upload_csv():
    file = request.files.get('csv_file')
    if not file:
        flash("No file uploaded!", 'danger')
        return redirect(url_for('dashboard'))
    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        count  = 0
        for row in reader:
            ok, _ = add_switch(row.get('name', 'Unnamed'), row.get('ip'),
                               row.get('enable_pass', ''))
            if ok:
                count += 1
        flash(f"{count} switch imported!", 'success')
        _refresh_accounting_switches()
    except Exception as e:
        flash(f"CSV Error: {str(e)}", 'danger')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:sw_id>')
def delete(sw_id):
    monitor.disable(sw_id, reason="switch deleted")
    delete_switch(sw_id)
    _refresh_accounting_switches()
    flash("Switch deleted!", 'success')
    return redirect(url_for('dashboard'))


@app.route('/switch/<int:sw_id>')
def switch_detail(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        flash("Switch not found!", 'danger')
        return redirect(url_for('dashboard'))
    return render_template('switch_detail.html', sw=sw)


@app.route('/traffic')
def traffic_all_page():
    return render_template('traffic_all.html')


# ============================================================
# CORE NETWORK PAGES & AUTH
# ============================================================
@app.route('/core/login', methods=['GET', 'POST'])
def core_login():
    if session.get('core_auth'):
        return redirect(url_for('core_network'))

    if request.method == 'POST':
        u = request.form.get('username', '').strip()
        p = request.form.get('password', '')
        if u == CORE_USER and p == CORE_PASS:
            session.permanent = True
            session['core_auth'] = True
            session['core_user'] = u
            nxt = request.args.get('next') or url_for('core_network')
            return redirect(nxt)
        return render_template('core_login.html',
                               error="Invalid Username or Password",
                               next_url=request.args.get('next', ''))

    return render_template('core_login.html',
                           next_url=request.args.get('next', ''))


@app.route('/core/logout')
def core_logout():
    session.pop('core_auth', None)
    session.pop('core_user', None)
    flash("Logged out from Core Network", 'success')
    return redirect(url_for('dashboard'))


@app.route('/core')
@core_required
def core_network():
    return render_template('core_network.html',
                           core_user=session.get('core_user', 'user'))


# ============================================================
# API — SWITCHES / STATS
# ============================================================
@app.route('/api/switches')
def api_switches():
    q        = request.args.get('q', '').strip()
    model    = request.args.get('model', '').strip()
    status   = request.args.get('status', '').strip()
    sort     = request.args.get('sort', 'id')
    order    = request.args.get('order', 'desc')
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(6, int(request.args.get('per_page', 24))))
    
    # search_switches now filters out core switches automatically
    rows, total = search_switches(q, model, status, sort, order, page, per_page)
    
    for r in rows:
        job = _get_job(r['id'])
        if job and job.get('status') in ('running', 'queued'):
            r['live_status']   = job['status']
            r['live_progress'] = job.get('progress', 0)
        else:
            r['live_status'] = None
        r['snmp_enabled'] = monitor.is_enabled(r['id'])
    return jsonify({"switches": rows, "total": total, "page": page,
                    "per_page": per_page,
                    "pages": (total + per_page - 1) // per_page})


@app.route('/api/stats')
def api_stats():
    # get_stats now counts only non-core switches
    s = get_stats()
    with scan_lock:
        s['queue_size']   = len(queued_ids)
        s['active_count'] = len(active_ids)
    return jsonify(s)


# ============================================================
# API — SCAN
# ============================================================
@app.route('/api/scan/<int:sw_id>', methods=['POST'])
def scan_switch(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404
    added = _enqueue_scan(sw_id)
    return jsonify({"status": "queued" if added else "already_running",
                    "sw_id": sw_id})


@app.route('/api/scan-bulk', methods=['POST'])
def scan_bulk():
    data     = request.get_json() or {}
    ids      = data.get('ids', [])
    scan_all = data.get('all', False)
    if scan_all:
        # Only scan non-core switches from normal dashboard
        rows, _ = search_switches(per_page=10000)
        ids = [r['id'] for r in rows]
    else:
        ids = [int(x) for x in ids if str(x).isdigit()]
    queued = 0
    for sw_id in ids:
        if _enqueue_scan(sw_id):
            queued += 1
    return jsonify({"status": "ok", "queued": queued, "total": len(ids)})


@app.route('/api/scan/<int:sw_id>/status')
def scan_status(sw_id):
    job = _get_job(sw_id)
    return jsonify(job if job else {"status": "idle"})


@app.route('/api/queue-status')
def queue_status():
    with scan_lock:
        active = []
        for sw_id in list(active_ids):
            job = scan_jobs.get(sw_id, {})
            active.append({
                "sw_id":    sw_id,
                "progress": job.get("progress", 0),
                "message":  job.get("message", ""),
            })
        return jsonify({
            "active":         active,
            "active_count":   len(active_ids),
            "queued_count":   len(queued_ids),
            "max_concurrent": MAX_CONCURRENT,
        })


@app.route('/api/delete-bulk', methods=['POST'])
def delete_bulk():
    data = request.get_json() or {}
    ids  = [int(x) for x in data.get('ids', []) if str(x).isdigit()]
    for sw_id in ids:
        monitor.disable(sw_id, reason="bulk delete")
    deleted = bulk_delete_switches(ids)
    _refresh_accounting_switches()
    return jsonify({"status": "ok", "deleted": deleted})


@app.route('/api/data/<int:sw_id>/<section>')
def get_section_data(sw_id, section):
    data = get_scan(sw_id, section)
    if not data:
        return jsonify({"status": "empty", "message": "No data yet."})
    return jsonify({"status": "success", "data": data})


# ============================================================
# API — LIVE TRAFFIC (on-demand per switch)
# ============================================================
@app.route('/api/traffic/<int:sw_id>/enable', methods=['POST'])
def api_traffic_enable(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404

    ttl = request.args.get('ttl', None)
    try:
        ttl = int(ttl) if ttl else None
    except ValueError:
        ttl = None

    monitor.enable(sw_id, sw['ip'], ttl=ttl)

    try:
        accounting.set_skip_ids(monitor.enabled_ids())
    except Exception as e:
        print(f"[accounting] skip_ids sync error: {e}")

    print(f"[API] enable SNMP for sw_id={sw_id} ({sw['ip']}) ttl={ttl}")
    return jsonify({"status": "ok", "state": monitor.state(sw_id)})


@app.route('/api/traffic/<int:sw_id>/disable', methods=['POST'])
def api_traffic_disable(sw_id):
    monitor.disable(sw_id, reason="manual (UI)")

    try:
        accounting.set_skip_ids(monitor.enabled_ids())
    except Exception as e:
        print(f"[accounting] skip_ids sync error: {e}")

    print(f"[API] disable SNMP for sw_id={sw_id}")
    return jsonify({"status": "ok"})


@app.route('/api/traffic/<int:sw_id>/state')
def api_traffic_state(sw_id):
    return jsonify(monitor.state(sw_id))


@app.route('/api/traffic/<int:sw_id>')
def api_traffic(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404

    state = monitor.state(sw_id)
    if not state.get('enabled'):
        return jsonify({
            "status":  "disabled",
            "message": "SNMP polling is OFF for this switch.",
            "sw_ip":   sw['ip'],
            "state":   state,
        })

    entry, err = monitor.get(sw_id)
    if not entry:
        return jsonify({
            "status":  "warming_up",
            "message": "Collecting SNMP data — first poll takes up to 5s...",
            "error":   err,
            "sw_ip":   sw['ip'],
            "state":   state,
        })

    top = monitor.get_top_talkers(sw_id, n=5)
    return jsonify({
        "status":      "ok",
        "sw_ip":       sw['ip'],
        "timestamp":   entry['ts'],
        "age_sec":     round(time.time() - entry['ts'], 1),
        "ports":       list(entry['rates'].values()),
        "top_talkers": top,
        "state":       state,
    })


@app.route('/api/traffic-status')
def api_traffic_status():
    return jsonify({
        'live':       monitor.status(),
        'accounting': accounting.status(),
    })


@app.route('/api/accounting-status')
def api_accounting_status():
    return jsonify(accounting.status())


@app.route('/api/traffic/<int:sw_id>/history')
def api_traffic_history(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404
    if not monitor.is_enabled(sw_id):
        return jsonify({"status": "disabled", "history": {}})
    hist = monitor.get_history(sw_id)
    now  = time.time()
    out  = {}
    for port, samples in hist.items():
        out[port] = [{'t': round(now - ts, 1),
                      'in': int(i), 'out': int(o)}
                     for ts, i, o in samples]
    return jsonify({"status": "ok", "history": out})


@app.route('/api/traffic/<int:sw_id>/chart')
def api_traffic_chart(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404

    port   = request.args.get('port', '').lower().strip()
    range_ = request.args.get('range', '1h')
    if not port:
        return jsonify({"status": "error", "message": "port required"}), 400

    configs = {
        '5m':  (300,    10),
        '1h':  (3600,   60),
        '24h': (86400,  300),
        '7d':  (604800, 3600),
    }
    seconds_back, bucket_sec = configs.get(range_, (3600, 60))
    since = int(time.time()) - seconds_back

    rows = get_traffic_history_bucketed(sw_id, port, since, bucket_sec)
    return jsonify({
        "status":     "ok",
        "port":       port,
        "range":      range_,
        "bucket_sec": bucket_sec,
        "points":     rows,
    })


@app.route('/api/traffic/<int:sw_id>/totals')
def api_traffic_totals(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404

    range_  = request.args.get('range', '24h')
    configs = {'1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000}
    seconds_back = configs.get(range_, 86400)
    since = int(time.time()) - seconds_back

    rows = get_volume_totals(sw_id, since)

    total_in    = sum(r['in_bytes']  for r in rows)
    total_out   = sum(r['out_bytes'] for r in rows)
    grand_total = total_in + total_out or 1
    coverage_sec = max((r['coverage_sec'] for r in rows), default=0)

    for r in rows:
        r['pct'] = round(r['total_bytes'] / grand_total * 100, 2)

    return jsonify({
        "status":       "ok",
        "range":        range_,
        "since":        since,
        "total_in":     total_in,
        "total_out":    total_out,
        "grand_total":  grand_total,
        "ports":        rows,
        "coverage_sec": coverage_sec,
        "source":       "traffic_volume",
    })


@app.route('/api/alerts')
def api_alerts():
    thr = request.args.get('threshold', None)
    if thr is not None:
        try:
            thr = float(thr)
        except ValueError:
            thr = None
    alerts = monitor.get_alerts(thr)
    return jsonify({"alerts": alerts,
                    "threshold": thr or monitor.alert_thresh})


# ============================================================
# API — MULTI-SWITCH TRAFFIC (Normal Dashboard)
# ============================================================
@app.route('/api/traffic-all')
def api_traffic_all():
    # ⚠️ Filter out Core switches so they don't appear on the normal dashboard
    all_switches = [s for s in get_all_switches() if not s.get('is_core')]
    latest       = monitor.get_all_latest()
    alerts       = monitor.get_alerts()

    alert_count = {}
    for a in alerts:
        alert_count[a['sw_id']] = alert_count.get(a['sw_id'], 0) + 1

    since_24h = int(time.time()) - 86400
    volume_rows = get_volume_totals_all(since_24h)
    vol_by_sw = {v['switch_id']: v for v in volume_rows}

    rows = []
    for sw in all_switches:
        enabled = monitor.is_enabled(sw['id'])
        entry   = latest.get(sw['id'])
        vol     = vol_by_sw.get(sw['id'], {})

        if entry and enabled:
            rates      = list(entry['rates'].values())
            total_in   = sum(p['in_bps']  for p in rates)
            total_out  = sum(p['out_bps'] for p in rates)
            active     = sum(1 for p in rates
                             if p['oper_up'] or p['in_bps'] or p['out_bps'])
            top_port   = max(rates,
                             key=lambda p: p['in_bps'] + p['out_bps'],
                             default=None)
            rows.append({
                'sw_id':        sw['id'],
                'name':         sw['name'],
                'ip':           sw['ip'],
                'model':        sw.get('model', 'Unknown'),
                'last_status':  sw.get('last_status', 'unknown'),
                'total_in':     total_in,
                'total_out':    total_out,
                'total_bps':    total_in + total_out,
                'active_ports': active,
                'total_ports':  len(rates),
                'top_port':     top_port['name'] if top_port else None,
                'top_port_bps': (top_port['in_bps'] + top_port['out_bps'])
                                if top_port else 0,
                'alerts':       alert_count.get(sw['id'], 0),
                'age_sec':      round(time.time() - entry['ts'], 1),
                'snmp_enabled': True,
                'bytes_24h':    vol.get('total_bytes', 0),
                'bytes_in_24h': vol.get('in_bytes', 0),
                'bytes_out_24h': vol.get('out_bytes', 0),
            })
        else:
            rows.append({
                'sw_id':        sw['id'],
                'name':         sw['name'],
                'ip':           sw['ip'],
                'model':        sw.get('model', 'Unknown'),
                'last_status':  sw.get('last_status', 'unknown'),
                'total_in':     0,
                'total_out':    0,
                'total_bps':    0,
                'active_ports': 0,
                'total_ports':  0,
                'top_port':     None,
                'top_port_bps': 0,
                'alerts':       0,
                'age_sec':      None,
                'snmp_enabled': enabled,
                'bytes_24h':    vol.get('total_bytes', 0),
                'bytes_in_24h': vol.get('in_bytes', 0),
                'bytes_out_24h': vol.get('out_bytes', 0),
            })

    rows.sort(key=lambda r: r['bytes_24h'] or r['total_bps'], reverse=True)

    return jsonify({
        'switches':  rows,
        'count':     len(rows),
        'total_in':  sum(r['total_in']  for r in rows),
        'total_out': sum(r['total_out'] for r in rows),
        'bytes_24h_total': sum(r['bytes_24h'] for r in rows),
        'alerts':    alerts,
        'timestamp': time.time(),
    })


# ============================================================
# API — CORE NETWORK (protected)
# ============================================================
@app.route('/api/core/session')
@core_required
def api_core_session():
    return jsonify({
        "authenticated": True,
        "user":          session.get('core_user', 'user'),
    })


@app.route('/api/core/available')
@core_required
def api_core_available():
    """Returns non-core switches that can be added to Core Network."""
    return jsonify({"switches": get_available_for_core()})


@app.route('/api/core/switches')
@core_required
def api_core_switches():
    core_switches = get_core_switches()
    latest        = monitor.get_all_latest()
    alerts        = monitor.get_alerts()

    alert_count = {}
    for a in alerts:
        alert_count[a['sw_id']] = alert_count.get(a['sw_id'], 0) + 1

    since_24h = int(time.time()) - 86400
    volume_rows = get_volume_totals_all(since_24h)
    vol_by_sw = {v['switch_id']: v for v in volume_rows}

    rows = []
    for sw in core_switches:
        enabled = monitor.is_enabled(sw['id'])
        entry   = latest.get(sw['id'])
        vol     = vol_by_sw.get(sw['id'], {})

        if entry and enabled:
            rates     = list(entry['rates'].values())
            total_in  = sum(p['in_bps']  for p in rates)
            total_out = sum(p['out_bps'] for p in rates)
            active    = sum(1 for p in rates
                            if p['oper_up'] or p['in_bps'] or p['out_bps'])
            top_port  = max(rates,
                            key=lambda p: p['in_bps'] + p['out_bps'],
                            default=None)
            rows.append({
                'sw_id':         sw['id'],
                'name':          sw['name'],
                'ip':            sw['ip'],
                'model':         sw.get('model', 'Unknown'),
                'last_status':   sw.get('last_status', 'unknown'),
                'total_in':      total_in,
                'total_out':     total_out,
                'total_bps':     total_in + total_out,
                'active_ports':  active,
                'total_ports':   len(rates),
                'top_port':      top_port['name'] if top_port else None,
                'top_port_bps':  (top_port['in_bps'] + top_port['out_bps'])
                                 if top_port else 0,
                'alerts':        alert_count.get(sw['id'], 0),
                'age_sec':       round(time.time() - entry['ts'], 1),
                'snmp_enabled':  True,
                'bytes_24h':     vol.get('total_bytes', 0),
                'bytes_in_24h':  vol.get('in_bytes', 0),
                'bytes_out_24h': vol.get('out_bytes', 0),
            })
        else:
            rows.append({
                'sw_id':         sw['id'],
                'name':          sw['name'],
                'ip':            sw['ip'],
                'model':         sw.get('model', 'Unknown'),
                'last_status':   sw.get('last_status', 'unknown'),
                'total_in':      0,
                'total_out':     0,
                'total_bps':     0,
                'active_ports':  0,
                'total_ports':   0,
                'top_port':      None,
                'top_port_bps':  0,
                'alerts':        0,
                'age_sec':       None,
                'snmp_enabled':  enabled,
                'bytes_24h':     vol.get('total_bytes', 0),
                'bytes_in_24h':  vol.get('in_bytes', 0),
                'bytes_out_24h': vol.get('out_bytes', 0),
            })

    rows.sort(key=lambda r: r['bytes_24h'] or r['total_bps'], reverse=True)

    return jsonify({
        'switches':        rows,
        'count':           len(rows),
        'total_in':        sum(r['total_in']  for r in rows),
        'total_out':       sum(r['total_out'] for r in rows),
        'bytes_24h_total': sum(r['bytes_24h'] for r in rows),
        'alerts':          alerts,
        'timestamp':       time.time(),
    })


@app.route('/api/core/mark/<int:sw_id>', methods=['POST'])
@core_required  # ⚠️ সিকিউরিটি যোগ করা হলো, শুধু লগইন করা ইউজার পারবে
def api_core_mark(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404

    data    = request.get_json() or {}
    is_core = bool(data.get('is_core', False))
    set_core_status(sw_id, is_core)

    print(f"[API] core mark sw_id={sw_id} -> {is_core}")
    return jsonify({"status": "ok", "sw_id": sw_id, "is_core": is_core})


# ============================================================
# EXPORT (CSV)
# ============================================================
def _csv_response(filename, header, rows):
    buf    = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    for r in rows:
        writer.writerow(r)
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/export/<int:sw_id>/traffic.csv')
def export_traffic_csv(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return "Switch not found", 404
    entry, _ = monitor.get(sw_id)
    if not entry:
        return "No traffic data (SNMP may be off)", 404

    ports = sorted(entry['rates'].values(),
                   key=lambda p: p['in_bps'] + p['out_bps'], reverse=True)

    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"traffic_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for p in ports:
        rows.append([
            p['name'], p['descr'], p['speed_mbps'],
            'Up' if p['oper_up'] else 'Down',
            p['in_bps'], p['out_bps'],
            p['in_util_pct'], p['out_util_pct'],
            round(p['in_bps']  / 1_000_000, 3),
            round(p['out_bps'] / 1_000_000, 3),
        ])

    header = ['Port', 'Description', 'Speed (Mbps)', 'Status',
              'IN (bps)', 'OUT (bps)', 'IN Util %', 'OUT Util %',
              'IN (Mbps)', 'OUT (Mbps)']
    return _csv_response(filename, header, rows)


@app.route('/export/<int:sw_id>/top-talkers.csv')
def export_top_talkers_csv(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return "Switch not found", 404
    top = monitor.get_top_talkers(sw_id, n=20)
    if not top:
        return "No traffic data", 404

    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"top_talkers_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for i, p in enumerate(top, 1):
        rows.append([
            i, p['name'], p['descr'], p['speed_mbps'],
            p['in_bps'], p['out_bps'],
            round(p['in_bps']  / 1_000_000, 3),
            round(p['out_bps'] / 1_000_000, 3),
            max(p['in_util_pct'], p['out_util_pct']),
        ])

    header = ['Rank', 'Port', 'Description', 'Speed (Mbps)',
              'IN (bps)', 'OUT (bps)', 'IN (Mbps)', 'OUT (Mbps)', 'Util %']
    return _csv_response(filename, header, rows)


@app.route('/export/<int:sw_id>/totals.csv')
def export_totals_csv(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return "Switch not found", 404

    range_  = request.args.get('range', '24h')
    configs = {'1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000}
    since   = int(time.time()) - configs.get(range_, 86400)
    rows_data = get_volume_totals(sw_id, since)

    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"totals_{range_}_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for i, r in enumerate(rows_data, 1):
        rows.append([
            i, r['port'],
            r['in_bytes'], r['out_bytes'], r['total_bytes'],
            round(r['in_bytes']    / 1024**3, 3),
            round(r['out_bytes']   / 1024**3, 3),
            round(r['total_bytes'] / 1024**3, 3),
            r['samples'],
            r['coverage_sec'],
        ])

    header = ['Rank', 'Port', 'In (bytes)', 'Out (bytes)', 'Total (bytes)',
              'In (GB)', 'Out (GB)', 'Total (GB)', 'Samples', 'Coverage (s)']
    return _csv_response(filename, header, rows)


@app.route('/export/all/traffic.csv')
def export_all_traffic_csv():
    all_switches = [s for s in get_all_switches() if not s.get('is_core')]
    latest       = monitor.get_all_latest()

    since_24h = int(time.time()) - 86400
    vol_by_sw = {v['switch_id']: v for v in get_volume_totals_all(since_24h)}

    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"all_switches_traffic_{ts}.csv"

    rows = []
    for sw in all_switches:
        entry = latest.get(sw['id'])
        vol   = vol_by_sw.get(sw['id'], {})
        vol_gb = round(vol.get('total_bytes', 0) / 1024**3, 3)

        if not entry or not monitor.is_enabled(sw['id']):
            rows.append([sw['name'], sw['ip'], sw.get('model', ''),
                         sw.get('last_status', ''),
                         0, 0, 0, 0, 0, 0, '', 'SNMP off', vol_gb])
            continue
        rates      = list(entry['rates'].values())
        total_in   = sum(p['in_bps']  for p in rates)
        total_out  = sum(p['out_bps'] for p in rates)
        active     = sum(1 for p in rates
                         if p['oper_up'] or p['in_bps'] or p['out_bps'])
        top_port   = max(rates,
                         key=lambda p: p['in_bps'] + p['out_bps'],
                         default=None)
        rows.append([
            sw['name'], sw['ip'], sw.get('model', ''),
            sw.get('last_status', ''),
            len(rates), active,
            total_in, total_out,
            round(total_in  / 1_000_000, 3),
            round(total_out / 1_000_000, 3),
            top_port['name'] if top_port else '',
            'ON',
            vol_gb,
        ])

    header = ['Name', 'IP', 'Model', 'Status', 'Total Ports', 'Active Ports',
              'IN (bps)', 'OUT (bps)', 'IN (Mbps)', 'OUT (Mbps)',
              'Top Port', 'SNMP', 'Volume 24h (GB)']
    return _csv_response(filename, header, rows)


# ============================================================
# DEBUG / TEST
# ============================================================
@app.route('/debug/<int:sw_id>/<section>')
def debug_raw(sw_id, section):
    data = get_scan(sw_id, section)
    if not data:
        return f"<h3>No data for section '{section}'</h3>", 404
    raw = data.get('raw', '') or '(empty)'
    return (f"<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;"
            f"font-family:monospace'><h2 style='color:#58a6ff'>Raw: {section}</h2>"
            f"<pre style='white-space:pre-wrap;font-size:13px'>{raw}</pre>"
            "</body></html>")


@app.route('/api/snmp-test/<int:sw_id>')
def api_snmp_test(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404

    t0 = time.time()
    try:
        snap = read_port_counters_full(sw['ip'])
    except Exception as e:
        return jsonify({
            "status":  "error",
            "message": str(e),
            "switch":  sw['name'],
            "ip":      sw['ip'],
            "elapsed": round(time.time() - t0, 2),
        })
    dt = time.time() - t0

    return jsonify({
        "status":     "ok" if snap else "no_ports",
        "switch":     sw['name'],
        "ip":         sw['ip'],
        "elapsed":    round(dt, 2),
        "port_count": len(snap),
        "sample": [
            {
                "idx":        idx,
                "name":       v['name'],
                "descr":      v['descr'],
                "speed_mbps": v['speed_mbps'],
                "up":         v['oper_up'],
                "in_octets":  v['in_octets'],
                "out_octets": v['out_octets'],
            }
            for idx, v in list(snap.items())[:10]
        ] if snap else [],
    })


@app.route('/api/monitor-status')
def api_monitor_status():
    return jsonify({
        'live':       monitor.status(),
        'accounting': accounting.status(),
        'server_time': int(time.time()),
    })


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    print("\n🚀 Cisco Manager — http://0.0.0.0:5000\n")
    print(f"   Max concurrent scans: {MAX_CONCURRENT}")
    print(f"   Live monitor:       {monitor.status()}")
    print(f"   Accounting monitor: {accounting.status()}\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
