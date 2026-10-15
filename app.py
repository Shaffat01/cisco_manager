from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response
import csv
import io
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from snmp_poller import monitor
from database import (init_db, add_switch, get_all_switches, get_switch,
                      get_switches_by_ids, search_switches, get_stats,
                      delete_switch, bulk_delete_switches, update_model,
                      update_switch_status, save_scan, get_scan,
                      save_traffic_samples, get_traffic_history_bucketed,
                      get_traffic_history_ports, prune_traffic_history,
                      get_traffic_totals)
from ssh_engine import CiscoSSH
from parser import (parse_overview, parse_vlans, parse_vlan_ips, parse_radius,
                    parse_snmp, parse_logging, parse_cdp, parse_interfaces,
                    parse_interface_usage, parse_live_status_map)

app = Flask(__name__)
app.secret_key = "cisco_secret_key_change_this"

SW_USER = "root"
SW_PASS = "WhqAcc*&^8u7y"
SW_ENABLE_PASS = "WhqAcc*&^8u7y"
SW_PORT = 22

init_db()


# ============================================================
# SNMP TRAFFIC MONITOR
# ============================================================
def _refresh_monitor_switches():
    try:
        sws = get_all_switches()
        monitor.set_switches([{'id': s['id'], 'ip': s['ip']} for s in sws])
        print(f"[TrafficMonitor] registered {len(sws)} switches")
    except Exception as e:
        print(f"[TrafficMonitor] refresh error: {e}")

monitor.save_callback = save_traffic_samples
monitor.save_every = 60
_refresh_monitor_switches()
monitor.start()


def _prune_worker():
    while True:
        try:
            cutoff = int(time.time()) - 7 * 86400
            n = prune_traffic_history(cutoff)
            if n:
                print(f"[Prune] removed {n} old traffic rows")
        except Exception as e:
            print(f"[Prune] error: {e}")
        time.sleep(3600)

threading.Thread(target=_prune_worker, daemon=True, name="prune").start()


# ============================================================
# SCAN QUEUE
# ============================================================
MAX_CONCURRENT = 8
JOB_TTL_SECONDS = 300

scan_jobs = {}
queued_ids = []
active_ids = set()
scan_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT, thread_name_prefix="scan")


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
        _update_job(sw_id, status="error", progress=0, message="Switch not found",
                    finished_at=time.time())
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
                  parse_interface_usage(int_status, running, status_map=status_map))
        save_scan(sw_id, 'raw_config', running, {"config": running})
        save_scan(sw_id, 'raw_int_status', int_status, {})
        save_scan(sw_id, 'logging', syslogs, parse_logging(running, syslogs))

        ssh.disconnect()
        update_switch_status(sw_id, "online")
        _update_job(sw_id, status="done", progress=100,
                    message="Scan completed!", model=ssh.model,
                    finished_at=time.time())
    except Exception as e:
        import traceback; traceback.print_exc()
        try: ssh.disconnect()
        except Exception: pass
        update_switch_status(sw_id, "offline")
        _update_job(sw_id, status="error", message=str(e), finished_at=time.time())


# ============================================================
# ROUTES
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
        _refresh_monitor_switches()
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
        count = 0
        for row in reader:
            ok, _ = add_switch(row.get('name', 'Unnamed'), row.get('ip'),
                               row.get('enable_pass', ''))
            if ok: count += 1
        flash(f"{count} switch imported!", 'success')
        _refresh_monitor_switches()
    except Exception as e:
        flash(f"CSV Error: {str(e)}", 'danger')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:sw_id>')
def delete(sw_id):
    delete_switch(sw_id)
    _refresh_monitor_switches()
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
# API — SWITCHES / STATS
# ============================================================
@app.route('/api/switches')
def api_switches():
    q = request.args.get('q', '').strip()
    model = request.args.get('model', '').strip()
    status = request.args.get('status', '').strip()
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'desc')
    page = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(6, int(request.args.get('per_page', 24))))
    rows, total = search_switches(q, model, status, sort, order, page, per_page)
    for r in rows:
        job = _get_job(r['id'])
        if job and job.get('status') in ('running', 'queued'):
            r['live_status'] = job['status']
            r['live_progress'] = job.get('progress', 0)
        else:
            r['live_status'] = None
    return jsonify({"switches": rows, "total": total, "page": page,
                    "per_page": per_page,
                    "pages": (total + per_page - 1) // per_page})


@app.route('/api/stats')
def api_stats():
    s = get_stats()
    with scan_lock:
        s['queue_size'] = len(queued_ids)
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
    return jsonify({"status": "queued" if added else "already_running", "sw_id": sw_id})


@app.route('/api/scan-bulk', methods=['POST'])
def scan_bulk():
    data = request.get_json() or {}
    ids = data.get('ids', [])
    scan_all = data.get('all', False)
    if scan_all:
        rows, _ = search_switches(per_page=10000)
        ids = [r['id'] for r in rows]
    else:
        ids = [int(x) for x in ids if str(x).isdigit()]
    queued = 0
    for sw_id in ids:
        if _enqueue_scan(sw_id): queued += 1
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
            active.append({"sw_id": sw_id, "progress": job.get("progress", 0),
                           "message": job.get("message", "")})
        return jsonify({"active": active, "active_count": len(active_ids),
                        "queued_count": len(queued_ids),
                        "max_concurrent": MAX_CONCURRENT})


@app.route('/api/delete-bulk', methods=['POST'])
def delete_bulk():
    data = request.get_json() or {}
    ids = [int(x) for x in data.get('ids', []) if str(x).isdigit()]
    deleted = bulk_delete_switches(ids)
    _refresh_monitor_switches()
    return jsonify({"status": "ok", "deleted": deleted})


@app.route('/api/data/<int:sw_id>/<section>')
def get_section_data(sw_id, section):
    data = get_scan(sw_id, section)
    if not data:
        return jsonify({"status": "empty", "message": "No data yet."})
    return jsonify({"status": "success", "data": data})


# ============================================================
# API — LIVE TRAFFIC
# ============================================================
@app.route('/api/traffic/<int:sw_id>')
def api_traffic(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error", "message": "Switch not found"}), 404
    entry, err = monitor.get(sw_id)
    if not entry:
        return jsonify({"status": "warming_up",
                        "message": "Collecting SNMP data — first poll takes up to 5s...",
                        "error": err, "sw_ip": sw['ip']})
    top = monitor.get_top_talkers(sw_id, n=5)
    return jsonify({"status": "ok", "sw_ip": sw['ip'],
                    "timestamp": entry['ts'],
                    "age_sec": round(time.time() - entry['ts'], 1),
                    "ports": list(entry['rates'].values()),
                    "top_talkers": top})


@app.route('/api/traffic-status')
def api_traffic_status():
    return jsonify(monitor.status())


@app.route('/api/traffic/<int:sw_id>/history')
def api_traffic_history(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404
    hist = monitor.get_history(sw_id)
    now  = time.time()
    out  = {}
    for port, samples in hist.items():
        out[port] = [{'t': round(now - ts, 1), 'in': int(i), 'out': int(o)}
                     for ts, i, o in samples]
    return jsonify({"status": "ok", "history": out})


@app.route('/api/traffic/<int:sw_id>/chart')
def api_traffic_chart(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404

    port  = request.args.get('port', '').lower().strip()
    range_ = request.args.get('range', '1h')
    if not port:
        return jsonify({"status": "error", "message": "port required"}), 400

    configs = {
        '5m':  (300,     10),
        '1h':  (3600,    60),
        '24h': (86400,   300),
        '7d':  (604800,  3600),
    }
    seconds_back, bucket_sec = configs.get(range_, (3600, 60))
    since = int(time.time()) - seconds_back

    rows = get_traffic_history_bucketed(sw_id, port, since, bucket_sec)
    return jsonify({
        "status": "ok", "port": port, "range": range_,
        "bucket_sec": bucket_sec, "points": rows,
    })


@app.route('/api/traffic/<int:sw_id>/totals')
def api_traffic_totals(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        return jsonify({"status": "error"}), 404

    range_ = request.args.get('range', '24h')
    configs = {'1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000}
    seconds_back = configs.get(range_, 86400)
    since = int(time.time()) - seconds_back

    rows = get_traffic_totals(sw_id, since, sample_interval=60)

    total_in  = sum(r['in_bytes']  for r in rows)
    total_out = sum(r['out_bytes'] for r in rows)
    grand_total = total_in + total_out or 1
    for r in rows:
        r['pct'] = round(r['total_bytes'] / grand_total * 100, 2)

    return jsonify({
        "status": "ok", "range": range_, "since": since,
        "total_in": total_in, "total_out": total_out,
        "grand_total": grand_total, "ports": rows,
    })


@app.route('/api/alerts')
def api_alerts():
    thr = request.args.get('threshold', None)
    if thr is not None:
        try: thr = float(thr)
        except ValueError: thr = None
    alerts = monitor.get_alerts(thr)
    return jsonify({"alerts": alerts, "threshold": thr or monitor.alert_thresh})


# ============================================================
# API — MULTI-SWITCH TRAFFIC
# ============================================================
@app.route('/api/traffic-all')
def api_traffic_all():
    all_switches = get_all_switches()
    latest = monitor.get_all_latest()
    alerts = monitor.get_alerts()

    alert_count = {}
    for a in alerts:
        alert_count[a['sw_id']] = alert_count.get(a['sw_id'], 0) + 1

    rows = []
    for sw in all_switches:
        entry = latest.get(sw['id'])
        if entry:
            rates = list(entry['rates'].values())
            total_in  = sum(p['in_bps']  for p in rates)
            total_out = sum(p['out_bps'] for p in rates)
            active    = sum(1 for p in rates if p['oper_up'] or p['in_bps'] or p['out_bps'])
            top_port  = max(rates, key=lambda p: p['in_bps'] + p['out_bps'], default=None)
            rows.append({
                'sw_id': sw['id'], 'name': sw['name'], 'ip': sw['ip'],
                'model': sw.get('model', 'Unknown'),
                'last_status': sw.get('last_status', 'unknown'),
                'total_in': total_in, 'total_out': total_out,
                'total_bps': total_in + total_out,
                'active_ports': active, 'total_ports': len(rates),
                'top_port': top_port['name'] if top_port else None,
                'top_port_bps': (top_port['in_bps'] + top_port['out_bps']) if top_port else 0,
                'alerts': alert_count.get(sw['id'], 0),
                'age_sec': round(time.time() - entry['ts'], 1),
            })
        else:
            rows.append({
                'sw_id': sw['id'], 'name': sw['name'], 'ip': sw['ip'],
                'model': sw.get('model', 'Unknown'),
                'last_status': sw.get('last_status', 'unknown'),
                'total_in': 0, 'total_out': 0, 'total_bps': 0,
                'active_ports': 0, 'total_ports': 0,
                'top_port': None, 'top_port_bps': 0,
                'alerts': alert_count.get(sw['id'], 0),
                'age_sec': None,
            })

    rows.sort(key=lambda r: r['total_bps'], reverse=True)

    return jsonify({
        'switches': rows, 'count': len(rows),
        'total_in':  sum(r['total_in']  for r in rows),
        'total_out': sum(r['total_out'] for r in rows),
        'alerts': alerts, 'timestamp': time.time(),
    })


# ============================================================
# EXPORT (CSV)
# ============================================================
def _csv_response(filename, header, rows):
    buf = io.StringIO()
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
        return "No traffic data yet", 404

    ports = sorted(entry['rates'].values(),
                   key=lambda p: p['in_bps'] + p['out_bps'], reverse=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"traffic_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for p in ports:
        rows.append([
            p['name'], p['descr'], p['speed_mbps'],
            'Up' if p['oper_up'] else 'Down',
            p['in_bps'], p['out_bps'],
            p['in_util_pct'], p['out_util_pct'],
            round(p['in_bps'] / 1_000_000, 3),
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

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"top_talkers_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for i, p in enumerate(top, 1):
        rows.append([
            i, p['name'], p['descr'], p['speed_mbps'],
            p['in_bps'], p['out_bps'],
            round(p['in_bps'] / 1_000_000, 3),
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

    range_ = request.args.get('range', '24h')
    configs = {'1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000}
    since = int(time.time()) - configs.get(range_, 86400)
    rows_data = get_traffic_totals(sw_id, since)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"totals_{range_}_{sw['name']}_{ts}.csv".replace(" ", "_")

    rows = []
    for i, r in enumerate(rows_data, 1):
        rows.append([
            i, r['port'],
            r['in_bytes'], r['out_bytes'], r['total_bytes'],
            round(r['in_bytes'] / 1024**3, 3),
            round(r['out_bytes'] / 1024**3, 3),
            round(r['total_bytes'] / 1024**3, 3),
            r['samples'],
        ])

    header = ['Rank', 'Port', 'In (bytes)', 'Out (bytes)', 'Total (bytes)',
              'In (GB)', 'Out (GB)', 'Total (GB)', 'Samples']
    return _csv_response(filename, header, rows)


@app.route('/export/all/traffic.csv')
def export_all_traffic_csv():
    all_switches = get_all_switches()
    latest = monitor.get_all_latest()

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"all_switches_traffic_{ts}.csv"

    rows = []
    for sw in all_switches:
        entry = latest.get(sw['id'])
        if not entry:
            rows.append([sw['name'], sw['ip'], sw.get('model', ''),
                         sw.get('last_status', ''), 0, 0, 0, 0, 0, 0, ''])
            continue
        rates = list(entry['rates'].values())
        total_in  = sum(p['in_bps']  for p in rates)
        total_out = sum(p['out_bps'] for p in rates)
        active    = sum(1 for p in rates if p['oper_up'] or p['in_bps'] or p['out_bps'])
        top_port  = max(rates, key=lambda p: p['in_bps'] + p['out_bps'], default=None)
        rows.append([
            sw['name'], sw['ip'], sw.get('model', ''),
            sw.get('last_status', ''),
            len(rates), active,
            total_in, total_out,
            round(total_in / 1_000_000, 3),
            round(total_out / 1_000_000, 3),
            top_port['name'] if top_port else '',
        ])

    header = ['Name', 'IP', 'Model', 'Status', 'Total Ports', 'Active Ports',
              'IN (bps)', 'OUT (bps)', 'IN (Mbps)', 'OUT (Mbps)', 'Top Port']
    return _csv_response(filename, header, rows)


# ============================================================
# DEBUG
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


if __name__ == '__main__':
    print("\n🚀 Cisco Manager — http://127.0.0.1:5000\n")
    print(f"   Max concurrent scans: {MAX_CONCURRENT}")
    print(f"   SNMP monitor: {monitor.status()}\n")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)