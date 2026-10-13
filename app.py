from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import csv
import io
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from database import (init_db, add_switch, get_all_switches, get_switch,
                      get_switches_by_ids, search_switches, get_stats,
                      delete_switch, bulk_delete_switches, update_model,
                      update_switch_status, save_scan, get_scan)
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
# GLOBAL SCAN QUEUE + WORKER POOL
# ============================================================
MAX_CONCURRENT = 8                # 8 concurrent SSH sessions
JOB_TTL_SECONDS = 300

scan_jobs = {}                    # { sw_id: {status, progress, message, ...} }
queued_ids = []                   # FIFO queue of sw_ids pending
active_ids = set()                # currently running
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
    """Add a switch to the queue if not already queued or active."""
    with scan_lock:
        if sw_id in queued_ids or sw_id in active_ids:
            return False
        job = scan_jobs.get(sw_id)
        if job and job.get("status") == "running":
            return False
        queued_ids.append(sw_id)
        scan_jobs[sw_id] = {
            "status": "queued",
            "progress": 0,
            "message": "Queued...",
            "started_at": time.time(),
            "updated_at": time.time(),
            "model": ""
        }
    executor.submit(_queue_worker, sw_id)
    return True


def _queue_worker(sw_id):
    """Wait until concurrency slot is free, then run the scan."""
    with scan_lock:
        if sw_id in queued_ids:
            queued_ids.remove(sw_id)

    # Simple gate: allow MAX_CONCURRENT to run at once
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


# ============================================================
# SCAN LOGIC
# ============================================================
def _cmd(ssh, command, timeout=30):
    try:
        out = ssh.send_command(command, timeout=timeout) or ""
    except Exception as e:
        print(f"    [CMD ERROR] '{command}' -> {e}")
        return ""
    print(f"    [CMD OK] '{command}' -> {len(out)} chars")
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
        print(f"[SCAN {sw['ip']}] connected, model={ssh.model}")

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

        _update_job(sw_id, progress=70, message="CDP neighbors...")
        cdp = _cmd(ssh, "show cdp neighbors detail", timeout=25)

        _update_job(sw_id, progress=80, message="System logs...")
        syslogs = _cmd(ssh, "show logging", timeout=40)

        _update_job(sw_id, progress=88, message="Parsing...")

        update_model(sw_id, ssh.model)

        overview = parse_overview(running, version)
        overview["model"] = ssh.model

        status_map = parse_live_status_map(int_status) if int_status else {}
        print(f"[SCAN {sw['ip']}] status_map={len(status_map)} entries")

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
        _update_job(sw_id, status="error", message=str(e),
                    finished_at=time.time())


# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        ok, msg = add_switch(
            request.form['name'],
            request.form['ip'],
            request.form.get('enable_pass', '')
        )
        flash(msg, 'success' if ok else 'danger')
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
            if ok:
                count += 1
        flash(f"{count} switch imported successfully!", 'success')
    except Exception as e:
        flash(f"CSV Error: {str(e)}", 'danger')
    return redirect(url_for('dashboard'))


@app.route('/delete/<int:sw_id>')
def delete(sw_id):
    delete_switch(sw_id)
    flash("Switch deleted!", 'success')
    return redirect(url_for('dashboard'))


@app.route('/switch/<int:sw_id>')
def switch_detail(sw_id):
    sw = get_switch(sw_id)
    if not sw:
        flash("Switch not found!", 'danger')
        return redirect(url_for('dashboard'))
    return render_template('switch_detail.html', sw=sw)


# ============================================================
# API — LIST / SEARCH / STATS
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

    # Merge live scan status
    for r in rows:
        job = _get_job(r['id'])
        if job and job.get('status') in ('running', 'queued'):
            r['live_status'] = job['status']
            r['live_progress'] = job.get('progress', 0)
        else:
            r['live_status'] = None

    return jsonify({
        "switches": rows,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    })


@app.route('/api/stats')
def api_stats():
    s = get_stats()
    # Augment with live queue info
    with scan_lock:
        s['queue_size'] = len(queued_ids)
        s['active_count'] = len(active_ids)
    return jsonify(s)


# ============================================================
# API — SCAN (single / bulk)
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
        if _enqueue_scan(sw_id):
            queued += 1

    return jsonify({"status": "ok", "queued": queued, "total": len(ids)})


@app.route('/api/scan/<int:sw_id>/status')
def scan_status(sw_id):
    job = _get_job(sw_id)
    if not job:
        return jsonify({"status": "idle"})
    return jsonify(job)


@app.route('/api/queue-status')
def queue_status():
    with scan_lock:
        active = []
        for sw_id in list(active_ids):
            job = scan_jobs.get(sw_id, {})
            active.append({
                "sw_id": sw_id,
                "progress": job.get("progress", 0),
                "message": job.get("message", "")
            })
        return jsonify({
            "active": active,
            "active_count": len(active_ids),
            "queued_count": len(queued_ids),
            "max_concurrent": MAX_CONCURRENT
        })


# ============================================================
# API — BULK DELETE
# ============================================================
@app.route('/api/delete-bulk', methods=['POST'])
def delete_bulk():
    data = request.get_json() or {}
    ids = [int(x) for x in data.get('ids', []) if str(x).isdigit()]
    deleted = bulk_delete_switches(ids)
    return jsonify({"status": "ok", "deleted": deleted})


@app.route('/api/data/<int:sw_id>/<section>')
def get_section_data(sw_id, section):
    data = get_scan(sw_id, section)
    if not data:
        return jsonify({"status": "empty", "message": "No data yet."})
    return jsonify({"status": "success", "data": data})


@app.route('/debug/<int:sw_id>/<section>')
def debug_raw(sw_id, section):
    data = get_scan(sw_id, section)
    if not data:
        return f"<h3>No data for section '{section}'</h3>", 404
    raw = data.get('raw', '') or '(empty)'
    return (
        "<html><body style='background:#0d1117;color:#c9d1d9;padding:20px;font-family:monospace'>"
        f"<h2 style='color:#58a6ff'>Raw output: {section}</h2>"
        f"<pre style='white-space:pre-wrap;font-size:13px'>{raw}</pre>"
        "</body></html>"
    )


if __name__ == '__main__':
    print("\n🚀 Cisco Manager running on http://127.0.0.1:5000\n")
    print(f"   Max concurrent scans: {MAX_CONCURRENT}")
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)