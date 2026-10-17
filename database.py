import os
import sqlite3
import json
from datetime import datetime

DB_FILE = os.environ.get("DB_FILE", "switches.db")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS switches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        ip TEXT UNIQUE NOT NULL,
        enable_pass TEXT,
        model TEXT DEFAULT 'Unknown',
        added_date TEXT,
        last_status TEXT DEFAULT 'unknown',
        last_scan_time TEXT,
        is_core INTEGER DEFAULT 0
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS scan_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        switch_id INTEGER,
        section TEXT,
        raw_data TEXT,
        parsed_data TEXT,
        scanned_at TEXT,
        FOREIGN KEY (switch_id) REFERENCES switches(id) ON DELETE CASCADE
    )''')

    # Safe migration for existing DB
    for col, spec in [
        ('last_status',    "TEXT DEFAULT 'unknown'"),
        ('last_scan_time', "TEXT"),
        ('is_core',        "INTEGER DEFAULT 0"),
    ]:
        try:
            c.execute(f'ALTER TABLE switches ADD COLUMN {col} {spec}')
        except sqlite3.OperationalError:
            pass

    # bps samples — live view / charts
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        switch_id INTEGER,
        port TEXT,
        in_bps INTEGER,
        out_bps INTEGER,
        ts INTEGER
    )''')

    # byte deltas — accounting / 24h totals
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_volume (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        switch_id INTEGER,
        port TEXT,
        in_bytes INTEGER,
        out_bytes INTEGER,
        ts INTEGER
    )''')

    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_name    ON switches(name)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_ip      ON switches(ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_model   ON switches(model)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_status  ON switches(last_status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_core    ON switches(is_core)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_scan_sw_section  ON scan_data(switch_id, section)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_th_sw_port_ts    ON traffic_history(switch_id, port, ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_th_ts            ON traffic_history(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tv_sw_port_ts    ON traffic_volume(switch_id, port, ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_tv_ts            ON traffic_volume(ts)')

    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ---------------- Switches ----------------
def add_switch(name, ip, enable_pass=""):
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO switches (name, ip, enable_pass, added_date, last_status) "
            "VALUES (?, ?, ?, ?, 'unknown')",
            (name, ip, enable_pass, datetime.now().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()
        return True, "Switch added successfully!"
    except sqlite3.IntegrityError:
        return False, f"Switch with IP {ip} already exists!"
    finally:
        conn.close()


def get_all_switches():
    """Returns ALL switches (core + non-core). Used by SNMP pollers."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM switches ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_switches(query="", model="", status="", sort="id", order="desc",
                    page=1, per_page=24):
    sort_cols = {
        "id": "id", "name": "name", "ip": "ip",
        "model": "model", "status": "last_status",
        "scanned": "last_scan_time", "added": "added_date"
    }
    sort_col = sort_cols.get(sort, "id")
    order = "ASC" if order.lower() == "asc" else "DESC"

    # ⚠️ Filter: Only show non-core switches on normal dashboard
    where = ["(is_core=0 OR is_core IS NULL)"]
    params = []
    
    if query:
        where.append("(name LIKE ? OR ip LIKE ? OR model LIKE ?)")
        like = f"%{query}%"
        params += [like, like, like]
    if model:
        where.append("model = ?")
        params.append(model)
    if status:
        where.append("last_status = ?")
        params.append(status)

    sql_where = "WHERE " + " AND ".join(where)

    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) FROM switches {sql_where}",
                         params).fetchone()[0]
    offset = (page - 1) * per_page
    rows = conn.execute(
        f"SELECT * FROM switches {sql_where} ORDER BY {sort_col} {order} LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    conn.close()

    return [dict(r) for r in rows], total


def get_switch(sw_id):
    conn = get_conn()
    row = conn.execute("SELECT * FROM switches WHERE id=?", (sw_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_core_switches():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM switches WHERE is_core=1 ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_available_for_core():
    """Returns non-core switches that can be added to Core Network."""
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, ip, model FROM switches WHERE is_core=0 OR is_core IS NULL ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def set_core_status(sw_id, is_core):
    conn = get_conn()
    conn.execute("UPDATE switches SET is_core=? WHERE id=?",
                 (1 if is_core else 0, sw_id))
    conn.commit()
    conn.close()
    return True


def delete_switch(sw_id):
    conn = get_conn()
    conn.execute("DELETE FROM scan_data WHERE switch_id=?", (sw_id,))
    conn.execute("DELETE FROM traffic_history WHERE switch_id=?", (sw_id,))
    conn.execute("DELETE FROM traffic_volume WHERE switch_id=?", (sw_id,))
    conn.execute("DELETE FROM switches WHERE id=?", (sw_id,))
    conn.commit()
    conn.close()


def bulk_delete_switches(ids):
    if not ids:
        return 0
    conn = get_conn()
    ph = ",".join("?" * len(ids))
    conn.execute(f"DELETE FROM scan_data WHERE switch_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM traffic_history WHERE switch_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM traffic_volume WHERE switch_id IN ({ph})", ids)
    deleted = conn.execute(
        f"DELETE FROM switches WHERE id IN ({ph})", ids).rowcount
    conn.commit()
    conn.close()
    return deleted


def update_model(sw_id, model):
    conn = get_conn()
    conn.execute("UPDATE switches SET model=? WHERE id=?", (model, sw_id))
    conn.commit()
    conn.close()


def update_switch_status(sw_id, status):
    conn = get_conn()
    conn.execute(
        "UPDATE switches SET last_status=?, last_scan_time=? WHERE id=?",
        (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sw_id)
    )
    conn.commit()
    conn.close()


def get_stats():
    conn = get_conn()
    # ⚠️ Only count non-core switches for normal dashboard stats
    total    = conn.execute("SELECT COUNT(*) FROM switches WHERE is_core=0 OR is_core IS NULL").fetchone()[0]
    online   = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='online' AND (is_core=0 OR is_core IS NULL)").fetchone()[0]
    offline  = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='offline' AND (is_core=0 OR is_core IS NULL)").fetchone()[0]
    scanning = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='scanning' AND (is_core=0 OR is_core IS NULL)").fetchone()[0]
    unknown  = conn.execute("SELECT COUNT(*) FROM switches WHERE (last_status='unknown' OR last_status IS NULL) AND (is_core=0 OR is_core IS NULL)").fetchone()[0]
    
    models   = conn.execute(
        "SELECT model, COUNT(*) as c FROM switches WHERE is_core=0 OR is_core IS NULL GROUP BY model ORDER BY c DESC"
    ).fetchall()
    conn.close()
    return {
        "total": total, "online": online, "offline": offline,
        "scanning": scanning, "unknown": unknown,
        "models": [dict(m) for m in models]
    }


# ---------------- Scans ----------------
def save_scan(sw_id, section, raw_data, parsed_data):
    conn = get_conn()
    conn.execute("DELETE FROM scan_data WHERE switch_id=? AND section=?",
                 (sw_id, section))
    conn.execute(
        "INSERT INTO scan_data (switch_id, section, raw_data, parsed_data, scanned_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (sw_id, section, raw_data, json.dumps(parsed_data),
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def get_scan(sw_id, section):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM scan_data WHERE switch_id=? AND section=?",
        (sw_id, section)
    ).fetchone()
    conn.close()
    if row:
        return {
            "raw":        row["raw_data"],
            "parsed":     json.loads(row["parsed_data"]),
            "scanned_at": row["scanned_at"]
        }
    return None


# ---------------- Live bps samples (traffic_history) ----------------
def save_traffic_samples(samples):
    """samples: list of (sw_id, port, in_bps, out_bps, ts)"""
    if not samples:
        return
    conn = get_conn()
    try:
        conn.executemany(
            "INSERT INTO traffic_history (switch_id, port, in_bps, out_bps, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            samples
        )
        conn.commit()
    finally:
        conn.close()


def get_traffic_history_bucketed(sw_id, port, since_ts, bucket_sec):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT (ts / ?) * ? AS bucket_ts,
               AVG(in_bps)  AS in_bps,
               AVG(out_bps) AS out_bps
        FROM traffic_history
        WHERE switch_id=? AND port=? AND ts>=?
        GROUP BY bucket_ts
        ORDER BY bucket_ts ASC
        """,
        (bucket_sec, bucket_sec, sw_id, port, since_ts)
    ).fetchall()
    conn.close()
    return [{'ts': r['bucket_ts'],
             'in_bps': int(r['in_bps'] or 0),
             'out_bps': int(r['out_bps'] or 0)} for r in rows]


def prune_traffic_history(older_than_ts):
    conn = get_conn()
    n = conn.execute("DELETE FROM traffic_history WHERE ts < ?",
                     (older_than_ts,)).rowcount
    conn.commit()
    conn.close()
    return n


# ---------------- Byte deltas (traffic_volume) ----------------
def save_volume_samples(samples):
    """samples: list of (sw_id, port, in_bytes, out_bytes, ts)"""
    if not samples:
        return
    conn = get_conn()
    try:
        conn.executemany(
            "INSERT INTO traffic_volume (switch_id, port, in_bytes, out_bytes, ts) "
            "VALUES (?, ?, ?, ?, ?)",
            samples
        )
        conn.commit()
    finally:
        conn.close()


def get_volume_totals(sw_id, since_ts):
    """
    Exact byte totals for a switch since a timestamp.
    Returns [{port, in_bytes, out_bytes, total_bytes, samples, coverage_sec}, ...]
    sorted by total_bytes DESC.
    """
    conn = get_conn()
    rows = conn.execute("""
        SELECT port,
               SUM(in_bytes)  AS sum_in,
               SUM(out_bytes) AS sum_out,
               COUNT(*)       AS n,
               MIN(ts)        AS first_ts,
               MAX(ts)        AS last_ts
        FROM traffic_volume
        WHERE switch_id=? AND ts>=?
        GROUP BY port
        ORDER BY (SUM(in_bytes) + SUM(out_bytes)) DESC
    """, (sw_id, since_ts)).fetchall()
    conn.close()

    out = []
    for r in rows:
        in_b  = int(r['sum_in']  or 0)
        out_b = int(r['sum_out'] or 0)
        coverage = (r['last_ts'] - r['first_ts']) if r['n'] > 1 else 0
        out.append({
            'port':         r['port'],
            'in_bytes':     in_b,
            'out_bytes':    out_b,
            'total_bytes':  in_b + out_b,
            'samples':      r['n'],
            'coverage_sec': coverage,
        })
    return out


def get_volume_totals_all(since_ts):
    """All-switch totals aggregated per switch."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT switch_id,
               SUM(in_bytes)  AS sum_in,
               SUM(out_bytes) AS sum_out,
               COUNT(*)       AS n
        FROM traffic_volume
        WHERE ts>=?
        GROUP BY switch_id
    """, (since_ts,)).fetchall()
    conn.close()
    return [{
        'switch_id':   r['switch_id'],
        'in_bytes':    int(r['sum_in']  or 0),
        'out_bytes':   int(r['sum_out'] or 0),
        'total_bytes': int(r['sum_in']  or 0) + int(r['sum_out'] or 0),
        'samples':     r['n'],
    } for r in rows]


def prune_volume_history(older_than_ts):
    conn = get_conn()
    n = conn.execute("DELETE FROM traffic_volume WHERE ts < ?",
                     (older_than_ts,)).rowcount
    conn.commit()
    conn.close()
    return n
