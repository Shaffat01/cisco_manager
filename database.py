import sqlite3
import json
from datetime import datetime

DB_FILE = "switches.db"


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
        last_scan_time TEXT
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

    # ---- Safe migration for existing DB ----
    for col, spec in [
        ('last_status',    "TEXT DEFAULT 'unknown'"),
        ('last_scan_time', "TEXT"),
    ]:
        try:
            c.execute(f'ALTER TABLE switches ADD COLUMN {col} {spec}')
        except sqlite3.OperationalError:
            pass  # already exists

    # ---- Indexes for 200+ switches ----
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_name    ON switches(name)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_ip      ON switches(ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_model   ON switches(model)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_switches_status  ON switches(last_status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_scan_sw_section  ON scan_data(switch_id, section)')

    conn.commit()
    conn.close()


def get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # better concurrency
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


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
    conn = get_conn()
    rows = conn.execute("SELECT * FROM switches ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_switches(query="", model="", status="", sort="id", order="desc",
                    page=1, per_page=24):
    """
    Returns (rows, total_count) with search + filter + sort + pagination.
    """
    sort_cols = {
        "id": "id", "name": "name", "ip": "ip",
        "model": "model", "status": "last_status",
        "scanned": "last_scan_time", "added": "added_date"
    }
    sort_col = sort_cols.get(sort, "id")
    order = "ASC" if order.lower() == "asc" else "DESC"

    where = []
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

    sql_where = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_conn()
    total = conn.execute(f"SELECT COUNT(*) FROM switches {sql_where}", params).fetchone()[0]

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


def get_switches_by_ids(ids):
    if not ids:
        return []
    conn = get_conn()
    placeholders = ",".join("?" * len(ids))
    rows = conn.execute(f"SELECT * FROM switches WHERE id IN ({placeholders})", ids).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_switch(sw_id):
    conn = get_conn()
    conn.execute("DELETE FROM scan_data WHERE switch_id=?", (sw_id,))
    conn.execute("DELETE FROM switches WHERE id=?", (sw_id,))
    conn.commit()
    conn.close()


def bulk_delete_switches(ids):
    if not ids:
        return 0
    conn = get_conn()
    placeholders = ",".join("?" * len(ids))
    conn.execute(f"DELETE FROM scan_data WHERE switch_id IN ({placeholders})", ids)
    deleted = conn.execute(f"DELETE FROM switches WHERE id IN ({placeholders})", ids).rowcount
    conn.commit()
    conn.close()
    return deleted


def update_model(sw_id, model):
    conn = get_conn()
    conn.execute("UPDATE switches SET model=? WHERE id=?", (model, sw_id))
    conn.commit()
    conn.close()


def update_switch_status(sw_id, status):
    """status: 'online' | 'offline' | 'scanning' | 'unknown'"""
    conn = get_conn()
    conn.execute(
        "UPDATE switches SET last_status=?, last_scan_time=? WHERE id=?",
        (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sw_id)
    )
    conn.commit()
    conn.close()


def get_stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM switches").fetchone()[0]
    online = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='online'").fetchone()[0]
    offline = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='offline'").fetchone()[0]
    scanning = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='scanning'").fetchone()[0]
    unknown = conn.execute("SELECT COUNT(*) FROM switches WHERE last_status='unknown' OR last_status IS NULL").fetchone()[0]

    models = conn.execute(
        "SELECT model, COUNT(*) as c FROM switches GROUP BY model ORDER BY c DESC"
    ).fetchall()
    conn.close()

    return {
        "total": total, "online": online, "offline": offline,
        "scanning": scanning, "unknown": unknown,
        "models": [dict(m) for m in models]
    }


def save_scan(sw_id, section, raw_data, parsed_data):
    conn = get_conn()
    conn.execute("DELETE FROM scan_data WHERE switch_id=? AND section=?", (sw_id, section))
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
            "raw": row["raw_data"],
            "parsed": json.loads(row["parsed_data"]),
            "scanned_at": row["scanned_at"]
        }
    return None