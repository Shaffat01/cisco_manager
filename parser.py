import re


def clean_text(raw_text):
    if not raw_text:
        return ""
    return raw_text.replace('\r\n', '\n').replace('\r', '\n')


def normalize_port(port_name):
    """Normalizes port names: gigabitethernet1 -> gi1, GigabitEthernet1/0/1 -> gi1/0/1"""
    s = port_name.lower().strip()
    s = re.sub(r'^gigabitethernet', 'gi', s)
    s = re.sub(r'^fastethernet', 'fa', s)
    s = re.sub(r'^tengigabitethernet', 'te', s)
    s = re.sub(r'^port-channel', 'po', s)
    return s


# ============================================================
# OVERVIEW
# ============================================================
def parse_overview(running_config, version_output):
    running_config = clean_text(running_config)
    version_output = clean_text(version_output)

    data = {
        "hostname": "Unknown",
        "gateway": "N/A",
        "version": "N/A",
        "uptime": "N/A",
        "model": "N/A"
    }

    h = re.search(r'^hostname\s+(\S+)', running_config, re.IGNORECASE | re.MULTILINE)
    if h:
        data["hostname"] = h.group(1)

    g = re.search(r'ip default-gateway\s+([\d\.]+)', running_config, re.IGNORECASE)
    if g:
        data["gateway"] = g.group(1)

    for pat in [
        r'(?:Cisco IOS Software|SW version|Software Version|Version)[^\n]*?(\d+\.\d+[\w\.\(\)]*)',
        r'v(\d+\.\d+\.\d+\.\d+)',
        r'System Software Version[:\s]+(\S+)',
    ]:
        v = re.search(pat, version_output + "\n" + running_config, re.IGNORECASE)
        if v:
            data["version"] = v.group(1)
            break

    for pat in [
        r'uptime is\s+([^\n]+)',
        r'System Up Time[:\s]+([^\n]+)',
        r'Up time[:\s]+([^\n]+)',
    ]:
        u = re.search(pat, version_output, re.IGNORECASE)
        if u:
            data["uptime"] = u.group(1).strip()
            break

    for pat in [
        r'Model\s*(?:Number|Name)?[:\s]+([^\n]+)',
        r'System Description[:\s]+([^\n]+)',
        r'cisco\s+((?:WS-C|C|SG|CBS|Catalyst)\S+)',
    ]:
        m = re.search(pat, version_output, re.IGNORECASE)
        if m:
            data["model"] = m.group(1).strip()
            break

    return data


# ============================================================
# VLANS
# ============================================================
def parse_vlans(vlan_output):
    vlan_output = clean_text(vlan_output)
    vlans = []

    for line in vlan_output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        if re.match(r'^\s*-{3,}', line):
            continue
        if re.search(r'(Vlan\s+Name|VLAN\s+Name|Vlan\s+Id|VLAN\s+Id)', line, re.IGNORECASE):
            continue
        if re.search(r'Created by:', line, re.IGNORECASE):
            continue
        if re.search(r'Tagged\s+Ports', line, re.IGNORECASE) and re.search(r'UnTagged', line, re.IGNORECASE):
            continue

        m = re.match(
            r'^\s*(\d+)\s+(\S+)(?:\s+(static|dynamic|active|act/\S+|suspended|inactive|Default))?\s*(.*)$',
            line, re.IGNORECASE
        )
        if m:
            vlans.append({
                "id": m.group(1),
                "name": m.group(2),
                "status": m.group(3) or "active",
                "ports": (m.group(4) or "").strip() or "-"
            })
            continue

        m2 = re.match(
            r'^\s*(\d+)\s+(\S+)\s+([\w\s,/\.\-]*?)\s*([\w\s,/\.\-]*?)\s+([DSGRV]+)\s*$',
            line
        )
        if m2:
            untagged = m2.group(4).strip()
            tagged = m2.group(3).strip()
            ports = untagged if untagged else tagged
            vlans.append({
                "id": m2.group(1),
                "name": m2.group(2),
                "status": "active",
                "ports": ports or "-"
            })

    seen = set()
    unique = []
    for v in vlans:
        if v["id"] not in seen:
            seen.add(v["id"])
            unique.append(v)
    return unique


# ============================================================
# VLAN IPs
# ============================================================
def parse_vlan_ips(running_config):
    running_config = clean_text(running_config)
    ips = []

    pattern = re.compile(
        r'^interface\s+vlan\s*(\d+)\s*\n(.*?)(?=^interface\s|\Z)',
        re.IGNORECASE | re.MULTILINE | re.DOTALL
    )

    for m in pattern.finditer(running_config):
        vlan_id = m.group(1)
        body = m.group(2)
        ip_m = re.search(r'ip address\s+([\d\.]+)\s+([\d\.]+)', body, re.IGNORECASE)
        if ip_m:
            ips.append({
                "vlan": vlan_id,
                "ip": ip_m.group(1),
                "mask": ip_m.group(2)
            })

    return ips


# ============================================================
# RADIUS
# ============================================================
def parse_radius(running_config):
    running_config = clean_text(running_config)
    servers = []
    seen = set()

    for m in re.finditer(
        r'(?:encrypted\s+)?radius-server\s+host\s+([\d\.]+)',
        running_config, re.IGNORECASE
    ):
        ip = m.group(1)
        if ip in seen:
            continue
        seen.add(ip)
        snippet = running_config[m.start():m.start() + 300]
        has_key = bool(re.search(r'\bkey\b', snippet, re.IGNORECASE))
        servers.append({"ip": ip, "key": "Configured (Hidden)" if has_key else "Not Set"})

    for m in re.finditer(
        r'^radius\s+server\s+(\S+)\s*\n(.*?)(?=^radius\s+server\s+|\Z)',
        running_config, re.IGNORECASE | re.MULTILINE | re.DOTALL
    ):
        body = m.group(2)
        ip_m = re.search(r'address\s+ipv4\s+([\d\.]+)', body, re.IGNORECASE)
        if ip_m:
            ip = ip_m.group(1)
            if ip in seen:
                continue
            seen.add(ip)
            has_key = bool(re.search(r'^\s*key\b', body, re.IGNORECASE | re.MULTILINE))
            servers.append({"ip": ip, "key": "Configured (Hidden)" if has_key else "Not Set"})

    return servers


# ============================================================
# SNMP
# ============================================================
def parse_snmp(running_config):
    running_config = clean_text(running_config)
    data = {"communities": [], "hosts": [], "enabled": False}

    if re.search(r'snmp-server\s+(server|community)', running_config, re.IGNORECASE):
        data["enabled"] = True

    for m in re.finditer(
        r'snmp-server\s+community\s+(\S+)(?:\s+(ro|rw))?',
        running_config, re.IGNORECASE
    ):
        community = m.group(1)
        hidden = community[:9]
        data["communities"].append({
            "community": hidden,
            "access": (m.group(2) or "ro").upper(),
            "view": "Default"
        })

    for m in re.finditer(
        r'snmp-server\s+host\s+([\d\.]+)(?:\s+(\S+))?(?:\s+version\s+(\S+))?',
        running_config, re.IGNORECASE
    ):
        data["hosts"].append({
            "ip": m.group(1),
            "type": m.group(2) or "traps",
            "version": m.group(3) or "v2c"
        })

    return data


# ============================================================
# LOGGING
# ============================================================
def parse_logging(running_config, show_log_output=""):
    running_config = clean_text(running_config)
    show_log_output = clean_text(show_log_output)

    data = {"servers": [], "console": "Enabled", "buffered": "Not Set",
            "file": "Enabled", "recent_logs": ""}

    for m in re.finditer(r'logging\s+(?:host\s+)?([\d\.]+)', running_config, re.IGNORECASE):
        ip = m.group(1)
        if not any(s["ip"] == ip for s in data["servers"]):
            data["servers"].append({"ip": ip})

    if re.search(r'no logging console', running_config, re.IGNORECASE):
        data["console"] = "Disabled"
    if re.search(r'no logging file', running_config, re.IGNORECASE):
        data["file"] = "Disabled"

    b = re.search(r'logging buffered\s+(\S+)', running_config, re.IGNORECASE)
    if b:
        data["buffered"] = b.group(1)

    log_lines = show_log_output.splitlines()
    if log_lines:
        data["recent_logs"] = "\n".join(log_lines[-150:])
    else:
        data["recent_logs"] = "No logs found in switch buffer."

    return data


# ============================================================
# CDP
# ============================================================
def parse_cdp(cdp_output):
    cdp_output = clean_text(cdp_output)
    neighbors = []
    blocks = re.split(r'-{5,}|_{5,}', cdp_output)

    for block in blocks:
        if not re.search(r'Device[- ]ID', block, re.IGNORECASE):
            continue

        dev = re.search(r'Device[- ]ID:\s*(\S+)', block, re.IGNORECASE)
        plat = re.search(r'Platform:\s*(.+?)(?:,|\n|Capabilities)', block, re.IGNORECASE)
        local = re.search(r'Interface:\s*([^,\n]+)', block, re.IGNORECASE)
        remote = re.search(
            r'Port ID\s*\([^)]*\):\s*(\S+)|Port ID[^:]*:\s*(\S+)',
            block, re.IGNORECASE
        )
        ip = re.search(r'(?:IP|IPv4)\s*(?:address)?[:\s]+([\d\.]+)', block, re.IGNORECASE)
        cap = re.search(r'Capabilities:\s*([^\n]+)', block, re.IGNORECASE)

        remote_port = "N/A"
        if remote:
            remote_port = (remote.group(1) or remote.group(2) or "N/A").strip()

        neighbors.append({
            "device": dev.group(1).strip() if dev else "Unknown",
            "platform": plat.group(1).strip() if plat else "Unknown",
            "capability": cap.group(1).strip() if cap else "N/A",
            "local_port": local.group(1).strip() if local else "N/A",
            "remote_port": remote_port,
            "ip": ip.group(1).strip() if ip else "N/A"
        })

    return neighbors


# ============================================================
# LIVE STATUS MAP
# ============================================================
def parse_live_status_map(status_output):
    """
    Parses 'show interfaces status'.
    Returns {normalized_port: 'Up'|'Down'|'Disabled'}
    Works for Cisco IOS / CBS350 / SG300/350.
    """
    status_output = clean_text(status_output)
    status_map = {}

    for line in status_output.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        if re.match(r'^\s*-{3,}', line):
            continue

        parts = re.split(r'\s+', line.strip())
        if len(parts) < 2:
            continue
        if not re.match(r'^[a-zA-Z]+\s*\d', parts[0]):
            continue

        port_norm = normalize_port(parts[0])
        state = None
        for token in parts[1:]:
            t = token.lower()
            if t in ('up', 'connected'):
                state = "Up"
                break
            if t in ('down', 'notconnect', 'notconnected'):
                state = "Down"
                break
            if t in ('disabled', 'err-disabled', 'errdisabled'):
                state = "Disabled"
                break

        if state:
            status_map[port_norm] = state

    return status_map


# ============================================================
# INTERFACES
# ============================================================
def parse_interfaces(running_config, status_output="", status_map=None):
    """
    If status_map is provided, skip re-parsing status_output.
    """
    running_config = clean_text(running_config)
    if status_map is None:
        status_map = parse_live_status_map(status_output) if status_output else {}
    ints = []

    blocks = re.split(r'\ninterface\s+', running_config, flags=re.IGNORECASE)

    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines:
            continue

        port = lines[0].strip()
        if re.match(r'(vlan|port-channel|loopback|tunnel|null|range)', port, re.IGNORECASE):
            continue

        desc = "-"
        mode = "Access"
        vlans = "1"
        is_shutdown = False
        portfast = False

        for line in lines[1:]:
            lc = line.strip()
            ll = lc.lower()

            if ll.startswith("description"):
                desc = lc[11:].strip().lstrip("- ").strip() or "-"

            if "switchport mode access" in ll:
                mode = "Access"
            if "switchport access vlan" in ll:
                mode = "Access"
                vlans = ll.split()[-1]

            if "switchport mode trunk" in ll:
                mode = "Trunk"
            if "switchport trunk allowed vlan" in ll:
                mode = "Trunk"
                if "add " in ll:
                    vlans = lc.split("add ")[-1].strip()
                elif "all" in ll:
                    vlans = "All"
                else:
                    parts = lc.split()
                    vlans = parts[-1] if parts else "All"
            if "switchport trunk native vlan" in ll:
                mode = "Trunk"
                native = ll.split()[-1]
                vlans = f"{vlans} (Native {native})" if vlans not in ("1", "All") else f"Native {native}"

            if ll in ("shutdown", "disable"):
                is_shutdown = True
            if "spanning-tree portfast" in ll and not ll.startswith("no"):
                portfast = True

        port_norm = normalize_port(port)
        if is_shutdown:
            final_status = "Admin Down"
        else:
            final_status = status_map.get(port_norm, "Up" if not status_map else "Down")

        ints.append({
            "port": port,
            "description": desc,
            "mode": mode,
            "vlans": vlans,
            "status": final_status,
            "portfast": "Yes" if portfast else "No"
        })

    return ints


# ============================================================
# INTERFACE USAGE (used / unused)
# ============================================================
def parse_interface_usage(status_output, running_config, status_map=None):
    """
    If status_map is provided, skip re-parsing status_output.
    """
    status_output = clean_text(status_output)
    running_config = clean_text(running_config)

    if status_map is None:
        status_map = parse_live_status_map(status_output)

    used, unused = [], []

    # ---- Ports from running-config ----
    all_ports = []
    seen = set()
    for m in re.finditer(
        r'^\s*interface\s+((?:gigabitethernet|fastethernet|tengigabitethernet|gi|fa|te)[\w/]+)',
        running_config, re.IGNORECASE | re.MULTILINE
    ):
        p = m.group(1)
        p_norm = normalize_port(p)
        if p_norm not in seen:
            seen.add(p_norm)
            all_ports.append(p)

    # ---- Names from status output ----
    names_map = {}
    for line in status_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r'^-{3,}', line):
            continue
        if not re.match(r'^[a-zA-Z]+\s*\d', line):
            continue

        parts = re.split(r'\s{2,}', line)
        if len(parts) >= 2:
            p_norm = normalize_port(parts[0])
            cand = parts[1].strip()
            if cand and cand.lower() not in (
                '1g-copper', '1g-combo-c', '1g-combo-f',
                'connected', 'down', 'up', 'full', 'half',
                'disabled', 'notconnect', 'enabled', '--'
            ):
                names_map[p_norm] = cand

    for port in all_ports:
        p_norm = normalize_port(port)
        st = status_map.get(p_norm, "Down")
        name = names_map.get(p_norm, "-")

        entry = {
            "port": port,
            "name": name,
            "status": st,
            "vlan": "-"
        }

        if st == "Up":
            used.append(entry)
        else:
            unused.append(entry)

    return {
        "used": used,
        "unused": unused,
        "total": len(used) + len(unused)
    }