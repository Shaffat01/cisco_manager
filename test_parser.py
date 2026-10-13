from ssh_engine import CiscoSSH
from parser import parse_live_status_map, normalize_port, parse_interfaces

IP = "192.168.130.250"
USER = "root"
PASS = "WhqAcc*&^8u7y"
ENABLE = "WhqAcc*&^8u7y"

ssh = CiscoSSH()
ssh.connect(IP, USER, PASS, 22, ENABLE)

# Fetch both outputs
rc = ssh.send_command("show running-config")
st = ssh.send_command("show interfaces status")
ssh.disconnect()

print("\n" + "=" * 60)
print("STEP 1: STATUS MAP from 'show interfaces status'")
print("=" * 60)
status_map = parse_live_status_map(st)
for k in sorted(status_map):
    print(f"  {k:12} -> {status_map[k]}")
print(f"Total: {len(status_map)} entries")

print("\n" + "=" * 60)
print("STEP 2: Port names from running-config")
print("=" * 60)
import re
for m in re.finditer(
    r'^\s*interface\s+((?:gigabitethernet|fastethernet|tengigabitethernet|gi|fa|te)[\w/]+)',
    rc, re.IGNORECASE | re.MULTILINE
):
    p = m.group(1)
    p_norm = normalize_port(p)
    print(f"  {p:20} -> {p_norm:10} -> status={status_map.get(p_norm, 'NOT FOUND')}")

print("\n" + "=" * 60)
print("STEP 3: parse_interfaces() result")
print("=" * 60)
ints = parse_interfaces(rc, st)
for i in ints[:5]:
    print(f"  {i['port']:20} status={i['status']}")