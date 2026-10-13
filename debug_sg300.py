from ssh_engine import CiscoSSH

IP = "192.168.102.6"      # <-- আপনার SG300 এর IP
USER = "root"
PASS = "WhqAcc*&^8u7y"
ENABLE = "WhqAcc*&^8u7y"

ssh = CiscoSSH()
ssh.connect(IP, USER, PASS, 22, ENABLE)

print("=" * 70)
print("1) SHOW INTERFACES STATUS")
print("=" * 70)
out1 = ssh.send_command("show interfaces status")
print(repr(out1[:2000]))     # repr দিলে whitespace exact দেখা যাবে
print()
print("=== PRETTY ===")
print(out1)

print()
print("=" * 70)
print("2) ALL INTERFACE LINES FROM RUNNING-CONFIG")
print("=" * 70)
rc = ssh.send_command("show running-config")
for line in rc.splitlines():
    if line.strip().lower().startswith("interface "):
        print(repr(line))

ssh.disconnect()