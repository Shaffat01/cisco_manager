import paramiko
import socket
import time
import re
import warnings

warnings.filterwarnings(action='ignore', module='.*paramiko.*')

paramiko.Transport._preferred_kex = (
    'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1',
    'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha256',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'curve25519-sha256',
)
paramiko.Transport._preferred_ciphers = (
    'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
    'aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc'
)
paramiko.Transport._preferred_keys = ('ssh-rsa', 'ssh-dss')


class CiscoSSH:
    def __init__(self):
        self.client = None
        self.transport = None
        self.channel = None
        self.prompt = ""
        self.model = "Cisco Switch"

    def connect(self, ip, username, password, port=22, enable_pass=None):
        self.disconnect()

        # PATH A: Standard SSH
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=ip, port=port, username=username, password=password,
                look_for_keys=False, allow_agent=False, timeout=8, auth_timeout=8
            )
            self.channel = self.client.invoke_shell(term='vt100', width=200, height=200)
            time.sleep(1.5)

            buf = self._read_available(timeout=3)
            if "#" in buf or ">" in buf:
                self.prompt = self._extract_prompt(buf)
                self._post_login(enable_pass, password)
                return True
            self.disconnect()
        except Exception:
            self.disconnect()

        # PATH B: Transport Login (CBS350 / SG350 inner terminal)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(12)
            sock.connect((ip, port))

            self.transport = paramiko.Transport(sock)
            self.transport.start_client()

            try:
                self.transport.auth_none(username)
            except paramiko.BadAuthenticationType:
                try:
                    def handler(t, i, p):
                        return [password] * len(p)
                    self.transport.auth_interactive(username, handler)
                except Exception:
                    self.transport.auth_password(username, password)
            except Exception:
                try:
                    self.transport.auth_none("")
                except Exception:
                    self.transport.auth_password(username, password)

            self.channel = self.transport.open_session()
            self.channel.get_pty()
            self.channel.invoke_shell()
            time.sleep(2)

            login_complete = False
            start_time = time.time()

            while time.time() - start_time < 15:
                if self.channel.recv_ready():
                    output = self.channel.recv(9999).decode('utf-8', errors='ignore')
                    if "user name:" in output.lower() or "username:" in output.lower():
                        self.channel.send(username + "\r")
                    elif "password:" in output.lower():
                        self.channel.send(password + "\r")
                    elif "#" in output or ">" in output:
                        self.prompt = self._extract_prompt(output)
                        login_complete = True
                        break
                else:
                    self.channel.send("\r")
                time.sleep(1)

            if not login_complete:
                raise Exception("Login Timeout: Could not get switch prompt.")

            self._post_login(enable_pass, password)
            return True

        except Exception as e:
            self.disconnect()
            raise Exception(f"Login Failed: {str(e)}")

    def _post_login(self, enable_pass, password):
        self.channel.send("terminal length 0\r")
        time.sleep(0.4)
        self.channel.send("terminal datadump\r")
        time.sleep(0.4)
        self._read_available(timeout=2)

        if ">" in self.prompt:
            self.channel.send("enable\r")
            time.sleep(0.5)
            ep = enable_pass if enable_pass else password
            self.channel.send(ep + "\r")
            time.sleep(0.5)
            buf = self._read_available(timeout=2)
            if "#" in buf:
                self.prompt = self._extract_prompt(buf)

        ver = self.send_command("show version", timeout=15)
        self.model = self._detect_model(ver)

    def _read_available(self, timeout=2):
        output = ""
        start = time.time()
        while time.time() - start < timeout:
            if self.channel and self.channel.recv_ready():
                output += self.channel.recv(9999).decode('utf-8', errors='ignore')
            time.sleep(0.2)
        return output

    def _extract_prompt(self, text):
        lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
        if lines:
            last = lines[-1]
            if last.endswith("#") or last.endswith(">"):
                return last
        return "Switch#"

    def _detect_model(self, text):
        t = text.lower()
        if "cbs350" in t or "cbs 350" in t: return "Cisco CBS350"
        if "cbs250" in t or "cbs 250" in t: return "Cisco CBS250"
        if "sg350" in t or "sg 350" in t:   return "Cisco SG350"
        if "sg300" in t or "sg 300" in t:   return "Cisco SG300"
        if "sg250" in t or "sg 250" in t:   return "Cisco SG250"
        if "2960" in t:                     return "Cisco Catalyst 2960"
        if "3560" in t:                     return "Cisco Catalyst 3560"
        if "3750" in t:                     return "Cisco Catalyst 3750"
        if "catalyst" in t:                 return "Cisco Catalyst"
        return "Cisco Switch"

    def send_command(self, cmd, timeout=30):
        if not self.channel:
            return ""

        self._read_available(timeout=0.3)
        self.channel.send(cmd.strip() + "\r")
        time.sleep(0.5)

        output = ""
        start_time = time.time()
        prompt_re = re.compile(r'(?:^|\n)[\w\-\.]+(?:\([^\)\n]+\))?[#>]\s*$')

        while time.time() - start_time < timeout:
            if self.channel.recv_ready():
                data = self.channel.recv(9999).decode('utf-8', errors='ignore')
                output += data

                if "--More--" in data or "More:" in data or "<--- More --->" in data:
                    self.channel.send(" ")
                    time.sleep(0.1)
                    continue

                if prompt_re.search(output.strip()):
                    time.sleep(0.3)
                    while self.channel.recv_ready():
                        output += self.channel.recv(9999).decode('utf-8', errors='ignore')
                    break
            else:
                time.sleep(0.3)

        lines = output.splitlines()
        if len(lines) > 2:
            return "\n".join(lines[1:-1])
        return output

    def disconnect(self):
        try:
            if self.channel: self.channel.close()
            if self.transport: self.transport.close()
            if self.client: self.client.close()
        except Exception:
            pass
        self.channel = None
        self.transport = None
        self.client = None